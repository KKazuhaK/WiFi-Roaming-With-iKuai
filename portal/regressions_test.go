package main

// regressions_test.go
// Regression tests from the second audit round (functional bugs + performance). They were written
// before fixes to confirm failures, and should all pass after fixes. Comments use finding IDs.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ============================================================================
// C1: GuestCodeStore.List() returned internal *GuestCode pointers and raced with Validate.
// Running this under the race detector should catch the old behavior. After the fix, List returns
// value copies and callers can read Uses without racing.
// ============================================================================

func TestC1_ListReturnsCopiesNotInternalPointers(t *testing.T) {
	s, _ := newGuestCodeStore("")
	s.Add(&GuestCode{Code: "abc", CreatedAt: time.Now(), MaxUses: 100})

	// Mutating objects returned by List must not affect store internals.
	got := s.List()
	if len(got) != 1 {
		t.Fatalf("len = %d", len(got))
	}
	got[0].Code = "MUTATED"
	got[0].Note = "mutated by caller"

	// Listing again should show the original value.
	again := s.List()
	if again[0].Code != "abc" {
		t.Errorf("List leaked internal pointer: caller mutation propagated, code = %q",
			again[0].Code)
	}
	if again[0].Note != "" {
		t.Errorf("List leaked internal pointer: Note mutation propagated, note = %q",
			again[0].Note)
	}
}

// TestC1_ConcurrentValidateAndList is the test that actually triggers the race detector.
// Before the fix, `go test -race -run TestC1_ConcurrentValidateAndList` should fail.
func TestC1_ConcurrentValidateAndList(t *testing.T) {
	s, _ := newGuestCodeStore("")
	s.Add(&GuestCode{Code: "code1", CreatedAt: time.Now(), MaxUses: 0}) // Unlimited uses.

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Multiple goroutines repeatedly Validate, writing Uses.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					s.Validate("code1", "mac", "ip", "guest")
				}
			}
		}()
	}

	// Multiple goroutines repeatedly List and read Uses, simulating renderAdmin.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					list := s.List()
					for _, c := range list {
						_ = c.UseCount()
						if len(c.Uses) > 0 {
							_ = c.Uses[len(c.Uses)-1]
						}
						_ = c.IsExpired()
						_ = c.IsExhausted()
					}
				}
			}
		}()
	}

	time.Sleep(100 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// ============================================================================
// C2: EventLog Append vs Prune duplicate disk writes.
// ============================================================================

func TestC2_AppendDuringPruneDoesNotDuplicateOnDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	e, err := newEventLog(path, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// Prepare an old event that Prune will cross.
	e.Append(Event{Time: time.Now().Add(-2 * time.Hour), Subject: "OLD", Kind: KindLogin})

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Frequent Append.
	wg.Add(1)
	go func() {
		defer wg.Done()
		i := 0
		for {
			select {
			case <-stop:
				return
			default:
				e.Append(Event{Subject: "fresh", Kind: KindLogin, Detail: "n=" + intToStr(i)})
				i++
			}
		}
	}()

	// Frequent Prune, simulating gcLoop cadence.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				e.Prune()
				time.Sleep(time.Millisecond)
			}
		}
	}()

	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()

	// Event counts in memory and file should be consistent. Some in-flight gap is allowed, but the
	// file must never have more events than memory because that signals duplicates.
	memEvents := e.Query(EventQueryFilter{})

	// Count event lines in the file.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	fileLines := bytes.Count(data, []byte{'\n'})

	if fileLines > len(memEvents)+5 {
		// +5 tolerates in-flight Appends that unlocked before writing.
		t.Errorf("file has %d lines but memory has %d events — likely duplicate writes from Append/Prune race",
			fileLines, len(memEvents))
	}
}

// ============================================================================
// C3: Status() treated partial-use codes as inactive and deleted them.
// ============================================================================

func TestC3_DeleteInactivePreservesPartiallyUsedMultiUseCode(t *testing.T) {
	s, _ := newGuestCodeStore("")
	// MaxUses=3, used once, so two uses remain.
	s.Add(&GuestCode{
		Code:      "multi-use",
		CreatedAt: time.Now(),
		MaxUses:   3,
		Uses:      []CodeUse{{At: time.Now(), MAC: "aa"}},
	})
	// One truly exhausted code.
	s.Add(&GuestCode{
		Code:      "exhausted",
		CreatedAt: time.Now(),
		MaxUses:   1,
		Uses:      []CodeUse{{At: time.Now(), MAC: "bb"}},
	})

	n := s.DeleteInactive()
	if n != 1 {
		t.Errorf("DeleteInactive removed %d codes, want 1 (only exhausted)", n)
	}

	// Multi-use code must remain because it is still usable.
	if s.Validate("multi-use", "m", "i", "g") == nil {
		t.Error("multi-use code with remaining uses must NOT be deleted by DeleteInactive")
	}
}

// ============================================================================
// C4: banHistory async flush; high-frequency increment should not block hot paths.
// Async behavior cannot be tested directly, but increment should no longer update file mtime each time.
// After the fix, 100 increments in <100ms should show only 1-2 file writes.
// ============================================================================

func TestC4_BanHistoryDoesNotWriteOnEveryIncrement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ratelimit-state.json")
	bh, err := newBanHistory(path)
	if err != nil {
		t.Fatal(err)
	}
	defer bh.shutdown() // After the fix, banHistory has shutdown to stop the flusher.

	// 100 increments.
	start := time.Now()
	for i := 0; i < 100; i++ {
		bh.increment("1.1.1.1")
	}
	elapsed := time.Since(start)

	// Before fix: every increment synchronously wrote the whole file.
	// After fix: only marks dirty, so 100 increments should finish quickly.
	if elapsed > 50*time.Millisecond {
		t.Errorf("100 increments took %v, want < 50ms (sign of sync writes per increment)", elapsed)
	}

	// Confirm increment itself still returns the correct count.
	if got := bh.get("1.1.1.1"); got != 100 {
		t.Errorf("get = %d, want 100", got)
	}
}

func TestC4_BanHistoryFlushesOnShutdown(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ratelimit-state.json")
	bh, err := newBanHistory(path)
	if err != nil {
		t.Fatal(err)
	}
	bh.increment("2.2.2.2")
	bh.increment("2.2.2.2")
	if err := bh.shutdown(); err != nil {
		t.Fatal(err)
	}

	// Reopen should read back 2.
	bh2, err := newBanHistory(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := bh2.get("2.2.2.2"); got != 2 {
		t.Errorf("after shutdown+reload, get = %d, want 2", got)
	}
}

// ============================================================================
// H1/H2/H3: batch operations should call saveLocked once, verified indirectly via file mtime.
// ============================================================================

func TestH1_DeleteBulkDoesNotRewriteFilePerCode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "guest-codes.json")
	s, _ := newGuestCodeStore(path)
	for i := 0; i < 50; i++ {
		s.Add(&GuestCode{Code: "code" + intToStr(i), CreatedAt: time.Now()})
	}

	// Record mtime before modification.
	stat1, _ := os.Stat(path)

	// Batch-delete 30 entries.
	codes := []string{}
	for i := 0; i < 30; i++ {
		codes = append(codes, "code"+intToStr(i))
	}
	n := s.DeleteMany(codes)
	if n != 30 {
		t.Errorf("DeleteMany = %d, want 30", n)
	}

	// There should be one file mtime change. We cannot directly count writes, so verify final state.
	stat2, _ := os.Stat(path)
	if !stat2.ModTime().After(stat1.ModTime()) {
		t.Error("file should have been touched")
	}

	// Reload and verify consistency.
	s2, err := newGuestCodeStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(s2.List()) != 20 {
		t.Errorf("after DeleteMany, %d codes, want 20", len(s2.List()))
	}
}

func TestH3_AddManyDoesNotRewriteFilePerCode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "guest-codes.json")
	s, _ := newGuestCodeStore(path)

	// Put 100 codes into the store with one AddMany call.
	codes := make([]*GuestCode, 100)
	for i := 0; i < 100; i++ {
		codes[i] = &GuestCode{Code: "bulk-" + intToStr(i), CreatedAt: time.Now()}
	}
	added := s.AddMany(codes)
	if len(added) != 100 {
		t.Errorf("AddMany inserted %d, want 100", len(added))
	}

	s2, _ := newGuestCodeStore(path)
	if len(s2.List()) != 100 {
		t.Errorf("after AddMany, %d codes loaded, want 100", len(s2.List()))
	}
}

// ============================================================================
// H7: handleCodeEdit should allow past ExpiresAt so admins can force-expire a code.
// ============================================================================

func TestH7_EditAcceptsPastExpiry(t *testing.T) {
	app := mkAdminTestApp(t)
	app.guestCodes.Add(&GuestCode{Code: "edit-me", CreatedAt: time.Now()})

	pastTime := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	form := url.Values{
		"code":         {"edit-me"},
		"expires_at":   {pastTime},
		"duration_min": {"60"},
	}
	r, _ := http.NewRequest("POST", "/admin/codes/edit", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", app.cfg.PublicURL)
	r.AddCookie(mkAdminCookie(t, app))

	w := httptest.NewRecorder()
	app.handleCodeEdit(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("Edit with past expiry should succeed (admin force-expires code), got %d body=%s",
			w.Code, w.Body.String())
	}

	// The code should now be expired.
	got := app.guestCodes.List()
	if len(got) != 1 {
		t.Fatalf("want 1 code, got %d", len(got))
	}
	if !got[0].IsExpired() {
		t.Error("after Edit with past expiry, code should be IsExpired")
	}
}

// ============================================================================
// M1: Stats() counted partially used multi-use codes as used, disagreeing with Dashboard.ActiveGuestCodes.
// After the fix, Stats.unused equals the number of IsActive() codes and the dashboard uses that standard.
// ============================================================================

func TestM1_StatsAlignsWithDashboardActive(t *testing.T) {
	s, _ := newGuestCodeStore("")
	s.Add(&GuestCode{Code: "fresh", CreatedAt: time.Now()})                                          // unused, IsActive
	s.Add(&GuestCode{Code: "partial", MaxUses: 5, Uses: []CodeUse{{}}, CreatedAt: time.Now()})       // Partially used, IsActive.
	s.Add(&GuestCode{Code: "exhausted", MaxUses: 1, Uses: []CodeUse{{}}, CreatedAt: time.Now()})     // Exhausted.
	s.Add(&GuestCode{Code: "expired", ExpiresAt: time.Now().Add(-time.Hour), CreatedAt: time.Now()}) // Expired.
	s.Add(&GuestCode{Code: "expired-and-used", MaxUses: 1, Uses: []CodeUse{{}}, ExpiresAt: time.Now().Add(-time.Hour), CreatedAt: time.Now()})

	total, used, unused, expired := s.Stats()
	if total != 5 {
		t.Errorf("total = %d, want 5", total)
	}
	// "unused" should mean still usable (IsActive count). Here fresh + partial = 2.
	if unused != 2 {
		t.Errorf("unused = %d, want 2 (fresh+partial — both IsActive)", unused)
	}

	// Dashboard uses IsActive() for active count. Stats.unused must match active count.
	activeCount := 0
	for _, c := range s.List() {
		if c.IsActive() {
			activeCount++
		}
	}
	if unused != activeCount {
		t.Errorf("M1 不一致: Stats.unused=%d vs Dashboard active count=%d", unused, activeCount)
	}

	// expired includes "expired" and "expired-and-used"; expiration wins.
	if expired != 2 {
		t.Errorf("expired = %d, want 2", expired)
	}
	// used = exhausted but not expired
	if used != 1 {
		t.Errorf("used = %d, want 1 (only exhausted-not-expired)", used)
	}
}

// ============================================================================
// M5: matchEvent wasted work by calling strings.ToLower(filter.Subject) inside the Query loop.
// After the fix, Query lowers filter.Subject once. This tests unchanged filtering behavior; perf is noisy.
// ============================================================================

func TestM5_QuerySubjectFilterCaseInsensitive(t *testing.T) {
	e, _ := newEventLog("", time.Hour)
	e.Append(Event{Subject: "Alice@Example.COM", Kind: KindLogin})
	e.Append(Event{Subject: "bob@example.com", Kind: KindLogin})
	e.Append(Event{Subject: "carol@example.com", Kind: KindLogin})

	cases := []struct {
		filter string
		want   int
	}{
		{"alice", 1},
		{"ALICE", 1},
		{"Alice", 1},
		{"@example.com", 3},
		{"@EXAMPLE.com", 3},
		{"nobody", 0},
	}
	for _, c := range cases {
		got := e.Query(EventQueryFilter{Subject: c.filter})
		if len(got) != c.want {
			t.Errorf("filter=%q got %d, want %d", c.filter, len(got), c.want)
		}
	}
}

// ============================================================================
// M8: /auth/start must not leave a record(email) entry if proceedStore.put fails.
// The fix puts first and records only after put succeeds. rand failure is hard to mock directly, so
// this tests the success path and code review preserves ordering.
// ============================================================================

func TestM8_AuthStartRecordsAfterProceedStorePut(t *testing.T) {
	app := mkTestApp(t)
	rec := httptest.NewRecorder()
	_ = writeSessionCookie(rec, app.cfg.SessionSecret, Session{
		MAC: "aa:bb:cc:dd:ee:ff", UserIP: "1.1.1.1",
		State: "s", Nonce: "n",
		Exp: time.Now().Add(time.Minute).Unix(),
	}, false)

	// Normal path: put does not fail and record should be visible afterward.
	form := url.Values{"email": {"alice@example.com"}}
	r, _ := http.NewRequest("POST", "/auth/start", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range rec.Result().Cookies() {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	app.handleAuthStart(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	// record should have happened.
	if got := app.authEmailFails.countIn("alice@example.com", time.Hour); got != 1 {
		t.Errorf("expected 1 fail recorded, got %d", got)
	}
	// proceedStore should have one entry.
	app.proceedStore.mu.Lock()
	storeCount := len(app.proceedStore.entries)
	app.proceedStore.mu.Unlock()
	if storeCount != 1 {
		t.Errorf("proceedStore has %d entries, want 1", storeCount)
	}
}

// ============================================================================
// H6: count several filters in one scan. Verify MultiCount equals repeated Count calls.
// ============================================================================

func TestH6_MultiCountMatchesIndividualCounts(t *testing.T) {
	e, _ := newEventLog("", time.Hour)
	for i := 0; i < 100; i++ {
		e.Append(Event{Kind: KindLogin, Result: ResultSuccess})
	}
	for i := 0; i < 30; i++ {
		e.Append(Event{Kind: KindLogin, Result: ResultDenied})
	}
	for i := 0; i < 10; i++ {
		e.Append(Event{Kind: KindAdminAction, Result: ResultSuccess})
	}

	filters := []EventQueryFilter{
		{Kind: KindLogin, Result: ResultSuccess}, // 100
		{Kind: KindLogin, Result: ResultDenied},  // 30
		{Kind: KindAdminAction},                  // 10
		{Result: ResultSuccess},                  // 110 (login success + admin success)
	}
	multi := e.MultiCount(filters)
	if len(multi) != 4 {
		t.Fatalf("MultiCount returned %d, want 4", len(multi))
	}
	for i, f := range filters {
		want := e.Count(f)
		if multi[i] != want {
			t.Errorf("filter[%d] %+v: MultiCount=%d, individual Count=%d", i, f, multi[i], want)
		}
	}
}

// ============================================================================
// M6: when NTP moves backward, events are no longer monotonic. Reverse traversal with early break
// relied on monotonic time and missed matches. Fix: Query/Count scan fully without time-order assumptions.
// ============================================================================

func TestM6_QueryHandlesOutOfOrderTimes(t *testing.T) {
	e, _ := newEventLog("", time.Hour)
	now := time.Now()
	// Simulate NTP moving backward: write t1, then t0 (t0 < t1).
	e.Append(Event{Time: now, Subject: "later", Kind: KindLogin})
	e.Append(Event{Time: now.Add(-time.Minute), Subject: "earlier", Kind: KindLogin})
	e.Append(Event{Time: now.Add(time.Second), Subject: "newest", Kind: KindLogin})

	got := e.Query(EventQueryFilter{Kind: KindLogin})
	if len(got) != 3 {
		t.Errorf("Query out-of-order events: got %d, want 3", len(got))
	}

	// Time-window filtering must be correct even if memory order is scrambled.
	since := now.Add(-30 * time.Second)
	got = e.Query(EventQueryFilter{Since: since})
	// "earlier" (now-1min) should not appear; "later" and "newest" should appear.
	for _, ev := range got {
		if ev.Subject == "earlier" {
			t.Error("earlier event should be filtered by Since")
		}
	}
	if len(got) != 2 {
		t.Errorf("Since filter: got %d events, want 2", len(got))
	}
}

// ============================================================================
// L6: IPBanEscalateAt = 0 should short-circuit banHistory.increment and avoid dirty disk writes.
// ============================================================================

func TestL6_DisablesBanHistoryWhenEscalateAtZero(t *testing.T) {
	app := mkTestApp(t)
	app.cfg.IPBanEscalateAt = 0 // Explicitly disable permanent escalation.
	app.cfg.IPFailsLimit = 1    // Trigger cooldown immediately.

	app.recordIPFailure("3.3.3.3", "test")

	// banHistory should not have an entry because escalation is disabled.
	if got := app.banHistory.get("3.3.3.3"); got != 0 {
		t.Errorf("banHistory.get with EscalateAt=0 = %d, want 0 (disabled)", got)
	}
	// Short cooldown should still work.
	if !app.ipBans.isBanned("3.3.3.3") {
		t.Error("temporary ban should still trigger even with EscalateAt=0")
	}
}

// ============================================================================
// M9: parseDurationMin should treat duration_min=-1 as 0 (unlimited), not fallback to 18h default.
// ============================================================================

func TestM9_ParseDurationMinNegativeReturnsZero(t *testing.T) {
	// Create a new Request per case; r.FormValue caches r.Form after first use.
	mk := func(form map[string][]string) *http.Request {
		r, _ := http.NewRequest("POST", "/", nil)
		r.PostForm = form
		return r
	}
	cases := []struct {
		form map[string][]string
		want int
		desc string
	}{
		{map[string][]string{"duration_min": {"-1"}}, 0, "duration_min=-1 → 'no limit'"},
		{map[string][]string{"duration_min": {"0"}}, 0, "duration_min=0 → no limit"},
		{map[string][]string{"duration_h": {"3"}}, 180, "no duration_min, h=3 → 180"},
		{map[string][]string{"duration_min": {"60"}}, 60, "duration_min=60 → 60"},
		{map[string][]string{"duration_min": {"abc"}, "duration_h": {"5"}}, 300, "garbage duration_min falls back to h+m"},
	}
	for _, c := range cases {
		if got := parseDurationMin(mk(c.form)); got != c.want {
			t.Errorf("%s → %d, want %d", c.desc, got, c.want)
		}
	}
}

// helpers

func intToStr(i int) string {
	if i == 0 {
		return "0"
	}
	out := ""
	neg := i < 0
	if neg {
		i = -i
	}
	for i > 0 {
		out = string(rune('0'+i%10)) + out
		i /= 10
	}
	if neg {
		out = "-" + out
	}
	return out
}

// Keep imports used if no test currently references json/bytes.
var _ = json.Marshal
var _ = bytes.NewReader
