package main

// scale_test.go
// The properties that only matter at size, and the ones that only matter with
// more than one instance.
//
// Both classes of bug are invisible in a single-instance test with ten rows:
// a full-table read is fast when the table is small, and a per-process ban is
// indistinguishable from a shared one when there is only one process.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kazuhahub/wifi-portal/internal/dbstore"
)

// seedCodes inserts n codes with a mix of statuses, plus one redemption for
// every fourth code.
func seedCodes(t *testing.T, s *GuestCodeStore, n int) {
	t.Helper()
	now := time.Now()
	for i := range n {
		c := &GuestCode{
			Code:        fmt.Sprintf("CODE%06d", i),
			CreatedAt:   now.Add(-time.Duration(i) * time.Minute),
			DurationMin: 120,
			MaxUses:     1,
			Note:        fmt.Sprintf("desk %d", i%7),
		}
		switch i % 3 {
		case 0:
			c.ExpiresAt = now.Add(-time.Hour) // expired
		case 1:
			c.ExpiresAt = now.Add(24 * time.Hour)
		default: // never expires
		}
		if !s.Add(c) {
			t.Fatalf("seeding code %d failed", i)
		}
	}
	for i := 0; i < n; i += 4 {
		if s.Validate(fmt.Sprintf("CODE%06d", i), "aa:bb:cc:dd:ee:ff", "10.0.0.1", "") == nil {
			// Expired codes refuse redemption, which is the point of seeding a
			// mix; only the failure to redeem a *valid* one would be a problem.
			continue
		}
	}
}

// A page must be a page: the query returns what was asked for, not the table.
func TestGuestCodePageBounds(t *testing.T) {
	s := newTestGuestCodeStore(t)
	seedCodes(t, s, 120)

	first, total := s.Page(CodeQuery{Limit: 25})
	if total != 120 {
		t.Fatalf("total = %d, want 120", total)
	}
	if len(first) != 25 {
		t.Fatalf("page size = %d, want 25", len(first))
	}
	second, _ := s.Page(CodeQuery{Limit: 25, Offset: 25})
	if len(second) != 25 {
		t.Fatalf("second page size = %d", len(second))
	}
	// Pages must not overlap, or an operator paging through sees the same code
	// twice and never sees another.
	seen := map[string]bool{}
	for _, c := range append(first, second...) {
		if seen[c.Code] {
			t.Fatalf("code %s appeared on two pages", c.Code)
		}
		seen[c.Code] = true
	}
	// Newest first, matching the order the UI promises.
	if !first[0].CreatedAt.After(first[len(first)-1].CreatedAt) {
		t.Fatal("page is not ordered newest first")
	}

	last, _ := s.Page(CodeQuery{Limit: 25, Offset: 115})
	if len(last) != 5 {
		t.Fatalf("final page = %d rows, want 5", len(last))
	}
	past, _ := s.Page(CodeQuery{Limit: 25, Offset: 500})
	if len(past) != 0 {
		t.Fatalf("past the end returned %d rows", len(past))
	}
}

// The status counts and the status filter have to agree. They are two SQL
// expressions of the same rule, and when they drift the table shows a tab
// labelled "expired (40)" that opens onto 37 rows.
func TestGuestCodePageStatusMatchesStats(t *testing.T) {
	s := newTestGuestCodeStore(t)
	seedCodes(t, s, 90)

	total, used, unused, expired := s.Stats()
	if total != 90 {
		t.Fatalf("total = %d", total)
	}
	if used+unused+expired != total {
		t.Fatalf("stats do not add up: %d + %d + %d != %d", used, unused, expired, total)
	}

	for _, tc := range []struct {
		status string
		want   int
	}{
		{"used", used}, {"unused", unused}, {"expired", expired},
	} {
		rows, n := s.Page(CodeQuery{Status: tc.status, Limit: 500})
		if n != tc.want {
			t.Errorf("%s: filter counted %d, stats said %d", tc.status, n, tc.want)
		}
		for _, c := range rows {
			if c.Status() != tc.status {
				t.Errorf("%s filter returned a %s code (%s)", tc.status, c.Status(), c.Code)
			}
		}
	}
}

func TestGuestCodePageSearch(t *testing.T) {
	s := newTestGuestCodeStore(t)
	seedCodes(t, s, 40)

	// By note, case-insensitively.
	rows, n := s.Page(CodeQuery{Search: "DESK 3", Limit: 100})
	if n == 0 {
		t.Fatal("searching a note that exists found nothing")
	}
	for _, c := range rows {
		if !strings.Contains(strings.ToLower(c.Note), "desk 3") {
			t.Fatalf("search returned %q, which does not match", c.Note)
		}
	}

	// By code.
	if _, n := s.Page(CodeQuery{Search: "code000007", Limit: 10}); n != 1 {
		t.Fatalf("searching for one code matched %d rows", n)
	}
	if _, n := s.Page(CodeQuery{Search: "no such thing", Limit: 10}); n != 0 {
		t.Fatalf("a search with no matches returned %d", n)
	}
}

// The dashboard counter has to mean the same thing as the table's own idea of
// "active", or the two disagree on the same page.
func TestActiveCountMatchesUnusedFilter(t *testing.T) {
	s := newTestGuestCodeStore(t)
	seedCodes(t, s, 60)
	_, _, unused, _ := s.Stats()
	if got := s.ActiveCount(); got != unused {
		t.Fatalf("ActiveCount = %d, unused = %d", got, unused)
	}
}

func TestDenylistPaging(t *testing.T) {
	s := newTestDenylistStore(t)
	for i := range 75 {
		_, added, err := s.AddMAC(fmt.Sprintf("aa:bb:cc:00:%02x:%02x", i/256, i%256),
			fmt.Sprintf("reason %d", i%5), "ops@example.org")
		if err != nil || !added {
			t.Fatalf("seeding MAC %d failed: added=%v err=%v", i, added, err)
		}
	}
	rows, total := s.PageMACs("", 0, 20)
	if total != 75 || len(rows) != 20 {
		t.Fatalf("page: %d rows of %d total", len(rows), total)
	}
	if got := s.CountMACs(); got != 75 {
		t.Fatalf("CountMACs = %d", got)
	}
	if _, n := s.PageMACs("reason 3", 0, 100); n != 15 {
		t.Fatalf("search matched %d, want 15", n)
	}
	if _, n := s.PageMACs("nothing", 0, 100); n != 0 {
		t.Fatalf("a search with no matches returned %d", n)
	}
}

// The page-size cap is what stops a paginated endpoint being turned back into a
// full-table read by a query parameter.
func TestPageParamsCap(t *testing.T) {
	cases := []struct {
		query               string
		wantOffset, wantLim int
	}{
		{"", 0, 50},
		{"limit=10&offset=30", 30, 10},
		{"limit=1000000", 0, 500},
		{"limit=-5", 0, 50},
		{"limit=abc&offset=xyz", 0, 50},
		{"offset=-1", 0, 50},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodGet, "/admin/api/codes?"+c.query, nil)
		offset, limit := pageParams(r.URL.Query())
		if offset != c.wantOffset || limit != c.wantLim {
			t.Errorf("%q → offset=%d limit=%d, want %d/%d", c.query, offset, limit, c.wantOffset, c.wantLim)
		}
	}
}

// --- multi-instance ---

// A ban issued by one instance has to be enforced by the others. This is the
// property the in-memory map could not have, and the reason the cooldowns moved
// into the database.
func TestIPBansAreSharedBetweenInstances(t *testing.T) {
	db := testDB(t)
	a := newIPBanList(db)
	b := newIPBanList(db)

	a.ban("203.0.113.7", time.Hour)
	if !a.isBanned("203.0.113.7") {
		t.Fatal("the instance that issued the ban does not enforce it")
	}

	// The second instance's cache predates the ban; it picks it up on refresh.
	b.refresh()
	if !b.isBanned("203.0.113.7") {
		t.Fatal("a ban issued on one instance is not enforced on another")
	}

	// And lifting it propagates the same way.
	if !a.unban("203.0.113.7") {
		t.Fatal("unban reported nothing to lift")
	}
	b.refresh()
	if b.isBanned("203.0.113.7") {
		t.Fatal("an unban on one instance did not reach the other")
	}
}

// The cached view must not be stale for longer than banCacheTTL, since that is
// the window an attacker gets against the instances that did not ban them.
func TestIPBanCacheRefreshesOnItsOwn(t *testing.T) {
	db := testDB(t)
	a := newIPBanList(db)
	b := newIPBanList(db)

	a.ban("198.51.100.4", time.Hour)
	if b.isBanned("198.51.100.4") {
		// Possible only if the TTL had already elapsed between the two
		// constructor refreshes, which would make the rest of the test vacuous.
		t.Skip("the cache refreshed before the assertion could run")
	}
	// Age the cached view rather than sleeping out the TTL.
	b.mu.Lock()
	b.refreshed = time.Now().Add(-2 * banCacheTTL)
	b.mu.Unlock()
	if !b.isBanned("198.51.100.4") {
		t.Fatal("a stale cache did not refresh on read")
	}
}

// Concurrent bans of the same IP must not lose the longest one — an escalation
// to a permanent ban racing an ordinary cooldown must not be shortened by it.
func TestIPBanKeepsTheLongestExpiry(t *testing.T) {
	db := testDB(t)
	list := newIPBanList(db)

	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if i%2 == 0 {
				list.ban("192.0.2.9", 2*time.Minute)
			} else {
				list.ban("192.0.2.9", time.Until(PermanentBanUntil))
			}
		}()
	}
	wg.Wait()

	list.refresh()
	exp, ok := list.expiryOf("192.0.2.9")
	if !ok {
		t.Fatal("the IP is not banned at all")
	}
	if !IsPermanent(exp) {
		t.Fatalf("the permanent ban was overwritten by a short one: %s", exp)
	}
}

// Retention sweeps in batches, and the batching must not change the outcome:
// everything past the window goes, everything inside it stays.
func TestEventPruneBatches(t *testing.T) {
	db := testDB(t)
	log := newEventLog(db, time.Hour)

	old := time.Now().UTC().Add(-2 * time.Hour)
	rows := make([]dbstore.Event, 0, pruneBatch+250)
	for i := range pruneBatch + 250 {
		rows = append(rows, dbstore.Event{
			Time: old.Add(-time.Duration(i) * time.Second),
			Kind: KindLogin, Result: ResultSuccess, Subject: "old@example.org",
		})
	}
	for i := range 40 {
		rows = append(rows, dbstore.Event{
			Time: time.Now().UTC().Add(-time.Duration(i) * time.Minute),
			Kind: KindLogin, Result: ResultSuccess, Subject: "recent@example.org",
		})
	}
	if err := db.CreateInBatches(&rows, 500).Error; err != nil {
		t.Fatal(err)
	}

	// More than one batch, so the loop is actually exercised.
	if n := log.Prune(); n != pruneBatch+250 {
		t.Fatalf("pruned %d, want %d", n, pruneBatch+250)
	}
	if n := log.Count(EventQueryFilter{}); n != 40 {
		t.Fatalf("%d events left, want the 40 inside the window", n)
	}
	// Idempotent: a second sweep with nothing to do deletes nothing.
	if n := log.Prune(); n != 0 {
		t.Fatalf("a second sweep deleted %d", n)
	}
}
