package main

// ratelimit_test.go
// Core semantics for failure counts, cooldowns, and permanent-ban escalation. Focus:
//   - failCounter window boundaries
//   - failCounter reset / resetAll behavior
//   - ipBanList automatic expiry
//   - banHistory increment / reset
//   - clearSuccessfulAuthState does not clear banHistory (M3 regression)
//   - recordIPFailure triggers cooldown and permanent escalation
//   - usedStateSet TTL expiry

import (
	"fmt"
	"html/template"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- failCounter ---

func TestFailCounter_WindowBoundary(t *testing.T) {
	c := newFailCounter(time.Minute)

	c.record("a")
	c.record("a")
	c.record("a")

	if got := c.countIn("a", time.Minute); got != 3 {
		t.Errorf("countIn 1m = %d, want 3", got)
	}
	// A far-too-small zero-length window should return 0.
	if got := c.countIn("a", time.Nanosecond); got != 0 {
		t.Errorf("countIn 1ns = %d, want 0 (timestamps are older)", got)
	}
	// Different keys do not interact.
	if got := c.countIn("b", time.Minute); got != 0 {
		t.Errorf("unrelated key counted as %d, want 0", got)
	}
}

func TestFailCounter_ResetClearsKey(t *testing.T) {
	c := newFailCounter(time.Minute)
	c.record("a")
	c.record("a")
	c.reset("a")
	if got := c.countIn("a", time.Minute); got != 0 {
		t.Errorf("after reset want 0 got %d", got)
	}
}

func TestFailCounter_ResetAllClearsEverything(t *testing.T) {
	c := newFailCounter(time.Minute)
	c.record("a")
	c.record("b")
	c.record("c")
	if n := c.resetAll(); n != 3 {
		t.Errorf("resetAll returned %d, want 3", n)
	}
	if got := c.countIn("a", time.Minute); got != 0 {
		t.Errorf("after resetAll, key a should be empty, got %d", got)
	}
}

func TestFailCounter_OldEntriesIgnoredByCount(t *testing.T) {
	c := newFailCounter(time.Hour)
	c.mu.Lock()
	c.entries["k"] = []time.Time{
		time.Now().Add(-30 * time.Minute), // 30 minutes ago.
		time.Now().Add(-2 * time.Minute),  // 2 minutes ago.
		time.Now(),
	}
	c.mu.Unlock()
	if got := c.countIn("k", 5*time.Minute); got != 2 {
		t.Errorf("countIn 5m = %d, want 2 (only last 2 are within window)", got)
	}
}

// --- ipBanList ---

func TestIPBanList_AutoExpire(t *testing.T) {
	b := newIPBanList()
	b.ban("1.1.1.1", time.Millisecond)
	if !b.isBanned("1.1.1.1") {
		t.Fatal("just banned, must be banned")
	}
	time.Sleep(5 * time.Millisecond)
	if b.isBanned("1.1.1.1") {
		t.Fatal("after expiry, must not be banned")
	}
}

func TestIPBanList_ExpiryOfRespectsExpiry(t *testing.T) {
	b := newIPBanList()
	b.ban("1.1.1.1", time.Hour)
	exp, ok := b.expiryOf("1.1.1.1")
	if !ok {
		t.Fatal("expiryOf must report banned")
	}
	if !exp.After(time.Now()) {
		t.Errorf("expiry %v should be in future", exp)
	}
	// Not in the list.
	if _, ok := b.expiryOf("2.2.2.2"); ok {
		t.Error("expiryOf for unbanned IP must return ok=false")
	}
}

func TestIPBanList_UnbanReturnsWhetherWasBanned(t *testing.T) {
	b := newIPBanList()
	if b.unban("never-banned") {
		t.Error("unban of never-banned should return false")
	}
	b.ban("x", time.Hour)
	if !b.unban("x") {
		t.Error("unban of banned IP should return true")
	}
	if b.isBanned("x") {
		t.Error("after unban, should not be banned")
	}
}

// --- banHistory ---

func TestBanHistory_IncrementCounts(t *testing.T) {
	bh, err := newBanHistory("") // Memory mode, no disk writes.
	if err != nil {
		t.Fatal(err)
	}
	if bh.increment("ip-a") != 1 {
		t.Error("first increment must return 1")
	}
	if bh.increment("ip-a") != 2 {
		t.Error("second increment must return 2")
	}
	if bh.increment("ip-b") != 1 {
		t.Error("different ip starts from 1")
	}
	if bh.get("ip-a") != 2 {
		t.Errorf("get ip-a = %d, want 2", bh.get("ip-a"))
	}
}

func TestBanHistory_ResetClearsOnlyTarget(t *testing.T) {
	bh, _ := newBanHistory("")
	bh.increment("a")
	bh.increment("a")
	bh.increment("b")
	bh.reset("a")
	if bh.get("a") != 0 {
		t.Errorf("reset(a) failed: %d", bh.get("a"))
	}
	if bh.get("b") != 1 {
		t.Errorf("reset(a) leaked into b: %d", bh.get("b"))
	}
}

// --- M3 regression: clearSuccessfulAuthState must not clear banHistory ---

func TestClearSuccessfulAuthState_PreservesBanHistory(t *testing.T) {
	// Core M3 scenario: an attacker accumulated IP ban history; one legitimate login must not reset
	// that history, or permanent escalation could never be reached.
	app := mkTestApp(t)
	const ip = "5.5.5.5"
	const email = "alice@example.com"

	// Simulate this IP having already been cooled down three times in banHistory.
	app.banHistory.increment(ip)
	app.banHistory.increment(ip)
	app.banHistory.increment(ip)
	if app.banHistory.get(ip) != 3 {
		t.Fatalf("setup: banHistory should be 3, got %d", app.banHistory.get(ip))
	}

	// Also simulate current failure count and active cooldown.
	app.ipFails.record(ip)
	app.ipFails.record(ip)
	app.ipBans.ban(ip, time.Hour)
	app.authEmailFails.record(email)

	// This IP now logs in legitimately. clearSuccessfulAuthState should:
	//   - clear ipFails
	//   - clear the current ipBans cooldown
	//   - preserve banHistory, which is the core M3 fix
	r, _ := http.NewRequest("GET", "/", nil)
	r.RemoteAddr = ip + ":12345"
	prev := trustProxyHeaders
	trustProxyHeaders = false
	defer func() { trustProxyHeaders = prev }()
	sess := Session{Email: email, MAC: "aa:bb:cc:dd:ee:ff", UserIP: ip}

	app.clearSuccessfulAuthState(r, sess)

	if got := app.banHistory.get(ip); got != 3 {
		t.Errorf("banHistory MUST be preserved across legit login, got %d, want 3", got)
	}
	if app.ipBans.isBanned(ip) {
		t.Error("current cooldown should be cleared")
	}
	if app.ipFails.countIn(ip, time.Hour) != 0 {
		t.Error("ipFails should be cleared")
	}
	if app.authEmailFails.countIn(email, time.Hour) != 0 {
		t.Error("authEmailFails should be cleared")
	}
}

// --- recordIPFailure: threshold-triggered cooldown / permanent escalation ---

func TestRecordIPFailure_TriggersCooldownAtThreshold(t *testing.T) {
	app := mkTestApp(t)
	app.cfg.IPFailsLimit = 3
	app.cfg.IPFailsWindow = time.Hour
	app.cfg.IPBanDuration = time.Minute
	app.cfg.IPBanEscalateAt = 999999

	const ip = "7.7.7.7"
	app.recordIPFailure(ip, "test")
	app.recordIPFailure(ip, "test")
	if app.ipBans.isBanned(ip) {
		t.Error("at 2 fails (< limit 3) should not be banned yet")
	}
	app.recordIPFailure(ip, "test")
	if !app.ipBans.isBanned(ip) {
		t.Error("at 3 fails (== limit) should trigger cooldown")
	}
}

func TestRecordIPFailure_EscalatesToPermanent(t *testing.T) {
	app := mkTestApp(t)
	app.cfg.IPFailsLimit = 1
	app.cfg.IPFailsWindow = time.Hour
	app.cfg.IPBanDuration = time.Minute
	app.cfg.IPBanEscalateAt = 3 // Third cooldown becomes permanent.

	const ip = "8.8.8.8"

	// First time: trigger short cooldown, banHistory=1.
	app.recordIPFailure(ip, "test")
	exp, _ := app.ipBans.expiryOf(ip)
	if IsPermanent(exp) {
		t.Error("first ban must be temporary")
	}
	if app.banHistory.get(ip) != 1 {
		t.Errorf("banHistory after 1st = %d, want 1", app.banHistory.get(ip))
	}

	// Simulate cooldown expiry. Attacker fails again.
	app.ipBans.unban(ip)
	app.recordIPFailure(ip, "test")
	if app.banHistory.get(ip) != 2 {
		t.Errorf("banHistory after 2nd = %d, want 2", app.banHistory.get(ip))
	}

	// Third time: trigger permanent ban.
	app.ipBans.unban(ip)
	app.recordIPFailure(ip, "test")
	exp3, ok := app.ipBans.expiryOf(ip)
	if !ok {
		t.Fatal("third trigger should ban")
	}
	if !IsPermanent(exp3) {
		t.Errorf("third ban should be PERMANENT, got expiry %v", exp3)
	}
}

func TestRecordIPFailure_DoesNotRebanWhileCooling(t *testing.T) {
	// More failures while already cooling down should not increment banHistory or extend cooldown.
	app := mkTestApp(t)
	app.cfg.IPFailsLimit = 1
	app.cfg.IPBanDuration = time.Hour
	app.cfg.IPBanEscalateAt = 5

	const ip = "9.9.9.9"
	app.recordIPFailure(ip, "test")
	if app.banHistory.get(ip) != 1 {
		t.Fatalf("setup: banHistory should be 1, got %d", app.banHistory.get(ip))
	}

	// Already banned; record more failures.
	for i := 0; i < 5; i++ {
		app.recordIPFailure(ip, "test")
	}
	if app.banHistory.get(ip) != 1 {
		t.Errorf("banHistory should stay at 1 while cooling, got %d", app.banHistory.get(ip))
	}
}

// --- usedStateSet ---

func TestUsedStateSet_TTLAutoRefreshAfterExpiry(t *testing.T) {
	s := newUsedStateSet(20 * time.Millisecond)
	if !s.markUsed("abc") {
		t.Fatal("first markUsed must succeed")
	}
	if s.markUsed("abc") {
		t.Fatal("immediate second markUsed must fail")
	}
	time.Sleep(40 * time.Millisecond)
	if !s.markUsed("abc") {
		t.Fatal("after TTL expiry, same state should be re-acceptable")
	}
}

// --- requestIPKeys ---

func TestRequestIPKeys_DeduplicatesClientAndSessionIP(t *testing.T) {
	prev := trustProxyHeaders
	trustProxyHeaders = false
	defer func() { trustProxyHeaders = prev }()

	r, _ := http.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.1.1.1:1111"

	// Same session IP and client IP -> return one key.
	keys := requestIPKeys(r, &Session{UserIP: "1.1.1.1"})
	if len(keys) != 1 || keys[0] != "1.1.1.1" {
		t.Errorf("identical client/session IPs should dedupe, got %v", keys)
	}

	// Different session IP -> include both reverse-proxy IP and iKuai-reported IP.
	keys = requestIPKeys(r, &Session{UserIP: "2.2.2.2"})
	if len(keys) != 2 {
		t.Errorf("different IPs should both appear, got %v", keys)
	}

	// No session.
	keys = requestIPKeys(r, nil)
	if len(keys) != 1 || keys[0] != "1.1.1.1" {
		t.Errorf("no session: only client IP, got %v", keys)
	}
}

// --- proceedTokenStore ---

func TestProceedTokenStore_OneTimeConsumption(t *testing.T) {
	s := newProceedTokenStore(time.Minute)
	tok, err := s.put("/somewhere", "state-x", "u@x")
	if err != nil {
		t.Fatal(err)
	}
	e, ok := s.take(tok)
	if !ok {
		t.Fatal("first take must succeed")
	}
	if e.URL != "/somewhere" {
		t.Errorf("URL mismatch: %q", e.URL)
	}
	// Second use must fail.
	if _, ok := s.take(tok); ok {
		t.Fatal("second take of same token must fail (one-time)")
	}
}

func TestProceedTokenStore_ExpiredRejected(t *testing.T) {
	s := newProceedTokenStore(time.Millisecond)
	tok, _ := s.put("/x", "s", "u@x")
	time.Sleep(5 * time.Millisecond)
	if _, ok := s.take(tok); ok {
		t.Fatal("expired token must not be accepted")
	}
}

// --- H4 regression: admin POST must be blocked by same-origin validation ---

func TestRequireAdmin_BlocksCrossOriginPOST(t *testing.T) {
	app := mkTestApp(t)
	app.cfg.AdminEmails = []string{"admin@example.com"}

	// Cross-site Origin should be blocked even with a valid admin cookie.
	rec := httptest.NewRecorder()
	_ = writeAdminCookie(rec, app.cfg.SessionSecret, AdminSession{
		UPN: "admin@example.com",
		Exp: time.Now().Add(time.Hour).Unix(),
	}, false)

	r, _ := http.NewRequest("POST", "/admin/codes/delete-bulk",
		strings.NewReader("codes=1234"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://evil.example.com")
	for _, c := range rec.Result().Cookies() {
		r.AddCookie(c)
	}

	w := httptest.NewRecorder()
	_, ok := app.requireAdmin(w, r, true)
	if ok {
		t.Fatal("requireAdmin must reject cross-origin POST even with valid cookie")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestRequireAdmin_AllowsSameOriginPOST(t *testing.T) {
	app := mkTestApp(t)
	app.cfg.AdminEmails = []string{"admin@example.com"}

	rec := httptest.NewRecorder()
	_ = writeAdminCookie(rec, app.cfg.SessionSecret, AdminSession{
		UPN: "admin@example.com",
		Exp: time.Now().Add(time.Hour).Unix(),
	}, false)

	r, _ := http.NewRequest("POST", "/admin/codes/delete-bulk",
		strings.NewReader("codes=1234"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", app.cfg.PublicURL)
	for _, c := range rec.Result().Cookies() {
		r.AddCookie(c)
	}

	w := httptest.NewRecorder()
	_, ok := app.requireAdmin(w, r, true)
	if !ok {
		t.Errorf("requireAdmin must allow same-origin POST, got status %d", w.Code)
	}
}

func TestRequireAdmin_BlocksPOSTWithoutOriginHeader(t *testing.T) {
	// Defense in depth: modern browser form POSTs include Origin/Referer. Missing headers are usually
	// curl, forged clients, or old browsers, so reject them.
	app := mkTestApp(t)
	app.cfg.AdminEmails = []string{"admin@example.com"}

	rec := httptest.NewRecorder()
	_ = writeAdminCookie(rec, app.cfg.SessionSecret, AdminSession{
		UPN: "admin@example.com",
		Exp: time.Now().Add(time.Hour).Unix(),
	}, false)

	r, _ := http.NewRequest("POST", "/admin/codes/delete-bulk",
		strings.NewReader("codes=1234"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range rec.Result().Cookies() {
		r.AddCookie(c)
	}

	w := httptest.NewRecorder()
	_, ok := app.requireAdmin(w, r, true)
	if ok {
		t.Fatal("requireAdmin must reject POST without Origin/Referer")
	}
}

func TestRequireAdmin_AllowsGETWithoutOrigin(t *testing.T) {
	// GET for page rendering/status queries does not require Origin because many browser GETs omit it.
	app := mkTestApp(t)
	app.cfg.AdminEmails = []string{"admin@example.com"}

	rec := httptest.NewRecorder()
	_ = writeAdminCookie(rec, app.cfg.SessionSecret, AdminSession{
		UPN: "admin@example.com",
		Exp: time.Now().Add(time.Hour).Unix(),
	}, false)

	r, _ := http.NewRequest("GET", "/admin/ratelimit/status", nil)
	for _, c := range rec.Result().Cookies() {
		r.AddCookie(c)
	}

	w := httptest.NewRecorder()
	_, ok := app.requireAdmin(w, r, true)
	if !ok {
		t.Errorf("GET without Origin should pass, got %d", w.Code)
	}
}

// --- handleAuthProceed: mismatched state must be rejected ---

func TestHandleAuthProceed_StateMismatchRejected(t *testing.T) {
	app := mkTestApp(t)

	// Browser cookie has session.State = "session-state".
	rec := httptest.NewRecorder()
	sess := Session{
		State: "session-state",
		Nonce: "n",
		MAC:   "aa:bb:cc:dd:ee:ff",
		Exp:   time.Now().Add(time.Minute).Unix(),
	}
	if err := writeSessionCookie(rec, app.cfg.SessionSecret, sess, false); err != nil {
		t.Fatal(err)
	}

	// proceed token is bound to another state, simulating replay with someone else's token.
	tok, _ := app.proceedStore.put("/login?hint=victim@example.com",
		"OTHER-STATE", "victim@example.com")

	r, _ := http.NewRequest("GET", "/auth/proceed?token="+tok, nil)
	for _, c := range rec.Result().Cookies() {
		r.AddCookie(c)
	}
	rec2 := httptest.NewRecorder()
	app.handleAuthProceed(rec2, r)
	if rec2.Code != http.StatusBadRequest {
		t.Errorf("state mismatch should return 400, got %d", rec2.Code)
	}
	// Must not 302 to the real URL inside the token.
	if loc := rec2.Header().Get("Location"); strings.Contains(loc, "victim@example.com") {
		t.Errorf("must not redirect to mismatched URL: %q", loc)
	}
}

// --- clientIP / reverse-proxy trust boundary (H1 fix) ---

func TestClientIP_RightmostXFFWhenProxied(t *testing.T) {
	prev := trustProxyHeaders
	trustProxyHeaders = true
	defer func() { trustProxyHeaders = prev }()

	r, _ := http.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:54321"
	// Attacker-forged XFF plus the real client IP appended by the reverse proxy.
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8, 9.9.9.9")

	got := clientIP(r)
	if got != "9.9.9.9" {
		t.Fatalf("clientIP = %q, want %q (rightmost — nginx-appended real client)", got, "9.9.9.9")
	}
}

func TestClientIP_XRealIPWinsOverXFF(t *testing.T) {
	prev := trustProxyHeaders
	trustProxyHeaders = true
	defer func() { trustProxyHeaders = prev }()

	r, _ := http.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:54321"
	r.Header.Set("X-Real-IP", "10.0.0.1")
	r.Header.Set("X-Forwarded-For", "1.2.3.4")

	if got := clientIP(r); got != "10.0.0.1" {
		t.Fatalf("clientIP = %q, want X-Real-IP value 10.0.0.1", got)
	}
}

func TestClientIP_RejectsMalformedXRealIP(t *testing.T) {
	prev := trustProxyHeaders
	trustProxyHeaders = true
	defer func() { trustProxyHeaders = prev }()

	// An attacker injects arbitrary X-Real-IP through proxy misconfiguration. The old implementation
	// used it directly, polluting failCounter/ipBans keys and event logs. The new one falls back.
	cases := []string{
		"not-an-ip",
		"192.168.1.1; rm -rf /",
		"<script>alert(1)</script>",
		" 10.0.0.1 extra junk",
		"",
	}
	for _, val := range cases {
		r, _ := http.NewRequest("GET", "/", nil)
		r.RemoteAddr = "203.0.113.5:11111"
		r.Header.Set("X-Real-IP", val)
		if got := clientIP(r); got != "203.0.113.5" {
			t.Errorf("X-Real-IP=%q: clientIP = %q, want fallback 203.0.113.5", val, got)
		}
	}
}

func TestClientIP_RejectsMalformedXForwardedFor(t *testing.T) {
	prev := trustProxyHeaders
	trustProxyHeaders = true
	defer func() { trustProxyHeaders = prev }()

	// If the rightmost segment is invalid, scan left for the first valid IP; all invalid falls back.
	t.Run("rightmost garbage falls through to next legal", func(t *testing.T) {
		r, _ := http.NewRequest("GET", "/", nil)
		r.RemoteAddr = "203.0.113.5:11111"
		r.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8, bogus-value")
		if got := clientIP(r); got != "5.6.7.8" {
			t.Errorf("clientIP = %q, want 5.6.7.8 (skip rightmost bogus)", got)
		}
	})

	t.Run("all garbage falls back to RemoteAddr", func(t *testing.T) {
		r, _ := http.NewRequest("GET", "/", nil)
		r.RemoteAddr = "203.0.113.5:11111"
		r.Header.Set("X-Forwarded-For", "not-ip, also-not-ip")
		if got := clientIP(r); got != "203.0.113.5" {
			t.Errorf("clientIP = %q, want 203.0.113.5 (all XFF bogus)", got)
		}
	})

	t.Run("ipv6 accepted", func(t *testing.T) {
		r, _ := http.NewRequest("GET", "/", nil)
		r.RemoteAddr = "203.0.113.5:11111"
		r.Header.Set("X-Forwarded-For", "2001:db8::1")
		if got := clientIP(r); got != "2001:db8::1" {
			t.Errorf("clientIP = %q, want 2001:db8::1", got)
		}
	})
}

func TestClientIP_TrustProxyFalseIgnoresHeaders(t *testing.T) {
	prev := trustProxyHeaders
	trustProxyHeaders = false
	defer func() { trustProxyHeaders = prev }()

	r, _ := http.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.5:11111"
	r.Header.Set("X-Real-IP", "1.2.3.4")
	r.Header.Set("X-Forwarded-For", "5.6.7.8, 9.9.9.9")

	if got := clientIP(r); got != "203.0.113.5" {
		t.Fatalf("clientIP = %q, want RemoteAddr host 203.0.113.5 (headers should be ignored)", got)
	}
}

// TestBanHistory_ShutdownIsSafeConcurrentlyAndIdempotent: multiple goroutines calling shutdown()
// must not panic with close-of-closed-channel. sync.Once fixes the old select+close TOCTOU race.
func TestBanHistory_ShutdownIsSafeConcurrentlyAndIdempotent(t *testing.T) {
	dir := t.TempDir()
	bh, err := newBanHistory(filepath.Join(dir, "ratelimit-state.json"))
	if err != nil {
		t.Fatalf("newBanHistory: %v", err)
	}
	bh.increment("1.1.1.1") // Produce dirty state so shutdown takes the flush branch.

	// Trigger N concurrent shutdowns. Any panic would crash the process before t.Fatal runs.
	const N = 20
	done := make(chan error, N)
	for i := 0; i < N; i++ {
		go func() {
			defer func() {
				if r := recover(); r != nil {
					done <- fmt.Errorf("panic: %v", r)
				}
			}()
			done <- bh.shutdown()
		}()
	}
	for i := 0; i < N; i++ {
		if err := <-done; err != nil {
			t.Errorf("shutdown #%d: %v", i, err)
		}
	}
}

// --- usedStateSet (M2 OIDC state replay defense) ---

func TestUsedStateSet_BlocksReplay(t *testing.T) {
	s := newUsedStateSet(10 * time.Second)

	if !s.markUsed("abc") {
		t.Fatal("first markUsed should return true (fresh)")
	}
	if s.markUsed("abc") {
		t.Fatal("second markUsed for same state must return false (replay)")
	}
	if !s.markUsed("def") {
		t.Fatal("different state should still be accepted")
	}
}

func TestUsedStateSet_EmptyStateRejected(t *testing.T) {
	s := newUsedStateSet(time.Minute)
	if s.markUsed("") {
		t.Fatal("empty state must not be accepted")
	}
}

// --- failCounter capacity cap (H3 memory-growth DOS) ---

func TestFailCounterCapacity(t *testing.T) {
	c := newFailCounter(time.Hour)
	for i := 0; i < maxFailCounterEntries+100; i++ {
		c.record(uniqKey(i))
	}
	c.mu.Lock()
	n := len(c.entries)
	c.mu.Unlock()
	if n > maxFailCounterEntries {
		t.Fatalf("failCounter exceeded cap: %d > %d", n, maxFailCounterEntries)
	}
}

func uniqKey(i int) string {
	const alpha = "0123456789abcdef"
	buf := make([]byte, 8)
	for j := 0; j < 8; j++ {
		buf[j] = alpha[(i>>(4*j))&0xf]
	}
	return string(buf)
}

// --- helpers ---

// mkTestApp builds a minimal usable *App for rate-limit and middleware-path tests.
// It does not start gcLoop, connect OIDC, or write to disk. Templates and i18n use real files so
// renderError does not nil-panic.
func mkTestApp(t *testing.T) *App {
	t.Helper()
	loadTranslations()
	cfg := Config{
		SessionSecret: testSecret(t),
		PublicURL:     "https://wifi.test",
		// Rate-limit defaults; most tests override these.
		AuthEmailFailsShort:  5,
		AuthEmailWindowShort: 3 * time.Minute,
		AuthEmailFailsLong:   20,
		AuthEmailWindowLong:  time.Hour,
		GuestCodeMacFails:    6,
		GuestCodeMacWindow:   30 * time.Minute,
		IPFailsLimit:         20,
		IPFailsWindow:        5 * time.Minute,
		IPBanDuration:        2 * time.Minute,
		IPBanEscalateAt:      999999,
		AuthProceedTTL:       5 * time.Minute,
		TrustProxy:           true,
	}
	bh, err := newBanHistory("")
	if err != nil {
		t.Fatal(err)
	}
	dl, err := newDenylistStore("")
	if err != nil {
		t.Fatal(err)
	}
	tmpl, err := template.New("").Funcs(template.FuncMap{
		"T":        T,
		"jsonI18N": jsonI18N,
	}).ParseFS(templateFS, "templates/*.html")
	if err != nil {
		t.Fatal(err)
	}
	return &App{
		cfg:            cfg,
		denylist:       dl,
		templates:      tmpl,
		authEmailFails: newFailCounter(cfg.AuthEmailWindowLong),
		guestCodeFails: newFailCounter(cfg.GuestCodeMacWindow),
		ipFails:        newFailCounter(cfg.IPFailsWindow),
		ipBans:         newIPBanList(),
		banHistory:     bh,
		proceedStore:   newProceedTokenStore(cfg.AuthProceedTTL),
		usedStates:     newUsedStateSet(sessionTTL),
	}
}
