package main

// handlers_test.go
// End-to-end HTTP handler tests for security contracts on real paths:
//   - handleCodeCreate: user-provided code length cap (M7 regression)
//   - handleCodeCreate: audit detail has only code suffix, not the full code (H2 regression)
//   - handleCodeDelete / handleCodeEdit: same audit redaction
//   - handleAuthStart: account-enumeration defense with identical email responses
//   - handleAuthStart: dual-window email failure counts
//   - handlePortal: denylisted MAC is rejected directly
//
// These tests do not hit OIDC or Duo; clients are nil to use fallback branches.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func mkAdminCookie(t *testing.T, app *App) *http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	if err := writeAdminCookie(rec, app.cfg.SessionSecret, AdminSession{
		UPN: "admin@example.com",
		Exp: time.Now().Add(time.Hour).Unix(),
	}, false); err != nil {
		t.Fatal(err)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("want 1 cookie, got %d", len(cookies))
	}
	return cookies[0]
}

func mkAdminTestApp(t *testing.T) *App {
	t.Helper()
	app := mkTestApp(t)
	app.cfg.AdminEmails = []string{"admin@example.com"}
	gc, err := newGuestCodeStore("")
	if err != nil {
		t.Fatal(err)
	}
	app.guestCodes = gc
	policies, err := newIKuaiPolicyStore(map[IKuaiAuthProfile]IKuaiPolicy{
		IKuaiProfileSSO: {}, IKuaiProfileDuo: {}, IKuaiProfileGuest: {},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	app.ikuaiPolicies = policies
	app.eventLog, _ = newEventLog("", time.Hour)
	return app
}

// adminPOST builds a POST request with a valid admin cookie and same-origin Origin.
func adminPOST(t *testing.T, app *App, path string, form url.Values) *http.Request {
	t.Helper()
	r, _ := http.NewRequest("POST", path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", app.cfg.PublicURL)
	r.AddCookie(mkAdminCookie(t, app))
	return r
}

// --- handleCodeCreate ---

func TestHandleCodeCreate_RejectsLongCode(t *testing.T) {
	// M7 regression: user-provided code must not exceed 64 chars.
	app := mkAdminTestApp(t)
	form := url.Values{
		"code": {strings.Repeat("a", 65)},
	}
	w := httptest.NewRecorder()
	app.handleCodeCreate(w, adminPOST(t, app, "/admin/codes/create", form))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for over-long code", w.Code)
	}
}

// TestHandleCodeCreate_RejectsShortCode: audit #9.
// When an admin-provided code is too short (<6 chars), tailN(code, 4) is almost the full code,
// effectively persisting the short code in event logs. Reject it and require at least 6 chars.
func TestHandleCodeCreate_RejectsShortCode(t *testing.T) {
	app := mkAdminTestApp(t)
	for _, short := range []string{"1", "12", "123", "1234", "12345"} {
		form := url.Values{"code": {short}}
		w := httptest.NewRecorder()
		app.handleCodeCreate(w, adminPOST(t, app, "/admin/codes/create", form))
		if w.Code != http.StatusBadRequest {
			t.Errorf("short code %q: status = %d, want 400", short, w.Code)
		}
	}
	// Six chars and above are accepted.
	form := url.Values{"code": {"abcdef"}}
	w := httptest.NewRecorder()
	app.handleCodeCreate(w, adminPOST(t, app, "/admin/codes/create", form))
	if w.Code != http.StatusOK {
		t.Errorf("6-char code: status = %d, want 200, body=%s", w.Code, w.Body.String())
	}
}

// TestHandleCodeCreate_AuditDoesNotLeakFullCode is the H2 regression.
// Creating a guest code must not write the full code into audit detail.
func TestHandleCodeCreate_AuditDoesNotLeakFullCode(t *testing.T) {
	app := mkAdminTestApp(t)
	const myCode = "VERY-SECRET-CODE-1234"
	form := url.Values{
		"code":         {myCode},
		"duration_min": {"60"},
	}
	w := httptest.NewRecorder()
	app.handleCodeCreate(w, adminPOST(t, app, "/admin/codes/create", form))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	events := app.eventLog.Query(EventQueryFilter{Kind: KindAdminAction})
	if len(events) != 1 {
		t.Fatalf("want 1 admin event, got %d", len(events))
	}
	detail := events[0].Detail
	if strings.Contains(detail, myCode) {
		t.Errorf("audit detail leaked full code: %q", detail)
	}
	// Should include code-suffix wording.
	if !strings.Contains(detail, "code-suffix=") {
		t.Errorf("detail missing 'code-suffix=': %q", detail)
	}
	// Last four chars (1234) should appear.
	if !strings.Contains(detail, "1234") {
		t.Errorf("detail missing last 4 chars: %q", detail)
	}
}

func TestHandleCodeDelete_AuditUsesSuffix(t *testing.T) {
	// H2 regression: delete audit also keeps only the last four chars.
	app := mkAdminTestApp(t)
	app.guestCodes.Add(&GuestCode{
		Code:      "AAAA-BBBB-CCCC-DDDD",
		CreatedAt: time.Now(),
	})
	form := url.Values{"code": {"AAAA-BBBB-CCCC-DDDD"}}
	w := httptest.NewRecorder()
	app.handleCodeDelete(w, adminPOST(t, app, "/admin/codes/delete", form))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	events := app.eventLog.Query(EventQueryFilter{Kind: KindAdminAction})
	if len(events) != 1 {
		t.Fatalf("want 1 event, got %d", len(events))
	}
	if strings.Contains(events[0].Detail, "AAAA-BBBB") {
		t.Errorf("delete audit leaked full code: %q", events[0].Detail)
	}
	if !strings.Contains(events[0].Detail, "DDDD") {
		t.Errorf("delete audit missing suffix DDDD: %q", events[0].Detail)
	}
}

// --- handleAuthStart account-enumeration defense ---

func TestHandleAuthStart_OpaqueResponseRegardlessOfDuoStatus(t *testing.T) {
	// Key design: /auth/start returns the same shape for all valid emails (opaque token), so attackers
	// cannot use response differences to detect Duo enrollment. duo=nil uses SSO fallback here.
	app := mkTestApp(t)

	// /auth/start requires a valid wifi session cookie first.
	rec := httptest.NewRecorder()
	sess := Session{
		MAC:    "aa:bb:cc:dd:ee:ff",
		UserIP: "192.168.1.10",
		State:  "s", Nonce: "n",
		Lang: "en",
		Exp:  time.Now().Add(time.Minute).Unix(),
	}
	if err := writeSessionCookie(rec, app.cfg.SessionSecret, sess, false); err != nil {
		t.Fatal(err)
	}

	bodyOf := func(email string) (int, string) {
		form := url.Values{"email": {email}}
		r, _ := http.NewRequest("POST", "/auth/start", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for _, c := range rec.Result().Cookies() {
			r.AddCookie(c)
		}
		w := httptest.NewRecorder()
		app.handleAuthStart(w, r)
		body, _ := io.ReadAll(w.Result().Body)
		return w.Code, string(body)
	}

	for _, email := range []string{"alice@example.com", "bob@example.com", "anyone@test.org"} {
		code, body := bodyOf(email)
		if code != http.StatusOK {
			t.Errorf("email=%q got status %d, body=%s", email, code, body)
			continue
		}
		// Response must contain only redirect, not email information or deny signals.
		if !strings.Contains(body, "/auth/proceed?token=") {
			t.Errorf("email=%q response missing opaque token: %s", email, body)
		}
		if strings.Contains(body, "duo") || strings.Contains(body, "deny") {
			t.Errorf("email=%q response leaked Duo/deny signal: %s", email, body)
		}
	}
}

func TestHandleAuthStart_RejectsInvalidEmail(t *testing.T) {
	app := mkTestApp(t)
	rec := httptest.NewRecorder()
	_ = writeSessionCookie(rec, app.cfg.SessionSecret, Session{
		MAC: "aa", UserIP: "1.1.1.1",
		State: "s", Nonce: "n",
		Exp: time.Now().Add(time.Minute).Unix(),
	}, false)

	cases := []string{
		"",
		"not-an-email",
		"two@@at.com",
		"with space@x.com",
		strings.Repeat("a", 300) + "@x.com",
	}
	for _, email := range cases {
		form := url.Values{"email": {email}}
		r, _ := http.NewRequest("POST", "/auth/start", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for _, c := range rec.Result().Cookies() {
			r.AddCookie(c)
		}
		w := httptest.NewRecorder()
		app.handleAuthStart(w, r)
		if w.Code != http.StatusBadRequest {
			t.Errorf("email=%q got %d, want 400", email, w.Code)
		}
	}
}

func TestHandleAuthStart_RejectsGET(t *testing.T) {
	app := mkTestApp(t)
	r, _ := http.NewRequest("GET", "/auth/start", nil)
	w := httptest.NewRecorder()
	app.handleAuthStart(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET should be 405, got %d", w.Code)
	}
}

// --- handlePortal MAC denylist ---

func TestHandlePortal_BlocksDeniedMAC(t *testing.T) {
	app := mkTestApp(t)
	app.denylist.AddMAC("aa:bb:cc:dd:ee:ff", "abuse", "admin")

	// Simulate iKuai redirect and an existing cookie carrying this MAC.
	rec := httptest.NewRecorder()
	_ = writeSessionCookie(rec, app.cfg.SessionSecret, Session{
		MAC:    "aa:bb:cc:dd:ee:ff",
		UserIP: "192.168.1.10",
		State:  "s", Nonce: "n",
		Exp: time.Now().Add(time.Minute).Unix(),
	}, false)

	r, _ := http.NewRequest("GET", "/portal", nil)
	for _, c := range rec.Result().Cookies() {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	app.handlePortal(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("denied MAC should get 403, got %d", w.Code)
	}
}

// --- handleAdminLoginStart M6 regression ---

// --- Pure function / helper tests (M1, M7, L3 fix paths) ---

func TestCapLen(t *testing.T) {
	cases := []struct {
		in   string
		n    int
		want string
	}{
		{"", 5, ""},
		{"abc", 5, "abc"},
		{"abcdef", 3, "abc"},
		{"abc", 3, "abc"},
	}
	for _, c := range cases {
		if got := capLen(c.in, c.n); got != c.want {
			t.Errorf("capLen(%q, %d) = %q, want %q", c.in, c.n, got, c.want)
		}
	}
}

func TestIsLoopbackListen(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:28080", true},
		{"localhost:28080", true},
		{"[::1]:28080", true},
		{"0.0.0.0:28080", false},
		{":28080", false},
		{"203.0.113.5:28080", false},
		{"not_an_addr", false},
	}
	for _, c := range cases {
		if got := isLoopbackListen(c.addr); got != c.want {
			t.Errorf("isLoopbackListen(%q) = %v, want %v", c.addr, got, c.want)
		}
	}
}

func TestIsSameOriginRequest(t *testing.T) {
	app := &App{cfg: Config{PublicURL: "https://wifi.example.com"}}

	cases := []struct {
		name    string
		origin  string
		referer string
		want    bool
	}{
		{"matching Origin", "https://wifi.example.com", "", true},
		{"matching Origin trailing slash", "https://wifi.example.com/", "", true},
		{"foreign Origin", "https://evil.com", "", false},
		{"http vs https", "http://wifi.example.com", "", false},
		{"matching Referer", "", "https://wifi.example.com/admin", true},
		{"foreign Referer", "", "https://evil.com/x", false},
		{"both missing → reject", "", "", false},
		{"Origin overrides Referer", "https://wifi.example.com", "https://evil.com/x", true},
		{"foreign Origin even with good Referer", "https://evil.com", "https://wifi.example.com/admin", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, _ := http.NewRequest("POST", "/admin/codes/create", nil)
			if c.origin != "" {
				r.Header.Set("Origin", c.origin)
			}
			if c.referer != "" {
				r.Header.Set("Referer", c.referer)
			}
			if got := app.isSameOriginRequest(r); got != c.want {
				t.Errorf("origin=%q referer=%q → %v, want %v", c.origin, c.referer, got, c.want)
			}
		})
	}
}

func TestParseDurationMinClamp(t *testing.T) {
	r, _ := http.NewRequest("POST", "/", nil)
	r.PostForm = map[string][]string{
		"duration_h": {"99999999999"}, // Far beyond reasonable input.
		"duration_m": {"0"},
	}
	got := parseDurationMin(r)
	if got < 0 || got > maxDurationMin {
		t.Fatalf("parseDurationMin overflow / out of range: got %d, expected 0..%d", got, maxDurationMin)
	}
}

// --- DATA_DIR / init subcommand (mode D bare-binary deployment) ---

func TestMakeDataPaths_DefaultData(t *testing.T) {
	p := makeDataPaths("/data")
	if p.GuestCodes != "/data/guest-codes.json" {
		t.Errorf("guest path: %q", p.GuestCodes)
	}
	if p.EventLog != "/data/events.jsonl" {
		t.Errorf("event log path: %q", p.EventLog)
	}
}

func TestMakeDataPaths_OverrideDir(t *testing.T) {
	p := makeDataPaths("/var/lib/wifi-portal")
	wants := map[string]string{
		"guest":    "/var/lib/wifi-portal/guest-codes.json",
		"denylist": "/var/lib/wifi-portal/denylist.json",
		"policy":   "/var/lib/wifi-portal/ikuai-policy.json",
		"banhist":  "/var/lib/wifi-portal/ratelimit-state.json",
		"events":   "/var/lib/wifi-portal/events.jsonl",
	}
	got := map[string]string{
		"guest":    p.GuestCodes,
		"denylist": p.Denylist,
		"policy":   p.IKuaiPolicy,
		"banhist":  p.BanHistory,
		"events":   p.EventLog,
	}
	for k, want := range wants {
		if got[k] != want {
			t.Errorf("%s = %q, want %q", k, got[k], want)
		}
	}
}

func TestRunInit_RejectsPositional(t *testing.T) {
	dir := t.TempDir()
	if err := runInit([]string{dir}); err == nil {
		t.Error("positional arg should be rejected with clear error")
	}
}

func TestRunInit_CustomPathsFlowIntoUnit(t *testing.T) {
	dir := t.TempDir()
	if err := runInit([]string{
		"--out-dir", dir,
		"--conf-dir", "/etc/wifi-portal",
		"--data-dir", "/srv/wifi-portal",
		"--bin-path", "/opt/wp/bin",
	}); err != nil {
		t.Fatal(err)
	}
	unit, _ := os.ReadFile(dir + "/wifi-portal.service")
	s := string(unit)
	for _, want := range []string{
		"EnvironmentFile=/etc/wifi-portal/wifi-portal.env",
		"ReadWritePaths=/srv/wifi-portal",
		"ExecStart=/opt/wp/bin",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("systemd unit missing %q\n--- unit ---\n%s", want, s)
		}
	}
	env, _ := os.ReadFile(dir + "/wifi-portal.env")
	if !strings.Contains(string(env), "DATA_DIR=/srv/wifi-portal") {
		t.Error(".env should set DATA_DIR matching --data-dir")
	}
}

func TestRunInit_WritesFiles(t *testing.T) {
	dir := t.TempDir()
	if err := runInit([]string{"--out-dir", dir}); err != nil {
		t.Fatal(err)
	}

	// .env should exist with 0600 mode because it contains secrets.
	envPath := dir + "/wifi-portal.env"
	info, err := os.Stat(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Errorf(".env mode = %o, want no group/other access", info.Mode().Perm())
	}
	// Content should include .env.example plus init header.
	data, _ := os.ReadFile(envPath)
	if !strings.Contains(string(data), "wifi-portal init") {
		t.Error(".env missing init header")
	}
	if !strings.Contains(string(data), "TENANT_ID") {
		t.Error(".env missing embedded template (TENANT_ID)")
	}

	// systemd unit should exist with 0644 mode because systemd reads it.
	servicePath := dir + "/wifi-portal.service"
	info, err = os.Stat(servicePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf(".service mode = %o, want 0644", info.Mode().Perm())
	}
	data, _ = os.ReadFile(servicePath)
	if !strings.Contains(string(data), "[Unit]") || !strings.Contains(string(data), "[Service]") {
		t.Errorf(".service file missing systemd sections")
	}
}

func TestLooksUninitialized(t *testing.T) {
	keys := []string{"TENANT_ID", "CLIENT_ID", "CLIENT_SECRET", "IKUAI_APPKEY", "PUBLIC_URL", "SESSION_SECRET"}

	// Backup and clear all key env vars.
	saved := map[string]string{}
	for _, k := range keys {
		saved[k] = os.Getenv(k)
		os.Unsetenv(k)
	}
	defer func() {
		for k, v := range saved {
			if v == "" {
				os.Unsetenv(k)
			} else {
				os.Setenv(k, v)
			}
		}
	}()

	// All empty -> uninitialized.
	if !looksUninitialized() {
		t.Error("all empty env should report uninitialized")
	}

	// Any one set -> initialized; mustEnv will report the specific missing key.
	os.Setenv("TENANT_ID", "xxx")
	if looksUninitialized() {
		t.Error("partial env should NOT trigger first-run (mustEnv reports specific missing key)")
	}
	os.Unsetenv("TENANT_ID")

	// Whitespace does not count as set.
	os.Setenv("PUBLIC_URL", "   ")
	if !looksUninitialized() {
		t.Error("whitespace-only env should still be considered empty")
	}
}

func TestRunInit_DoesNotOverwriteExisting(t *testing.T) {
	dir := t.TempDir()
	envPath := dir + "/wifi-portal.env"
	if err := os.WriteFile(envPath, []byte("MY-EXISTING-CONFIG=xxx\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runInit([]string{"--out-dir", dir}); err != nil {
		t.Fatal(err)
	}
	// .env should keep original content.
	data, _ := os.ReadFile(envPath)
	if string(data) != "MY-EXISTING-CONFIG=xxx\n" {
		t.Errorf("existing .env was overwritten: %q", string(data))
	}
	// systemd unit did not exist and should be written.
	if _, err := os.Stat(dir + "/wifi-portal.service"); err != nil {
		t.Error(".service should be written when missing")
	}
}

func TestHandleAdminLoginStart_RejectsGET(t *testing.T) {
	// M6 regression: GET must not write cookies. After POST-only enforcement, GET returns 405.
	app := mkAdminTestApp(t)
	r, _ := http.NewRequest("GET", "/admin/login/start", nil)
	w := httptest.NewRecorder()
	app.handleAdminLoginStart(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET to /admin/login/start should be 405, got %d", w.Code)
	}
	// No cookie should be written.
	if len(w.Result().Cookies()) > 0 {
		t.Error("GET must not set any cookie")
	}
}
