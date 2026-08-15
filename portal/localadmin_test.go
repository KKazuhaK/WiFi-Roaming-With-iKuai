package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kazuhahub/wifi-portal/internal/dbstore"
)

const goodPassword = "correct-horse-battery-staple"

func TestPasswordHashRoundTrip(t *testing.T) {
	hash, err := hashPassword(goodPassword)
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	if strings.Contains(hash, goodPassword) {
		t.Fatalf("the password appears in its own hash: %q", hash)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("hash is not argon2id: %q", hash)
	}
	if !verifyPassword(goodPassword, hash) {
		t.Error("the correct password did not verify")
	}
	if verifyPassword("wrong-password-entirely", hash) {
		t.Error("a wrong password verified")
	}
	// A near miss must fail as decisively as a wild guess.
	if verifyPassword(goodPassword+"x", hash) {
		t.Error("a one-character-longer password verified")
	}
}

func TestPasswordHashIsSalted(t *testing.T) {
	a, _ := hashPassword(goodPassword)
	b, _ := hashPassword(goodPassword)
	if a == b {
		t.Error("two hashes of the same password are identical; the salt is not random")
	}
	// Both must still verify — a salt that is not stored is worse than none.
	if !verifyPassword(goodPassword, a) || !verifyPassword(goodPassword, b) {
		t.Error("a salted hash failed to verify")
	}
}

func TestVerifyPasswordRejectsMalformedHashes(t *testing.T) {
	// A malformed stored hash must fail closed rather than panic or, worse,
	// match everything.
	for _, bad := range []string{
		"", "not-a-hash", "$argon2id$", "$argon2i$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA",
		"$argon2id$v=19$m=65536,t=3,p=4$!!!$aGFzaA",
		"$argon2id$v=19$bad-params$c2FsdA$aGFzaA",
	} {
		if verifyPassword(goodPassword, bad) {
			t.Errorf("malformed hash %q verified", bad)
		}
	}
}

func TestCheckPasswordStrength(t *testing.T) {
	if err := checkPasswordStrength("short"); err == nil {
		t.Error("a 5-character password was accepted")
	}
	if err := checkPasswordStrength("123456789012"); err != nil {
		t.Errorf("a 12-character password was rejected: %v", err)
	}
	// Length is counted in runes, not bytes: a Chinese passphrase of twelve
	// characters is 36 bytes and must not pass on that basis alone.
	if err := checkPasswordStrength("密码密码密码"); err == nil {
		t.Error("a 6-rune password passed; length is being counted in bytes")
	}
}

func TestAuthenticateLocalAdmin(t *testing.T) {
	db := testDB(t)
	if err := createLocalAdmin(db, "Alice", goodPassword); err != nil {
		t.Fatalf("createLocalAdmin: %v", err)
	}

	// Usernames are stored and matched lower-case.
	upn, err := authenticateLocalAdmin(db, "ALICE", goodPassword)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if upn != "alice" {
		t.Errorf("username = %q, want the normalised form", upn)
	}

	if _, err := authenticateLocalAdmin(db, "alice", "wrong"); err == nil {
		t.Error("a wrong password authenticated")
	}
	// An unknown account must fail the same way, so the endpoint cannot be used
	// to discover which usernames exist.
	_, unknownErr := authenticateLocalAdmin(db, "nobody", goodPassword)
	_, wrongErr := authenticateLocalAdmin(db, "alice", "wrong")
	if unknownErr == nil || wrongErr == nil {
		t.Fatal("both failure paths must error")
	}
	if unknownErr.Error() != wrongErr.Error() {
		t.Errorf("unknown-user error %q differs from wrong-password error %q; that is an enumeration oracle",
			unknownErr, wrongErr)
	}
}

func TestAuthenticateLocalAdminLocksOut(t *testing.T) {
	db := testDB(t)
	if err := createLocalAdmin(db, "bob", goodPassword); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < localAdminMaxFailures; i++ {
		if _, err := authenticateLocalAdmin(db, "bob", "wrong"); err == nil {
			t.Fatalf("attempt %d: a wrong password authenticated", i)
		}
	}

	// Now even the correct password is refused — the per-IP limiter cannot bound
	// this on its own, because an attacker with many IPs has only one username
	// worth guessing.
	_, err := authenticateLocalAdmin(db, "bob", goodPassword)
	if err == nil {
		t.Fatal("the account was not locked after the failure threshold")
	}
	if !strings.Contains(err.Error(), "locked") {
		t.Errorf("error = %q, want it to say the account is locked", err)
	}

	// A lockout has to expire on its own; an operator locked out by their own
	// typo during an outage must not need a second recovery tool.
	var row dbstore.LocalAdmin
	if err := db.Where("username = ?", "bob").First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.LockedUntil == nil {
		t.Fatal("LockedUntil was not set")
	}
	past := time.Now().UTC().Add(-time.Minute)
	row.LockedUntil = &past
	if err := db.Save(&row).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := authenticateLocalAdmin(db, "bob", goodPassword); err != nil {
		t.Errorf("after the lockout expired, the correct password was still refused: %v", err)
	}
}

func TestAuthenticateLocalAdminSuccessClearsFailures(t *testing.T) {
	db := testDB(t)
	if err := createLocalAdmin(db, "carol", goodPassword); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < localAdminMaxFailures-1; i++ {
		authenticateLocalAdmin(db, "carol", "wrong") //nolint:errcheck
	}
	if _, err := authenticateLocalAdmin(db, "carol", goodPassword); err != nil {
		t.Fatalf("a correct password below the threshold was refused: %v", err)
	}

	var row dbstore.LocalAdmin
	db.Where("username = ?", "carol").First(&row)
	if row.FailedAttempts != 0 {
		t.Errorf("FailedAttempts = %d after a success, want 0 — otherwise the counter accumulates across weeks and locks out a legitimate operator", row.FailedAttempts)
	}
	if row.LastLoginAt == nil {
		t.Error("LastLoginAt was not recorded")
	}
}

func TestDisabledAccountCannotAuthenticate(t *testing.T) {
	db := testDB(t)
	if err := createLocalAdmin(db, "dave", goodPassword); err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&dbstore.LocalAdmin{}).Where("username = ?", "dave").
		Update("enabled", false).Error; err != nil {
		t.Fatal(err)
	}
	_, err := authenticateLocalAdmin(db, "dave", goodPassword)
	if !errors.Is(err, errLocalAdminDisabled) {
		t.Errorf("error = %v, want errLocalAdminDisabled", err)
	}
}

func TestLocalAdminAllowedFrom(t *testing.T) {
	cases := []struct {
		spec  string
		ip    string
		allow bool
	}{
		{"", "8.8.8.8", true}, // No restriction configured.
		{"10.0.0.0/8", "10.1.2.3", true},
		{"10.0.0.0/8", "192.168.1.1", false},
		{"10.0.0.0/8,192.168.0.0/16", "192.168.1.1", true},
		{"127.0.0.1", "127.0.0.1", true}, // A bare address is a host route.
		{"127.0.0.1", "127.0.0.2", false},
		{"::1", "::1", true},
		{"10.0.0.0/8", "not-an-ip", false},
	}
	for _, c := range cases {
		nets, err := localAdminAllowedFrom(c.spec)
		if err != nil {
			t.Errorf("localAdminAllowedFrom(%q): %v", c.spec, err)
			continue
		}
		if got := ipAllowed(nets, c.ip); got != c.allow {
			t.Errorf("spec %q, ip %q: allowed = %v, want %v", c.spec, c.ip, got, c.allow)
		}
	}

	if _, err := localAdminAllowedFrom("not a network"); err == nil {
		t.Error("a malformed network spec was accepted; it would 404 the login page during an outage")
	}
}

// The endpoint must be invisible, not merely refused, when local login is off —
// a deployment that does not use it should not advertise that the mechanism
// exists.
func TestLocalAdminEndpointIsInvisibleWhenDisabled(t *testing.T) {
	app := mkTestApp(t)
	app.db = testDB(t)
	cfg := *app.conf()
	cfg.LocalAdminEnabled = false
	setTestConfig(app, cfg)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/login/local", nil)
	app.handleLocalAdminLogin(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 so the endpoint does not announce itself", rec.Code)
	}
}

func TestLocalAdminEndpointRefusesOutsideAllowedNetwork(t *testing.T) {
	app := mkTestApp(t)
	app.db = testDB(t)
	cfg := *app.conf()
	cfg.LocalAdminEnabled = true
	cfg.LocalAdminAllowedFrom = "10.0.0.0/8"
	setTestConfig(app, cfg)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/login/local", nil)
	req.RemoteAddr = "203.0.113.7:1234"
	app.handleLocalAdminLogin(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for a source outside the allowed network", rec.Code)
	}
}

func TestLocalAdminEndpointRejectsCrossOrigin(t *testing.T) {
	app := mkTestApp(t)
	app.db = testDB(t)
	cfg := *app.conf()
	cfg.LocalAdminEnabled = true
	setTestConfig(app, cfg)
	if err := createLocalAdmin(app.db, "erin", goodPassword); err != nil {
		t.Fatal(err)
	}

	body := strings.NewReader("username=erin&password=" + goodPassword)
	req := httptest.NewRequest(http.MethodPost, "/admin/login/local", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://evil.example.com")
	rec := httptest.NewRecorder()
	app.handleLocalAdminLogin(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for a cross-origin post", rec.Code)
	}
	if len(rec.Result().Cookies()) > 0 {
		t.Error("a cross-origin request received a session cookie")
	}
}

func TestLocalAdminLoginIssuesSession(t *testing.T) {
	app := mkTestApp(t)
	app.db = testDB(t)
	app.eventLog = newEventLog(app.db, time.Hour)
	cfg := *app.conf()
	cfg.LocalAdminEnabled = true
	setTestConfig(app, cfg)
	if err := createLocalAdmin(app.db, "frank", goodPassword); err != nil {
		t.Fatal(err)
	}

	body := strings.NewReader("username=frank&password=" + goodPassword)
	req := httptest.NewRequest(http.MethodPost, "/admin/login/local", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", app.conf().PublicURL)
	rec := httptest.NewRecorder()
	app.handleLocalAdminLogin(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	var cookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == adminCookieName {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("no admin cookie was set")
	}

	// The session must be readable and must carry the @local suffix, which is
	// what makes the break-glass path unmistakable in the audit trail.
	replay := httptest.NewRequest(http.MethodGet, "/admin", nil)
	replay.AddCookie(cookie)
	sess, err := readAdminCookie(replay, app.conf().SessionSecret)
	if err != nil {
		t.Fatalf("the issued cookie does not verify: %v", err)
	}
	if sess.UPN != "frank@local" {
		t.Errorf("session UPN = %q, want frank@local", sess.UPN)
	}

	// And the login has to be in the audit log.
	events := app.eventLog.Query(EventQueryFilter{Kind: KindAdminAction})
	found := false
	for _, ev := range events {
		if ev.Subject == "frank@local" && ev.Result == ResultSuccess {
			found = true
		}
	}
	if !found {
		t.Errorf("the break-glass login was not audited: %+v", events)
	}
}

func TestLocalAdminLoginRejectsBadPassword(t *testing.T) {
	app := mkTestApp(t)
	app.db = testDB(t)
	app.eventLog = newEventLog(app.db, time.Hour)
	cfg := *app.conf()
	cfg.LocalAdminEnabled = true
	setTestConfig(app, cfg)
	if err := createLocalAdmin(app.db, "grace", goodPassword); err != nil {
		t.Fatal(err)
	}

	body := strings.NewReader("username=grace&password=nope")
	req := httptest.NewRequest(http.MethodPost, "/admin/login/local", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", app.conf().PublicURL)
	rec := httptest.NewRecorder()
	app.handleLocalAdminLogin(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == adminCookieName {
			t.Error("a failed login issued an admin cookie")
		}
	}
	// A failed attempt must be audited too — this is the surface an attacker
	// would try, so its failures are worth more than its successes.
	if len(app.eventLog.Query(EventQueryFilter{Result: ResultDenied})) == 0 {
		t.Error("the failed break-glass attempt was not audited")
	}
}
