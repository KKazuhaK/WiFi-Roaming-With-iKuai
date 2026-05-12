package main

// session_test.go
// Security semantics for HMAC-signed cookies:
//   - sign+verify succeeds.
//   - verification with the wrong secret fails, preventing signature forgery.
//   - tampered payload fails.
//   - tampered sig fails.
//   - expired cookie fails.
//   - malformed cookie fails.
//   - admin and wifi cookies reuse the same signing mechanism.
//
// These are the only attack surfaces left when attackers do not have SESSION_SECRET.

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testSecret(t *testing.T) []byte {
	t.Helper()
	// 32 random bytes; isolated across tests.
	return []byte("\x00\x01\x02\x03\x04\x05\x06\x07" +
		"\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f" +
		"\x10\x11\x12\x13\x14\x15\x16\x17" +
		"\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f")
}

// roundTrip writes a session cookie into ResponseRecorder, copies it to a new request, and reads it
// back to simulate a browser request/response round-trip.
func roundTrip(t *testing.T, secret []byte, sess Session) (Session, error) {
	t.Helper()
	rec := httptest.NewRecorder()
	if err := writeSessionCookie(rec, secret, sess, false); err != nil {
		t.Fatalf("writeSessionCookie: %v", err)
	}
	r, _ := http.NewRequest("GET", "/", nil)
	for _, c := range rec.Result().Cookies() {
		r.AddCookie(c)
	}
	return readSessionCookie(r, secret)
}

func TestSession_RoundTrip(t *testing.T) {
	secret := testSecret(t)
	original := Session{
		UserIP:  "192.168.1.50",
		MAC:     "aa:bb:cc:dd:ee:ff",
		State:   "abc123",
		Nonce:   "nonce456",
		Email:   "user@example.com",
		Lang:    "zh-cn",
		Purpose: "wifi",
		Exp:     time.Now().Add(5 * time.Minute).Unix(),
	}
	got, err := roundTrip(t, secret, original)
	if err != nil {
		t.Fatalf("roundTrip: %v", err)
	}
	if got.UserIP != original.UserIP || got.MAC != original.MAC ||
		got.State != original.State || got.Nonce != original.Nonce ||
		got.Email != original.Email || got.Lang != original.Lang ||
		got.Purpose != original.Purpose {
		t.Errorf("session mismatch after round trip: got %+v want %+v", got, original)
	}
}

func TestSession_WrongSecretRejected(t *testing.T) {
	secret := testSecret(t)
	other := append([]byte(nil), secret...)
	other[0] ^= 0xff // Changing one byte makes a different key.

	rec := httptest.NewRecorder()
	if err := writeSessionCookie(rec, secret, Session{
		State: "x", Nonce: "y",
		Exp: time.Now().Add(time.Minute).Unix(),
	}, false); err != nil {
		t.Fatalf("write: %v", err)
	}
	r, _ := http.NewRequest("GET", "/", nil)
	for _, c := range rec.Result().Cookies() {
		r.AddCookie(c)
	}
	if _, err := readSessionCookie(r, other); err == nil {
		t.Fatal("expected verify failure with wrong secret, got success")
	}
}

func TestSession_TamperedPayloadRejected(t *testing.T) {
	secret := testSecret(t)
	rec := httptest.NewRecorder()
	_ = writeSessionCookie(rec, secret, Session{
		UserIP: "1.1.1.1", MAC: "aa:bb:cc:dd:ee:ff",
		State: "x", Nonce: "y",
		Exp: time.Now().Add(time.Minute).Unix(),
	}, false)

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("want 1 cookie, got %d", len(cookies))
	}
	parts := strings.SplitN(cookies[0].Value, ".", 2)
	if len(parts) != 2 {
		t.Fatalf("malformed cookie: %q", cookies[0].Value)
	}

	// Decode payload, change IP, and re-encode to simulate tampering while keeping original sig.
	body, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var s Session
	_ = json.Unmarshal(body, &s)
	s.UserIP = "9.9.9.9"
	tampered, _ := json.Marshal(s)
	newPayload := base64.RawURLEncoding.EncodeToString(tampered)
	tamperedCookie := newPayload + "." + parts[1]

	r, _ := http.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: tamperedCookie})
	if _, err := readSessionCookie(r, secret); err == nil {
		t.Fatal("expected sig mismatch on tampered payload, got success")
	}
}

func TestSession_TamperedSigRejected(t *testing.T) {
	secret := testSecret(t)
	rec := httptest.NewRecorder()
	_ = writeSessionCookie(rec, secret, Session{
		State: "x", Nonce: "y",
		Exp: time.Now().Add(time.Minute).Unix(),
	}, false)

	cookies := rec.Result().Cookies()
	parts := strings.SplitN(cookies[0].Value, ".", 2)
	// Flip the first hex character in sig.
	var flip byte = '0'
	if parts[1][0] != '0' {
		flip = '0'
	} else {
		flip = '1'
	}
	tamperedSig := string(flip) + parts[1][1:]
	tamperedCookie := parts[0] + "." + tamperedSig

	r, _ := http.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: tamperedCookie})
	if _, err := readSessionCookie(r, secret); err == nil {
		t.Fatal("expected verify failure with tampered sig, got success")
	}
}

func TestSession_ExpiredRejected(t *testing.T) {
	secret := testSecret(t)
	expired := Session{
		State: "x", Nonce: "y",
		Exp: time.Now().Add(-time.Second).Unix(),
	}
	if _, err := roundTrip(t, secret, expired); err == nil {
		t.Fatal("expired session must be rejected")
	}
}

func TestSession_MalformedRejected(t *testing.T) {
	secret := testSecret(t)
	cases := []string{
		"",             // Empty.
		"abc",          // No dot separator.
		"abc.def.ghi",  // Multiple dots.
		".sigonly",     // Empty payload.
		"payloadonly.", // Empty sig.
		"!!!.@@@",      // Invalid base64.
		"YWJj.0",       // Valid base64 plus 1-char sig, impossible to match.
	}
	for _, val := range cases {
		r, _ := http.NewRequest("GET", "/", nil)
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: val})
		if _, err := readSessionCookie(r, secret); err == nil {
			t.Errorf("malformed cookie %q must be rejected", val)
		}
	}
}

func TestSession_NoCookieRejected(t *testing.T) {
	secret := testSecret(t)
	r, _ := http.NewRequest("GET", "/", nil)
	if _, err := readSessionCookie(r, secret); err == nil {
		t.Fatal("missing cookie must error")
	}
}

func TestSession_ClearWritesEmptyMaxAgeNeg(t *testing.T) {
	rec := httptest.NewRecorder()
	clearSessionCookie(rec, false)
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	c := cookies[0]
	if c.Name != sessionCookieName || c.Value != "" || c.MaxAge != -1 {
		t.Errorf("clearSessionCookie wrong: %+v", c)
	}
}

// --- admin cookie ---

func TestAdminSession_RoundTrip(t *testing.T) {
	secret := testSecret(t)
	rec := httptest.NewRecorder()
	if err := writeAdminCookie(rec, secret, AdminSession{
		UPN: "admin@example.com",
		Exp: time.Now().Add(time.Hour).Unix(),
	}, false); err != nil {
		t.Fatalf("write admin: %v", err)
	}
	r, _ := http.NewRequest("GET", "/", nil)
	for _, c := range rec.Result().Cookies() {
		r.AddCookie(c)
	}
	got, err := readAdminCookie(r, secret)
	if err != nil {
		t.Fatalf("read admin: %v", err)
	}
	if got.UPN != "admin@example.com" {
		t.Errorf("UPN mismatch: %q", got.UPN)
	}
}

func TestAdminSession_WrongSecretRejected(t *testing.T) {
	secret := testSecret(t)
	other := append([]byte(nil), secret...)
	other[1] ^= 0xff

	rec := httptest.NewRecorder()
	_ = writeAdminCookie(rec, secret, AdminSession{
		UPN: "x@y", Exp: time.Now().Add(time.Hour).Unix(),
	}, false)
	r, _ := http.NewRequest("GET", "/", nil)
	for _, c := range rec.Result().Cookies() {
		r.AddCookie(c)
	}
	if _, err := readAdminCookie(r, other); err == nil {
		t.Fatal("admin cookie must reject wrong secret")
	}
}

func TestAdminSession_StrictSameSite(t *testing.T) {
	// H4 fix: admin cookie uses SameSite=Strict to stop admin POST from cross-site forms.
	rec := httptest.NewRecorder()
	_ = writeAdminCookie(rec, testSecret(t), AdminSession{
		UPN: "x@y", Exp: time.Now().Add(time.Hour).Unix(),
	}, true)
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("want 1 cookie, got %d", len(cookies))
	}
	if cookies[0].SameSite != http.SameSiteStrictMode {
		t.Errorf("admin cookie SameSite = %v, want Strict", cookies[0].SameSite)
	}
	if !cookies[0].HttpOnly || !cookies[0].Secure {
		t.Errorf("admin cookie should be HttpOnly+Secure, got HttpOnly=%v Secure=%v",
			cookies[0].HttpOnly, cookies[0].Secure)
	}
}

func TestSessionCookie_LaxSameSite(t *testing.T) {
	// Wifi session cookie must stay Lax; Entra/Duo cross-site callbacks need the browser to send it
	// for state/nonce validation. Strict would break every OIDC round-trip.
	rec := httptest.NewRecorder()
	_ = writeSessionCookie(rec, testSecret(t), Session{
		State: "x", Nonce: "y",
		Exp: time.Now().Add(time.Minute).Unix(),
	}, true)
	cookies := rec.Result().Cookies()
	if cookies[0].SameSite != http.SameSiteLaxMode {
		t.Errorf("wifi session SameSite = %v, want Lax (OIDC round-trip needs Lax)",
			cookies[0].SameSite)
	}
}

func TestNewSession_RandomState(t *testing.T) {
	// state must differ each time, or OIDC CSRF protection is useless.
	a, err := newSession("ip", "mac", "zh-cn")
	if err != nil {
		t.Fatal(err)
	}
	b, err := newSession("ip", "mac", "zh-cn")
	if err != nil {
		t.Fatal(err)
	}
	if a.State == b.State {
		t.Errorf("two newSession calls produced identical State (must be cryptographically random)")
	}
	if a.Nonce == b.Nonce {
		t.Errorf("two newSession calls produced identical Nonce")
	}
	if len(a.State) < 16 {
		t.Errorf("State too short: %d bytes", len(a.State))
	}
}
