package main

// session_test.go
// HMAC 签名 cookie 的安全语义:
//   - sign+verify 走通
//   - 用错的 secret 验签必失败 (防签名伪造)
//   - 篡改 payload 必失败
//   - 篡改 sig 必失败
//   - 过期必失败
//   - cookie 格式错乱必失败
//   - admin cookie 跟 wifi cookie 用同一签名机制 (复用)
//
// 这些是攻击者在偷不到 SESSION_SECRET 时唯一能尝试的攻击面.

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
	// 32 bytes 随机. 测试间互相隔离.
	return []byte("\x00\x01\x02\x03\x04\x05\x06\x07" +
		"\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f" +
		"\x10\x11\x12\x13\x14\x15\x16\x17" +
		"\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f")
}

// roundTrip 把 session 写进 ResponseRecorder 的 cookie, 再把 cookie 头复制
// 到一个新 Request 上读回, 模拟浏览器一来一回.
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
	other[0] ^= 0xff // 改 1 byte 即不同 key

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

	// 解码 payload, 改 IP, 重新编码 — 模拟攻击者改 cookie 内容但保留原 sig.
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
	// 翻转 sig 第一个 hex 字符
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
		"",             // 空
		"abc",          // 没有点分隔
		"abc.def.ghi",  // 多个点
		".sigonly",     // 空 payload
		"payloadonly.", // 空 sig
		"!!!.@@@",      // 不是合法 base64
		"YWJj.0",       // 合法 base64 + 1 字符 sig (不可能匹配)
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
	// H4 修复: admin cookie 改成 SameSite=Strict, 防 admin POST 被跨站 form 触发.
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
	// wifi session cookie 必须保持 Lax — Entra/Duo 跨站回跳后浏览器要带回 cookie
	// 才能验 state/nonce. 改 Strict 会让所有 OIDC round-trip 失败.
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
	// state 必须每次不同 — 否则 OIDC CSRF 防护就废了.
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
