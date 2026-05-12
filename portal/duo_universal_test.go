package main

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// helper: build a JWT with arbitrary claims, signed with the given secret.
// 故意手写而不复用 signJWTHS512 — 测试要能构造不带 exp 的非法 token,
// 而 signJWTHS512 不会主动剔 exp; 但日后如果 signJWTHS512 改成强制注入 exp,
// 测试也不能跟着崩.
func mintTestJWT(t *testing.T, claims map[string]any, secret string) string {
	t.Helper()
	header := map[string]string{"alg": "HS512", "typ": "JWT"}
	h, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	p, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(h) + "." + enc.EncodeToString(p)
	mac := hmac.New(sha512.New, []byte(secret))
	mac.Write([]byte(signingInput))
	return signingInput + "." + enc.EncodeToString(mac.Sum(nil))
}

func TestVerifyJWTHS512_RejectsMissingExp(t *testing.T) {
	secret := "test-secret-do-not-use-in-prod"
	// 故意不带 exp 字段
	tok := mintTestJWT(t, map[string]any{
		"iss": "client-id",
		"aud": "client-id",
		"iat": time.Now().Unix(),
	}, secret)
	if _, err := verifyJWTHS512(tok, secret); err == nil {
		t.Fatalf("expected verifyJWTHS512 to reject JWT with no exp, got nil error")
	} else if !strings.Contains(err.Error(), "exp") {
		t.Errorf("expected error to mention exp, got: %v", err)
	}
}

func TestVerifyJWTHS512_RejectsNonNumericExp(t *testing.T) {
	secret := "test-secret-do-not-use-in-prod"
	// exp 是字符串 — 旧实现 type assertion 失败后悄无声息走过, 现在必须拒
	tok := mintTestJWT(t, map[string]any{
		"iss": "client-id",
		"aud": "client-id",
		"exp": "not-a-number",
	}, secret)
	if _, err := verifyJWTHS512(tok, secret); err == nil {
		t.Fatalf("expected verifyJWTHS512 to reject JWT with non-numeric exp, got nil error")
	} else if !strings.Contains(err.Error(), "exp") {
		t.Errorf("expected error to mention exp, got: %v", err)
	}
}

func TestVerifyJWTHS512_AcceptsValidExp(t *testing.T) {
	secret := "test-secret-do-not-use-in-prod"
	tok := mintTestJWT(t, map[string]any{
		"iss": "client-id",
		"aud": "client-id",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	}, secret)
	claims, err := verifyJWTHS512(tok, secret)
	if err != nil {
		t.Fatalf("expected verifyJWTHS512 to accept valid token, got: %v", err)
	}
	if claims["iss"] != "client-id" {
		t.Errorf("claims not parsed: %v", claims)
	}
}

// --- readBoundedBody (审计 #13 — io.ReadAll 无上限) ---

func TestReadBoundedBody_UnderLimit(t *testing.T) {
	r := strings.NewReader("small payload")
	got, err := readBoundedBody(r, 1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != "small payload" {
		t.Errorf("got %q, want full payload", got)
	}
}

func TestReadBoundedBody_AtLimit(t *testing.T) {
	// 恰好等于上限 — 必须读完, 不报错
	payload := strings.Repeat("x", 1024)
	got, err := readBoundedBody(strings.NewReader(payload), 1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1024 {
		t.Errorf("read %d bytes, want 1024", len(got))
	}
}

func TestReadBoundedBody_OverLimitRejected(t *testing.T) {
	// 多出 1 byte → 报错而非默默截断 (静默截断会破坏 JSON parse,
	// 错误信息也不指向真因, 排查 painful).
	payload := strings.Repeat("x", 1025)
	if _, err := readBoundedBody(strings.NewReader(payload), 1024); err == nil {
		t.Fatalf("expected error when body exceeds limit, got nil")
	}
}

func TestVerifyJWTHS512_RejectsExpiredExp(t *testing.T) {
	secret := "test-secret-do-not-use-in-prod"
	// 1 小时前过期, 远超 30 秒容错窗口
	tok := mintTestJWT(t, map[string]any{
		"iss": "client-id",
		"aud": "client-id",
		"exp": time.Now().Add(-time.Hour).Unix(),
	}, secret)
	if _, err := verifyJWTHS512(tok, secret); err == nil {
		t.Fatalf("expected verifyJWTHS512 to reject expired token, got nil")
	} else if !strings.Contains(err.Error(), "expired") {
		t.Errorf("expected 'expired' in error, got: %v", err)
	}
}
