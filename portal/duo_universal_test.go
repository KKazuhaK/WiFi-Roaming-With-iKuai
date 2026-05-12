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
// Intentionally hand-written instead of reusing signJWTHS512: tests need to construct invalid tokens
// without exp. If signJWTHS512 later starts injecting exp, these tests should remain independent.
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
	// Intentionally omit exp.
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
	// exp is a string. The old implementation silently skipped this after type assertion failure.
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

// --- readBoundedBody (audit #13: unbounded io.ReadAll) ---

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
	// Exactly at the limit must read fully without error.
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
	// One byte over the limit must error rather than silently truncating; truncation would break JSON
	// parsing with a misleading error.
	payload := strings.Repeat("x", 1025)
	if _, err := readBoundedBody(strings.NewReader(payload), 1024); err == nil {
		t.Fatalf("expected error when body exceeds limit, got nil")
	}
}

func TestVerifyJWTHS512_RejectsExpiredExp(t *testing.T) {
	secret := "test-secret-do-not-use-in-prod"
	// Expired one hour ago, far beyond the 30-second leeway.
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
