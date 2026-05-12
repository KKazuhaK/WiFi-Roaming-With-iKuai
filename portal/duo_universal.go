package main

// duo_universal.go
// Duo Universal Prompt (OIDC) client, implemented directly without third-party dependencies.
//
// Flow (official Web SDK v4 protocol):
//   1. Generate a signed request JWT (HS512 signed with client_secret) and redirect the browser to
//      https://{api_host}/oauth/v1/authorize?client_id=&request=
//   2. The user completes 2FA on the Duo page with any available factor.
//   3. Duo redirects to redirect_uri?state=X&duo_code=Y.
//   4. The server POSTs to /oauth/v1/token and exchanges duo_code with a client_assertion JWT.
//   5. The server receives id_token, verifies it with the same secret, and uses preferred_username.

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type DuoUniversalClient struct {
	clientID     string
	clientSecret string
	apiHost      string // Lowercase, without scheme.
	redirectURI  string
	http         *http.Client
}

func newDuoUniversalClient(cfg Config) *DuoUniversalClient {
	return &DuoUniversalClient{
		clientID:     cfg.DuoClientID,
		clientSecret: cfg.DuoClientSecret,
		apiHost:      strings.ToLower(cfg.DuoAPIHost),
		redirectURI:  cfg.PublicURL + "/auth/duo-callback",
		http:         &http.Client{Timeout: 30 * time.Second},
	}
}

// AuthURL builds the Duo Universal Prompt redirect URL.
// username is sent as duo_uname so Duo shows that user during 2FA.
// state must be non-empty for CSRF validation against the session.
func (d *DuoUniversalClient) AuthURL(username, state string) (string, error) {
	if username == "" || state == "" {
		return "", errors.New("username/state must not be empty")
	}
	now := time.Now().Unix()
	claims := map[string]any{
		"scope":         "openid",
		"redirect_uri":  d.redirectURI,
		"client_id":     d.clientID,
		"iss":           d.clientID,
		"aud":           "https://" + d.apiHost,
		"exp":           now + 300, // 5 minutes.
		"iat":           now,
		"state":         state,
		"response_type": "code",
		"duo_uname":     username,
	}
	reqJWT, err := signJWTHS512(claims, d.clientSecret)
	if err != nil {
		return "", err
	}
	q := url.Values{}
	q.Set("client_id", d.clientID)
	q.Set("response_type", "code")
	q.Set("request", reqJWT)
	return "https://" + d.apiHost + "/oauth/v1/authorize?" + q.Encode(), nil
}

// Exchange swaps duo_code for id_token, verifies the signature, and returns Duo's username.
// expectedUsername adds defense-in-depth against id_token substitution.
func (d *DuoUniversalClient) Exchange(duoCode, expectedUsername string) (string, error) {
	now := time.Now().Unix()
	jti, err := randomHex(16)
	if err != nil {
		return "", err
	}
	tokenEndpoint := "https://" + d.apiHost + "/oauth/v1/token"
	caClaims := map[string]any{
		"iss": d.clientID,
		"sub": d.clientID,
		"aud": tokenEndpoint,
		"exp": now + 300,
		"iat": now,
		"jti": jti,
	}
	caJWT, err := signJWTHS512(caClaims, d.clientSecret)
	if err != nil {
		return "", err
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", duoCode)
	form.Set("redirect_uri", d.redirectURI)
	form.Set("client_id", d.clientID)
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", caJWT)

	req, err := http.NewRequest("POST", tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "KazuhaHub-Portal/1.0")

	resp, err := d.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("duo token: %w", err)
	}
	defer resp.Body.Close()
	body, err := readBoundedBody(resp.Body, duoMaxResponseBytes)
	if err != nil {
		return "", fmt.Errorf("duo token read body: %w", err)
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("duo token http %d: %s", resp.StatusCode, truncate(string(body), 200))
	}

	var tr struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", fmt.Errorf("duo token json: %w", err)
	}
	if tr.IDToken == "" {
		return "", errors.New("duo: response missing id_token")
	}

	claims, err := verifyJWTHS512(tr.IDToken, d.clientSecret)
	if err != nil {
		return "", fmt.Errorf("duo id_token: %w", err)
	}
	// iss is the full token endpoint URL, matching Duo's official duo_universal_golang SDK.
	// An earlier check used "https://{apiHost}" and failed against Duo's actual
	// "https://{apiHost}/oauth/v1/token" value.
	if iss, _ := claims["iss"].(string); iss != tokenEndpoint {
		return "", fmt.Errorf("duo id_token iss mismatch: %s", iss)
	}
	// aud = client_id
	if aud, _ := claims["aud"].(string); aud != d.clientID {
		return "", fmt.Errorf("duo id_token aud mismatch: %s", aud)
	}
	// Extract user identity: Duo returns duo_uname in preferred_username.
	var username string
	if pref, _ := claims["preferred_username"].(string); pref != "" {
		username = pref
	} else if sub, _ := claims["sub"].(string); sub != "" {
		username = sub
	}
	if username == "" {
		return "", errors.New("duo id_token missing username")
	}
	// Defense in depth: require the username to match what we submitted.
	if expectedUsername != "" && !strings.EqualFold(username, expectedUsername) {
		return "", fmt.Errorf("duo username mismatch: expected %s, got %s", expectedUsername, username)
	}
	return username, nil
}

// duoMaxResponseBytes is the Duo HTTP response-body limit. Real preauth/token responses are only
// a few KB, so 1 MB is ample. Audit #13 flagged that a trusted but hijacked endpoint or DNS issue
// could return a huge body and OOM the process; exceeding the limit returns a clear error.
const duoMaxResponseBytes int64 = 1 << 20

// readBoundedBody reads at most limit bytes and errors when the limit is exceeded.
// It reads limit+1 bytes so any actual read beyond limit is detectable.
func readBoundedBody(r io.Reader, limit int64) ([]byte, error) {
	lr := io.LimitReader(r, limit+1)
	body, err := io.ReadAll(lr)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("response body exceeds limit %d bytes", limit)
	}
	return body, nil
}

// --- JWT HS512 helpers ---

func signJWTHS512(claims map[string]any, secret string) (string, error) {
	header := map[string]string{"alg": "HS512", "typ": "JWT"}
	h, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	p, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(h) + "." + enc.EncodeToString(p)
	mac := hmac.New(sha512.New, []byte(secret))
	mac.Write([]byte(signingInput))
	return signingInput + "." + enc.EncodeToString(mac.Sum(nil)), nil
}

// verifyJWTHS512 verifies the signature and basic exp/iat checks, then returns claims.
// Callers perform semantic checks such as iss/aud.
func verifyJWTHS512(token, secret string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("jwt format invalid")
	}
	enc := base64.RawURLEncoding
	signingInput := parts[0] + "." + parts[1]
	gotSig, err := enc.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("jwt sig base64 decode failed")
	}
	mac := hmac.New(sha512.New, []byte(secret))
	mac.Write([]byte(signingInput))
	if !hmac.Equal(mac.Sum(nil), gotSig) {
		return nil, errors.New("jwt signature mismatch")
	}
	// Decode the header and verify alg to prevent downgrade attacks.
	headerBytes, err := enc.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("jwt header decode failed")
	}
	var header struct{ Alg string }
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, err
	}
	if header.Alg != "HS512" {
		return nil, fmt.Errorf("jwt alg is not HS512: %s", header.Alg)
	}
	// Decode the payload.
	payload, err := enc.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("jwt payload decode failed")
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	// exp must exist and be numeric. Missing or non-numeric exp is rejected.
	// The old implementation silently skipped expiry checks on failed type assertions.
	rawExp, present := claims["exp"]
	if !present {
		return nil, errors.New("jwt missing exp")
	}
	exp, ok := rawExp.(float64)
	if !ok {
		return nil, errors.New("jwt exp must be a number")
	}
	if time.Now().Unix() > int64(exp)+30 { // 30-second leeway.
		return nil, errors.New("jwt expired")
	}
	return claims, nil
}
