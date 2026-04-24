package main

// duo_universal.go
// Duo Universal Prompt (OIDC) 客户端 — 手写实现, 不引第三方 dep.
//
// 流程 (官方 Web SDK v4 协议):
//   1. 我们生成一个签名的 request JWT (HS512 用 client_secret 签),
//      把浏览器 302 到 https://{api_host}/oauth/v1/authorize?client_id=&request=
//   2. 用户在 Duo 页面做 2FA (push / 电话 / 硬件 token 随便选)
//   3. Duo 302 到 redirect_uri?state=X&duo_code=Y
//   4. 服务端 POST /oauth/v1/token 用 client_assertion JWT 交换 duo_code
//   5. 拿到 id_token (JWT), 用同一把 secret 验签, 读 preferred_username 作为用户身份

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
	apiHost      string // 小写, 不带 scheme
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

// AuthURL 生成 Duo Universal Prompt 跳转 URL.
// username 会作为 duo_uname 传给 Duo, Duo 页面会显示这个用户做 2FA.
// state 必须非空, 用于 CSRF 校验 (我们存 session 里比对).
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
		"exp":           now + 300, // 5 分钟
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

// Exchange: 用 duo_code 换 id_token, 验签, 返回 Duo 认定的 username.
// 我们还传入 expectedUsername 做 defense-in-depth 校验 — 防止 id_token 被换成别人的.
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
	body, err := io.ReadAll(resp.Body)
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
	// iss = 完整的 token endpoint URL (对照 Duo 官方 duo_universal_golang SDK).
	// 早先这里按 "https://{apiHost}" 校验, 被 Duo 实际返回的
	// "https://{apiHost}/oauth/v1/token" 给挂了.
	if iss, _ := claims["iss"].(string); iss != tokenEndpoint {
		return "", fmt.Errorf("duo id_token iss mismatch: %s", iss)
	}
	// aud = client_id
	if aud, _ := claims["aud"].(string); aud != d.clientID {
		return "", fmt.Errorf("duo id_token aud mismatch: %s", aud)
	}
	// 提取用户身份: Duo 用 preferred_username 传 duo_uname
	var username string
	if pref, _ := claims["preferred_username"].(string); pref != "" {
		username = pref
	} else if sub, _ := claims["sub"].(string); sub != "" {
		username = sub
	}
	if username == "" {
		return "", errors.New("duo id_token missing username")
	}
	// defense in depth: 要求和我们提交时的 username 对得上
	if expectedUsername != "" && !strings.EqualFold(username, expectedUsername) {
		return "", fmt.Errorf("duo username mismatch: expected %s, got %s", expectedUsername, username)
	}
	return username, nil
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

// verifyJWTHS512: 验签 + 基础 (exp / iat) 检查. 返回 claims.
// iss/aud 等语义校验由调用方做.
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
	// 解 header 验 alg (防降级攻击)
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
	// 解 payload
	payload, err := enc.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("jwt payload decode failed")
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	// exp 检查
	if exp, ok := claims["exp"].(float64); ok {
		if time.Now().Unix() > int64(exp)+30 { // 30 秒容错
			return nil, errors.New("jwt expired")
		}
	}
	return claims, nil
}
