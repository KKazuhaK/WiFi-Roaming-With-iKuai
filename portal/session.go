package main

// session.go
// 两种签名 cookie:
//   - kz_wifi_sess   短命 (15 分钟), 撑 OIDC round-trip (Entra 或 Duo Universal Prompt)
//   - kz_admin_sess  较长 (1 小时), admin 登录后访问 /admin 用
// 都是 HMAC-SHA256 签名的 JSON, 不加密.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	sessionCookieName = "kz_wifi_sess"
	sessionTTL        = 15 * time.Minute
	adminCookieName   = "kz_admin_sess"
	adminSessionTTL   = time.Hour
)

// Session: state/nonce 可被 Entra 或 Duo 任一 OAuth 流程复用.
// Email 在用户提交邮箱后填入 (/auth/start 写).
// Purpose 决定 /auth/callback (Entra 回调) 或 /auth/duo-callback (Duo 回调) 之后干什么:
//
//	""/"wifi"  → 放行 iKuai
//	"admin"    → 验 admin UPN 后写 admin cookie
type Session struct {
	UserIP  string `json:"user_ip,omitempty"`
	MAC     string `json:"mac,omitempty"`
	State   string `json:"state"`
	Nonce   string `json:"nonce"`
	Exp     int64  `json:"exp"`
	Lang    string `json:"lang,omitempty"`
	Email   string `json:"email,omitempty"`
	Purpose string `json:"purpose,omitempty"`
}

func newSession(userIP, mac, lang string) (Session, error) {
	state, err := randomHex(16)
	if err != nil {
		return Session{}, err
	}
	nonce, err := randomHex(16)
	if err != nil {
		return Session{}, err
	}
	return Session{
		UserIP:  userIP,
		MAC:     mac,
		State:   state,
		Nonce:   nonce,
		Exp:     time.Now().Add(sessionTTL).Unix(),
		Lang:    lang,
		Purpose: "wifi",
	}, nil
}

// newAdminPreloginSession: /admin/login → Entra 的 round-trip, 不带 IP/MAC.
func newAdminPreloginSession(lang string) (Session, error) {
	state, err := randomHex(16)
	if err != nil {
		return Session{}, err
	}
	nonce, err := randomHex(16)
	if err != nil {
		return Session{}, err
	}
	return Session{
		State:   state,
		Nonce:   nonce,
		Exp:     time.Now().Add(sessionTTL).Unix(),
		Lang:    lang,
		Purpose: "admin",
	}, nil
}

func writeSessionCookie(w http.ResponseWriter, secret []byte, s Session, secure bool) error {
	body, err := json.Marshal(s)
	if err != nil {
		return err
	}
	payload := base64.RawURLEncoding.EncodeToString(body)
	sig := sign(secret, payload)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    payload + "." + sig,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
	return nil
}

func readSessionCookie(r *http.Request, secret []byte) (Session, error) {
	var s Session
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return s, errors.New("no session cookie")
	}
	parts := strings.Split(c.Value, ".")
	if len(parts) != 2 {
		return s, errors.New("malformed session")
	}
	payload, sig := parts[0], parts[1]
	if !hmac.Equal([]byte(sign(secret, payload)), []byte(sig)) {
		return s, errors.New("bad signature")
	}
	body, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return s, errors.New("bad payload")
	}
	if err := json.Unmarshal(body, &s); err != nil {
		return s, errors.New("bad json")
	}
	if time.Now().Unix() > s.Exp {
		return s, errors.New("expired")
	}
	return s, nil
}

func clearSessionCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// --- admin session ---

type AdminSession struct {
	UPN string `json:"upn"`
	Exp int64  `json:"exp"`
}

func writeAdminCookie(w http.ResponseWriter, secret []byte, s AdminSession, secure bool) error {
	body, err := json.Marshal(s)
	if err != nil {
		return err
	}
	payload := base64.RawURLEncoding.EncodeToString(body)
	sig := sign(secret, payload)
	http.SetCookie(w, &http.Cookie{
		Name:     adminCookieName,
		Value:    payload + "." + sig,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		// admin 不需要跨站发起请求 — 用 Strict 比 Lax 更严, 阻断跨站 form POST
		// 类 CSRF (受害者 admin 在另一个 tab 访问攻击页, <form action=...> 自动 submit
		// 即可触发 admin 操作). 配合 requireAdmin 里的 Origin 校验做双保险.
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(adminSessionTTL.Seconds()),
	})
	return nil
}

func readAdminCookie(r *http.Request, secret []byte) (AdminSession, error) {
	var s AdminSession
	c, err := r.Cookie(adminCookieName)
	if err != nil {
		return s, errors.New("no admin cookie")
	}
	parts := strings.Split(c.Value, ".")
	if len(parts) != 2 {
		return s, errors.New("malformed")
	}
	if !hmac.Equal([]byte(sign(secret, parts[0])), []byte(parts[1])) {
		return s, errors.New("bad signature")
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return s, errors.New("bad payload")
	}
	if err := json.Unmarshal(body, &s); err != nil {
		return s, errors.New("bad json")
	}
	if time.Now().Unix() > s.Exp {
		return s, errors.New("expired")
	}
	return s, nil
}

func clearAdminCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     adminCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

// --- 密码学小工具 ---

func sign(secret []byte, data string) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(data))
	return hex.EncodeToString(m.Sum(nil))
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("randomHex: %w", err)
	}
	return hex.EncodeToString(b), nil
}
