package main

// session.go
// 无状态的签名 cookie 实现。
// 覆盖两条认证流程的往返状态:
//   a) Entra SSO: /portal → /login → Entra → /auth/callback 期间保留 state/nonce/IP/MAC
//   b) Duo 免密: /portal → POST /auth/duo-start → 循环 /auth/duo-status → /auth/duo-finish 期间保留 IP/MAC/Email/TxID
// 默认 15 分钟失效 (足以覆盖推送等待 60 秒 + 人类迟疑时间).
// 用 HMAC-SHA256 签名, 不加密 — cookie 内容里没有真正敏感的数据 (都是短效一次性状态).
//
// Cookie 格式: <base64url(json)>.<hex(hmac)>

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
)

// Session 在 Portal 的各个跳转之间存状态. 各字段按流程填:
//
//   /portal 写: UserIP, MAC, State, Nonce, Exp, Lang
//   /auth/duo-start 追加: Email, DuoTxID
//
// DuoTxID / Email 在 Entra SSO 路径里始终为空, 在 Duo 免密路径里被填上.
type Session struct {
	UserIP  string `json:"user_ip"`
	MAC     string `json:"mac"`
	State   string `json:"state"`
	Nonce   string `json:"nonce"`
	Exp     int64  `json:"exp"`
	Lang    string `json:"lang"`
	Email   string `json:"email,omitempty"`
	DuoTxID string `json:"duo_txid,omitempty"`
}

// newSession 创建一个带新鲜 state/nonce 的会话.
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
		UserIP: userIP,
		MAC:    mac,
		State:  state,
		Nonce:  nonce,
		Exp:    time.Now().Add(sessionTTL).Unix(),
		Lang:   lang,
	}, nil
}

// writeSessionCookie 把 session 序列化 + 签名 + 写入 Set-Cookie header.
func writeSessionCookie(w http.ResponseWriter, secret []byte, s Session, secure bool) error {
	body, err := json.Marshal(s)
	if err != nil {
		return err
	}
	payload := base64.RawURLEncoding.EncodeToString(body)
	sig := sign(secret, payload)
	value := payload + "." + sig

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
	return nil
}

// readSessionCookie 从请求里解 session.
// 失败时一律返回同一个错误, 不透露细节.
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
	expect := sign(secret, payload)
	if !hmac.Equal([]byte(expect), []byte(sig)) {
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

// clearSessionCookie 在流程完成后主动让 cookie 过期.
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
