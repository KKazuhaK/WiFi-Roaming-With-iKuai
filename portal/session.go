package main

// session.go
// 无状态的签名 cookie 实现。
// 只撑过 OIDC 一次 round-trip (浏览器 → Entra → 回调)，默认 15 分钟失效。
// 用 HMAC-SHA256 签名，不加密——cookie 内容里没有真正敏感的数据。
//
// Cookie 格式: <base64url(json)>.<hex(hmac)>
// 生成:   payload = base64url(json(session))
//         sig     = hex(hmac_sha256(secret, payload))
//         cookie  = payload + "." + sig
// 校验:   拆成 payload + sig, 重算 hmac, 常量时间对比
//
// 为什么不用 JWT 库:
//   - 依赖多一个
//   - JWT 规范里的 "alg: none" 漏洞历史包袱
//   - 我们只需要签名 + 过期，纯手写 30 行更可控

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
	sessionTTL        = 15 * time.Minute // OIDC round-trip 最多撑 15 分钟
)

// Session 是我们在 OIDC 跳转之间要记住的东西。
type Session struct {
	UserIP string `json:"user_ip"` // 设备 IP, iKuai 给的
	MAC    string `json:"mac"`     // 设备 MAC, iKuai 给的
	State  string `json:"state"`   // OIDC state, 防 CSRF
	Nonce  string `json:"nonce"`   // OIDC nonce, 防重放
	Exp    int64  `json:"exp"`     // Unix 秒, 过期时间
	Lang   string `json:"lang"`    // zh / en, 让 callback 页沿用用户选的语言
}

// newSession 创建一个带新鲜 state/nonce 的会话。
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

// writeSessionCookie 把 session 序列化 + 签名 + 写入 Set-Cookie header。
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
		Secure:   secure,               // 生产环境 true，本地调试 false
		SameSite: http.SameSiteLaxMode, // OIDC callback 需要 Lax (跨站 302 能带 cookie)
		MaxAge:   int(sessionTTL.Seconds()),
	})
	return nil
}

// readSessionCookie 从请求里解 session。
// 失败原因: 没 cookie / 签名不对 / 过期 / JSON 坏。都一律返回同一个错误，不透露细节。
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

// clearSessionCookie 在流程完成后主动让 cookie 过期。
func clearSessionCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1, // 立即过期
	})
}

// --- 密码学小工具 ---

// sign: HMAC-SHA256 签名, 返回 hex 字符串。
func sign(secret []byte, data string) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(data))
	return hex.EncodeToString(m.Sum(nil))
}

// randomHex: 生成 n 字节随机数的 hex 字符串 (输出长度 2n)。
// 用 crypto/rand 保证密码学强度，不能用 math/rand。
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("randomHex: %w", err)
	}
	return hex.EncodeToString(b), nil
}
