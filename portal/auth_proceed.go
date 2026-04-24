package main

// auth_proceed.go
// /auth/start 不再直接返回真实的 Duo URL 或 Entra URL — 攻击者借此差异做账号枚举.
// 改成返回一个 opaque token, 浏览器 GET /auth/proceed?token=X 才做真实 302.
//
// 对外可观察:
//   POST /auth/start → 200 {"redirect":"/auth/proceed?token=abc..."} (所有 email 一致)
//   GET  /auth/proceed?token=abc → 302 到 Duo Universal Prompt / Entra /login / 错误页
//
// 攻击者想枚举就得为每个 email 多发一次 GET + 跟 302, 成本翻倍且会触发规则 1 / 6.
//
// token 绑定到发起请求的 session.State (CSRF), 一次性用 (取一次就删).

import (
	"log"
	"net/http"
	"sync"
	"time"
)

type proceedKind int

const (
	proceedDuo   proceedKind = iota // 302 到 Duo Universal Prompt URL
	proceedEntra                    // 302 到 Entra /login?hint=...
	proceedDeny                     // 账号被拒, 走 Entra /login 让 Entra 自己拒, 避免暴露 "deny" 信号
)

type proceedEntry struct {
	URL          string
	SessionState string // 必须和 cookie 里的 session.State 一致
	Kind         proceedKind
	Email        string // 用于日志 / 调试
	Expires      time.Time
}

type proceedTokenStore struct {
	mu      sync.Mutex
	entries map[string]proceedEntry
	ttl     time.Duration
}

func newProceedTokenStore(ttl time.Duration) *proceedTokenStore {
	return &proceedTokenStore{
		entries: make(map[string]proceedEntry),
		ttl:     ttl,
	}
}

// put 随机生成 token 并记一条. 返回 token 字符串.
func (s *proceedTokenStore) put(url, sessionState, email string, kind proceedKind) (string, error) {
	tok, err := randomHex(16)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	s.entries[tok] = proceedEntry{
		URL:          url,
		SessionState: sessionState,
		Kind:         kind,
		Email:        email,
		Expires:      time.Now().Add(s.ttl),
	}
	s.mu.Unlock()
	return tok, nil
}

// take 一次性拿走 token. 返回 ok=false 表示 token 不存在或过期.
func (s *proceedTokenStore) take(token string) (proceedEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[token]
	if !ok {
		return proceedEntry{}, false
	}
	delete(s.entries, token)
	if time.Now().After(e.Expires) {
		return proceedEntry{}, false
	}
	return e, true
}

// gcLoop 定期清过期 token, 防内存堆积.
func (s *proceedTokenStore) gcLoop() {
	t := time.NewTicker(2 * time.Minute)
	defer t.Stop()
	for range t.C {
		s.mu.Lock()
		now := time.Now()
		for k, e := range s.entries {
			if now.After(e.Expires) {
				delete(s.entries, k)
			}
		}
		s.mu.Unlock()
	}
}

// handleAuthProceed: GET /auth/proceed?token=X
// 校验 token 存在 + 未过期 + session.State 匹配, 然后 302 到真正目的地.
func (a *App) handleAuthProceed(w http.ResponseWriter, r *http.Request) {
	lang := pickLang(r)
	sess, err := readSessionCookie(r, a.cfg.SessionSecret)
	if err != nil {
		a.renderError(w, r, lang, lang.s().SessionLostMsg, http.StatusBadRequest)
		return
	}
	if sess.Lang != "" {
		lang = Lang(sess.Lang)
	}
	if _, denied := a.denylist.IsMACDenied(sess.MAC); denied {
		log.Printf("拒绝已封禁 MAC auth/proceed: mac=%s ip=%s", sess.MAC, sess.UserIP)
		a.logLogin("(unknown)", ResultDenied, "", sess.MAC, sess.UserIP, "mac_denylist")
		a.renderError(w, r, lang, lang.s().RateLimitedPermanent, http.StatusForbidden)
		return
	}
	token := r.URL.Query().Get("token")
	if token == "" {
		a.renderError(w, r, lang, lang.s().ExpiredMsg, http.StatusBadRequest)
		return
	}
	entry, ok := a.proceedStore.take(token)
	if !ok {
		a.renderError(w, r, lang, lang.s().ExpiredMsg, http.StatusBadRequest)
		return
	}
	if entry.SessionState != sess.State {
		log.Printf("/auth/proceed state 不匹配 (token=%s)", token[:8])
		a.renderError(w, r, lang, lang.s().ErrorGenericMsg, http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, entry.URL, http.StatusFound)
}
