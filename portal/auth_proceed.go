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
	"crypto/subtle"
	"log"
	"net/http"
	"sort"
	"sync"
	"time"
)

// proceedKind 仅在 main.go 里用作"刚才分流到 Duo 还是 Entra"的局部判断 (决定
// 事件日志记 method=duo 还是 sso). 这里不再存进 proceedEntry — Kind 字段历史上
// 注释说"用于日志/调试", 但实际从未被读取过 (L8 死代码清理).
type proceedKind int

const (
	proceedDuo   proceedKind = iota // 302 到 Duo Universal Prompt URL
	proceedEntra                    // 302 到 Entra /login?hint=...
	proceedDeny                     // 账号被拒, 走 Entra /login 让 Entra 自己拒, 避免暴露 "deny" 信号
)

type proceedEntry struct {
	URL          string
	SessionState string // 必须和 cookie 里的 session.State 一致
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

// maxProceedEntries 防内存增长 DOS: 攻击者反复 /auth/start 但不消费 token.
// 触顶时同步清过期项 + 必要时丢最早 Expires 的.
const maxProceedEntries = 50000

// put 随机生成 token 并记一条. 返回 token 字符串.
func (s *proceedTokenStore) put(url, sessionState, email string) (string, error) {
	tok, err := randomHex(16)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	if len(s.entries) >= maxProceedEntries {
		now := time.Now()
		for k, e := range s.entries {
			if now.After(e.Expires) {
				delete(s.entries, k)
			}
		}
		if len(s.entries) >= maxProceedEntries {
			type kv struct {
				k   string
				exp time.Time
			}
			all := make([]kv, 0, len(s.entries))
			for k, e := range s.entries {
				all = append(all, kv{k, e.Expires})
			}
			sort.Slice(all, func(i, j int) bool { return all[i].exp.Before(all[j].exp) })
			target := maxProceedEntries * 9 / 10
			for i := 0; i < len(all) && len(s.entries) > target; i++ {
				delete(s.entries, all[i].k)
			}
		}
	}
	s.entries[tok] = proceedEntry{
		URL:          url,
		SessionState: sessionState,
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
		a.renderError(w, r, lang, T(lang, "errors.sessionLost"), http.StatusBadRequest)
		return
	}
	if sess.Lang != "" {
		lang = Lang(sess.Lang)
	}
	if _, denied := a.denylist.IsMACDenied(sess.MAC); denied {
		log.Printf("deny banned MAC at /auth/proceed: mac=%s ip=%s", sess.MAC, sess.UserIP)
		a.logLogin("(unknown)", ResultDenied, "", sess.MAC, sess.UserIP, "mac_denylist")
		a.renderError(w, r, lang, T(lang, "errors.rateLimitedPermanent"), http.StatusForbidden)
		return
	}
	token := r.URL.Query().Get("token")
	if token == "" {
		a.renderError(w, r, lang, T(lang, "errors.expired"), http.StatusBadRequest)
		return
	}
	entry, ok := a.proceedStore.take(token)
	if !ok {
		a.renderError(w, r, lang, T(lang, "errors.expired"), http.StatusBadRequest)
		return
	}
	if subtle.ConstantTimeCompare([]byte(entry.SessionState), []byte(sess.State)) != 1 {
		log.Printf("/auth/proceed state mismatch (token=%s)", token[:8])
		a.renderError(w, r, lang, T(lang, "errors.generic"), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, entry.URL, http.StatusFound)
}
