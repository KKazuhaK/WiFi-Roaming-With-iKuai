package main

// auth_proceed.go
// /auth/start no longer returns the real Duo or Entra URL, because that difference enables account
// enumeration. It now returns an opaque token; the browser GETs /auth/proceed?token=X to get the real 302.
//
// Externally observable behavior:
//   POST /auth/start -> 200 {"redirect":"/auth/proceed?token=abc..."} for every email.
//   GET  /auth/proceed?token=abc -> 302 to Duo Universal Prompt, Entra /login, or an error page.
//
// Enumerators must spend an extra GET and follow a 302 per email, increasing cost and triggering rules 1/6.
//
// The token is bound to the initiating session.State for CSRF protection and is single-use.

import (
	"crypto/subtle"
	"log"
	"net/http"
	"sort"
	"sync"
	"time"
)

// proceedKind is only a local main.go decision for "Duo vs Entra" routing, which selects the event
// log method. It is no longer stored in proceedEntry; the old Kind field was documented for logging
// and debugging but was never read (L8 dead-code cleanup).
type proceedKind int

const (
	proceedDuo   proceedKind = iota // 302 to the Duo Universal Prompt URL.
	proceedEntra                    // 302 to Entra /login?hint=...
	proceedDeny                     // Denied account; let Entra reject it to avoid exposing a "deny" signal.
)

type proceedEntry struct {
	URL          string
	SessionState string // Must match session.State in the cookie.
	Email        string // For logging/debugging.
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

// maxProceedEntries prevents memory-growth DOS from repeated /auth/start calls without consuming tokens.
// When full, expired entries are pruned synchronously and the earliest Expires value is dropped if needed.
const maxProceedEntries = 50000

// put randomly generates a token, stores one entry, and returns the token string.
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

// take consumes a token once. ok=false means the token is missing or expired.
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

// gcLoop periodically removes expired tokens to prevent memory buildup.
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
// Validate that the token exists, is not expired, and matches session.State, then 302 to the real destination.
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
