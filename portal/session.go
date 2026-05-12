package main

// session.go
// Two signed cookies:
//   - kz_wifi_sess   short-lived (15 minutes), used for OIDC round-trips.
//   - kz_admin_sess  longer-lived (1 hour), used after admin login for /admin.
// Both are HMAC-SHA256-signed JSON and are not encrypted.

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

// Session state/nonce can be reused by either Entra or Duo OAuth flows.
// Email is populated after the user submits it in /auth/start.
// Purpose decides what happens after /auth/callback or /auth/duo-callback:
//
//	""/"wifi"  -> allow-list in iKuai
//	"admin"    -> verify admin UPN and write the admin cookie
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

// newAdminPreloginSession is the /admin/login -> Entra round-trip and does not include IP/MAC.
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
		// Admin does not need cross-site request initiation. Strict is stronger than Lax and blocks
		// cross-site form POST CSRF; requireAdmin Origin checks provide a second layer.
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

// --- Crypto helpers ---

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
