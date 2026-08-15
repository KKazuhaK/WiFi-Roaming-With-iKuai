package main

// localadmin.go
// The break-glass administrator account.
//
// Why this exists: administrator access is Entra SSO, and since the settings
// migration the Entra configuration itself lives in the database and is edited
// from the admin console. That closes a loop. One wrong tenant ID typed into
// that form — or an expired client secret, or Entra being unreachable — locks
// every administrator out of the only interface that can fix it, permanently,
// with no recovery short of hand-editing the database.
//
// The design keeps the new attack surface as small as the job allows:
//
//   - Disabled by default. A deployment that never creates a local account
//     never grows a password on its admin surface, and /admin/login/local
//     answers 404 rather than a login form.
//   - Created only from the command line (`wifi-portal admin add`), which
//     already requires shell access to the host. There is no self-service
//     enrolment and no way to create the first account over HTTP.
//   - argon2id, with per-account lockout on top of the portal's existing
//     per-IP limiter. An attacker with a botnet has plenty of IPs and only one
//     username worth guessing, so per-IP counting alone does not bound this.
//   - Optionally restricted by source network, so an account can exist while
//     being reachable only from a management subnet.

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
	"gorm.io/gorm"

	"github.com/kazuhahub/wifi-portal/internal/dbstore"
)

// Argon2id parameters.
//
// RFC 9106's second recommended option (64 MiB, 3 passes, 4 lanes), chosen over
// the first (2 GiB) because this runs on router-adjacent hardware where a
// 2 GiB allocation per verification is not available — and because the accounts
// it protects are created by an operator from a CLI, not chosen by end users, so
// the passwords have no dictionary to attack.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 4
	argonKeyLen  = 32
	argonSaltLen = 16
)

// Lockout policy. Deliberately short: this is a break-glass account, so an
// operator locked out by their own typo during an outage must not have to wait
// out a punitive window on top of whatever they were already fixing.
const (
	localAdminMaxFailures = 10
	localAdminLockout     = 15 * time.Minute
)

var errLocalAdminDisabled = errors.New("local admin login is disabled")

// hashPassword returns an encoded argon2id hash carrying its own parameters and
// salt, so a future parameter change can still verify old hashes.
func hashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// verifyPassword checks a password against an encoded hash, reading the
// parameters from the hash rather than assuming today's constants.
func verifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}
	var memory uint32
	var timeCost uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &timeCost, &threads); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, timeCost, memory, threads, uint32(len(want)))
	// Constant-time: a length-dependent or short-circuiting comparison leaks how
	// much of a guess was right.
	return subtle.ConstantTimeCompare(got, want) == 1
}

// --- account management, called from the CLI ---

// createLocalAdmin adds or replaces an account. Replacing is how
// `wifi-portal admin passwd` works, and it clears any lockout — an operator
// resetting a password from the host has already proven more than the lockout
// was protecting against.
func createLocalAdmin(db *dbstore.DB, username, password string) error {
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return errors.New("username is required")
	}
	if err := checkPasswordStrength(password); err != nil {
		return err
	}
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	row := dbstore.LocalAdmin{
		Username: username, PasswordHash: hash, Enabled: true, CreatedAt: time.Now().UTC(),
	}
	return db.Save(&row).Error
}

// checkPasswordStrength enforces a length floor and nothing else.
//
// No character-class rules: they push operators towards Passw0rd! and are worse
// than a length requirement at the same memorability. Twelve characters against
// an argon2id hash behind a ten-attempt lockout is not the weak link here.
func checkPasswordStrength(password string) error {
	if len([]rune(password)) < 12 {
		return errors.New("password must be at least 12 characters")
	}
	return nil
}

func deleteLocalAdmin(db *dbstore.DB, username string) (bool, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	res := db.Where("username = ?", username).Delete(&dbstore.LocalAdmin{})
	return res.RowsAffected > 0, res.Error
}

func listLocalAdmins(db *dbstore.DB) ([]dbstore.LocalAdmin, error) {
	var rows []dbstore.LocalAdmin
	err := db.Order("username").Find(&rows).Error
	return rows, err
}

// --- authentication ---

// authenticateLocalAdmin verifies a username and password.
//
// It returns the same opaque error for an unknown user and a wrong password, so
// the endpoint cannot be used to enumerate account names. The lockout counter is
// only touched for an account that exists, which means a flood of guesses at
// nonexistent names cannot lock out the real one.
func authenticateLocalAdmin(db *dbstore.DB, username, password string) (string, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	var row dbstore.LocalAdmin
	if err := db.Where("username = ?", username).First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Spend the time a real verification would, so response latency does
			// not distinguish a missing account from a wrong password.
			hashPassword(password) //nolint:errcheck // Timing equalisation only.
			return "", errors.New("invalid credentials")
		}
		return "", err
	}
	if !row.Enabled {
		return "", errLocalAdminDisabled
	}
	if row.LockedUntil != nil && time.Now().Before(*row.LockedUntil) {
		return "", fmt.Errorf("account locked until %s", row.LockedUntil.Format(time.RFC3339))
	}

	if !verifyPassword(password, row.PasswordHash) {
		row.FailedAttempts++
		if row.FailedAttempts >= localAdminMaxFailures {
			until := time.Now().UTC().Add(localAdminLockout)
			row.LockedUntil = &until
			row.FailedAttempts = 0
			log.Printf("local admin: %q locked for %s after %d failed attempts",
				username, localAdminLockout, localAdminMaxFailures)
		}
		if err := db.Save(&row).Error; err != nil {
			log.Printf("local admin: recording a failed attempt for %q failed: %v", username, err)
		}
		return "", errors.New("invalid credentials")
	}

	now := time.Now().UTC()
	row.FailedAttempts = 0
	row.LockedUntil = nil
	row.LastLoginAt = &now
	if err := db.Save(&row).Error; err != nil {
		log.Printf("local admin: recording a successful login for %q failed: %v", username, err)
	}
	return row.Username, nil
}

// localAdminUPN is the identity a local session carries.
//
// Suffixed so it can never collide with a real UPN from Entra, and so the audit
// log makes the distinction obvious: "alice@local" in the event trail is
// unmistakably the break-glass path, not an SSO sign-in.
func localAdminUPN(username string) string { return username + "@local" }

// --- HTTP ---

// localAdminAllowedFrom parses the optional source restriction.
//
// Empty means no restriction. Anything else is a comma-separated list of CIDRs
// or bare addresses, so an operator can keep the account reachable only from a
// management subnet — the account exists for an emergency, and an emergency
// rarely arrives from the public internet.
func localAdminAllowedFrom(spec string) ([]*net.IPNet, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	var out []*net.IPNet
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(part, "/") {
			// A bare address is a host route.
			if ip := net.ParseIP(part); ip != nil {
				bits := 32
				if ip.To4() == nil {
					bits = 128
				}
				part = part + "/" + strconv.Itoa(bits)
			}
		}
		_, n, err := net.ParseCIDR(part)
		if err != nil {
			return nil, fmt.Errorf("invalid network %q: %w", part, err)
		}
		out = append(out, n)
	}
	return out, nil
}

func ipAllowed(nets []*net.IPNet, addr string) bool {
	if len(nets) == 0 {
		return true
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// handleLocalAdminLogin serves the break-glass form and processes it.
//
// The endpoint is invisible — 404, not 403 — when local login is switched off,
// so a deployment that does not use it does not advertise that the mechanism
// exists.
func (a *App) handleLocalAdminLogin(w http.ResponseWriter, r *http.Request) {
	lang := pickLang(r)
	cfg := a.conf()

	if !cfg.LocalAdminEnabled {
		http.NotFound(w, r)
		return
	}
	nets, err := localAdminAllowedFrom(cfg.LocalAdminAllowedFrom)
	if err != nil {
		log.Printf("local admin: allowed-from is not parseable, refusing every request: %v", err)
		http.NotFound(w, r)
		return
	}
	client := clientIP(r)
	if !ipAllowed(nets, client) {
		log.Printf("local admin: refused login from %s (outside %s)", client, cfg.LocalAdminAllowedFrom)
		http.NotFound(w, r)
		return
	}

	switch r.Method {
	case http.MethodGet:
		a.renderSPA(w, r, "portal.html", a.baseSPAData("localLogin", lang), http.StatusOK)
		return
	case http.MethodPost:
	default:
		w.Header().Set("Allow", "GET, POST")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}

	// Same-origin check, matching every other state-changing admin endpoint.
	if !a.isSameOriginRequest(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross_origin"})
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")

	// The shared IP limiter still applies. It is not sufficient on its own —
	// hence the per-account lockout — but it is what stops one host from
	// running an unbounded guessing loop.
	if a.ipBans.isBanned(client) {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "rate_limited"})
		return
	}

	upn, err := authenticateLocalAdmin(a.db, username, password)
	if err != nil {
		a.recordIPFailure(client, "local admin login")
		a.logAdminAction(localAdminUPN(username), client, ResultDenied, "local admin login failed")
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_credentials"})
		return
	}

	sess := AdminSession{UPN: localAdminUPN(upn), Exp: time.Now().Add(adminSessionTTL).Unix()}
	if err := writeAdminCookie(w, cfg.SessionSecret, sess, strings.HasPrefix(cfg.PublicURL, "https://")); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cookie_write"})
		return
	}
	a.logAdminAction(sess.UPN, client, ResultSuccess, "local admin login (break-glass)")
	log.Printf("local admin login: %s from %s", sess.UPN, client)
	writeJSON(w, http.StatusOK, map[string]string{"redirect": "/admin"})
}
