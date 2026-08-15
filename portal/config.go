package main

// config.go
// Read environment variables into the Config struct.

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config contains all settings required to run the portal.
type Config struct {
	// --- Entra (Azure AD) OIDC ---
	TenantID     string
	ClientID     string
	ClientSecret string // Sensitive.

	// --- iKuai custom authentication ---
	IKuaiAppKey         string // Sensitive.
	IKuaiWebAuthURL     string
	IKuaiReleaseType    string
	IKuaiPolicyDefaults map[IKuaiAuthProfile]IKuaiPolicy

	// --- Portal runtime ---
	SessionSecret []byte // Sensitive.
	PublicURL     string
	ListenAddr    string
	// TrustProxy controls whether X-Real-IP / X-Forwarded-For are trusted. It defaults to true for
	// existing reverse-proxy deployments. Set it to false when the portal is directly exposed,
	// otherwise attackers can spoof IPs and bypass rate limits.
	TrustProxy bool
	// DataDir is the root for persistent files. /data works for containers where docker-compose
	// bind-mounts /data to ./data. Bare binary + systemd deployments usually use /var/lib/wifi-portal.
	DataDir string

	// --- Branding ---
	BrandName    string
	BrandColor   string
	BrandLogoURL string

	// --- iKuai field-name compatibility ---
	IKuaiIPKeys  []string
	IKuaiMACKeys []string

	// --- Duo integration (optional) ---
	// Requires two application types in the Duo Admin Panel:
	//   1. "Auth API" -> DUO_IKEY + DUO_SKEY, only for preauth user lookup.
	//   2. "Web SDK"  -> DUO_CLIENT_ID + DUO_CLIENT_SECRET, for the Universal Prompt OIDC flow.
	// DUO_API_HOST is shared by both applications in the same Duo tenant.
	// Duo is disabled when either credential set is missing.
	DuoIKey             string
	DuoSKey             string // Sensitive.
	DuoClientID         string
	DuoClientSecret     string // Sensitive.
	DuoAPIHost          string
	AllowedEmailDomains []string // Email-domain allowlist to stop external domains from triggering Duo prompts.

	// --- Guest-code admin (optional) ---
	// /admin can be authorized in either or both ways:
	//   AdminEmails    UPN allowlist, useful for small teams.
	//   AdminGroupIDs  Entra Security Group Object IDs; members become admins without env changes.
	// If both are empty, the admin console is fully disabled.
	AdminEmails   []string
	AdminGroupIDs []string

	// --- Rate-limit configuration ---
	// Rule 1: /auth/start counts email failures with two windows. Successful callbacks reset them.
	AuthEmailFailsShort  int           // Short-window limit (default 5).
	AuthEmailWindowShort time.Duration // Short-window duration (default 3m).
	AuthEmailFailsLong   int           // Long-window limit (default 20).
	AuthEmailWindowLong  time.Duration // Long-window duration (default 1h).
	// Rule 5: /auth/guest-code counts failures by MAC and resets on success.
	GuestCodeMacFails  int           // Default 6.
	GuestCodeMacWindow time.Duration // Default 30m.
	// Rule 6: one IP accumulates failures across endpoints and gets a short cooldown when over limit.
	// Permanent escalation is disabled by default because internal DHCP IPs are poor long-term identities.
	IPFailsLimit    int           // Default 20.
	IPFailsWindow   time.Duration // Default 5m.
	IPBanDuration   time.Duration // Cooldown duration, default 2m.
	IPBanEscalateAt int           // Trigger permanent deny at the Nth cooldown, default 999999 (effectively off).
	// Account-enumeration defense: /auth/start returns an opaque token; /auth/proceed performs the redirect.
	AuthProceedTTL time.Duration // Token lifetime (default 5m).

	// --- Event log (admin observability) ---
	EventLogRetention time.Duration // Events older than this are garbage-collected, default 7 days.

	// --- Break-glass local administrator ---
	// Off unless an operator turns it on from the CLI, so a deployment that does
	// not want a password on its admin surface never grows one. See localadmin.go
	// for why the mechanism exists at all.
	LocalAdminEnabled bool
	// LocalAdminAllowedFrom optionally restricts the login endpoint to a list of
	// CIDRs. Empty means no restriction.
	LocalAdminAllowedFrom string

	// --- TLS and the public listener ---
	// TLSMode is "proxy" (something in front terminates TLS, the historical and
	// still-default arrangement) or "standalone" (the portal binds 443 itself).
	TLSMode string
	// TLSDomain is the hostname the certificate is issued for. Derived from
	// PublicURL when unset, because they are almost always the same and asking
	// twice invites them to disagree.
	TLSDomain string
	// TLSListenAddr is where the HTTPS listener binds in standalone mode.
	TLSListenAddr string
	// TLSRedirectHTTP sends plain HTTP to HTTPS. Off by default in standalone
	// mode because port 80 is also where iKuai sends captive clients and where
	// ACME answers its challenge; an operator turns it on once they know the
	// rest works.
	TLSRedirectHTTP bool

	ACMEEnabled bool
	ACMEEmail   string
	// ACMEStaging points at Let's Encrypt's staging directory: untrusted
	// certificates, generous rate limits. The place to debug a failing challenge
	// without burning five real orders a week.
	ACMEStaging bool
}

// BootstrapConfig is the part of the configuration that has to exist before the
// database can be opened, so it is the only part still read from the
// environment. Everything else moved into the setting table — see
// config_settings.go for why the environment is an import source rather than an
// override.
type BootstrapConfig struct {
	// ListenAddr is where the process binds at startup. TLS and a
	// database-configured listener replace this later; this value is what gets
	// the admin UI reachable in the first place, including after a bad TLS
	// change, so it stays in the file an operator can edit over SSH.
	ListenAddr string
	// SessionSecret signs the cookies that authenticate the administrator who
	// edits everything else. It cannot live in the database it protects access
	// to.
	SessionSecret []byte
	// EncryptionKey protects credentials stored in the database. Empty means
	// they are stored in plaintext, which is allowed so an existing deployment
	// still starts after an upgrade — with a loud warning.
	EncryptionKey string
	// DataDir holds the default SQLite file and anything else on disk.
	DataDir string
	// DBDSN selects and addresses the database. Empty means SQLite in DataDir.
	DBDSN string
	// DBMaxOpenConns caps the connection pool for MySQL and PostgreSQL. Zero
	// takes the storage layer's default. It is a bootstrap value rather than a
	// setting because the pool is built before the settings table can be read,
	// and because the number an operator needs is a property of their database
	// server — max_connections divided by the number of portal instances — not
	// of the portal.
	DBMaxOpenConns int
	// TrustProxy decides whether X-Forwarded-For is believed. It gates the
	// client-IP parsing that the rate limiter and the audit log depend on, so it
	// is read before any request is served and is not runtime-editable: getting
	// it wrong from a settings page would silently disable abuse protection.
	TrustProxy bool
}

// loadBootstrap reads the environment-only configuration. It exits on a problem,
// which is still right here: none of these can be repaired from a UI the portal
// has not managed to start.
func loadBootstrap() BootstrapConfig {
	b := BootstrapConfig{
		ListenAddr:     envOr("LISTEN_ADDR", "127.0.0.1:28080"),
		EncryptionKey:  strings.TrimSpace(envOr("ENCRYPTION_KEY", "")),
		DataDir:        envOr("DATA_DIR", "/data"),
		DBDSN:          strings.TrimSpace(envOr("DB_DSN", "")),
		DBMaxOpenConns: envOrInt("DB_MAX_OPEN_CONNS", 0),
		TrustProxy:     envOrBool("TRUST_PROXY", true),
	}

	secretHex := mustEnv("SESSION_SECRET")
	sec, err := hex.DecodeString(secretHex)
	if err != nil {
		log.Fatalf("SESSION_SECRET must be a hex string: %v", err)
	}
	if len(sec) < 32 {
		log.Fatalf("SESSION_SECRET must be at least 32 bytes (64 hex chars), got %d", len(sec))
	}
	b.SessionSecret = sec

	if b.EncryptionKey == "" {
		log.Printf("WARNING: ENCRYPTION_KEY is not set, so credentials in the database " +
			"(OIDC client secret, iKuai app key, Duo keys) are stored in PLAINTEXT. " +
			"Generate one with `openssl rand -hex 32` and set it before the database " +
			"is backed up or replicated. Existing plaintext values are re-encrypted on the next save.")
	} else if len(b.EncryptionKey) < 32 {
		log.Fatalf("ENCRYPTION_KEY must be at least 32 characters, got %d", len(b.EncryptionKey))
	}

	return b
}

// applyBootstrap copies the bootstrap fields into a Config. Config keeps holding
// both halves so the ~60 call sites reading a.conf().X did not have to learn
// which half a field came from.
func applyBootstrap(cfg *Config, b BootstrapConfig) {
	cfg.ListenAddr = b.ListenAddr
	cfg.SessionSecret = b.SessionSecret
	cfg.DataDir = b.DataDir
	cfg.TrustProxy = b.TrustProxy
}

// IsDuoEnabled reports whether all five Duo fields are configured.
func (c Config) IsDuoEnabled() bool {
	return c.DuoIKey != "" && c.DuoSKey != "" &&
		c.DuoClientID != "" && c.DuoClientSecret != "" &&
		c.DuoAPIHost != ""
}

// IsAdminEnabled reports whether the admin console and guest-code flow are enabled.
// Either UPN allowlist or group-based access enables it.
func (c Config) IsAdminEnabled() bool {
	return len(c.AdminEmails) > 0 || len(c.AdminGroupIDs) > 0
}

func (c Config) IsAdminEmail(upn string) bool {
	u := strings.ToLower(strings.TrimSpace(upn))
	for _, a := range c.AdminEmails {
		if strings.ToLower(strings.TrimSpace(a)) == u {
			return true
		}
	}
	return false
}

func (c Config) Issuer() string {
	return fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", c.TenantID)
}

func (c Config) RedirectURL() string {
	return c.PublicURL + "/auth/callback"
}

// --- Helpers ---

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("env %s is not set", key)
	}
	return v
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envOrInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		log.Fatalf("env %s must be an integer, got: %q", key, v)
	}
	return n
}

func envOrNonNegativeInt(key string, fallback int) int {
	n := envOrInt(key, fallback)
	if n < 0 {
		log.Fatalf("env %s must be a non-negative integer, got: %d", key, n)
	}
	return n
}

// envOrDuration parses time.Duration values such as "5m" or "1h30m". Empty uses fallback.
// envOrBool parses "true/false/1/0/yes/no/on/off". Empty uses fallback.
// Other strings are fatal because rate-limit misconfiguration should be surfaced immediately.
func envOrBool(key string, fallback bool) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if v == "" {
		return fallback
	}
	switch v {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	log.Fatalf("env %s must be a boolean (true/false), got: %q", key, v)
	return fallback
}

func envOrDuration(key string, fallback time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		log.Fatalf("env %s must be a duration (e.g. 5m, 1h), got: %q", key, v)
	}
	return d
}

// sanitizeBrandColor validates that BRAND_COLOR is a safe CSS color (#rgb / #rrggbb / #rrggbbaa).
// Invalid values silently fall back so a bad admin value does not prevent startup.
//
// Reason: the value is inserted into <style>--brand: X;</style>. html/template CSS-context escaping
// does not prevent CSS syntax injection, so the entry point must enforce an allowlist.
func sanitizeBrandColor(raw, fallback string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return fallback
	}
	if !isHexColor(s) {
		return fallback
	}
	return s
}

// isHexColor strictly matches #RGB / #RRGGBB / #RRGGBBAA with [0-9a-fA-F] only.
// Avoid regexp here to keep startup-path validation small.
func isHexColor(s string) bool {
	if len(s) < 4 || s[0] != '#' {
		return false
	}
	rest := s[1:]
	switch len(rest) {
	case 3, 6, 8:
	default:
		return false
	}
	for _, c := range rest {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
