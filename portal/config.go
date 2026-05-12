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
}

func loadConfig() Config {
	cfg := Config{
		TenantID:     mustEnv("TENANT_ID"),
		ClientID:     mustEnv("CLIENT_ID"),
		ClientSecret: mustEnv("CLIENT_SECRET"),
		IKuaiAppKey:  mustEnv("IKUAI_APPKEY"),
		PublicURL:    mustEnv("PUBLIC_URL"),

		IKuaiWebAuthURL: envOr("IKUAI_WEBAUTH_URL",
			"https://portal.ikuai8-wifi.com/Action/webauth-up"),
		IKuaiReleaseType:    envOr("IKUAI_RELEASE_TYPE", "1"),
		IKuaiPolicyDefaults: defaultIKuaiPoliciesFromEnv(),

		ListenAddr:   envOr("LISTEN_ADDR", "127.0.0.1:28080"),
		BrandName:    envOr("BRAND_NAME", "Kazuha Hub"),
		BrandColor:   sanitizeBrandColor(envOr("BRAND_COLOR", ""), "#2563eb"),
		BrandLogoURL: envOr("BRAND_LOGO_URL", ""),

		IKuaiIPKeys:  splitCSV(envOr("IKUAI_IP_KEYS", "user_ip,ip,ipaddr")),
		IKuaiMACKeys: splitCSV(envOr("IKUAI_MAC_KEYS", "user_mac,mac,usrmac,devmac")),

		DuoIKey:             envOr("DUO_IKEY", ""),
		DuoSKey:             envOr("DUO_SKEY", ""),
		DuoClientID:         envOr("DUO_CLIENT_ID", ""),
		DuoClientSecret:     envOr("DUO_CLIENT_SECRET", ""),
		DuoAPIHost:          envOr("DUO_API_HOST", ""),
		AllowedEmailDomains: splitCSV(envOr("ALLOWED_EMAIL_DOMAINS", "")),

		AdminEmails:   splitCSV(envOr("ADMIN_EMAILS", "")),
		AdminGroupIDs: splitCSV(envOr("ADMIN_GROUP_IDS", "")),

		AuthEmailFailsShort:  envOrInt("AUTH_EMAIL_FAILS_SHORT", 5),
		AuthEmailWindowShort: envOrDuration("AUTH_EMAIL_WINDOW_SHORT", 3*time.Minute),
		AuthEmailFailsLong:   envOrInt("AUTH_EMAIL_FAILS_LONG", 20),
		AuthEmailWindowLong:  envOrDuration("AUTH_EMAIL_WINDOW_LONG", time.Hour),
		GuestCodeMacFails:    envOrInt("GUEST_CODE_MAC_FAILS", 6),
		GuestCodeMacWindow:   envOrDuration("GUEST_CODE_MAC_WINDOW", 30*time.Minute),
		IPFailsLimit:         envOrInt("IP_FAILS_LIMIT", 20),
		IPFailsWindow:        envOrDuration("IP_FAILS_WINDOW", 5*time.Minute),
		IPBanDuration:        envOrDuration("IP_BAN_DURATION", 2*time.Minute),
		IPBanEscalateAt:      envOrInt("IP_BAN_ESCALATE_AT", 999999),
		AuthProceedTTL:       envOrDuration("AUTH_PROCEED_TTL", 5*time.Minute),

		EventLogRetention: time.Duration(envOrInt("EVENT_LOG_RETENTION_DAYS", 7)) * 24 * time.Hour,

		TrustProxy: envOrBool("TRUST_PROXY", true),
		DataDir:    envOr("DATA_DIR", "/data"),
	}

	secretHex := mustEnv("SESSION_SECRET")
	secret, err := hex.DecodeString(secretHex)
	if err != nil {
		log.Fatalf("SESSION_SECRET must be a hex string: %v", err)
	}
	if len(secret) < 32 {
		log.Fatalf("SESSION_SECRET must be at least 32 bytes (64 hex chars), got %d", len(secret))
	}
	cfg.SessionSecret = secret

	if !strings.HasPrefix(cfg.PublicURL, "https://") {
		log.Fatalf("PUBLIC_URL must start with https://, got: %s", cfg.PublicURL)
	}
	cfg.PublicURL = strings.TrimRight(cfg.PublicURL, "/")

	// Duo: all five fields must be either set or empty; partial configuration is fatal.
	duoFields := map[string]string{
		"DUO_IKEY":          cfg.DuoIKey,
		"DUO_SKEY":          cfg.DuoSKey,
		"DUO_CLIENT_ID":     cfg.DuoClientID,
		"DUO_CLIENT_SECRET": cfg.DuoClientSecret,
		"DUO_API_HOST":      cfg.DuoAPIHost,
	}
	filled, empty := 0, 0
	for _, v := range duoFields {
		if v == "" {
			empty++
		} else {
			filled++
		}
	}
	if filled > 0 && empty > 0 {
		log.Fatalf("Duo config incomplete: the following 5 fields must all be set or all be empty: %v", duoFields)
	}
	if cfg.IsDuoEnabled() && len(cfg.AllowedEmailDomains) == 0 {
		log.Fatalf("Duo requires ALLOWED_EMAIL_DOMAINS to be set")
	}

	return cfg
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
