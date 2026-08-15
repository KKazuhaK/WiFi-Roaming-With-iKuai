package main

// config_settings.go
// The registry that maps database settings onto Config, and the loader that
// builds a Config from a settings snapshot.
//
// This lives next to Config rather than inside internal/settings because the two
// have to change together: adding a Config field without a registry entry gives
// a field that silently stays at its zero value, and the compiler cannot catch
// that. Keeping them in one package at least keeps them in one place, and
// TestSettingRegistryCoversConfig fails when they drift.
//
// Precedence, decided once and applied everywhere: environment variables are an
// import source, not an override. On a database with no settings, importEnv
// copies them in; after that the database is authoritative and the environment
// is ignored, with a startup warning naming every variable that no longer does
// anything. The alternative — env wins over database — would mean a brand name
// edited in the admin UI silently reverts on the next restart, which is exactly
// the two-places-to-configure problem this work exists to remove.

import (
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kazuhahub/wifi-portal/internal/settings"
)

// Setting sections. Constants rather than literals because they appear in the
// registry, in the admin API routes and in the import, and a typo in any of
// those produces a silently empty settings page.
const (
	secOIDC        = "oidc"
	secIKuai       = "ikuai"
	secIKuaiPolicy = "ikuai_policy"
	secPortal      = "portal"
	secBrand       = "brand"
	secDuo         = "duo"
	secAuth        = "auth"
	secAdmin       = "admin"
	secRateLimit   = "ratelimit"
	secEventLog    = "eventlog"
	secLocalAdmin  = "local_admin"
)

// settingDef describes one database-backed setting.
type settingDef struct {
	Section string
	Key     string
	// Env is the variable this setting was read from before the move to the
	// database. Used only by the one-time import and by the startup warning
	// about variables that no longer take effect. Empty means the setting never
	// had an environment form.
	Env string
	// Default is the value used when the key is absent. It is a string because
	// that is what the table stores; the typed readers parse it.
	Default string
	// Secret marks a credential: encrypted at rest, never returned by the admin
	// API, and shown masked by the CLI.
	Secret bool
}

// settingRegistry is the complete set of database-backed settings.
//
// Ordered by section so the CLI's `config list` output reads like the admin
// pages. The zero-length Default entries are deliberate: an unset OIDC tenant
// should be visibly unset rather than defaulted to something that half-works.
var settingRegistry = []settingDef{
	// --- Entra (Azure AD) OIDC ---
	{Section: secOIDC, Key: "tenant_id", Env: "TENANT_ID"},
	{Section: secOIDC, Key: "client_id", Env: "CLIENT_ID"},
	{Section: secOIDC, Key: "client_secret", Env: "CLIENT_SECRET", Secret: true},

	// --- iKuai custom authentication ---
	{Section: secIKuai, Key: "app_key", Env: "IKUAI_APPKEY", Secret: true},
	{Section: secIKuai, Key: "webauth_url", Env: "IKUAI_WEBAUTH_URL", Default: "https://portal.ikuai8-wifi.com/Action/webauth-up"},
	{Section: secIKuai, Key: "release_type", Env: "IKUAI_RELEASE_TYPE", Default: "1"},
	// iKuai firmware versions disagree about the query-parameter names carrying
	// the client's IP and MAC, so both are lists tried in order.
	{Section: secIKuai, Key: "ip_keys", Env: "IKUAI_IP_KEYS", Default: "user_ip,ip,ipaddr"},
	{Section: secIKuai, Key: "mac_keys", Env: "IKUAI_MAC_KEYS", Default: "user_mac,mac,usrmac,devmac"},

	// --- iKuai allow-policy seeds ---
	// These only seed the ikuai_policy table on a fresh install; afterwards that
	// table is authoritative and is edited from the admin panel.
	{Section: secIKuaiPolicy, Key: "sso_upload", Env: "IKUAI_SSO_UPLOAD", Default: "0"},
	{Section: secIKuaiPolicy, Key: "sso_download", Env: "IKUAI_SSO_DOWNLOAD", Default: "0"},
	{Section: secIKuaiPolicy, Key: "sso_timeout", Env: "IKUAI_SSO_TIMEOUT", Default: "0"},
	{Section: secIKuaiPolicy, Key: "sso_comment", Env: "IKUAI_SSO_COMMENT"},
	{Section: secIKuaiPolicy, Key: "duo_upload", Env: "IKUAI_DUO_UPLOAD", Default: "0"},
	{Section: secIKuaiPolicy, Key: "duo_download", Env: "IKUAI_DUO_DOWNLOAD", Default: "0"},
	{Section: secIKuaiPolicy, Key: "duo_timeout", Env: "IKUAI_DUO_TIMEOUT", Default: "0"},
	{Section: secIKuaiPolicy, Key: "duo_comment", Env: "IKUAI_DUO_COMMENT"},
	{Section: secIKuaiPolicy, Key: "guest_upload", Env: "IKUAI_GUEST_UPLOAD", Default: "0"},
	{Section: secIKuaiPolicy, Key: "guest_download", Env: "IKUAI_GUEST_DOWNLOAD", Default: "0"},
	{Section: secIKuaiPolicy, Key: "guest_comment", Env: "IKUAI_GUEST_COMMENT"},

	// --- Portal runtime ---
	{Section: secPortal, Key: "public_url", Env: "PUBLIC_URL"},

	// --- Branding ---
	{Section: secBrand, Key: "name", Env: "BRAND_NAME", Default: "Kazuha Hub"},
	{Section: secBrand, Key: "color", Env: "BRAND_COLOR", Default: "#2563eb"},
	{Section: secBrand, Key: "logo_url", Env: "BRAND_LOGO_URL"},

	// --- Duo ---
	{Section: secDuo, Key: "ikey", Env: "DUO_IKEY"},
	{Section: secDuo, Key: "skey", Env: "DUO_SKEY", Secret: true},
	{Section: secDuo, Key: "client_id", Env: "DUO_CLIENT_ID"},
	{Section: secDuo, Key: "client_secret", Env: "DUO_CLIENT_SECRET", Secret: true},
	{Section: secDuo, Key: "api_host", Env: "DUO_API_HOST"},

	// --- Sign-in policy ---
	{Section: secAuth, Key: "allowed_email_domains", Env: "ALLOWED_EMAIL_DOMAINS"},

	// --- Admin access ---
	{Section: secAdmin, Key: "emails", Env: "ADMIN_EMAILS"},
	{Section: secAdmin, Key: "group_ids", Env: "ADMIN_GROUP_IDS"},

	// --- Rate limiting ---
	{Section: secRateLimit, Key: "auth_email_fails_short", Env: "AUTH_EMAIL_FAILS_SHORT", Default: "5"},
	{Section: secRateLimit, Key: "auth_email_window_short", Env: "AUTH_EMAIL_WINDOW_SHORT", Default: "3m"},
	{Section: secRateLimit, Key: "auth_email_fails_long", Env: "AUTH_EMAIL_FAILS_LONG", Default: "20"},
	{Section: secRateLimit, Key: "auth_email_window_long", Env: "AUTH_EMAIL_WINDOW_LONG", Default: "1h"},
	{Section: secRateLimit, Key: "guest_code_mac_fails", Env: "GUEST_CODE_MAC_FAILS", Default: "6"},
	{Section: secRateLimit, Key: "guest_code_mac_window", Env: "GUEST_CODE_MAC_WINDOW", Default: "30m"},
	{Section: secRateLimit, Key: "ip_fails_limit", Env: "IP_FAILS_LIMIT", Default: "20"},
	{Section: secRateLimit, Key: "ip_fails_window", Env: "IP_FAILS_WINDOW", Default: "5m"},
	{Section: secRateLimit, Key: "ip_ban_duration", Env: "IP_BAN_DURATION", Default: "2m"},
	// Permanent escalation defaults to effectively off: internal DHCP addresses
	// are poor long-term identities and banning one can lock out a whole floor.
	{Section: secRateLimit, Key: "ip_ban_escalate_at", Env: "IP_BAN_ESCALATE_AT", Default: "999999"},
	{Section: secRateLimit, Key: "auth_proceed_ttl", Env: "AUTH_PROCEED_TTL", Default: "5m"},

	// --- Event log ---
	{Section: secEventLog, Key: "retention_days", Env: "EVENT_LOG_RETENTION_DAYS", Default: "7"},

	// --- Break-glass local administrator ---
	// No Env entry on purpose: this has never had an environment form, and
	// giving it one would let a stray variable in a compose file switch on a
	// password login the operator never asked for.
	{Section: secLocalAdmin, Key: "enabled", Default: "false"},
	{Section: secLocalAdmin, Key: "allowed_from"},
}

// settingIndex is the registry keyed "section.key", built once at init.
var settingIndex = func() map[string]settingDef {
	m := make(map[string]settingDef, len(settingRegistry))
	for _, d := range settingRegistry {
		k := settings.Key(d.Section, d.Key)
		if _, dup := m[k]; dup {
			// A duplicate would make one of the two definitions unreachable and
			// is always a copy-paste error; failing at init beats debugging a
			// setting that will not stick.
			panic("duplicate setting definition: " + k)
		}
		m[k] = d
	}
	return m
}()

// isSecretSetting implements settings.SecretKeys.
func isSecretSetting(section, key string) bool {
	return settingIndex[settings.Key(section, key)].Secret
}

// defaultSettingValues returns every registry default, used to seed a fresh
// database so the settings pages render populated rather than empty.
func defaultSettingValues() map[string]map[string]string {
	out := map[string]map[string]string{}
	for _, d := range settingRegistry {
		if d.Default == "" {
			continue
		}
		if out[d.Section] == nil {
			out[d.Section] = map[string]string{}
		}
		out[d.Section][d.Key] = d.Default
	}
	return out
}

// applyRuntimeSettings fills cfg's database-backed fields from a snapshot,
// leaving the bootstrap fields (listen address, session secret, data dir,
// proxy trust) untouched.
//
// Every read carries the registry default so a missing key behaves exactly as
// it did when the environment variable was unset.
func applyRuntimeSettings(cfg *Config, v settings.Values) {
	def := func(section, key string) string { return settingIndex[settings.Key(section, key)].Default }
	defInt := func(section, key string) int {
		n, _ := strconv.Atoi(def(section, key))
		return n
	}
	defDur := func(section, key string) time.Duration {
		d, _ := time.ParseDuration(def(section, key))
		return d
	}

	cfg.TenantID = v.String(secOIDC, "tenant_id", "")
	cfg.ClientID = v.String(secOIDC, "client_id", "")
	cfg.ClientSecret = v.String(secOIDC, "client_secret", "")

	cfg.IKuaiAppKey = v.String(secIKuai, "app_key", "")
	cfg.IKuaiWebAuthURL = v.String(secIKuai, "webauth_url", def(secIKuai, "webauth_url"))
	cfg.IKuaiReleaseType = v.String(secIKuai, "release_type", def(secIKuai, "release_type"))
	cfg.IKuaiIPKeys = v.List(secIKuai, "ip_keys", splitCSV(def(secIKuai, "ip_keys")))
	cfg.IKuaiMACKeys = v.List(secIKuai, "mac_keys", splitCSV(def(secIKuai, "mac_keys")))

	cfg.IKuaiPolicyDefaults = map[IKuaiAuthProfile]IKuaiPolicy{
		IKuaiProfileSSO: {
			Upload:   v.Int(secIKuaiPolicy, "sso_upload", 0),
			Download: v.Int(secIKuaiPolicy, "sso_download", 0),
			Timeout:  v.Int(secIKuaiPolicy, "sso_timeout", 0),
			Comment:  strings.TrimSpace(v.String(secIKuaiPolicy, "sso_comment", "")),
		},
		IKuaiProfileDuo: {
			Upload:   v.Int(secIKuaiPolicy, "duo_upload", 0),
			Download: v.Int(secIKuaiPolicy, "duo_download", 0),
			Timeout:  v.Int(secIKuaiPolicy, "duo_timeout", 0),
			Comment:  strings.TrimSpace(v.String(secIKuaiPolicy, "duo_comment", "")),
		},
		IKuaiProfileGuest: {
			Upload:   v.Int(secIKuaiPolicy, "guest_upload", 0),
			Download: v.Int(secIKuaiPolicy, "guest_download", 0),
			// A guest code carries its own session length, so a profile-wide
			// timeout would silently override every code's duration.
			Timeout: 0,
			Comment: strings.TrimSpace(v.String(secIKuaiPolicy, "guest_comment", "")),
		},
	}

	cfg.PublicURL = strings.TrimRight(v.String(secPortal, "public_url", ""), "/")

	cfg.BrandName = v.String(secBrand, "name", def(secBrand, "name"))
	cfg.BrandColor = sanitizeBrandColor(v.String(secBrand, "color", ""), def(secBrand, "color"))
	cfg.BrandLogoURL = v.String(secBrand, "logo_url", "")

	cfg.DuoIKey = v.String(secDuo, "ikey", "")
	cfg.DuoSKey = v.String(secDuo, "skey", "")
	cfg.DuoClientID = v.String(secDuo, "client_id", "")
	cfg.DuoClientSecret = v.String(secDuo, "client_secret", "")
	cfg.DuoAPIHost = v.String(secDuo, "api_host", "")

	cfg.AllowedEmailDomains = v.List(secAuth, "allowed_email_domains", nil)
	cfg.AdminEmails = v.List(secAdmin, "emails", nil)
	cfg.AdminGroupIDs = v.List(secAdmin, "group_ids", nil)

	cfg.AuthEmailFailsShort = v.Int(secRateLimit, "auth_email_fails_short", defInt(secRateLimit, "auth_email_fails_short"))
	cfg.AuthEmailWindowShort = v.Duration(secRateLimit, "auth_email_window_short", defDur(secRateLimit, "auth_email_window_short"))
	cfg.AuthEmailFailsLong = v.Int(secRateLimit, "auth_email_fails_long", defInt(secRateLimit, "auth_email_fails_long"))
	cfg.AuthEmailWindowLong = v.Duration(secRateLimit, "auth_email_window_long", defDur(secRateLimit, "auth_email_window_long"))
	cfg.GuestCodeMacFails = v.Int(secRateLimit, "guest_code_mac_fails", defInt(secRateLimit, "guest_code_mac_fails"))
	cfg.GuestCodeMacWindow = v.Duration(secRateLimit, "guest_code_mac_window", defDur(secRateLimit, "guest_code_mac_window"))
	cfg.IPFailsLimit = v.Int(secRateLimit, "ip_fails_limit", defInt(secRateLimit, "ip_fails_limit"))
	cfg.IPFailsWindow = v.Duration(secRateLimit, "ip_fails_window", defDur(secRateLimit, "ip_fails_window"))
	cfg.IPBanDuration = v.Duration(secRateLimit, "ip_ban_duration", defDur(secRateLimit, "ip_ban_duration"))
	cfg.IPBanEscalateAt = v.Int(secRateLimit, "ip_ban_escalate_at", defInt(secRateLimit, "ip_ban_escalate_at"))
	cfg.AuthProceedTTL = v.Duration(secRateLimit, "auth_proceed_ttl", defDur(secRateLimit, "auth_proceed_ttl"))

	cfg.EventLogRetention = time.Duration(v.Int(secEventLog, "retention_days", defInt(secEventLog, "retention_days"))) * 24 * time.Hour

	cfg.LocalAdminEnabled = v.Bool(secLocalAdmin, "enabled", false)
	cfg.LocalAdminAllowedFrom = v.String(secLocalAdmin, "allowed_from", "")
}

// ConfigProblem is a validation finding against a runtime configuration.
//
// Validation reports rather than exits, which is the change that matters most
// in this whole migration. The old loadConfig called log.Fatalf on a partial
// Duo configuration or a non-https PUBLIC_URL, and that was correct when the
// only way to fix either was to edit .env and restart. It is actively harmful
// now: the settings live behind an admin UI that the portal itself serves, so
// exiting on a bad value takes away the only tool an operator has for repairing
// it. The portal starts, logs loudly, and disables whatever cannot work.
type ConfigProblem struct {
	Section string
	Key     string
	Message string
	// Fatal marks a problem the portal genuinely cannot run with, as opposed to
	// one that only disables a feature.
	Fatal bool
}

func (p ConfigProblem) String() string {
	where := p.Section
	if p.Key != "" {
		where = settings.Key(p.Section, p.Key)
	}
	return fmt.Sprintf("%s: %s", where, p.Message)
}

// validateRuntimeConfig checks the database-backed fields.
func validateRuntimeConfig(cfg *Config) []ConfigProblem {
	var problems []ConfigProblem

	if cfg.TenantID == "" || cfg.ClientID == "" || cfg.ClientSecret == "" {
		problems = append(problems, ConfigProblem{
			Section: secOIDC,
			Message: "Entra SSO is not fully configured (tenant, client ID and client secret are all required); sign-in will fail until it is",
		})
	}
	if cfg.IKuaiAppKey == "" {
		problems = append(problems, ConfigProblem{
			Section: secIKuai, Key: "app_key",
			Message: "no iKuai app key: authenticated devices cannot be allow-listed on the router",
		})
	}
	if cfg.PublicURL == "" {
		problems = append(problems, ConfigProblem{
			Section: secPortal, Key: "public_url",
			Message: "not set; OIDC redirects and the same-origin CSRF check cannot work",
			Fatal:   true,
		})
	} else if !strings.HasPrefix(cfg.PublicURL, "https://") {
		// Not fatal: a lab deployment on plain http is a real thing an operator
		// may be mid-way through setting up, and refusing to boot would leave
		// them unable to reach the page that fixes it. Entra will reject the
		// redirect URI anyway, which is the feedback that matters.
		problems = append(problems, ConfigProblem{
			Section: secPortal, Key: "public_url",
			Message: "does not start with https://; Entra will reject the redirect URI and cookies marked Secure will not be sent",
		})
	}

	// Duo is all-or-nothing: five fields, either every one set or none.
	duo := map[string]string{
		"ikey": cfg.DuoIKey, "skey": cfg.DuoSKey,
		"client_id": cfg.DuoClientID, "client_secret": cfg.DuoClientSecret,
		"api_host": cfg.DuoAPIHost,
	}
	var missing []string
	filled := 0
	for k, val := range duo {
		if val == "" {
			missing = append(missing, k)
		} else {
			filled++
		}
	}
	if filled > 0 && len(missing) > 0 {
		sort.Strings(missing)
		problems = append(problems, ConfigProblem{
			Section: secDuo,
			Message: "partially configured, so Duo stays disabled; missing: " + strings.Join(missing, ", "),
		})
	}
	if cfg.IsDuoEnabled() && len(cfg.AllowedEmailDomains) == 0 {
		problems = append(problems, ConfigProblem{
			Section: secAuth, Key: "allowed_email_domains",
			Message: "Duo is enabled but no email domains are allowed; every address would be sent to Duo for preauth",
		})
	}
	return problems
}

// logConfigProblems reports validation findings at startup and after a settings
// save. Kept separate from validation so the admin API can return the same
// findings to the UI instead of only writing them to a log nobody is reading.
func logConfigProblems(problems []ConfigProblem, when string) {
	for _, p := range problems {
		if p.Fatal {
			log.Printf("config %s: FATAL %s", when, p)
			continue
		}
		log.Printf("config %s: %s", when, p)
	}
}

// warnIgnoredRuntimeEnv lists environment variables that used to configure the
// portal and no longer do.
//
// This exists because the failure it prevents is silent and infuriating: an
// operator changes BRAND_NAME in their .env, restarts, sees no change, and has
// no way to discover why. One log line at startup naming the variable and where
// the setting now lives turns that into a thirty-second fix.
func warnIgnoredRuntimeEnv() {
	var ignored []string
	for _, d := range settingRegistry {
		if d.Env == "" {
			continue
		}
		if os.Getenv(d.Env) != "" {
			ignored = append(ignored, fmt.Sprintf("%s (now %s)", d.Env, settings.Key(d.Section, d.Key)))
		}
	}
	if len(ignored) == 0 {
		return
	}
	sort.Strings(ignored)
	log.Printf("config: %d environment variable(s) are set but no longer take effect — "+
		"runtime settings live in the database and are edited in Admin -> Settings. "+
		"They were imported once, on the first start against an empty database. Ignored: %s",
		len(ignored), strings.Join(ignored, ", "))
}
