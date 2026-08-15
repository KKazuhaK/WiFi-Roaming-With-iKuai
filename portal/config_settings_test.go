package main

import (
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kazuhahub/wifi-portal/internal/settings"
)

// Bootstrap fields are populated by applyBootstrap, not by the settings
// registry, so they are exempt from the coverage check below.
var bootstrapConfigFields = map[string]bool{
	"ListenAddr":    true,
	"SessionSecret": true,
	"DataDir":       true,
	"TrustProxy":    true,
}

// The failure this guards against is silent: adding a Config field without a
// registry entry leaves it permanently at its zero value, and nothing in the
// build or the tests would say so. An operator would find a rate limit of zero
// or an empty allow-list the hard way.
func TestEverySettingsBackedConfigFieldIsPopulated(t *testing.T) {
	// A snapshot with every registry key set to a value distinguishable from
	// the zero value for its Go type.
	v := settings.Values{}
	for _, d := range settingRegistry {
		v[settings.Key(d.Section, d.Key)] = probeValueFor(d)
	}

	var cfg Config
	applyRuntimeSettings(&cfg, v)

	rt := reflect.TypeOf(cfg)
	rv := reflect.ValueOf(cfg)
	for i := 0; i < rt.NumField(); i++ {
		name := rt.Field(i).Name
		if bootstrapConfigFields[name] {
			continue
		}
		if rv.Field(i).IsZero() {
			t.Errorf("Config.%s is still zero after applyRuntimeSettings; "+
				"it has no entry in settingRegistry, or applyRuntimeSettings does not read it", name)
		}
	}
}

// probeValueFor produces a non-zero string for a setting, respecting the shape
// its consumer will parse it as.
func probeValueFor(d settingDef) string {
	switch {
	case strings.HasSuffix(d.Key, "_window") || strings.HasSuffix(d.Key, "_short") ||
		strings.HasSuffix(d.Key, "_long") || strings.HasSuffix(d.Key, "_ttl") ||
		strings.HasSuffix(d.Key, "duration"):
		// Duration-shaped keys, except the fail counters which are plain ints.
		if _, err := strconv.Atoi(d.Default); err == nil && d.Default != "" {
			return "7"
		}
		return "11m"
	case d.Default != "":
		if _, err := strconv.Atoi(d.Default); err == nil {
			return "13"
		}
		if _, err := time.ParseDuration(d.Default); err == nil {
			return "11m"
		}
		return d.Default + "-probe"
	default:
		return "probe-" + d.Key
	}
}

func TestRegistryHasNoDuplicateEnvNames(t *testing.T) {
	seen := map[string]string{}
	for _, d := range settingRegistry {
		if d.Env == "" {
			continue
		}
		if prev, dup := seen[d.Env]; dup {
			t.Errorf("%s maps to both %s and %s; the import would pick one arbitrarily",
				d.Env, prev, settings.Key(d.Section, d.Key))
		}
		seen[d.Env] = settings.Key(d.Section, d.Key)
	}
}

// Every credential must be marked Secret, or it lands in the database as
// plaintext and in the admin API response.
func TestKnownCredentialsAreMarkedSecret(t *testing.T) {
	mustBeSecret := []string{
		settings.Key(secOIDC, "client_secret"),
		settings.Key(secIKuai, "app_key"),
		settings.Key(secDuo, "skey"),
		settings.Key(secDuo, "client_secret"),
	}
	for _, k := range mustBeSecret {
		d, ok := settingIndex[k]
		if !ok {
			t.Errorf("%s is missing from the registry", k)
			continue
		}
		if !d.Secret {
			t.Errorf("%s is not marked Secret; it would be stored in plaintext and returned by the admin API", k)
		}
		if !isSecretSetting(d.Section, d.Key) {
			t.Errorf("isSecretSetting(%s) = false", k)
		}
	}

	// And the inverse: a non-credential marked secret would be hidden from its
	// own settings page for no reason.
	for _, k := range []string{
		settings.Key(secBrand, "name"),
		settings.Key(secOIDC, "tenant_id"),
		settings.Key(secDuo, "api_host"),
	} {
		if settingIndex[k].Secret {
			t.Errorf("%s is marked Secret but is not a credential; it would be unreadable in the admin UI", k)
		}
	}
}

func TestApplyRuntimeSettingsUsesDefaults(t *testing.T) {
	var cfg Config
	applyRuntimeSettings(&cfg, settings.Values{})

	// An empty database has to behave exactly as an unset environment did.
	if cfg.BrandName != "Kazuha Hub" {
		t.Errorf("BrandName = %q, want the registry default", cfg.BrandName)
	}
	if cfg.BrandColor != "#2563eb" {
		t.Errorf("BrandColor = %q", cfg.BrandColor)
	}
	if cfg.AuthEmailFailsShort != 5 || cfg.AuthEmailWindowShort != 3*time.Minute {
		t.Errorf("rate-limit defaults = %d/%s, want 5/3m", cfg.AuthEmailFailsShort, cfg.AuthEmailWindowShort)
	}
	if cfg.IPBanEscalateAt != 999999 {
		t.Errorf("IPBanEscalateAt = %d; permanent escalation must stay effectively off by default", cfg.IPBanEscalateAt)
	}
	if cfg.EventLogRetention != 7*24*time.Hour {
		t.Errorf("EventLogRetention = %s, want 7 days", cfg.EventLogRetention)
	}
	if len(cfg.IKuaiIPKeys) != 3 || cfg.IKuaiIPKeys[0] != "user_ip" {
		t.Errorf("IKuaiIPKeys = %v, want the default list", cfg.IKuaiIPKeys)
	}
	// The guest profile's timeout comes from each code's own session length; a
	// profile-wide value would silently override every code.
	if cfg.IKuaiPolicyDefaults[IKuaiProfileGuest].Timeout != 0 {
		t.Errorf("guest profile timeout = %d, want 0", cfg.IKuaiPolicyDefaults[IKuaiProfileGuest].Timeout)
	}
}

func TestApplyRuntimeSettingsNormalises(t *testing.T) {
	var cfg Config
	applyRuntimeSettings(&cfg, settings.Values{
		settings.Key(secPortal, "public_url"): "https://wifi.example.com/",
		settings.Key(secBrand, "color"):       "javascript:alert(1)",
		settings.Key(secAdmin, "emails"):      " a@example.org , , b@example.org ",
	})

	// A trailing slash would produce "https://host//auth/callback", which Entra
	// compares literally against the registered redirect URI.
	if cfg.PublicURL != "https://wifi.example.com" {
		t.Errorf("PublicURL = %q, want the trailing slash stripped", cfg.PublicURL)
	}
	// The colour is interpolated into a CSS custom property in the served HTML.
	if strings.Contains(cfg.BrandColor, "javascript") {
		t.Errorf("BrandColor = %q; an unsafe value reached the config", cfg.BrandColor)
	}
	if len(cfg.AdminEmails) != 2 || cfg.AdminEmails[0] != "a@example.org" {
		t.Errorf("AdminEmails = %#v, want trimmed with empties dropped", cfg.AdminEmails)
	}
}

func TestValidateRuntimeConfig(t *testing.T) {
	// A fully unconfigured portal reports problems but none that stop it from
	// serving the admin console — that is what makes the settings repairable.
	var empty Config
	problems := validateRuntimeConfig(&empty)
	if len(problems) == 0 {
		t.Fatal("an unconfigured portal reported no problems")
	}
	fatalCount := 0
	for _, p := range problems {
		if p.Fatal {
			fatalCount++
		}
	}
	// Only the missing public URL is fatal; SSO and iKuai gaps must be
	// survivable so an operator can sign in and fix them.
	if fatalCount != 1 {
		t.Errorf("%d fatal problems, want exactly 1 (public_url); the rest must be repairable in the UI: %v", fatalCount, problems)
	}

	good := Config{
		TenantID: "t", ClientID: "c", ClientSecret: "s",
		IKuaiAppKey: "k", PublicURL: "https://wifi.example.com",
	}
	if p := validateRuntimeConfig(&good); len(p) != 0 {
		t.Errorf("a complete configuration reported problems: %v", p)
	}

	// Partial Duo must be reported and must name what is missing.
	partial := good
	partial.DuoIKey = "i"
	p := validateRuntimeConfig(&partial)
	if len(p) == 0 || !strings.Contains(p[0].Message, "skey") {
		t.Errorf("partial Duo config = %v, want a problem naming the missing fields", p)
	}
}

func TestWarnIgnoredRuntimeEnvDoesNotPanic(t *testing.T) {
	// Purely a smoke test over the registry: the function's value is a log line,
	// but a nil map or a bad format verb in it would crash startup.
	t.Setenv("BRAND_NAME", "Something")
	t.Setenv("TENANT_ID", "tenant")
	warnIgnoredRuntimeEnv()

	// And with nothing set it must stay silent rather than logging an empty list.
	for _, d := range settingRegistry {
		if d.Env != "" {
			os.Unsetenv(d.Env)
		}
	}
	warnIgnoredRuntimeEnv()
}
