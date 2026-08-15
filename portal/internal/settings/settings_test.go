package settings

import (
	"strings"
	"testing"
	"time"

	"github.com/kazuhahub/wifi-portal/internal/dbstore"
	"github.com/kazuhahub/wifi-portal/internal/secret"
)

const testKey = "0123456789abcdef0123456789abcdef0123456789abcdef"

// Only these two are treated as credentials in the tests below.
func testSecrets(section, key string) bool {
	return section == "oidc" && (key == "client_secret" || key == "app_key")
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	db, err := dbstore.Open(dbstore.Options{DataDir: t.TempDir()})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := dbstore.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return New(db, secret.NewKeyring(testKey), testSecrets)
}

func TestSaveAndLoadRoundTrip(t *testing.T) {
	s := newTestStore(t)

	if err := s.Save("oidc", map[string]string{
		"tenant_id":     "tenant-123",
		"client_id":     "client-456",
		"client_secret": "hunter2",
	}, "admin@example.org"); err != nil {
		t.Fatalf("Save: %v", err)
	}

	all, err := s.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if got := all.String("oidc", "tenant_id", ""); got != "tenant-123" {
		t.Errorf("tenant_id = %q", got)
	}
	// The secret must come back decrypted for the OIDC client that consumes it.
	if got := all.String("oidc", "client_secret", ""); got != "hunter2" {
		t.Errorf("client_secret = %q, want the decrypted value", got)
	}
}

// The whole point of encrypting at rest: a database dump must not contain the
// credential.
func TestSecretsAreEncryptedInTheTable(t *testing.T) {
	s := newTestStore(t)
	if err := s.Save("oidc", map[string]string{
		"client_secret": "hunter2",
		"client_id":     "client-456",
	}, "admin"); err != nil {
		t.Fatalf("Save: %v", err)
	}

	var rows []dbstore.Setting
	if err := s.db.Find(&rows).Error; err != nil {
		t.Fatalf("raw read: %v", err)
	}
	var sawSecret, sawPlain bool
	for _, r := range rows {
		switch r.Key {
		case "client_secret":
			sawSecret = true
			if strings.Contains(r.Value, "hunter2") {
				t.Errorf("client_secret stored in plaintext: %q", r.Value)
			}
			if !secret.IsEncrypted(r.Value) {
				t.Errorf("client_secret is not in encrypted form: %q", r.Value)
			}
		case "client_id":
			sawPlain = true
			// A non-secret must stay readable, or an operator inspecting the
			// table for support cannot tell what is configured.
			if r.Value != "client-456" {
				t.Errorf("client_id was mangled: %q", r.Value)
			}
		}
	}
	if !sawSecret || !sawPlain {
		t.Fatalf("expected both rows, got %+v", rows)
	}
}

func TestSaveIsUpsert(t *testing.T) {
	s := newTestStore(t)
	if err := s.Save("brand", map[string]string{"name": "Old"}, "a"); err != nil {
		t.Fatal(err)
	}
	if err := s.Save("brand", map[string]string{"name": "New"}, "b"); err != nil {
		t.Fatal(err)
	}

	sec, err := s.LoadSection("brand")
	if err != nil {
		t.Fatal(err)
	}
	if sec["name"] != "New" {
		t.Errorf("name = %q, want New", sec["name"])
	}
	var count int64
	if err := s.db.Model(&dbstore.Setting{}).Where("section = ? AND key = ?", "brand", "name").Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("%d rows for brand.name; the upsert inserted a duplicate", count)
	}
}

// A page that renders part of a section must not blank the rest of it.
func TestSaveLeavesUnlistedKeysAlone(t *testing.T) {
	s := newTestStore(t)
	if err := s.Save("brand", map[string]string{"name": "Kazuha Hub", "color": "#2563eb"}, "a"); err != nil {
		t.Fatal(err)
	}
	if err := s.Save("brand", map[string]string{"name": "Renamed"}, "b"); err != nil {
		t.Fatal(err)
	}
	sec, _ := s.LoadSection("brand")
	if sec["color"] != "#2563eb" {
		t.Errorf("color = %q; saving name wiped an unrelated key", sec["color"])
	}
}

// The admin API must never hand back a stored credential.
func TestRedact(t *testing.T) {
	s := newTestStore(t)
	fields, present := s.Redact("oidc", map[string]string{
		"tenant_id":     "tenant-123",
		"client_secret": "hunter2",
		"app_key":       "",
	})
	if _, leaked := fields["client_secret"]; leaked {
		t.Error("client_secret survived redaction")
	}
	if fields["tenant_id"] != "tenant-123" {
		t.Errorf("non-secret was redacted: %v", fields)
	}
	if !present["client_secret"] {
		t.Error("a set secret should report present so the form can say so")
	}
	if present["app_key"] {
		t.Error("an unset secret must not report present")
	}
}

// Saving the OIDC page after changing only the tenant must not blank the client
// secret, which the form never had to send back.
func TestApplySecretUpdatesKeepsBlankSecrets(t *testing.T) {
	s := newTestStore(t)
	stored := map[string]string{"tenant_id": "old", "client_secret": "hunter2"}

	merged := s.ApplySecretUpdates("oidc", stored, map[string]string{
		"tenant_id":     "new",
		"client_secret": "",
	})
	if merged["tenant_id"] != "new" {
		t.Errorf("tenant_id = %q", merged["tenant_id"])
	}
	if merged["client_secret"] != "hunter2" {
		t.Errorf("client_secret = %q; a blank submission wiped it", merged["client_secret"])
	}

	// A non-blank submission must still replace it, or a secret could never be
	// rotated.
	merged = s.ApplySecretUpdates("oidc", stored, map[string]string{"client_secret": "rotated"})
	if merged["client_secret"] != "rotated" {
		t.Errorf("client_secret = %q, want the new value", merged["client_secret"])
	}

	// A blank NON-secret is a real edit — clearing an optional field has to work.
	merged = s.ApplySecretUpdates("oidc", map[string]string{"tenant_id": "old"}, map[string]string{"tenant_id": ""})
	if merged["tenant_id"] != "" {
		t.Errorf("tenant_id = %q; blanking a non-secret should clear it", merged["tenant_id"])
	}
}

// A lost encryption key must fail the load loudly. Skipping the unreadable key
// would start the portal with an empty client secret and surface as a sign-in
// failure hours later with nothing pointing at the cause.
func TestLoadFailsLoudlyOnUndecryptableSecret(t *testing.T) {
	s := newTestStore(t)
	if err := s.Save("oidc", map[string]string{"client_secret": "hunter2"}, "a"); err != nil {
		t.Fatal(err)
	}

	rotated := New(s.db, secret.NewKeyring("ffffffffffffffffffffffffffffffffffffffffffffffff"), testSecrets)
	if _, err := rotated.LoadAll(); err == nil {
		t.Fatal("LoadAll succeeded with the wrong encryption key")
	} else if !strings.Contains(err.Error(), "oidc.client_secret") {
		t.Errorf("error should name the offending key, got: %v", err)
	}
}

func TestTypedReaders(t *testing.T) {
	v := Values{
		"rl.email_short":  "5",
		"rl.window_short": "3m",
		"rl.enabled":      "true",
		"brand.name":      "Kazuha Hub",
		"auth.domains":    "example.org, example.com ,,",
		"rl.bad_int":      "not-a-number",
		"rl.bad_duration": "not-a-duration",
		"brand.empty":     "",
		"auth.empty_list": "  ,  ",
	}

	if got := v.Int("rl", "email_short", 1); got != 5 {
		t.Errorf("Int = %d", got)
	}
	if got := v.Duration("rl", "window_short", time.Second); got != 3*time.Minute {
		t.Errorf("Duration = %s", got)
	}
	if got := v.Bool("rl", "enabled", false); !got {
		t.Error("Bool = false")
	}
	if got := v.String("brand", "name", "x"); got != "Kazuha Hub" {
		t.Errorf("String = %q", got)
	}
	if got := v.List("auth", "domains", nil); len(got) != 2 || got[0] != "example.org" || got[1] != "example.com" {
		t.Errorf("List = %#v; want trimmed with empties dropped", got)
	}

	// Malformed and empty values fall back rather than failing startup. A bad
	// value means something went wrong upstream, and taking the portal down
	// over one unparseable integer turns a cosmetic bug into an outage.
	if got := v.Int("rl", "bad_int", 42); got != 42 {
		t.Errorf("malformed Int = %d, want the default", got)
	}
	if got := v.Duration("rl", "bad_duration", time.Minute); got != time.Minute {
		t.Errorf("malformed Duration = %s, want the default", got)
	}
	if got := v.String("brand", "empty", "fallback"); got != "fallback" {
		t.Errorf("empty String = %q, want the default", got)
	}
	if got := v.List("auth", "empty_list", []string{"d"}); len(got) != 1 || got[0] != "d" {
		t.Errorf("all-empty List = %#v, want the default", got)
	}
	if got := v.Int("rl", "missing", 7); got != 7 {
		t.Errorf("missing Int = %d, want the default", got)
	}
}
