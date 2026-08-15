package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kazuhahub/wifi-portal/internal/dbstore"
	"github.com/kazuhahub/wifi-portal/internal/secret"
	"github.com/kazuhahub/wifi-portal/internal/settings"
)

func newImportFixture(t *testing.T) (*dbstore.DB, *settings.Store, BootstrapConfig) {
	t.Helper()
	dir := t.TempDir()
	db, err := dbstore.Open(dbstore.Options{DataDir: dir})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := dbstore.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	store := settings.New(db, secret.NewKeyring("0123456789abcdef0123456789abcdef"), isSecretSetting)
	return db, store, BootstrapConfig{DataDir: dir}
}

func writeLegacyJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// The upgrade path in one test: an installation with .env and populated JSON
// files restarts on the new binary and finds everything where it was.
func TestImportAdoptsExistingInstallation(t *testing.T) {
	db, store, boot := newImportFixture(t)
	paths := makeDataPaths(boot.DataDir)

	t.Setenv("TENANT_ID", "tenant-abc")
	t.Setenv("CLIENT_SECRET", "super-secret")
	t.Setenv("BRAND_NAME", "Acme Wi-Fi")
	t.Setenv("IP_FAILS_LIMIT", "33")

	expiry := time.Now().Add(48 * time.Hour).Truncate(time.Second)
	writeLegacyJSON(t, paths.GuestCodes, []legacyGuestCode{
		{
			Code: "1234567890", CreatedAt: time.Now().Add(-time.Hour).Truncate(time.Second),
			ExpiresAt: expiry, DurationMin: 1080, MaxUses: 2, Note: "front desk",
			Uses: []legacyCodeUse{{At: time.Now().Add(-time.Minute).Truncate(time.Second), MAC: "aa:bb:cc:dd:ee:ff", IP: "10.0.0.5", GuestUPN: "Guest-abc12345"}},
		},
		// A code that never expires: the zero time must become NULL, not a
		// sentinel date that range queries would treat as real.
		{Code: "neverexpires", CreatedAt: time.Now().Truncate(time.Second), DurationMin: 120},
	})
	writeLegacyJSON(t, paths.Denylist, []legacyDeniedMAC{
		{MAC: "11:22:33:44:55:66", Reason: "abuse", CreatedAt: time.Now().Truncate(time.Second), CreatedBy: "admin@example.org"},
	})
	writeLegacyJSON(t, paths.IKuaiPolicy, map[string]IKuaiPolicy{
		"sso":   {Upload: 512, Download: 2048, Timeout: 60, Comment: "staff"},
		"guest": {Upload: 256, Download: 1024},
	})
	writeLegacyJSON(t, paths.BanHistory, map[string]int{"10.0.0.9": 3, "10.0.0.10": 1})

	// events.jsonl, including one malformed line that must be skipped without
	// abandoning the rest of the audit trail.
	events := ""
	for _, ev := range []legacyEvent{
		{Time: time.Now().Add(-2 * time.Hour), Kind: "login", Subject: "a@example.org", Result: "success", Method: "sso"},
		{Time: time.Now().Add(-time.Hour), Kind: "admin_action", Subject: "admin@example.org", Result: "success", Method: "admin", Detail: "add code"},
	} {
		b, _ := json.Marshal(ev)
		events += string(b) + "\n"
	}
	events += "{not valid json\n\n"
	if err := os.WriteFile(paths.EventLog, []byte(events), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := importLegacyState(db, store, boot); err != nil {
		t.Fatalf("import: %v", err)
	}
	// Called directly: importLegacyState does not run it yet, because the stores
	// still read the files it renames. See the note there.
	importLegacyStateFiles(db, makeDataPaths(boot.DataDir))

	// --- settings ---
	values, err := store.LoadAll()
	if err != nil {
		t.Fatalf("load settings: %v", err)
	}
	if got := values.String(secOIDC, "tenant_id", ""); got != "tenant-abc" {
		t.Errorf("tenant_id = %q", got)
	}
	if got := values.String(secBrand, "name", ""); got != "Acme Wi-Fi" {
		t.Errorf("brand name = %q", got)
	}
	if got := values.Int(secRateLimit, "ip_fails_limit", 0); got != 33 {
		t.Errorf("ip_fails_limit = %d", got)
	}
	// An env value the operator did not set must land on its registry default,
	// not on an empty string.
	if got := values.String(secIKuai, "release_type", ""); got != "1" {
		t.Errorf("release_type = %q, want the default", got)
	}
	// The imported client secret must be encrypted at rest.
	var row dbstore.Setting
	if err := db.Where("section = ? AND key = ?", secOIDC, "client_secret").First(&row).Error; err != nil {
		t.Fatalf("read client_secret row: %v", err)
	}
	if !secret.IsEncrypted(row.Value) {
		t.Errorf("imported client_secret is not encrypted: %q", row.Value)
	}

	// --- guest codes ---
	var codes []dbstore.GuestCode
	if err := db.Order("code").Find(&codes).Error; err != nil {
		t.Fatal(err)
	}
	if len(codes) != 2 {
		t.Fatalf("%d guest codes imported, want 2", len(codes))
	}
	byCode := map[string]dbstore.GuestCode{}
	for _, c := range codes {
		byCode[c.Code] = c
	}
	if c := byCode["1234567890"]; c.MaxUses != 2 || c.Note != "front desk" || c.DurationMin != 1080 {
		t.Errorf("code fields not carried over: %+v", c)
	}
	if c := byCode["1234567890"]; c.ExpiresAt == nil || !c.ExpiresAt.Equal(expiry.UTC()) {
		t.Errorf("expiry = %v, want %v", c.ExpiresAt, expiry.UTC())
	}
	if c := byCode["neverexpires"]; c.ExpiresAt != nil {
		t.Errorf("a never-expiring code got an expiry of %v; it must be NULL", c.ExpiresAt)
	}
	var uses int64
	db.Model(&dbstore.GuestCodeUse{}).Count(&uses)
	if uses != 1 {
		t.Errorf("%d redemptions imported, want 1", uses)
	}

	// --- other tables ---
	var macs int64
	db.Model(&dbstore.DeniedMAC{}).Count(&macs)
	if macs != 1 {
		t.Errorf("%d denied MACs, want 1", macs)
	}
	var policies []dbstore.IKuaiPolicy
	db.Find(&policies)
	if len(policies) != 2 {
		t.Errorf("%d policies, want 2", len(policies))
	}
	var bans int64
	db.Model(&dbstore.BanHistory{}).Count(&bans)
	if bans != 2 {
		t.Errorf("%d ban-history rows, want 2", bans)
	}
	var evs int64
	db.Model(&dbstore.Event{}).Count(&evs)
	if evs != 2 {
		t.Errorf("%d events, want 2 (the malformed line should be skipped, the valid ones kept)", evs)
	}

	// --- files renamed, never deleted ---
	for _, p := range []string{paths.GuestCodes, paths.Denylist, paths.IKuaiPolicy, paths.BanHistory, paths.EventLog} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s still exists under its original name; a restart would re-import it", filepath.Base(p))
		}
		if _, err := os.Stat(p + ".migrated"); err != nil {
			t.Errorf("%s.migrated missing; the import deleted data instead of renaming it", filepath.Base(p))
		}
	}
}

// The rule that protects an operator's own edits: once settings exist, the
// import must never run again, whatever is lying around on disk.
func TestImportIsSkippedOnAPopulatedDatabase(t *testing.T) {
	db, store, boot := newImportFixture(t)
	paths := makeDataPaths(boot.DataDir)

	if err := store.SetOne(secBrand, "name", "Configured By Admin", "admin"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BRAND_NAME", "From Env")
	writeLegacyJSON(t, paths.GuestCodes, []legacyGuestCode{{Code: "should-not-appear", CreatedAt: time.Now()}})

	if err := importLegacyState(db, store, boot); err != nil {
		t.Fatalf("import: %v", err)
	}

	values, _ := store.LoadAll()
	if got := values.String(secBrand, "name", ""); got != "Configured By Admin" {
		t.Errorf("brand name = %q; the import overwrote an admin's edit", got)
	}
	var codes int64
	db.Model(&dbstore.GuestCode{}).Count(&codes)
	if codes != 0 {
		t.Errorf("%d guest codes imported into a populated database; a stale file was resurrected", codes)
	}
	// And the file must be left alone for the same reason.
	if _, err := os.Stat(paths.GuestCodes); err != nil {
		t.Errorf("the skipped import renamed %s anyway", paths.GuestCodes)
	}
}

// A fresh install with nothing to adopt must still come up with defaults
// populated, so the settings pages render filled in rather than blank.
func TestImportOnFreshInstallSeedsDefaults(t *testing.T) {
	db, store, boot := newImportFixture(t)
	for _, d := range settingRegistry {
		if d.Env != "" {
			os.Unsetenv(d.Env)
		}
	}

	if err := importLegacyState(db, store, boot); err != nil {
		t.Fatalf("import: %v", err)
	}
	values, err := store.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	if got := values.String(secBrand, "name", ""); got != "Kazuha Hub" {
		t.Errorf("brand name = %q, want the registry default", got)
	}
	if got := values.String(secIKuai, "webauth_url", ""); got == "" {
		t.Error("webauth_url was not seeded")
	}

	// A second run must be a no-op now that settings exist.
	if err := importLegacyState(db, store, boot); err != nil {
		t.Fatalf("second import: %v", err)
	}
}

// A corrupt guest-code file is the worst case: the codes are in people's hands
// right now. It must not be silently swallowed, and it must not be deleted.
func TestImportLeavesCorruptGuestCodeFileIntact(t *testing.T) {
	db, store, boot := newImportFixture(t)
	paths := makeDataPaths(boot.DataDir)

	if err := os.WriteFile(paths.GuestCodes, []byte("{ this is not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := importLegacyState(db, store, boot); err != nil {
		t.Fatalf("a corrupt file must not fail the import: %v", err)
	}
	importLegacyStateFiles(db, paths)

	if _, err := os.Stat(paths.GuestCodes); err != nil {
		t.Error("the corrupt file was renamed or deleted; the operator needs it to recover")
	}
	if _, err := os.Stat(paths.GuestCodes + ".migrated"); err == nil {
		t.Error("a file that failed to import was marked migrated")
	}
}
