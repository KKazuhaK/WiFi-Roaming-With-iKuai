package dbstore

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDetectDriver(t *testing.T) {
	cases := []struct {
		dsn      string
		wantDrv  Driver
		wantConn string
	}{
		{"", DriverSQLite, ""},
		{"sqlite:./data/portal.db", DriverSQLite, "./data/portal.db"},
		{"file:/var/lib/wifi-portal/p.db", DriverSQLite, "file:/var/lib/wifi-portal/p.db"},
		{"/var/lib/wifi-portal/portal.db", DriverSQLite, "/var/lib/wifi-portal/portal.db"},
		{"./portal.sqlite3", DriverSQLite, "./portal.sqlite3"},
		{"postgres://u:p@h:5432/db?sslmode=disable", DriverPostgres, "postgres://u:p@h:5432/db?sslmode=disable"},
		{"postgresql://u:p@h/db", DriverPostgres, "postgresql://u:p@h/db"},
		{"host=127.0.0.1 user=psp dbname=portal", DriverPostgres, "host=127.0.0.1 user=psp dbname=portal"},
		{"user:pw@tcp(127.0.0.1:3306)/portal?parseTime=true", DriverMySQL, "user:pw@tcp(127.0.0.1:3306)/portal?parseTime=true"},
		{"user:pw@unix(/tmp/mysql.sock)/portal", DriverMySQL, "user:pw@unix(/tmp/mysql.sock)/portal"},
	}
	for _, c := range cases {
		gotDrv, gotConn := detectDriver(c.dsn)
		if gotDrv != c.wantDrv || gotConn != c.wantConn {
			t.Errorf("detectDriver(%q) = (%s, %q), want (%s, %q)", c.dsn, gotDrv, gotConn, c.wantDrv, c.wantConn)
		}
	}
}

// A DSN reaches the log on every startup and on every connection error. The
// password must not come with it.
func TestRedactDSN(t *testing.T) {
	cases := []struct {
		drv    Driver
		dsn    string
		absent string
	}{
		{DriverPostgres, "postgres://psp:hunter2@127.0.0.1:5432/portal", "hunter2"},
		{DriverMySQL, "psp:hunter2@tcp(127.0.0.1:3306)/portal", "hunter2"},
		{DriverPostgres, "host=127.0.0.1 user=psp password=hunter2 dbname=portal", "hunter2"},
	}
	for _, c := range cases {
		got := redactDSN(c.drv, c.dsn)
		if strings.Contains(got, c.absent) {
			t.Errorf("redactDSN(%s, %q) = %q, still contains the password", c.drv, c.dsn, got)
		}
		if got == "" {
			t.Errorf("redactDSN(%s, %q) returned empty", c.drv, c.dsn)
		}
	}

	// A SQLite path has no credentials and stays readable — it is the single
	// most useful thing in the startup log for a file-backed deployment.
	if got := redactDSN(DriverSQLite, "/var/lib/wifi-portal/portal.db"); got != "/var/lib/wifi-portal/portal.db" {
		t.Errorf("sqlite DSN was mangled: %q", got)
	}
}

// openTestDB gives each test its own SQLite file. t.TempDir cleans it up, and a
// file rather than :memory: is deliberate: the pragmas under test (WAL in
// particular) behave differently for an in-memory database, so testing against
// one would not exercise the configuration the portal actually runs.
func openTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(Options{DataDir: t.TempDir()})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return db
}

func TestOpenDefaultsToSQLiteInDataDir(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(Options{DataDir: dir})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	if db.Driver != DriverSQLite {
		t.Errorf("Driver = %s, want sqlite", db.Driver)
	}
	want := filepath.Join(dir, "portal.db")
	if !strings.HasPrefix(db.DSNRedacted, want) {
		t.Errorf("DSN = %q, want it to start with %q", db.DSNRedacted, want)
	}
}

func TestOpenWithoutDataDirOrDSNFails(t *testing.T) {
	if _, err := Open(Options{}); err == nil {
		t.Fatal("Open with neither DataDir nor DSN should fail")
	}
}

// The pragmas are the difference between a database the event writer and the
// admin panel can share and one where a single insert blocks every read.
func TestSQLitePragmasApplied(t *testing.T) {
	db := openTestDB(t)

	var journal string
	if err := db.Raw("PRAGMA journal_mode").Scan(&journal).Error; err != nil {
		t.Fatalf("read journal_mode: %v", err)
	}
	if !strings.EqualFold(journal, "wal") {
		t.Errorf("journal_mode = %q, want wal", journal)
	}

	var fk int
	if err := db.Raw("PRAGMA foreign_keys").Scan(&fk).Error; err != nil {
		t.Fatalf("read foreign_keys: %v", err)
	}
	if fk != 1 {
		t.Errorf("foreign_keys = %d, want 1 — a cascade delete would silently not cascade", fk)
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	db := openTestDB(t)
	// An upgrade restarts the binary against a database that already has the
	// schema; a second AutoMigrate is the normal path, not an edge case.
	if err := Migrate(db); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	for _, m := range AllModels() {
		if !db.Migrator().HasTable(m) {
			t.Errorf("table missing for %T", m)
		}
	}
}

func TestIsEmpty(t *testing.T) {
	db := openTestDB(t)

	empty, err := IsEmpty(db)
	if err != nil {
		t.Fatalf("IsEmpty: %v", err)
	}
	if !empty {
		t.Error("a freshly migrated database should report empty")
	}

	if err := db.Create(&Setting{Section: "brand", Key: "name", Value: "Kazuha Hub"}).Error; err != nil {
		t.Fatalf("insert setting: %v", err)
	}
	empty, err = IsEmpty(db)
	if err != nil {
		t.Fatalf("IsEmpty: %v", err)
	}
	if empty {
		t.Error("a database with settings must not report empty; the import would run again and overwrite operator changes")
	}

	// Deleting every guest code must not make the database look fresh again —
	// that is a normal operator action and re-running the import would resurrect
	// codes from a stale JSON file.
	if err := db.Where("1 = 1").Delete(&GuestCode{}).Error; err != nil {
		t.Fatalf("delete codes: %v", err)
	}
	empty, err = IsEmpty(db)
	if err != nil {
		t.Fatalf("IsEmpty: %v", err)
	}
	if empty {
		t.Error("IsEmpty must key off settings, not guest codes")
	}
}

func TestGuestCodeUsesCascade(t *testing.T) {
	db := openTestDB(t)

	code := GuestCode{Code: "1234567890", CreatedAt: time.Now().UTC(), DurationMin: 1080, MaxUses: 1}
	if err := db.Create(&code).Error; err != nil {
		t.Fatalf("create code: %v", err)
	}
	if err := db.Create(&GuestCodeUse{
		Code: code.Code, At: time.Now().UTC(), MAC: "aa:bb:cc:dd:ee:ff", IP: "10.0.0.5", GuestUPN: "Guest-abc12345",
	}).Error; err != nil {
		t.Fatalf("create use: %v", err)
	}

	if err := db.Delete(&GuestCode{Code: code.Code}).Error; err != nil {
		t.Fatalf("delete code: %v", err)
	}
	var orphans int64
	if err := db.Model(&GuestCodeUse{}).Where("code = ?", code.Code).Count(&orphans).Error; err != nil {
		t.Fatalf("count uses: %v", err)
	}
	if orphans != 0 {
		t.Errorf("%d use rows outlived their code; the cascade is not in effect", orphans)
	}
}

// ExpiresAt is a nullable column so "never expires" is not encoded as a
// sentinel date that range queries would treat as real.
func TestGuestCodeNeverExpiresIsNull(t *testing.T) {
	db := openTestDB(t)

	if err := db.Create(&GuestCode{Code: "never01", CreatedAt: time.Now().UTC()}).Error; err != nil {
		t.Fatalf("create: %v", err)
	}
	future := time.Now().UTC().Add(24 * time.Hour)
	if err := db.Create(&GuestCode{Code: "expires1", CreatedAt: time.Now().UTC(), ExpiresAt: &future}).Error; err != nil {
		t.Fatalf("create: %v", err)
	}

	var expiring []GuestCode
	if err := db.Where("expires_at IS NOT NULL AND expires_at < ?", time.Now().UTC().Add(48*time.Hour)).Find(&expiring).Error; err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(expiring) != 1 || expiring[0].Code != "expires1" {
		t.Errorf("expiry range query returned %+v, want only expires1", expiring)
	}
}

func TestEventIndexesExist(t *testing.T) {
	db := openTestDB(t)
	// These back the panel's default view, its kind/result filters and the
	// retention sweep. On the highest-volume table, a silently missing index is
	// a full scan per admin page load.
	for _, idx := range []string{"idx_event_time", "idx_event_kind_time", "idx_event_result_time"} {
		if !db.Migrator().HasIndex(&Event{}, idx) {
			t.Errorf("missing index %s on event", idx)
		}
	}
}

// Zero timestamps must never reach the database.
//
// Go's zero time.Time is year 1, which MySQL renders as '0000-00-00' and its
// default strict mode refuses — while SQLite and PostgreSQL accept it silently.
// So this is exactly the class of bug that passes every local test and breaks
// one engine in production: a legacy import whose record lost its timestamp, or
// a certificate row that exists only to record why issuance failed.
func TestZeroTimestampsAreFilledIn(t *testing.T) {
	db := openTestDB(t)

	code := GuestCode{Code: "ZEROTIME01"} // No CreatedAt.
	if err := db.Create(&code).Error; err != nil {
		t.Fatalf("inserting a code with no CreatedAt: %v", err)
	}
	if code.CreatedAt.IsZero() {
		t.Error("GuestCode.CreatedAt was left at zero")
	}

	use := GuestCodeUse{Code: "ZEROTIME01"} // No At.
	if err := db.Create(&use).Error; err != nil {
		t.Fatalf("inserting a use with no At: %v", err)
	}
	if use.At.IsZero() {
		t.Error("GuestCodeUse.At was left at zero")
	}

	// The shape a failed ACME issuance writes: a domain and an error, no
	// certificate and therefore no validity window.
	cert := Certificate{Domain: "portal.example.com", Source: "acme", LastError: "challenge failed"}
	if err := db.Create(&cert).Error; err != nil {
		t.Fatalf("inserting a certificate row with no dates: %v", err)
	}
	if cert.NotBefore.IsZero() || cert.NotAfter.IsZero() || cert.UpdatedAt.IsZero() {
		t.Errorf("certificate dates left at zero: %+v", cert)
	}

	// Read back, so the assertion is about what the database holds rather than
	// what the hook did to the struct in memory.
	var stored GuestCodeUse
	if err := db.Where("code = ?", "ZEROTIME01").First(&stored).Error; err != nil {
		t.Fatal(err)
	}
	if stored.At.IsZero() || stored.At.Year() < 2000 {
		t.Errorf("stored redemption timestamp is %s", stored.At)
	}
}
