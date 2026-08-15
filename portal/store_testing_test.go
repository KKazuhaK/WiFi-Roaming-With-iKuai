package main

import (
	"testing"

	"github.com/kazuhahub/wifi-portal/internal/dbstore"
)

// testDB gives a test its own migrated SQLite database, cleaned up with the
// temp dir.
//
// A file rather than :memory: on purpose: the pragmas the portal relies on —
// WAL in particular — behave differently for an in-memory database, so tests
// against one would not exercise the configuration that actually runs. The cost
// is a few milliseconds per test.
func testDB(t *testing.T) *dbstore.DB {
	t.Helper()
	db, err := dbstore.Open(dbstore.Options{DataDir: t.TempDir()})
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close test database: %v", err)
		}
	})
	if err := dbstore.Migrate(db); err != nil {
		t.Fatalf("migrate test database: %v", err)
	}
	return db
}

// newTestGuestCodeStore replaces the file-path constructor the tests used before
// storage moved into the database.
func newTestGuestCodeStore(t *testing.T) *GuestCodeStore {
	t.Helper()
	return newGuestCodeStore(testDB(t))
}

func newTestDenylistStore(t *testing.T) *DenylistStore {
	t.Helper()
	return newDenylistStore(testDB(t))
}
