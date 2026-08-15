package main

import (
	"os"
	"sync"
	"testing"

	"github.com/kazuhahub/wifi-portal/internal/dbstore"
)

// testDBDSN points the suite at a real MySQL or PostgreSQL server.
//
// Empty — the normal case, and what a contributor gets — means an embedded
// SQLite file per test. CI sets it to run the same tests against the other two
// engines, which is the only way the claim that they are supported means
// anything: upsert syntax, row locking, LIKE case-sensitivity and time
// precision all differ, and none of those differences show up against SQLite.
const testDBDSNEnv = "TEST_DB_DSN"

var (
	sharedDB     *dbstore.DB
	sharedDBOnce sync.Once
	truncatedMu  sync.Mutex
	truncatedFor = map[string]bool{}
)

// testDB gives a test a migrated, empty database.
//
// Against SQLite that is a fresh file per test, cleaned up with the temp dir. A
// file rather than :memory: on purpose: the pragmas the portal relies on — WAL
// in particular — behave differently for an in-memory database, so tests against
// one would not exercise the configuration that actually runs.
//
// Against a server it is one shared connection with every table emptied at the
// start of each test. Creating a database per test would be minutes of DDL, and
// the tests do not run in parallel, so "empty at the start of this test" is the
// same guarantee a fresh file gives. Repeated calls within one test hand back
// the same handle without re-emptying, because several tests build two stores
// over what they expect to be one database.
func testDB(t *testing.T) *dbstore.DB {
	t.Helper()
	dsn := os.Getenv(testDBDSNEnv)
	if dsn == "" {
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

	sharedDBOnce.Do(func() {
		db, err := dbstore.Open(dbstore.Options{DSN: dsn})
		if err != nil {
			t.Fatalf("open %s: %v", testDBDSNEnv, err)
		}
		if err := dbstore.Migrate(db); err != nil {
			t.Fatalf("migrate %s: %v", testDBDSNEnv, err)
		}
		sharedDB = db
	})
	if sharedDB == nil {
		t.Fatalf("%s is set but the database could not be opened", testDBDSNEnv)
	}

	truncatedMu.Lock()
	defer truncatedMu.Unlock()
	if !truncatedFor[t.Name()] {
		truncateAll(t, sharedDB)
		truncatedFor[t.Name()] = true
	}
	return sharedDB
}

// truncateAll empties every table.
//
// DELETE rather than TRUNCATE: the three engines spell TRUNCATE differently and
// disagree about foreign keys and identity columns, the volumes here are tiny,
// and a portable statement keeps this helper from becoming a second place where
// engine differences have to be tracked.
func truncateAll(t *testing.T, db *dbstore.DB) {
	t.Helper()
	for _, model := range dbstore.AllModels() {
		if err := db.Where("1 = 1").Delete(model).Error; err != nil {
			t.Fatalf("emptying %T: %v", model, err)
		}
	}
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
