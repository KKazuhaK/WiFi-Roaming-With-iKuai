package main

// denylist_test.go
// Core MAC denylist semantics:
//   - normalizeMAC converts many formats to aa:bb:cc:dd:ee:ff.
//   - AddMAC rejects invalid MACs, avoids duplicates, and writes to disk.
//   - DeleteMAC / DeleteAllMACs
//   - JSON persistence round-trip.
//   - L1 regression: createdBy is not overwritten by external input.

import (
	"testing"
)

func TestNormalizeMAC(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff"},
		{"AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee:ff"},
		{"aa-bb-cc-dd-ee-ff", "aa:bb:cc:dd:ee:ff"},
		{"AABBCCDDEEFF", "aa:bb:cc:dd:ee:ff"},
		{"aa bb cc dd ee ff", "aa:bb:cc:dd:ee:ff"},
		{"", ""},
		{"not-a-mac", "not-a-mac"}, // Non-12-hex input is returned lowercased as-is.
	}
	for _, c := range cases {
		if got := normalizeMAC(c.in); got != c.want {
			t.Errorf("normalizeMAC(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestIsNormalizedMAC(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"aa:bb:cc:dd:ee:ff", true},
		{"00:11:22:33:44:55", true},
		{"AA:BB:CC:DD:EE:FF", false}, // Uppercase is not normalized.
		{"aabbccddeeff", false},      // Missing colons is not normalized.
		{"aa:bb:cc:dd:ee", false},    // Too short.
		{"", false},
	}
	for _, c := range cases {
		if got := isNormalizedMAC(c.in); got != c.want {
			t.Errorf("isNormalizedMAC(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestDenylistStore_AddRejectsInvalidMAC(t *testing.T) {
	s := newTestDenylistStore(t)
	if _, _, err := s.AddMAC("not-a-mac", "reason", "admin@x"); err == nil {
		t.Error("invalid MAC must error")
	}
	if _, _, err := s.AddMAC("", "r", "a"); err == nil {
		t.Error("empty MAC must error")
	}
}

func TestDenylistStore_AddNormalizes(t *testing.T) {
	s := newTestDenylistStore(t)
	item, created, err := s.AddMAC("AA-BB-CC-DD-EE-FF", "spam", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Error("first add must report created=true")
	}
	if item.MAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("stored MAC = %q, want normalized", item.MAC)
	}
	// Different formats for the same MAC should match.
	if _, denied := s.IsMACDenied("aabbccddeeff"); !denied {
		t.Error("IsMACDenied must work across input formats")
	}
}

func TestDenylistStore_AddDuplicateNoOp(t *testing.T) {
	s := newTestDenylistStore(t)
	s.AddMAC("aa:bb:cc:dd:ee:ff", "first", "alice")
	item, created, err := s.AddMAC("AA:BB:CC:DD:EE:FF", "second", "bob")
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Error("duplicate Add must report created=false")
	}
	// Second add must not overwrite the original reason/createdBy, preserving audit traceability.
	if item.Reason != "first" || item.CreatedBy != "alice" {
		t.Errorf("duplicate Add overwrote original metadata: %+v", item)
	}
}

func TestDenylistStore_Delete(t *testing.T) {
	s := newTestDenylistStore(t)
	s.AddMAC("aa:bb:cc:dd:ee:ff", "r", "a")
	if !s.DeleteMAC("AA:BB:CC:DD:EE:FF") {
		t.Error("DeleteMAC must work case-insensitively")
	}
	if _, denied := s.IsMACDenied("aa:bb:cc:dd:ee:ff"); denied {
		t.Error("after delete, MAC should not be denied")
	}
	if s.DeleteMAC("aa:bb:cc:dd:ee:ff") {
		t.Error("Delete already-deleted should return false")
	}
}

func TestDenylistStore_DeleteAll(t *testing.T) {
	s := newTestDenylistStore(t)
	s.AddMAC("aa:bb:cc:dd:ee:ff", "r", "a")
	s.AddMAC("11:22:33:44:55:66", "r", "a")
	if n := s.DeleteAllMACs(); n != 2 {
		t.Errorf("DeleteAllMACs = %d, want 2", n)
	}
	if n := s.DeleteAllMACs(); n != 0 {
		t.Errorf("second DeleteAll on empty = %d, want 0", n)
	}
}

// The file-permission test that used to live here checked that denylist.json
// was 0600, because it holds operational notes about specific devices. That file
// is gone; the equivalent protection is now the database's own access control,
// which is the operator's to configure — for the default SQLite file it is the
// data directory's mode, already asserted by ensureDataDirWritable.
//
// What is still worth pinning is that a second store sees the first one's writes
// and that MAC normalisation survives the trip.
func TestDenylistStore_PersistRoundTrip(t *testing.T) {
	db := testDB(t)

	first := newDenylistStore(db)
	if _, _, err := first.AddMAC("AA:BB:CC:DD:EE:FF", "spam", "admin@x"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := first.AddMAC("11:22:33:44:55:66", "abuse", "admin@y"); err != nil {
		t.Fatal(err)
	}

	second := newDenylistStore(db)
	items := second.ListMACs()
	if len(items) != 2 {
		t.Fatalf("reload count = %d, want 2", len(items))
	}
	seen := map[string]string{}
	for _, item := range items {
		seen[item.MAC] = item.Reason
	}
	// Stored lower-cased and colon-separated whatever the operator typed.
	if seen["aa:bb:cc:dd:ee:ff"] != "spam" {
		t.Errorf("missing or wrong record: %+v", seen)
	}
	if seen["11:22:33:44:55:66"] != "abuse" {
		t.Errorf("missing or wrong record: %+v", seen)
	}
}
