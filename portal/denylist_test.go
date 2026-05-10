package main

// denylist_test.go
// MAC 封禁列表的核心语义:
//   - normalizeMAC: 各种格式 → aa:bb:cc:dd:ee:ff
//   - AddMAC 拒非法 MAC + 不重复添加 + 写盘
//   - DeleteMAC / DeleteAllMACs
//   - JSON 持久化 round-trip
//   - L1 回归: createdBy 不被外部覆盖 (在 main_handler_test.go 测 handler 路径)

import (
	"os"
	"path/filepath"
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
		{"not-a-mac", "not-a-mac"}, // 非 12 字符 hex 走原样 lowercase
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
		{"AA:BB:CC:DD:EE:FF", false}, // 大写不算 normalized
		{"aabbccddeeff", false},      // 没冒号不算 normalized
		{"aa:bb:cc:dd:ee", false},    // 不够长
		{"", false},
	}
	for _, c := range cases {
		if got := isNormalizedMAC(c.in); got != c.want {
			t.Errorf("isNormalizedMAC(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestDenylistStore_AddRejectsInvalidMAC(t *testing.T) {
	s, _ := newDenylistStore("")
	if _, _, err := s.AddMAC("not-a-mac", "reason", "admin@x"); err == nil {
		t.Error("invalid MAC must error")
	}
	if _, _, err := s.AddMAC("", "r", "a"); err == nil {
		t.Error("empty MAC must error")
	}
}

func TestDenylistStore_AddNormalizes(t *testing.T) {
	s, _ := newDenylistStore("")
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
	// 用不同格式查同一个 MAC 应能查到
	if _, denied := s.IsMACDenied("aabbccddeeff"); !denied {
		t.Error("IsMACDenied must work across input formats")
	}
}

func TestDenylistStore_AddDuplicateNoOp(t *testing.T) {
	s, _ := newDenylistStore("")
	s.AddMAC("aa:bb:cc:dd:ee:ff", "first", "alice")
	item, created, err := s.AddMAC("AA:BB:CC:DD:EE:FF", "second", "bob")
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Error("duplicate Add must report created=false")
	}
	// 第二次添加不应覆盖第一次的 reason / createdBy (重要: 审计可追溯)
	if item.Reason != "first" || item.CreatedBy != "alice" {
		t.Errorf("duplicate Add overwrote original metadata: %+v", item)
	}
}

func TestDenylistStore_Delete(t *testing.T) {
	s, _ := newDenylistStore("")
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
	s, _ := newDenylistStore("")
	s.AddMAC("aa:bb:cc:dd:ee:ff", "r", "a")
	s.AddMAC("11:22:33:44:55:66", "r", "a")
	if n := s.DeleteAllMACs(); n != 2 {
		t.Errorf("DeleteAllMACs = %d, want 2", n)
	}
	if n := s.DeleteAllMACs(); n != 0 {
		t.Errorf("second DeleteAll on empty = %d, want 0", n)
	}
}

func TestDenylistStore_PersistRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "denylist.json")

	{
		s, err := newDenylistStore(path)
		if err != nil {
			t.Fatal(err)
		}
		s.AddMAC("AA:BB:CC:DD:EE:FF", "spam", "admin@x")
		s.AddMAC("11:22:33:44:55:66", "abuse", "admin@y")
	}
	{
		s2, err := newDenylistStore(path)
		if err != nil {
			t.Fatalf("reload: %v", err)
		}
		items := s2.ListMACs()
		if len(items) != 2 {
			t.Fatalf("reload count = %d, want 2", len(items))
		}
		// 顺序按 CreatedAt 倒序, 但内容应稳定. 验证 normalize 也生效了.
		seen := map[string]string{}
		for _, item := range items {
			seen[item.MAC] = item.Reason
		}
		if seen["aa:bb:cc:dd:ee:ff"] != "spam" {
			t.Errorf("missing or wrong record: %+v", seen)
		}
		if seen["11:22:33:44:55:66"] != "abuse" {
			t.Errorf("missing or wrong record: %+v", seen)
		}
	}
}

func TestDenylistStore_PersistFileMode(t *testing.T) {
	// 持久化文件不能被其它用户读 (内含运维封禁原因等敏感信息)
	dir := t.TempDir()
	path := filepath.Join(dir, "denylist.json")
	s, err := newDenylistStore(path)
	if err != nil {
		t.Fatal(err)
	}
	s.AddMAC("aa:bb:cc:dd:ee:ff", "r", "a")

	// 文件应该是 0600
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	mode := info.Mode().Perm()
	if mode&0o077 != 0 {
		t.Errorf("denylist.json mode = %o, want no group/other access", mode)
	}
}
