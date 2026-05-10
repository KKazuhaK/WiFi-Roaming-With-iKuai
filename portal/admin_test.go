package main

// admin_test.go
// GuestCodeStore 的关键语义:
//   - Validate 持锁内 atomic 完成查找 + 检查 + append → 防 TOCTOU
//   - Add/Edit/Delete 串行语义 + 不允许覆盖
//   - JSON 持久化 round-trip (load 后保持原样)
//   - 过期 / 用尽语义
//   - Stats 计数正确

import (
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestGuestCode_NeverExpires(t *testing.T) {
	c := &GuestCode{ExpiresAt: time.Time{}}
	if c.IsExpired() {
		t.Error("zero ExpiresAt must mean never-expires")
	}
}

func TestGuestCode_Expired(t *testing.T) {
	c := &GuestCode{ExpiresAt: time.Now().Add(-time.Second)}
	if !c.IsExpired() {
		t.Error("past ExpiresAt should be expired")
	}
}

func TestGuestCode_Exhausted(t *testing.T) {
	c := &GuestCode{MaxUses: 0}
	if c.IsExhausted() {
		t.Error("MaxUses=0 means unlimited, never exhausted")
	}
	c = &GuestCode{MaxUses: 2, Uses: []CodeUse{{}, {}}}
	if !c.IsExhausted() {
		t.Error("Uses == MaxUses should be exhausted")
	}
	c = &GuestCode{MaxUses: 2, Uses: []CodeUse{{}}}
	if c.IsExhausted() {
		t.Error("Uses < MaxUses should not be exhausted")
	}
}

func TestGuestCodeStore_AddRejectsDuplicate(t *testing.T) {
	s, err := newGuestCodeStore("")
	if err != nil {
		t.Fatal(err)
	}
	if !s.Add(&GuestCode{Code: "abc", CreatedAt: time.Now()}) {
		t.Fatal("first Add must succeed")
	}
	// 同 code 不同 case 也应被视作重复 (key 是 lowercase)
	if s.Add(&GuestCode{Code: "ABC", CreatedAt: time.Now()}) {
		t.Error("Add must reject duplicate (case-insensitive)")
	}
	// 真重复
	if s.Add(&GuestCode{Code: "abc", CreatedAt: time.Now()}) {
		t.Error("Add must reject literal duplicate")
	}
}

func TestGuestCodeStore_AddTrimsAndCaseInsensitive(t *testing.T) {
	s, _ := newGuestCodeStore("")
	s.Add(&GuestCode{Code: "  ABC  ", CreatedAt: time.Now()})
	// Validate 也应该 case-insensitive + trim
	got := s.Validate("abc", "mac", "ip", "guest-1")
	if got == nil {
		t.Fatal("Validate must hit despite case + space differences")
	}
}

// TestGuestCodeStore_ValidateAtomic 是 TOCTOU 关键回归: 多 goroutine 并发
// Validate 同一个 MaxUses=1 的码, 必须只成功一次.
func TestGuestCodeStore_ValidateAtomic(t *testing.T) {
	s, _ := newGuestCodeStore("")
	s.Add(&GuestCode{
		Code:      "single-use",
		CreatedAt: time.Now(),
		MaxUses:   1,
	})

	const N = 50
	var wg sync.WaitGroup
	var winners int
	var mu sync.Mutex
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got := s.Validate("single-use", "mac", "ip", "guest"); got != nil {
				mu.Lock()
				winners++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if winners != 1 {
		t.Errorf("MaxUses=1 across %d concurrent attempts: %d winners, want exactly 1", N, winners)
	}
}

func TestGuestCodeStore_ValidateRejectsExpiredAndExhausted(t *testing.T) {
	s, _ := newGuestCodeStore("")
	s.Add(&GuestCode{
		Code:      "expired",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(-time.Hour),
	})
	if s.Validate("expired", "m", "i", "g") != nil {
		t.Error("expired code must not validate")
	}
	s.Add(&GuestCode{
		Code:    "used",
		MaxUses: 1,
		Uses:    []CodeUse{{}},
	})
	if s.Validate("used", "m", "i", "g") != nil {
		t.Error("exhausted code must not validate")
	}
	if s.Validate("nonexistent", "m", "i", "g") != nil {
		t.Error("missing code must return nil")
	}
}

func TestGuestCodeStore_DeleteInactiveKeepsActive(t *testing.T) {
	// C3 语义: DeleteInactive 删 "已经不能再用" 的码 (过期 OR 用尽). 半使用的多次性
	// 码 (MaxUses=5, Uses=1, 还能用 4 次) 必须保留 — 那是 admin 的资产.
	s, _ := newGuestCodeStore("")
	s.Add(&GuestCode{Code: "fresh", CreatedAt: time.Now()})
	s.Add(&GuestCode{Code: "expired", ExpiresAt: time.Now().Add(-time.Hour), CreatedAt: time.Now()})
	s.Add(&GuestCode{Code: "exhausted", MaxUses: 1, Uses: []CodeUse{{}}, CreatedAt: time.Now()})
	s.Add(&GuestCode{Code: "partial", MaxUses: 5, Uses: []CodeUse{{}}, CreatedAt: time.Now()})

	n := s.DeleteInactive()
	if n != 2 {
		t.Errorf("DeleteInactive removed %d, want 2 (expired+exhausted, NOT partial)", n)
	}
	// fresh + partial 都应留下
	if s.Validate("fresh", "m", "i", "g") == nil {
		t.Error("fresh unused code must remain")
	}
	if s.Validate("partial", "m", "i", "g") == nil {
		t.Error("partially-used multi-use code MUST remain (C3 regression)")
	}
}

func TestGuestCodeStore_Edit(t *testing.T) {
	s, _ := newGuestCodeStore("")
	s.Add(&GuestCode{Code: "edit-me", CreatedAt: time.Now(), DurationMin: 60})
	exp := time.Now().Add(24 * time.Hour)
	if !s.Edit("edit-me", exp, 30, 5, "new note") {
		t.Fatal("Edit existing code should succeed")
	}
	list := s.List()
	if len(list) != 1 || list[0].DurationMin != 30 || list[0].MaxUses != 5 || list[0].Note != "new note" {
		t.Errorf("Edit didn't apply: %+v", list[0])
	}
	if s.Edit("nonexistent", exp, 30, 5, "x") {
		t.Error("Edit must fail for missing code")
	}
}

func TestGuestCodeStore_Stats(t *testing.T) {
	// M1 语义: unused = IsActive (还能用), used = IsExhausted (用尽), expired = 过期.
	// MaxUses=0 不限, Uses=1 仍算 unused; MaxUses=1 Uses=1 才算 used.
	s, _ := newGuestCodeStore("")
	s.Add(&GuestCode{Code: "u1", CreatedAt: time.Now()})                                         // unused
	s.Add(&GuestCode{Code: "u2", CreatedAt: time.Now()})                                         // unused
	s.Add(&GuestCode{Code: "x1", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(-time.Hour)})  // expired
	s.Add(&GuestCode{Code: "exhausted", CreatedAt: time.Now(), MaxUses: 1, Uses: []CodeUse{{}}}) // used (用尽)
	s.Add(&GuestCode{Code: "unlimited-used", CreatedAt: time.Now(), Uses: []CodeUse{{}}})        // unused (MaxUses=0 不限)

	total, used, unused, expired := s.Stats()
	if total != 5 || used != 1 || unused != 3 || expired != 1 {
		t.Errorf("stats wrong: total=%d used=%d unused=%d expired=%d (want total=5 used=1 unused=3 expired=1)",
			total, used, unused, expired)
	}
}

// TestGuestCodeStore_PersistRoundTrip: load 之后存储应该跟原样一致. 启动时
// loadFromDisk 失败会 fatal — 这是关键路径, 落盘格式跟读取必须自洽.
func TestGuestCodeStore_PersistRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "guest-codes.json")

	// 写一份
	{
		s, err := newGuestCodeStore(path)
		if err != nil {
			t.Fatal(err)
		}
		s.Add(&GuestCode{
			Code:        "abc",
			CreatedAt:   time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
			DurationMin: 120,
			MaxUses:     3,
			Note:        "test",
			Uses:        []CodeUse{{At: time.Date(2026, 1, 1, 13, 0, 0, 0, time.UTC), MAC: "aa", IP: "1.1.1.1", GuestUPN: "g"}},
		})
	}
	// 读回来
	{
		s2, err := newGuestCodeStore(path)
		if err != nil {
			t.Fatalf("reload failed: %v", err)
		}
		got := s2.List()
		if len(got) != 1 {
			t.Fatalf("reload count = %d, want 1", len(got))
		}
		c := got[0]
		if c.Code != "abc" || c.DurationMin != 120 || c.MaxUses != 3 ||
			c.Note != "test" || len(c.Uses) != 1 || c.Uses[0].MAC != "aa" {
			t.Errorf("round-trip lost data: %+v", c)
		}
	}
}

func TestGenerateCode_AllCodeTypes(t *testing.T) {
	cases := []struct {
		typ     GuestCodeType
		alpha   string
		wantLen int
	}{
		{CodeNumeric, "0123456789", 10},
		{CodeAlpha, "abcdefghijklmnopqrstuvwxyz", 8},
		{CodeAlphaNumeric, "abcdefghijklmnopqrstuvwxyz0123456789", 12},
	}
	for _, c := range cases {
		got, err := generateCode(c.typ, c.wantLen)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != c.wantLen {
			t.Errorf("type %s: len = %d, want %d", c.typ, len(got), c.wantLen)
		}
		for _, r := range got {
			if !contains(c.alpha, byte(r)) {
				t.Errorf("type %s: char %q not in alphabet %q", c.typ, r, c.alpha)
			}
		}
	}
}

func TestGenerateCode_LengthClamp(t *testing.T) {
	got, _ := generateCode(CodeNumeric, 1)
	if len(got) < 4 {
		t.Errorf("length=1 should clamp to >= 4, got %d", len(got))
	}
	got, _ = generateCode(CodeNumeric, 1000)
	if len(got) > 64 {
		t.Errorf("length=1000 should clamp to <= 64, got %d", len(got))
	}
}

func TestGenerateCode_SufficientEntropy(t *testing.T) {
	// 同 type+length 跑 50 次, 应不会撞码 (10^10 空间)
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		c, err := generateCode(CodeNumeric, 10)
		if err != nil {
			t.Fatal(err)
		}
		if seen[c] {
			t.Errorf("collision after %d generates: %q", i, c)
		}
		seen[c] = true
	}
}

func contains(s string, b byte) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return true
		}
	}
	return false
}
