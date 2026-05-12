package main

// ikuai_policy_test.go
// Core iKuai allow-list policy semantics:
//   - Set/Get round-trip
//   - validate rejects negative values and long comments
//   - guest profile timeout is forced to 0 and does not use the global timeout
//   - persistence round-trip
//   - stable List order for UI rendering

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestIKuaiPolicy_ValidateRejectsNegative(t *testing.T) {
	cases := []IKuaiPolicy{
		{Upload: -1},
		{Download: -1},
		{Timeout: -1},
	}
	for _, p := range cases {
		if err := validateIKuaiPolicy(p); err == nil {
			t.Errorf("validateIKuaiPolicy(%+v) accepted negative value", p)
		}
	}
}

func TestIKuaiPolicy_ValidateRejectsLongComment(t *testing.T) {
	p := IKuaiPolicy{Comment: strings.Repeat("a", 129)}
	if err := validateIKuaiPolicy(p); err == nil {
		t.Error("comment > 128 bytes must error")
	}
	p = IKuaiPolicy{Comment: strings.Repeat("a", 128)}
	if err := validateIKuaiPolicy(p); err != nil {
		t.Errorf("comment == 128 bytes must pass: %v", err)
	}
}

func TestIKuaiPolicyStore_GuestTimeoutForcedZero(t *testing.T) {
	s, err := newIKuaiPolicyStore(map[IKuaiAuthProfile]IKuaiPolicy{
		IKuaiProfileGuest: {Timeout: 60},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	got := s.Get(IKuaiProfileGuest)
	if got.Timeout != 0 {
		t.Errorf("guest profile Timeout = %d, want forced 0 (guest codes use per-code DurationMin)",
			got.Timeout)
	}
	// Explicit Set should also be forced.
	if err := s.Set(IKuaiProfileGuest, IKuaiPolicy{Timeout: 30}); err != nil {
		t.Fatal(err)
	}
	got = s.Get(IKuaiProfileGuest)
	if got.Timeout != 0 {
		t.Errorf("guest Timeout after Set = %d, must still be 0", got.Timeout)
	}
}

func TestIKuaiPolicyStore_SetGetRoundTrip(t *testing.T) {
	s, _ := newIKuaiPolicyStore(map[IKuaiAuthProfile]IKuaiPolicy{
		IKuaiProfileSSO: {},
	}, "")
	want := IKuaiPolicy{Upload: 100, Download: 200, Timeout: 60, Comment: "test"}
	if err := s.Set(IKuaiProfileSSO, want); err != nil {
		t.Fatal(err)
	}
	got := s.Get(IKuaiProfileSSO)
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestIKuaiPolicyStore_RejectsInvalidProfile(t *testing.T) {
	s, _ := newIKuaiPolicyStore(map[IKuaiAuthProfile]IKuaiPolicy{}, "")
	if err := s.Set("not-a-real-profile", IKuaiPolicy{}); err == nil {
		t.Error("Set with invalid profile must error")
	}
}

func TestIKuaiPolicyStore_PersistRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ikuai-policy.json")

	defaults := map[IKuaiAuthProfile]IKuaiPolicy{
		IKuaiProfileSSO:   {Comment: "default-sso"},
		IKuaiProfileDuo:   {},
		IKuaiProfileGuest: {},
	}
	{
		s, err := newIKuaiPolicyStore(defaults, path)
		if err != nil {
			t.Fatal(err)
		}
		s.Set(IKuaiProfileSSO, IKuaiPolicy{Upload: 500, Comment: "edited"})
	}
	{
		s2, err := newIKuaiPolicyStore(defaults, path)
		if err != nil {
			t.Fatalf("reload: %v", err)
		}
		got := s2.Get(IKuaiProfileSSO)
		if got.Upload != 500 || got.Comment != "edited" {
			t.Errorf("reload lost data: %+v", got)
		}
		// Unchanged profiles should keep defaults.
		if d := s2.Get(IKuaiProfileDuo); d.Upload != 0 || d.Comment != "" {
			t.Errorf("Duo profile got polluted on reload: %+v", d)
		}
	}
}

func TestIKuaiPolicyStore_ListStableOrder(t *testing.T) {
	// Admin UI depends on stable List order (sso, duo, guest) and must not flicker from map iteration.
	s, _ := newIKuaiPolicyStore(map[IKuaiAuthProfile]IKuaiPolicy{
		IKuaiProfileSSO:   {},
		IKuaiProfileDuo:   {},
		IKuaiProfileGuest: {},
	}, "")
	for i := 0; i < 5; i++ {
		list := s.List()
		if len(list) != 3 {
			t.Fatalf("List len = %d, want 3", len(list))
		}
		if list[0].Profile != "sso" || list[1].Profile != "duo" || list[2].Profile != "guest" {
			t.Errorf("List order unstable: %+v", []string{list[0].Profile, list[1].Profile, list[2].Profile})
		}
	}
}

func TestParseIKuaiProfile(t *testing.T) {
	cases := []struct {
		in   string
		want IKuaiAuthProfile
		ok   bool
	}{
		{"sso", IKuaiProfileSSO, true},
		{"SSO", IKuaiProfileSSO, true}, // Case-insensitive.
		{"  duo  ", IKuaiProfileDuo, true},
		{"guest", IKuaiProfileGuest, true},
		{"unknown", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		got, ok := parseIKuaiProfile(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("parseIKuaiProfile(%q) = (%q, %v), want (%q, %v)",
				c.in, got, ok, c.want, c.ok)
		}
	}
}
