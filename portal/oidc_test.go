package main

import "testing"

// TestIsGuest_DetectsExternalUPN: Entra B2B guest UPNs look like:
//   alice_partner.com#EXT#@tenant.onmicrosoft.com
// Microsoft currently documents uppercase "#EXT#", but security decisions should not depend on one
// fixed casing. Use defensive case-insensitive matching.
func TestIsGuest_DetectsExternalUPN(t *testing.T) {
	cases := []struct {
		upn  string
		want bool
	}{
		{"alice@tenant.onmicrosoft.com", false},
		{"alice_partner.com#EXT#@tenant.onmicrosoft.com", true},
		// Defensive: if Entra ever lowercases it, still block it.
		{"alice_partner.com#ext#@tenant.onmicrosoft.com", true},
		// Mixed case should also be recognized as guest.
		{"alice_partner.com#Ext#@tenant.onmicrosoft.com", true},
		{"", false},
	}
	for _, c := range cases {
		u := UserInfo{UPN: c.upn}
		if got := u.IsGuest(); got != c.want {
			t.Errorf("IsGuest(%q) = %v, want %v", c.upn, got, c.want)
		}
	}
}
