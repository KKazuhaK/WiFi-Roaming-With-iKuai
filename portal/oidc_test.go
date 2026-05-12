package main

import "testing"

// TestIsGuest_DetectsExternalUPN: Entra B2B guest 的 UPN 形如
//   alice_partner.com#EXT#@tenant.onmicrosoft.com
// Microsoft 当前文档规定 "#EXT#" 是大写, 但靠依赖单一大小写做安全决策很脆 (供
// 应商有过悄悄改大小写的先例). 防御性 case-insensitive 匹配.
func TestIsGuest_DetectsExternalUPN(t *testing.T) {
	cases := []struct {
		upn  string
		want bool
	}{
		{"alice@tenant.onmicrosoft.com", false},
		{"alice_partner.com#EXT#@tenant.onmicrosoft.com", true},
		// 防御性: 若 Entra 哪天小写化, 这里也要拦下
		{"alice_partner.com#ext#@tenant.onmicrosoft.com", true},
		// 混大小写 — 同样应被识别为 guest
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
