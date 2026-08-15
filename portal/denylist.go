package main

// denylist.go
// MAC-address validation for the device denylist.
//
// The denylist blocks MACs, not UPNs: SSO handles user identity, the denylist
// handles device-level operational blocks, and IPs are only ever used for short
// cooldowns because a DHCP lease is not an identity.
//
// Storage lives in store_denylist.go. What stays here is the shape check every
// caller shares.

func isNormalizedMAC(mac string) bool {
	if len(mac) != 17 {
		return false
	}
	for i, c := range mac {
		if i%3 == 2 {
			if c != ':' {
				return false
			}
			continue
		}
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
