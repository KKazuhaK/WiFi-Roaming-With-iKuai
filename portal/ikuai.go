package main

// ikuai.go
// Two sides of the iKuai custom-auth protocol:
//   (a) Inbound: extractDeviceInfo reads device IP and MAC from the query redirected by iKuai.
//   (b) Outbound: buildWebAuthURL creates the allow-list URL with an MD5 token and redirects there.
//
// Based on the official iKuai custom-auth integration document.
// https://www.ikuai8.com/index.php?option=com_content&view=article&id=774
//
// Token formula from the document (MD5):
//   md5("user_ip={ip}&timestamp={ts}&mac={mac}&upload=0&download=0&key={appkey}")
// Allow-list URL per the official document:
//   https://portal.ikuai8-wifi.com/Action/webauth-up
//     ?type=20&user_id={id}&custom_name={name}&user_ip={ip}&timestamp={ts}
//     &mac={mac}&upload=0&download=0&token={hex}&release_type=1
//
// user_id / custom_name / release_type / timeout / comment are pass-through parameters and are not
// part of the MD5 token calculation:
//   user_id     — iKuai audit-log account column. Format is controlled by auth type:
//                  SSO → SSO-{UPN}, Duo → Duo-{UPN}, Guest → Guest-{id}
//   custom_name — same as user_id, for firmware that prefers custom_name in online-user pages.
//   release_type = IKUAI_RELEASE_TYPE env, default "1".
//   timeout      — iKuai auth timeout in minutes; 0 means never expires.
//   comment      — iKuai-side note for auth source; do not put sensitive data here.
//
// Notes:
//   - The official document uses HTTPS. External curl from a VPS may hit TLS handshake failures
//     because Cloudflare edge does not expose old TLS ciphers, but real client devices are inside
//     iKuai WiFi and the router intercepts the request on LAN before it reaches the public internet.
//   - If a firmware variant only accepts HTTP, change IKUAI_WEBAUTH_URL without rebuilding.
//   - Query field names differ by firmware version, so the inbound side uses firstNonEmpty.
//   - MD5 is used because iKuai requires it; security relies on appkey secrecy, not hash strength.

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DeviceInfo is the client-device information received from iKuai.
type DeviceInfo struct {
	IP  string
	MAC string
}

// extractDeviceInfo parses device information from the /portal request redirected by iKuai.
// It supports several field names for firmware compatibility.
// ok=false means the device identity cannot be determined and login should be rejected.
func extractDeviceInfo(r *http.Request, cfg Config) (DeviceInfo, bool) {
	q := r.URL.Query()
	ip := firstNonEmpty(q, cfg.IKuaiIPKeys)
	mac := firstNonEmpty(q, cfg.IKuaiMACKeys)

	// MACs are often URL-encoded as %3A; net/url decodes them, then normalize once more.
	mac = normalizeMAC(mac)

	if ip == "" || mac == "" {
		return DeviceInfo{}, false
	}
	return DeviceInfo{IP: ip, MAC: mac}, true
}

// buildWebAuthURL creates the iKuai allow-list URL used as the browser 302 target.
// userUPN is the user identity; profile controls the auth-source prefix shown in iKuai.
func buildWebAuthURL(cfg Config, dev DeviceInfo, userUPN string, profile IKuaiAuthProfile, policy IKuaiPolicy) string {
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	upload := fmt.Sprintf("%d", policy.Upload)
	download := fmt.Sprintf("%d", policy.Download)

	// The token source string must match iKuai's required order and format exactly.
	// user_id / custom_name / release_type are pass-through only and are not part of token calculation.
	raw := fmt.Sprintf(
		"user_ip=%s&timestamp=%s&mac=%s&upload=%s&download=%s&key=%s",
		dev.IP, timestamp, dev.MAC, upload, download, cfg.IKuaiAppKey,
	)
	sum := md5.Sum([]byte(raw))
	token := hex.EncodeToString(sum[:])

	userID := ikuaiUserID(profile, userUPN)

	// Build the final URL.
	params := url.Values{}
	params.Set("type", "20") // 20 = web authentication.
	params.Set("user_id", userID)
	// Some iKuai firmware displays custom_name instead of user_id on online-user pages.
	// Keep them identical so the page does not show only a fixed portal name.
	params.Set("custom_name", userID)
	params.Set("user_ip", dev.IP)
	params.Set("timestamp", timestamp)
	params.Set("mac", dev.MAC)
	params.Set("upload", upload)     // Upload speed limit; 0 means unlimited.
	params.Set("download", download) // Download speed limit; 0 means unlimited.
	params.Set("timeout", fmt.Sprintf("%d", policy.Timeout)) // Minutes; 0 means never expires.
	if policy.Comment != "" {
		params.Set("comment", policy.Comment)
	}
	params.Set("token", token)
	params.Set("release_type", cfg.IKuaiReleaseType)

	return cfg.IKuaiWebAuthURL + "?" + params.Encode()
}

func ikuaiUserID(profile IKuaiAuthProfile, identity string) string {
	identity = strings.TrimSpace(identity)
	switch profile {
	case IKuaiProfileSSO:
		return "SSO-" + identity
	case IKuaiProfileDuo:
		return "Duo-" + identity
	case IKuaiProfileGuest:
		guestID := strings.TrimPrefix(strings.TrimPrefix(identity, "guest-"), "Guest-")
		return "Guest-" + guestID
	default:
		return identity
	}
}

// --- helpers ---

// firstNonEmpty returns the first non-empty query value among candidate field names.
func firstNonEmpty(q url.Values, keys []string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(q.Get(k)); v != "" {
			return v
		}
	}
	return ""
}

// normalizeMAC converts a MAC to lowercase colon-separated form (aa:bb:cc:dd:ee:ff).
// iKuai may send AA-BB-CC-DD-EE-FF or aabbccddeeff, so normalize before use.
func normalizeMAC(mac string) string {
	if mac == "" {
		return ""
	}
	// Remove common separators.
	clean := strings.Map(func(r rune) rune {
		switch r {
		case '-', ':', ' ':
			return -1
		}
		return r
	}, mac)
	clean = strings.ToLower(clean)
	// If length is not 12 hex chars, return as-is and let iKuai reject it.
	if len(clean) != 12 {
		return strings.ToLower(mac)
	}
	// Insert colons every two characters.
	var b strings.Builder
	for i := 0; i < 12; i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(clean[i : i+2])
	}
	return b.String()
}
