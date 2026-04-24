package main

import (
	"net/url"
	"testing"
)

func TestBuildWebAuthURLUsesUserIDForCustomName(t *testing.T) {
	cfg := Config{
		IKuaiAppKey:      "secret",
		IKuaiWebAuthURL:  "https://portal.ikuai8-wifi.com/Action/webauth-up",
		IKuaiReleaseType: "1",
	}
	dev := DeviceInfo{IP: "192.168.1.23", MAC: "aa:bb:cc:dd:ee:ff"}
	userUPN := "user@example.com"
	want := "SSO-" + userUPN

	rawURL := buildWebAuthURL(cfg, dev, userUPN, IKuaiProfileSSO, IKuaiPolicy{})
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse webauth URL: %v", err)
	}
	q := parsed.Query()

	if got := q.Get("user_id"); got != want {
		t.Fatalf("user_id = %q, want %q", got, want)
	}
	if got := q.Get("custom_name"); got != want {
		t.Fatalf("custom_name = %q, want %q", got, want)
	}
}

func TestBuildWebAuthURLPrefixesDuoCustomNameWithAuthType(t *testing.T) {
	cfg := Config{
		IKuaiAppKey:      "secret",
		IKuaiWebAuthURL:  "https://portal.ikuai8-wifi.com/Action/webauth-up",
		IKuaiReleaseType: "1",
	}
	dev := DeviceInfo{IP: "192.168.1.23", MAC: "aa:bb:cc:dd:ee:ff"}
	want := "Duo-user@example.com"

	rawURL := buildWebAuthURL(cfg, dev, "user@example.com", IKuaiProfileDuo, IKuaiPolicy{})
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse webauth URL: %v", err)
	}
	q := parsed.Query()

	if got := q.Get("user_id"); got != want {
		t.Fatalf("user_id = %q, want %q", got, want)
	}
	if got := q.Get("custom_name"); got != want {
		t.Fatalf("custom_name = %q, want %q", got, want)
	}
}

func TestBuildWebAuthURLPrefixesGuestCustomNameWithAuthType(t *testing.T) {
	cfg := Config{
		IKuaiAppKey:      "secret",
		IKuaiWebAuthURL:  "https://portal.ikuai8-wifi.com/Action/webauth-up",
		IKuaiReleaseType: "1",
	}
	dev := DeviceInfo{IP: "192.168.1.23", MAC: "aa:bb:cc:dd:ee:ff"}
	want := "Guest-32585523"

	rawURL := buildWebAuthURL(cfg, dev, "Guest-32585523", IKuaiProfileGuest, IKuaiPolicy{})
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse webauth URL: %v", err)
	}
	q := parsed.Query()

	if got := q.Get("user_id"); got != want {
		t.Fatalf("user_id = %q, want %q", got, want)
	}
	if got := q.Get("custom_name"); got != want {
		t.Fatalf("custom_name = %q, want %q", got, want)
	}
}
