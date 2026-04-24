package main

import (
	"net/url"
	"testing"
)

func TestBuildWebAuthURLUsesUserIDForCustomName(t *testing.T) {
	cfg := Config{
		IKuaiAppKey:       "secret",
		IKuaiWebAuthURL:   "https://portal.ikuai8-wifi.com/Action/webauth-up",
		IKuaiReleaseType:  "1",
		IKuaiUserIDPrefix: "",
	}
	dev := DeviceInfo{IP: "192.168.1.23", MAC: "aa:bb:cc:dd:ee:ff"}
	userUPN := "user@example.com"

	rawURL := buildWebAuthURL(cfg, dev, userUPN, IKuaiPolicy{})
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse webauth URL: %v", err)
	}
	q := parsed.Query()

	if got := q.Get("user_id"); got != userUPN {
		t.Fatalf("user_id = %q, want %q", got, userUPN)
	}
	if got := q.Get("custom_name"); got != userUPN {
		t.Fatalf("custom_name = %q, want %q", got, userUPN)
	}
}

func TestBuildWebAuthURLPrefixesCustomNameWithUserID(t *testing.T) {
	cfg := Config{
		IKuaiAppKey:       "secret",
		IKuaiWebAuthURL:   "https://portal.ikuai8-wifi.com/Action/webauth-up",
		IKuaiReleaseType:  "1",
		IKuaiUserIDPrefix: "Kazuha_Hub",
	}
	dev := DeviceInfo{IP: "192.168.1.23", MAC: "aa:bb:cc:dd:ee:ff"}
	want := "Kazuha_Hub-user@example.com"

	rawURL := buildWebAuthURL(cfg, dev, "user@example.com", IKuaiPolicy{})
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
