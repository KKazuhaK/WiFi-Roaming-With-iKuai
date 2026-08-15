package main

// ikuai_policy.go
// iKuai allow-list policy: upload/download limits, auth timeout, and comment by auth source.
// Guest-code auth timeout comes from each code's per-use duration, not the global policy.
// Env provides startup defaults; admin changes can be persisted as JSON.

import (
	"fmt"
	"strings"
)

type IKuaiAuthProfile string

const (
	IKuaiProfileSSO   IKuaiAuthProfile = "sso"
	IKuaiProfileDuo   IKuaiAuthProfile = "duo"
	IKuaiProfileGuest IKuaiAuthProfile = "guest"
)

// allIKuaiProfiles is the canonical order the admin table and the seeding logic
// both use. Fixed rather than database-defined so the three rows do not
// reshuffle between page loads.
var allIKuaiProfiles = []IKuaiAuthProfile{IKuaiProfileSSO, IKuaiProfileDuo, IKuaiProfileGuest}

type IKuaiPolicy struct {
	Upload   int    `json:"upload"`   // KB/s, 0 means unlimited.
	Download int    `json:"download"` // KB/s, 0 means unlimited.
	Timeout  int    `json:"timeout"`  // Minutes, 0 means never expires.
	Comment  string `json:"comment,omitempty"`
}

type IKuaiPolicyRow struct {
	Profile  string
	Label    string
	Upload   int
	Download int
	Timeout  int
	Comment  string
}

func defaultIKuaiPoliciesFromEnv() map[IKuaiAuthProfile]IKuaiPolicy {
	return map[IKuaiAuthProfile]IKuaiPolicy{
		IKuaiProfileSSO: {
			Upload:   envOrNonNegativeInt("IKUAI_SSO_UPLOAD", 0),
			Download: envOrNonNegativeInt("IKUAI_SSO_DOWNLOAD", 0),
			Timeout:  envOrNonNegativeInt("IKUAI_SSO_TIMEOUT", 0),
			Comment:  strings.TrimSpace(envOr("IKUAI_SSO_COMMENT", "")),
		},
		IKuaiProfileDuo: {
			Upload:   envOrNonNegativeInt("IKUAI_DUO_UPLOAD", 0),
			Download: envOrNonNegativeInt("IKUAI_DUO_DOWNLOAD", 0),
			Timeout:  envOrNonNegativeInt("IKUAI_DUO_TIMEOUT", 0),
			Comment:  strings.TrimSpace(envOr("IKUAI_DUO_COMMENT", "")),
		},
		IKuaiProfileGuest: {
			Upload:   envOrNonNegativeInt("IKUAI_GUEST_UPLOAD", 0),
			Download: envOrNonNegativeInt("IKUAI_GUEST_DOWNLOAD", 0),
			Timeout:  0,
			Comment:  strings.TrimSpace(envOr("IKUAI_GUEST_COMMENT", "")),
		},
	}
}

func parseIKuaiProfile(s string) (IKuaiAuthProfile, bool) {
	switch IKuaiAuthProfile(strings.ToLower(strings.TrimSpace(s))) {
	case IKuaiProfileSSO:
		return IKuaiProfileSSO, true
	case IKuaiProfileDuo:
		return IKuaiProfileDuo, true
	case IKuaiProfileGuest:
		return IKuaiProfileGuest, true
	default:
		return "", false
	}
}

func ikuaiProfileLabel(p IKuaiAuthProfile) string {
	switch p {
	case IKuaiProfileSSO:
		return "SSO member"
	case IKuaiProfileDuo:
		return "Duo member"
	case IKuaiProfileGuest:
		return "guest_code"
	default:
		return string(p)
	}
}

func validateIKuaiPolicy(p IKuaiPolicy) error {
	if p.Upload < 0 || p.Download < 0 || p.Timeout < 0 {
		return fmt.Errorf("negative_value")
	}
	if len([]byte(strings.TrimSpace(p.Comment))) > 128 {
		return fmt.Errorf("comment_too_long")
	}
	return nil
}

func normalizeIKuaiPolicy(p IKuaiPolicy) IKuaiPolicy {
	p.Comment = strings.TrimSpace(p.Comment)
	return p
}

func normalizeIKuaiPolicyForProfile(profile IKuaiAuthProfile, p IKuaiPolicy) IKuaiPolicy {
	p = normalizeIKuaiPolicy(p)
	if profile == IKuaiProfileGuest {
		p.Timeout = 0
	}
	return p
}

func clonePolicyMap(in map[IKuaiAuthProfile]IKuaiPolicy) map[IKuaiAuthProfile]IKuaiPolicy {
	out := make(map[IKuaiAuthProfile]IKuaiPolicy, len(in))
	for k, v := range in {
		out[k] = normalizeIKuaiPolicyForProfile(k, v)
	}
	return out
}
