package main

// ikuai_policy.go
// iKuai 放行策略: 按认证来源设置上传 / 下载限速、认证超时和 comment.
// Env 提供启动默认值; Admin 修改后可选 JSON 持久化.

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type IKuaiAuthProfile string

const (
	IKuaiProfileSSO   IKuaiAuthProfile = "sso"
	IKuaiProfileDuo   IKuaiAuthProfile = "duo"
	IKuaiProfileGuest IKuaiAuthProfile = "guest"
)

type IKuaiPolicy struct {
	Upload   int    `json:"upload"`   // KB, 0 = 不限
	Download int    `json:"download"` // KB, 0 = 不限
	Timeout  int    `json:"timeout"`  // 分钟, 0 = 不过期
	Comment  string `json:"comment,omitempty"`
}

type IKuaiPolicyStore struct {
	mu          sync.RWMutex
	policies    map[IKuaiAuthProfile]IKuaiPolicy
	defaults    map[IKuaiAuthProfile]IKuaiPolicy
	persistPath string
}

func newIKuaiPolicyStore(defaults map[IKuaiAuthProfile]IKuaiPolicy, persistPath string) (*IKuaiPolicyStore, error) {
	s := &IKuaiPolicyStore{
		policies:    clonePolicyMap(defaults),
		defaults:    clonePolicyMap(defaults),
		persistPath: persistPath,
	}
	if persistPath == "" {
		return s, nil
	}
	if err := s.loadFromDisk(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *IKuaiPolicyStore) loadFromDisk() error {
	data, err := os.ReadFile(s.persistPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("读取 %s: %w", s.persistPath, err)
	}
	if len(data) == 0 {
		return nil
	}
	var raw map[string]IKuaiPolicy
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("解析 %s: %w", s.persistPath, err)
	}
	for k, p := range raw {
		profile, ok := parseIKuaiProfile(k)
		if !ok {
			continue
		}
		if err := validateIKuaiPolicy(p); err != nil {
			return fmt.Errorf("解析 %s: profile %s: %w", s.persistPath, profile, err)
		}
		s.policies[profile] = normalizeIKuaiPolicy(p)
	}
	log.Printf("iKuai 放行策略: 从 %s 加载", s.persistPath)
	return nil
}

func (s *IKuaiPolicyStore) Get(profile IKuaiAuthProfile) IKuaiPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if p, ok := s.policies[profile]; ok {
		return p
	}
	return s.defaults[profile]
}

func (s *IKuaiPolicyStore) Set(profile IKuaiAuthProfile, p IKuaiPolicy) error {
	if _, ok := parseIKuaiProfile(string(profile)); !ok {
		return fmt.Errorf("invalid_profile")
	}
	if err := validateIKuaiPolicy(p); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policies[profile] = normalizeIKuaiPolicy(p)
	s.saveLocked()
	return nil
}

func (s *IKuaiPolicyStore) List() []IKuaiPolicyRow {
	s.mu.RLock()
	defer s.mu.RUnlock()
	profiles := []IKuaiAuthProfile{IKuaiProfileSSO, IKuaiProfileDuo, IKuaiProfileGuest}
	out := make([]IKuaiPolicyRow, 0, len(profiles))
	for _, profile := range profiles {
		p := s.policies[profile]
		out = append(out, IKuaiPolicyRow{
			Profile:  string(profile),
			Label:    ikuaiProfileLabel(profile),
			Upload:   p.Upload,
			Download: p.Download,
			Timeout:  p.Timeout,
			Comment:  p.Comment,
		})
	}
	return out
}

func (s *IKuaiPolicyStore) saveLocked() {
	if s.persistPath == "" {
		return
	}
	raw := make(map[string]IKuaiPolicy, len(s.policies))
	for profile, policy := range s.policies {
		raw[string(profile)] = policy
	}
	data, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		log.Printf("iKuai 放行策略序列化失败: %v", err)
		return
	}
	dir := filepath.Dir(s.persistPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		log.Printf("iKuai 放行策略 mkdir %s 失败: %v", dir, err)
		return
	}
	tmp := s.persistPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		log.Printf("iKuai 放行策略写 %s 失败: %v", tmp, err)
		return
	}
	if err := os.Rename(tmp, s.persistPath); err != nil {
		log.Printf("iKuai 放行策略 rename %s → %s 失败: %v", tmp, s.persistPath, err)
	}
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
			Timeout:  envOrNonNegativeInt("IKUAI_GUEST_TIMEOUT", 0),
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
		return "SSO 成员"
	case IKuaiProfileDuo:
		return "Duo 成员"
	case IKuaiProfileGuest:
		return "访客码"
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

func clonePolicyMap(in map[IKuaiAuthProfile]IKuaiPolicy) map[IKuaiAuthProfile]IKuaiPolicy {
	out := make(map[IKuaiAuthProfile]IKuaiPolicy, len(in))
	for k, v := range in {
		out[k] = normalizeIKuaiPolicy(v)
	}
	return out
}
