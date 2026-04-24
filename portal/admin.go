package main

// admin.go
// 访客码管理后台: 数据模型 + 内存存储 + 可选 JSON 持久化 + 随机生成.
//
// 持久化: newGuestCodeStore(path) 的 path 非空时, 启动加载 + 每次变更原子写盘
// (tmp + rename). path 空 = 纯内存, 重启数据丢.
// 配合 docker-compose volume 把 path 所在目录挂出来, 容器重启不丢码.

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// GuestCodeType 批量生成时可选的字符集类型.
type GuestCodeType string

const (
	CodeNumeric      GuestCodeType = "numeric"
	CodeAlpha        GuestCodeType = "alpha"
	CodeAlphaNumeric GuestCodeType = "alphanumeric"
)

// GuestCode 是一条访客码记录.
// 设计备注:
//   - ExpiresAt 是绝对过期时间. 零值表示永不过期.
//   - DurationMin 是每次成功使用后在 iKuai 侧放行多久. 0 = 不限时.
//   - MaxUses 限制同一个码最多可成功使用多少次. 0 = 不限.
//   - Note 是 admin 的备注, 只用于后台显示.
type GuestCode struct {
	Code        string    `json:"code"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	DurationMin int       `json:"duration_min"`
	MaxUses     int       `json:"max_uses,omitempty"`
	Note        string    `json:"note,omitempty"`
	Uses        []CodeUse `json:"uses,omitempty"`
}

type CodeUse struct {
	At       time.Time `json:"at"`
	MAC      string    `json:"mac"`
	IP       string    `json:"ip"`
	GuestUPN string    `json:"guest_upn"` // 例 Guest-abc12345
}

func (c *GuestCode) IsExpired() bool {
	if c.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(c.ExpiresAt)
}

// IsExhausted: 达到 MaxUses 上限 (MaxUses=0 视为无限).
func (c *GuestCode) IsExhausted() bool {
	return c.MaxUses > 0 && len(c.Uses) >= c.MaxUses
}

func (c *GuestCode) UseCount() int {
	return len(c.Uses)
}

// Status: 给 UI 分类 Tabs 用. 用完的归到 "已使用", 不单独列一类.
func (c *GuestCode) Status() string {
	switch {
	case c.IsExpired():
		return "expired"
	case len(c.Uses) > 0:
		return "used"
	default:
		return "unused"
	}
}

// GuestCodeStore: 内存存储, 并发安全, 可选磁盘持久化.
// persistPath 空则不落盘.
type GuestCodeStore struct {
	mu          sync.RWMutex
	codes       map[string]*GuestCode // key = strings.ToLower(Code)
	persistPath string
}

// newGuestCodeStore: persistPath 空 = 纯内存; 非空则尝试从文件加载, 失败直接返回 err
// (启动阶段暴露, 不静默覆盖).
func newGuestCodeStore(persistPath string) (*GuestCodeStore, error) {
	s := &GuestCodeStore{
		codes:       make(map[string]*GuestCode),
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

// loadFromDisk: 只在启动时调一次, 不持锁.
func (s *GuestCodeStore) loadFromDisk() error {
	data, err := os.ReadFile(s.persistPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // 首次启动, 文件还没建
		}
		return fmt.Errorf("read %s: %w", s.persistPath, err)
	}
	if len(data) == 0 {
		return nil
	}
	var rawCodes []json.RawMessage
	if err := json.Unmarshal(data, &rawCodes); err != nil {
		return fmt.Errorf("parse %s: %w", s.persistPath, err)
	}
	for _, raw := range rawCodes {
		var c GuestCode
		if err := json.Unmarshal(raw, &c); err != nil {
			return fmt.Errorf("parse %s: %w", s.persistPath, err)
		}
		var fields map[string]json.RawMessage
		_ = json.Unmarshal(raw, &fields)
		if _, ok := fields["duration_min"]; !ok && !c.ExpiresAt.IsZero() {
			mins := int(c.ExpiresAt.Sub(c.CreatedAt).Minutes())
			if mins < 1 {
				mins = 1
			}
			c.DurationMin = mins
		}
		k := strings.ToLower(strings.TrimSpace(c.Code))
		if k == "" {
			continue
		}
		copied := c
		s.codes[k] = &copied
	}
	log.Printf("guest codes: loaded %d entries from %s", len(s.codes), s.persistPath)
	return nil
}

// saveLocked: 必须在已持写锁时调用. 原子写 (tmp → rename). 失败只记日志,
// 不回滚内存状态 — 下一次变更会再写一次, 重启才会丢这次变更.
func (s *GuestCodeStore) saveLocked() {
	if s.persistPath == "" {
		return
	}
	codes := make([]*GuestCode, 0, len(s.codes))
	for _, c := range s.codes {
		codes = append(codes, c)
	}
	data, err := json.MarshalIndent(codes, "", "  ")
	if err != nil {
		log.Printf("guest codes: marshal failed: %v", err)
		return
	}
	dir := filepath.Dir(s.persistPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		log.Printf("guest codes: mkdir %s failed: %v", dir, err)
		return
	}
	tmp := s.persistPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		log.Printf("guest codes: write %s failed: %v", tmp, err)
		return
	}
	if err := os.Rename(tmp, s.persistPath); err != nil {
		log.Printf("guest codes: rename %s -> %s failed: %v", tmp, s.persistPath, err)
	}
}

// List 返回按 CreatedAt 倒序排列的副本. 拿到后调用者不持锁.
// 时间相同时按 Code 字典序兜底, 保证多次刷新顺序稳定 (map 遍历本身无序).
func (s *GuestCodeStore) List() []*GuestCode {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*GuestCode, 0, len(s.codes))
	for _, c := range s.codes {
		out = append(out, c)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].Code < out[j].Code
	})
	return out
}

// Add: 码重复则返回 false, 不覆盖.
func (s *GuestCodeStore) Add(c *GuestCode) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := strings.ToLower(strings.TrimSpace(c.Code))
	if k == "" {
		return false
	}
	if _, exists := s.codes[k]; exists {
		return false
	}
	s.codes[k] = c
	s.saveLocked()
	return true
}

func (s *GuestCodeStore) Delete(code string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := strings.ToLower(strings.TrimSpace(code))
	if _, ok := s.codes[k]; !ok {
		return false
	}
	delete(s.codes, k)
	s.saveLocked()
	return true
}

// Edit 修改一个码的可变元数据 (过期时间 / 限时 / MaxUses / 备注). 不允许改 Code
// 本身 (那等于删了重建). 不存在 → 返回 false. 已经使用过的码也允许编辑 —
// 改 DurationMin 只影响后续放行, 已经在线的设备的 timeout 不受影响
// (那是 iKuai 侧的 token, portal 改不了).
func (s *GuestCodeStore) Edit(code string, expiresAt time.Time, durationMin, maxUses int, note string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := strings.ToLower(strings.TrimSpace(code))
	c, ok := s.codes[k]
	if !ok {
		return false
	}
	c.ExpiresAt = expiresAt
	c.DurationMin = durationMin
	c.MaxUses = maxUses
	c.Note = note
	s.saveLocked()
	return true
}

// DeleteInactive deletes codes that are no longer fresh in the admin UI:
// already used or expired. It keeps only "unused" codes.
func (s *GuestCodeStore) DeleteInactive() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for k, c := range s.codes {
		if c.Status() == "used" || c.Status() == "expired" {
			delete(s.codes, k)
			n++
		}
	}
	if n > 0 {
		s.saveLocked()
	}
	return n
}

// DeleteExpired is kept for older call sites; the admin action now treats
// "inactive" as used or expired.
func (s *GuestCodeStore) DeleteExpired() int {
	return s.DeleteInactive()
}

// Validate: 找到、未过期、未达 MaxUses 就记一次使用, 返回 code 对象. nil = 无效.
// guestUPN 是我们上报给 iKuai 的 user_id (每次连接都不同).
func (s *GuestCodeStore) Validate(code, mac, ip, guestUPN string) *GuestCode {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := strings.ToLower(strings.TrimSpace(code))
	if k == "" {
		return nil
	}
	c, ok := s.codes[k]
	if !ok || c.IsExpired() || c.IsExhausted() {
		return nil
	}
	c.Uses = append(c.Uses, CodeUse{
		At: time.Now(), MAC: mac, IP: ip, GuestUPN: guestUPN,
	})
	s.saveLocked()
	return c
}

// Stats 三分类计数, 给 UI Tabs 显示用.
func (s *GuestCodeStore) Stats() (total, used, unused, expired int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	total = len(s.codes)
	for _, c := range s.codes {
		switch c.Status() {
		case "used":
			used++
		case "expired":
			expired++
		default:
			unused++
		}
	}
	return
}

// --- 随机码生成 ---

func generateCode(codeType GuestCodeType, length int) (string, error) {
	if length < 4 {
		length = 4
	}
	if length > 64 {
		length = 64
	}
	var alphabet string
	switch codeType {
	case CodeAlpha:
		alphabet = "abcdefghijklmnopqrstuvwxyz"
	case CodeAlphaNumeric:
		alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	case CodeNumeric:
		fallthrough
	default:
		alphabet = "0123456789"
	}
	buf := make([]byte, length)
	maxIdx := big.NewInt(int64(len(alphabet)))
	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, maxIdx)
		if err != nil {
			return "", err
		}
		buf[i] = alphabet[n.Int64()]
	}
	return string(buf), nil
}
