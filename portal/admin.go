package main

// admin.go
// 访客码管理后台: 数据模型 + 内存存储 + 随机生成.
// 容器重启数据会丢 — 小团队运维场景下可接受. 要持久化就加 JSON 文件刷盘,
// 把 GuestCodeStore 的 Add/Delete/Validate 包一层磁盘写入.

import (
	"crypto/rand"
	"math/big"
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
//   - ExpiresAt 是绝对过期时间. 创建时如果 admin 显式填了 "过期时间" 用那个;
//     否则用 CreatedAt + 限时.
//   - 码可重复使用直到过期, 每次使用记到 Uses 里 (像 iKuai 的 "使用记录" 一列).
//   - Note 是 admin 的备注, 只用于后台显示.
type GuestCode struct {
	Code      string    `json:"code"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Note      string    `json:"note,omitempty"`
	Uses      []CodeUse `json:"uses,omitempty"`
}

type CodeUse struct {
	At       time.Time `json:"at"`
	MAC      string    `json:"mac"`
	IP       string    `json:"ip"`
	GuestUPN string    `json:"guest_upn"` // 例 guest-abc12345
}

func (c *GuestCode) IsExpired() bool {
	return time.Now().After(c.ExpiresAt)
}

func (c *GuestCode) UseCount() int {
	return len(c.Uses)
}

// Status: 给 UI 分类 Tabs 用.
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

// GuestCodeStore: 内存存储, 并发安全.
type GuestCodeStore struct {
	mu    sync.RWMutex
	codes map[string]*GuestCode // key = strings.ToLower(Code)
}

func newGuestCodeStore() *GuestCodeStore {
	return &GuestCodeStore{codes: make(map[string]*GuestCode)}
}

// List 返回按 CreatedAt 倒序排列的副本. 拿到后调用者不持锁.
func (s *GuestCodeStore) List() []*GuestCode {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*GuestCode, 0, len(s.codes))
	for _, c := range s.codes {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
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
	return true
}

// DeleteExpired 删所有过期码, 返回删除数量.
func (s *GuestCodeStore) DeleteExpired() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	now := time.Now()
	for k, c := range s.codes {
		if now.After(c.ExpiresAt) {
			delete(s.codes, k)
			n++
		}
	}
	return n
}

// Validate: 找到、未过期就记一次使用, 返回 code 对象. nil = 无效.
// guestUPN 是我们上报给 iKuai 的 user_id (每次连接都不同).
func (s *GuestCodeStore) Validate(code, mac, ip, guestUPN string) *GuestCode {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := strings.ToLower(strings.TrimSpace(code))
	if k == "" {
		return nil
	}
	c, ok := s.codes[k]
	if !ok || c.IsExpired() {
		return nil
	}
	c.Uses = append(c.Uses, CodeUse{
		At: time.Now(), MAC: mac, IP: ip, GuestUPN: guestUPN,
	})
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
