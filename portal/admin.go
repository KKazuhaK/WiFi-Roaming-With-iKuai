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

// Status: 给 UI 分类 Tabs 用. 用过一次就归 "used", 不细分用尽 vs 半用 — 那是
// IsActive 的活儿. 这样 admin.html 现有三 tab (全部 / 已使用 / 未使用 + 已过期)
// 不变.
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

// IsActive: 这个码现在还能用吗? = 没过期 + 没用完.
// 跟 Status 区分开 — Status 用于 UI tab 分类 (用过/没用过), IsActive 用于
// "DeleteInactive 该不该删" 等业务判定. C3 修复关键: 半使用的多次性码 IsActive=true
// 不该被清理.
func (c *GuestCode) IsActive() bool {
	return !c.IsExpired() && !c.IsExhausted()
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
//
// 注: M12 评估后**不修**. 异步写引入 goroutine 调度顺序不一致风险 (后写可能先
// 落盘导致数据丢失); 拆两把锁手术工程量大. 实际典型规模 (< 1000 码, ~150KB JSON)
// 同步持锁 ~5ms 不构成瓶颈, 跟 handleGuestCode 调 iKuai webauth 的 100ms+ 相比
// 微不足道. 高负载场景 (10k+ 码) 再回来重做.
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

// List 返回按 CreatedAt 倒序排列的**深拷贝**, 调用者拿到后随便读 / 改不影响 store.
// 时间相同时按 Code 字典序兜底, 保证多次刷新顺序稳定 (map 遍历本身无序).
//
// 关键: Validate 持锁内会 append c.Uses; 如果 List 返回内部指针, renderAdmin /
// buildDashboard 在锁外读 c.Uses 就跟 Validate 撞 race. 所以这里整张表 deep copy.
// 一次 List 通常用于 admin 页面渲染, 不在热路径, 多复制一份 GuestCode 不构成性能问题.
func (s *GuestCodeStore) List() []*GuestCode {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*GuestCode, 0, len(s.codes))
	for _, c := range s.codes {
		out = append(out, copyGuestCode(c))
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].Code < out[j].Code
	})
	return out
}

// copyGuestCode 深拷贝一个 GuestCode, 包括内部 Uses slice. Uses 元素是值,
// 直接 copy 即可.
func copyGuestCode(c *GuestCode) *GuestCode {
	dup := *c
	if len(c.Uses) > 0 {
		dup.Uses = make([]CodeUse, len(c.Uses))
		copy(dup.Uses, c.Uses)
	}
	return &dup
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

// AddMany 批量插入, 一把锁内一次写盘. 返回成功插入的码列表 (顺序与输入一致,
// 但跳过空码 / 重复码). 用于 handleCodeBatch 的 N 码批量生成, 避免每码触发一次
// saveLocked → O(N²) 文件写.
//
// 调用方往往希望知道"实际有哪些进了 store" — 返回 []string 而不是数量, 因为
// AddMany 跳过的可能在中间不是末尾, 不能简单 `inputs[:n]`.
func (s *GuestCodeStore) AddMany(codes []*GuestCode) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	added := make([]string, 0, len(codes))
	for _, c := range codes {
		k := strings.ToLower(strings.TrimSpace(c.Code))
		if k == "" {
			continue
		}
		if _, exists := s.codes[k]; exists {
			continue
		}
		s.codes[k] = c
		added = append(added, c.Code)
	}
	if len(added) > 0 {
		s.saveLocked()
	}
	return added
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

// DeleteMany 批量删, 一把锁内一次写盘. 返回真实删掉的数量
// (空字符串 / 不存在的码会被跳过, 不计入). 同 AddMany 防 O(N²) 写.
func (s *GuestCodeStore) DeleteMany(codes []string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	deleted := 0
	for _, code := range codes {
		k := strings.ToLower(strings.TrimSpace(code))
		if k == "" {
			continue
		}
		if _, ok := s.codes[k]; !ok {
			continue
		}
		delete(s.codes, k)
		deleted++
	}
	if deleted > 0 {
		s.saveLocked()
	}
	return deleted
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

// DeleteInactive 删 "已经不能再用" 的码: 过期 OR 用尽.
// 半使用的多次性码 (MaxUses>1 且还有剩余次数) 不删 — 那是 admin 的资产.
func (s *GuestCodeStore) DeleteInactive() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for k, c := range s.codes {
		if !c.IsActive() {
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

// Validate: 找到、未过期、未达 MaxUses 就记一次使用, 返回 code 对象的**副本**.
// guestUPN 是我们上报给 iKuai 的 user_id (每次连接都不同).
// 返回副本而非内部指针 — 防调用方在锁外读到正在被写的 Uses slice 引发 race.
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
	return copyGuestCode(c)
}

// Stats 给 UI / Dashboard 算计数:
//
//	total   — 全部
//	used    — 已用尽 (IsExhausted) 且未过期
//	unused  — 还能用 (IsActive: 没过期 + 没用尽), 包括完全没用过和半使用的多次性码
//	expired — 已过期 (无论是否用过)
//
// M1 修复: 旧实现按 Status() ("用过没用过") 划分, 把半使用的多次性码归 used,
// 跟 buildDashboard.ActiveGuestCodes (按 IsActive 算) 对不上 — admin 看顶部
// 数字和 Tab 数字不一致. 现在 Stats.unused 严格等于 Dashboard active count.
func (s *GuestCodeStore) Stats() (total, used, unused, expired int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	total = len(s.codes)
	for _, c := range s.codes {
		switch {
		case c.IsExpired():
			expired++
		case c.IsExhausted():
			used++
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
