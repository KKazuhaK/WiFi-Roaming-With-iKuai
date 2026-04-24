package main

// ratelimit.go
// 三套失败计数 / 冷却机制, 全内存, 单容器场景够用:
//
//   failCounter  记时间戳列表, 支持查询任意窗口内的失败次数, 支持成功清零.
//                用于规则 1 (邮箱双窗口 5m/1h) 和规则 5 (MAC 1h).
//
//   ipBanList    记 IP → 冷却到期时间, 到期自动失效.
//                用于规则 6: 单 IP 累计失败超限 → 短时冷却.
//
//   clientIP     从反代 header (X-Real-IP / X-Forwarded-For) 提取真实客户端 IP.
//                Portal 只绑 127.0.0.1, 所有连接都过 Nginx 反代, header 可信.

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// failCounter 每个 key 存一串失败时间戳, 支持 countIn(key, window) 查近 window 次数.
// 成功时 reset(key) 清零. gcLoop 定期 prune 老时间戳 + 空 key.
type failCounter struct {
	mu        sync.Mutex
	entries   map[string][]time.Time
	maxWindow time.Duration // GC 裁剪依据: 比这老的时间戳全丢
}

func newFailCounter(maxWindow time.Duration) *failCounter {
	return &failCounter{
		entries:   make(map[string][]time.Time),
		maxWindow: maxWindow,
	}
}

func (c *failCounter) record(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = append(c.entries[key], time.Now())
}

// countIn 返回近 window 时间内该 key 的失败次数.
func (c *failCounter) countIn(key string, window time.Duration) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	ts := c.entries[key]
	if len(ts) == 0 {
		return 0
	}
	cutoff := time.Now().Add(-window)
	n := 0
	for _, t := range ts {
		if t.After(cutoff) {
			n++
		}
	}
	return n
}

func (c *failCounter) reset(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}

// resetAll 清空所有 key. 仅供 admin "一键解除" 用.
func (c *failCounter) resetAll() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(c.entries)
	c.entries = make(map[string][]time.Time)
	return n
}

// FailSnapshot 给 admin 面板用: 某个 key 近 maxWindow 内累计多少次失败.
type FailSnapshot struct {
	Key     string `json:"key"`
	Count   int    `json:"count"`
	Latest  int64  `json:"latest_unix"` // 最近一次失败时间 Unix
}

// snapshot 返回所有 count > 0 的 key 的快照, 按 Count 降序.
// 窗口用的是 maxWindow (也就是失败数据保留多久), 比业务用的短窗口或长窗口都宽,
// 这样 admin 能看到所有相关 key, 不只是那些真触发限流的.
func (c *failCounter) snapshot() []FailSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	cutoff := time.Now().Add(-c.maxWindow)
	out := make([]FailSnapshot, 0, len(c.entries))
	for k, ts := range c.entries {
		n := 0
		var latest time.Time
		for _, t := range ts {
			if t.After(cutoff) {
				n++
				if t.After(latest) {
					latest = t
				}
			}
		}
		if n > 0 {
			out = append(out, FailSnapshot{Key: k, Count: n, Latest: latest.Unix()})
		}
	}
	// Count 降序 + Key 升序, 让最 "热" 的 key 顶上去, 同级时顺序稳定.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	return out
}

func (c *failCounter) gcLoop() {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for range t.C {
		cutoff := time.Now().Add(-c.maxWindow)
		c.mu.Lock()
		for k, ts := range c.entries {
			kept := ts[:0]
			for _, x := range ts {
				if x.After(cutoff) {
					kept = append(kept, x)
				}
			}
			if len(kept) == 0 {
				delete(c.entries, k)
			} else {
				c.entries[k] = kept
			}
		}
		c.mu.Unlock()
	}
}

// ipBanList 单 IP 冷却列表 + 到期时间. isBanned 读取时顺手清理到期项.
type ipBanList struct {
	mu   sync.Mutex
	bans map[string]time.Time // ip → banUntil
}

func newIPBanList() *ipBanList {
	return &ipBanList{bans: make(map[string]time.Time)}
}

func (b *ipBanList) ban(ip string, d time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.bans[ip] = time.Now().Add(d)
}

func (b *ipBanList) isBanned(ip string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	exp, ok := b.bans[ip]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(b.bans, ip)
		return false
	}
	return true
}

// expiryOf 返回该 IP 冷却到期时间, ok=false 表示没在冷却.
// 跟 isBanned 一样会顺手清掉过期条目.
func (b *ipBanList) expiryOf(ip string) (time.Time, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	exp, ok := b.bans[ip]
	if !ok {
		return time.Time{}, false
	}
	if time.Now().After(exp) {
		delete(b.bans, ip)
		return time.Time{}, false
	}
	return exp, true
}

func (b *ipBanList) gcLoop() {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for range t.C {
		b.mu.Lock()
		now := time.Now()
		for ip, exp := range b.bans {
			if now.After(exp) {
				delete(b.bans, ip)
			}
		}
		b.mu.Unlock()
	}
}

// unban: admin 手动解封指定 IP. 返回是否之前真的被封着.
func (b *ipBanList) unban(ip string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.bans[ip]; ok {
		delete(b.bans, ip)
		return true
	}
	return false
}

// unbanAll: admin "一键解封" 清空所有封禁. 返回清了几条.
func (b *ipBanList) unbanAll() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(b.bans)
	b.bans = make(map[string]time.Time)
	return n
}

// BanSnapshot 给 admin 面板用.
type BanSnapshot struct {
	IP         string `json:"ip"`
	ExpiresAt  int64  `json:"expires_unix"`  // 封禁到期 Unix
}

// snapshot 返回所有仍在封禁中的 IP, 按到期时间升序 (最快解封的排前).
func (b *ipBanList) snapshot() []BanSnapshot {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	out := make([]BanSnapshot, 0, len(b.bans))
	for ip, exp := range b.bans {
		if exp.After(now) {
			out = append(out, BanSnapshot{IP: ip, ExpiresAt: exp.Unix()})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ExpiresAt < out[j].ExpiresAt })
	return out
}

// banHistory 记录每个 IP 被冷却过多少次. 默认不持久化、不升级永久。
// 如果管理员显式把 IPBanEscalateAt 调小并设置持久化, 仍可作为升级模型使用。
// 内容只有 {ip: count}, 不涉及积累失败计数 (那些重启清零对合法用户更友好).
type banHistory struct {
	mu          sync.Mutex
	counts      map[string]int // ip → 被封过几次
	persistPath string         // 空 = 内存模式, 非空 = JSON 文件持久化
}

// newBanHistory: persistPath 空则纯内存; 非空则尝试从文件加载, 失败直接 err
// (启动阶段暴露, 不静默覆盖旧数据).
func newBanHistory(persistPath string) (*banHistory, error) {
	b := &banHistory{
		counts:      make(map[string]int),
		persistPath: persistPath,
	}
	if persistPath == "" {
		return b, nil
	}
	data, err := os.ReadFile(persistPath)
	if err != nil {
		if os.IsNotExist(err) {
			return b, nil
		}
		return nil, fmt.Errorf("读取 %s: %w", persistPath, err)
	}
	if len(data) == 0 {
		return b, nil
	}
	if err := json.Unmarshal(data, &b.counts); err != nil {
		return nil, fmt.Errorf("解析 %s: %w", persistPath, err)
	}
	log.Printf("ban history: 从 %s 加载 %d 条 IP 冷却历史", persistPath, len(b.counts))
	return b, nil
}

// increment: IP 被封一次, 计数 +1, 返回新的总封禁次数 (从 1 开始).
// 同步写盘, 失败只 log 不回滚内存 — 下次变更会再写.
func (b *banHistory) increment(ip string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.counts[ip]++
	n := b.counts[ip]
	b.saveLocked()
	return n
}

// get: 返回该 IP 已被封次数 (0 = 从未).
func (b *banHistory) get(ip string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.counts[ip]
}

// reset: admin 手动清除一个 IP 的封禁历史 (让他回到"初犯"状态).
func (b *banHistory) reset(ip string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.counts[ip]; ok {
		delete(b.counts, ip)
		b.saveLocked()
	}
}

// resetAll: admin "一键解封" 清空所有封禁历史 (所有 IP 回到初犯). 返回清了几条.
// 会写一次盘 (把空 map 覆盖掉旧文件).
func (b *banHistory) resetAll() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(b.counts)
	b.counts = make(map[string]int)
	b.saveLocked()
	return n
}

// snapshot: admin UI 用, 返回 {ip: count} 的副本.
func (b *banHistory) snapshot() map[string]int {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make(map[string]int, len(b.counts))
	for k, v := range b.counts {
		out[k] = v
	}
	return out
}

// saveLocked: 必须在持锁时调. 原子写 (tmp + rename). 失败只 log.
func (b *banHistory) saveLocked() {
	if b.persistPath == "" {
		return
	}
	data, err := json.MarshalIndent(b.counts, "", "  ")
	if err != nil {
		log.Printf("ban history 序列化失败: %v", err)
		return
	}
	dir := filepath.Dir(b.persistPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		log.Printf("ban history mkdir %s 失败: %v", dir, err)
		return
	}
	tmp := b.persistPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		log.Printf("ban history 写 %s 失败: %v", tmp, err)
		return
	}
	if err := os.Rename(tmp, b.persistPath); err != nil {
		log.Printf("ban history rename %s → %s 失败: %v", tmp, b.persistPath, err)
	}
}

// PermanentBanUntil 我们用来标记"永久封禁"的时间点. 实际是 1 百年后的某个 Unix 时间,
// 大得不可能被正常到期逻辑跨过去, 又能走正常的时间比较路径不用特殊分支.
var PermanentBanUntil = time.Date(2125, 1, 1, 0, 0, 0, 0, time.UTC)

// IsPermanent 判断一个到期时间点是不是"永久"标记.
func IsPermanent(t time.Time) bool {
	return t.After(time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC))
}

// clientIP 从反代 header 提真实 IP. Portal 绑 127.0.0.1, 所有连接都过 Nginx,
// 所以 X-Real-IP / X-Forwarded-For 可信. aaPanel 默认 Nginx 反代会填.
func clientIP(r *http.Request) string {
	if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" {
		return xri
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
