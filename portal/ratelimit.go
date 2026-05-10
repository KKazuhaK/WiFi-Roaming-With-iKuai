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

// maxFailCounterEntries 单个 failCounter 容纳的最大 key 数. 防内存增长 DOS:
// 攻击者用大量伪造 key (邮箱 / 伪造 IP) 灌爆. 触顶后 record 跑同步 prune,
// 仍满则丢弃最老 key (LRU 近似 — 用 latest 时间戳排序).
const maxFailCounterEntries = 100000

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
	if _, exists := c.entries[key]; !exists && len(c.entries) >= maxFailCounterEntries {
		c.evictOldestLocked()
	}
	c.entries[key] = append(c.entries[key], time.Now())
}

// evictOldestLocked: 触顶时同步剔除最老的 key. 先按窗口 prune 一遍 (gcLoop 的活儿)
// 还满则按"最近一次失败时间最早"剔到 90% 容量. 必须持锁.
func (c *failCounter) evictOldestLocked() {
	cutoff := time.Now().Add(-c.maxWindow)
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
	if len(c.entries) < maxFailCounterEntries {
		return
	}
	type kv struct {
		k    string
		last time.Time
	}
	all := make([]kv, 0, len(c.entries))
	for k, ts := range c.entries {
		var latest time.Time
		for _, t := range ts {
			if t.After(latest) {
				latest = t
			}
		}
		all = append(all, kv{k, latest})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].last.Before(all[j].last) })
	target := maxFailCounterEntries * 9 / 10
	for i := 0; i < len(all) && len(c.entries) > target; i++ {
		delete(c.entries, all[i].k)
	}
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
	Key    string `json:"key"`
	Count  int    `json:"count"`
	Latest int64  `json:"latest_unix"` // 最近一次失败时间 Unix
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

// maxIPBanEntries 单个 ipBanList 容纳的最大 IP 数. 触顶时清掉已过期项, 仍满则丢最早到期的.
const maxIPBanEntries = 50000

func (b *ipBanList) ban(ip string, d time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, exists := b.bans[ip]; !exists && len(b.bans) >= maxIPBanEntries {
		now := time.Now()
		for k, exp := range b.bans {
			if now.After(exp) {
				delete(b.bans, k)
			}
		}
		if len(b.bans) >= maxIPBanEntries {
			type kv struct {
				k   string
				exp time.Time
			}
			all := make([]kv, 0, len(b.bans))
			for k, exp := range b.bans {
				all = append(all, kv{k, exp})
			}
			sort.Slice(all, func(i, j int) bool { return all[i].exp.Before(all[j].exp) })
			target := maxIPBanEntries * 9 / 10
			for i := 0; i < len(all) && len(b.bans) > target; i++ {
				delete(b.bans, all[i].k)
			}
		}
	}
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
	IP        string `json:"ip"`
	ExpiresAt int64  `json:"expires_unix"` // 封禁到期 Unix
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
//
// **持久化策略**: 每次 increment 只标记 dirty, 不同步写盘 — 攻击下高频失败时,
// 同步写整个 ratelimit-state.json 会让 disk IO 串行化, 拖累所有 portal handler.
// 后台 flusher 周期 (默认 30s) flush 一次. shutdown 时同步 flush 一次保证不丢.
type banHistory struct {
	mu          sync.Mutex
	counts      map[string]int // ip → 被封过几次
	persistPath string         // 空 = 内存模式, 非空 = JSON 文件持久化
	dirty       bool
	flushStop   chan struct{}
	flushDone   chan struct{}
}

// banHistoryFlushInterval flusher 周期. 30s — 攻击场景下丢最多 30s 的 escalation
// 历史可接受 (反正 IPBanEscalateAt 默认 999999 等于不用; 真用时丢一两次 increment
// 不影响最终升级判断, 攻击者要么够多次要么不够).
var banHistoryFlushInterval = 30 * time.Second

// newBanHistory: persistPath 空则纯内存; 非空则尝试从文件加载, 失败直接 err
// (启动阶段暴露, 不静默覆盖旧数据). 启动时同时拉起 flusher goroutine.
func newBanHistory(persistPath string) (*banHistory, error) {
	b := &banHistory{
		counts:      make(map[string]int),
		persistPath: persistPath,
		flushStop:   make(chan struct{}),
		flushDone:   make(chan struct{}),
	}
	if persistPath == "" {
		close(b.flushDone)
		return b, nil
	}
	data, err := os.ReadFile(persistPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("read %s: %w", persistPath, err)
		}
	} else if len(data) > 0 {
		if err := json.Unmarshal(data, &b.counts); err != nil {
			return nil, fmt.Errorf("parse %s: %w", persistPath, err)
		}
		log.Printf("ban history: loaded %d IP cooldown entries from %s", len(b.counts), persistPath)
	}
	go b.flushLoop()
	return b, nil
}

// flushLoop 周期性把 dirty 的 banHistory 落盘. shutdown() 通过 close(flushStop) 退出.
func (b *banHistory) flushLoop() {
	defer close(b.flushDone)
	t := time.NewTicker(banHistoryFlushInterval)
	defer t.Stop()
	for {
		select {
		case <-b.flushStop:
			b.flushIfDirty()
			return
		case <-t.C:
			b.flushIfDirty()
		}
	}
}

func (b *banHistory) flushIfDirty() {
	b.mu.Lock()
	if !b.dirty {
		b.mu.Unlock()
		return
	}
	// marshal 在锁内拿快照, 写盘移到锁外.
	snapshot := make(map[string]int, len(b.counts))
	for k, v := range b.counts {
		snapshot[k] = v
	}
	b.dirty = false
	b.mu.Unlock()

	if err := b.writeSnapshot(snapshot); err != nil {
		log.Printf("ban history flush failed: %v", err)
		// 写失败 → 标回 dirty, 下次重试
		b.mu.Lock()
		b.dirty = true
		b.mu.Unlock()
	}
}

func (b *banHistory) writeSnapshot(snapshot map[string]int) error {
	if b.persistPath == "" {
		return nil
	}
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	dir := filepath.Dir(b.persistPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	tmp := b.persistPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, b.persistPath); err != nil {
		return fmt.Errorf("rename %s -> %s: %w", tmp, b.persistPath, err)
	}
	return nil
}

// shutdown 停 flusher goroutine 并做最后一次 flush. 启动后未调 → 进程退出时丢
// 最多一个周期的 ban history (一般可接受). 单元测试 / 优雅退出时应调.
func (b *banHistory) shutdown() error {
	if b.persistPath == "" {
		return nil
	}
	select {
	case <-b.flushStop:
		// 已经 stop, 防 close panic
	default:
		close(b.flushStop)
	}
	<-b.flushDone
	return nil
}

// increment: IP 被封一次, 计数 +1, 返回新的总封禁次数 (从 1 开始).
// 只标记 dirty, 由 flushLoop 周期性落盘. 攻击下不会因每次失败都同步写文件
// 阻塞热路径 (C4 修复).
func (b *banHistory) increment(ip string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.counts[ip]++
	b.dirty = true
	return b.counts[ip]
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
		b.dirty = true
	}
}

// resetAll: admin "一键解封" 清空所有封禁历史 (所有 IP 回到初犯). 返回清了几条.
func (b *banHistory) resetAll() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(b.counts)
	b.counts = make(map[string]int)
	if n > 0 {
		b.dirty = true
	}
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

// usedStateSet 记一段时间内消费过的 OIDC state, 防 cookie 偷取后重放. callback
// 验完 state 立刻 markUsed; 同一个 state 第二次来直接拒. TTL 跟 sessionTTL 对齐
// (15 分钟) — cookie 本身过期了, state 也没再用价值. 内存有限 maxUsedStates 触顶
// LRU 淘汰最早条目.
const maxUsedStates = 50000

type usedStateSet struct {
	mu     sync.Mutex
	states map[string]time.Time
	ttl    time.Duration
}

func newUsedStateSet(ttl time.Duration) *usedStateSet {
	return &usedStateSet{
		states: make(map[string]time.Time),
		ttl:    ttl,
	}
}

// markUsed 若 state 之前没用过 (或已过 TTL), 记下来并返回 true. 已用过返回 false.
func (s *usedStateSet) markUsed(state string) bool {
	if state == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if exp, ok := s.states[state]; ok && now.Before(exp) {
		return false
	}
	if len(s.states) >= maxUsedStates {
		// 同步 prune 过期项
		for k, exp := range s.states {
			if now.After(exp) {
				delete(s.states, k)
			}
		}
		// 仍满则丢最早过期的
		if len(s.states) >= maxUsedStates {
			type kv struct {
				k   string
				exp time.Time
			}
			all := make([]kv, 0, len(s.states))
			for k, exp := range s.states {
				all = append(all, kv{k, exp})
			}
			sort.Slice(all, func(i, j int) bool { return all[i].exp.Before(all[j].exp) })
			target := maxUsedStates * 9 / 10
			for i := 0; i < len(all) && len(s.states) > target; i++ {
				delete(s.states, all[i].k)
			}
		}
	}
	s.states[state] = now.Add(s.ttl)
	return true
}

func (s *usedStateSet) gcLoop() {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for range t.C {
		s.mu.Lock()
		now := time.Now()
		for k, exp := range s.states {
			if now.After(exp) {
				delete(s.states, k)
			}
		}
		s.mu.Unlock()
	}
}

// PermanentBanUntil 我们用来标记"永久封禁"的时间点. 实际是 1 百年后的某个 Unix 时间,
// 大得不可能被正常到期逻辑跨过去, 又能走正常的时间比较路径不用特殊分支.
var PermanentBanUntil = time.Date(2125, 1, 1, 0, 0, 0, 0, time.UTC)

// IsPermanent 判断一个到期时间点是不是"永久"标记.
func IsPermanent(t time.Time) bool {
	return t.After(time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC))
}

// trustProxyHeaders 启动时由 main 从 cfg.TrustProxy 注入. 默认 true 保持反代部署兼容.
// 直接暴露公网时, env TRUST_PROXY=false 让 clientIP 只信 r.RemoteAddr — 否则攻击者
// 可任意伪造 X-Real-IP / X-Forwarded-For 绕过所有 IP 限流 + 永久封禁.
var trustProxyHeaders = true

// clientIP 取真实客户端 IP.
//
// trustProxyHeaders=true (默认, 反代部署):
//
//	X-Real-IP 优先 (推荐反代设 X-Real-IP $remote_addr, nginx/Caddy 都支持).
//	没设 X-Real-IP 时回退 X-Forwarded-For — **取最右**, 因为 nginx
//	$proxy_add_x_forwarded_for 会把上一跳的源 IP append 到末尾,
//	攻击者发的伪造 XFF 被推到左侧. 取最左等于直接读攻击者输入.
//
// trustProxyHeaders=false (公网直暴露):
//
//	完全忽略 header, 只用 r.RemoteAddr.
func clientIP(r *http.Request) string {
	if trustProxyHeaders {
		if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" {
			return xri
		}
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if i := strings.LastIndex(xff, ","); i >= 0 {
				return strings.TrimSpace(xff[i+1:])
			}
			return strings.TrimSpace(xff)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
