package main

// ratelimit.go
// 三套失败计数 / 封禁机制, 全内存, 单容器场景够用:
//
//   failCounter  记时间戳列表, 支持查询任意窗口内的失败次数, 支持成功清零.
//                用于规则 1 (邮箱双窗口 5m/1h) 和规则 5 (MAC 1h).
//
//   ipBanList    记 IP → 封禁到期时间, 到期自动失效.
//                用于规则 6: 单 IP 累计失败超限 → 直接 ban 一段时间.
//
//   clientIP     从反代 header (X-Real-IP / X-Forwarded-For) 提取真实客户端 IP.
//                Portal 只绑 127.0.0.1, 所有连接都过 Nginx 反代, header 可信.

import (
	"net"
	"net/http"
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

// ipBanList 单 IP 黑名单 + 到期时间. isBanned 读取时顺手清理到期项.
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
