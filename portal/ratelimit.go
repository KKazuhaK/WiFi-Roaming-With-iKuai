package main

// ratelimit.go
// 内存 token bucket + 按 key (IP / email) 的限流器, 单容器场景够用.
//
// 用途: 防御 /auth/start 被脚本化刷, 从而利用我们把用户 302 到 Duo Universal
// Prompt → 自动点 "发送推送" 来做 MFA 轰炸 (受害者手机被狂推 Duo 推送).
//
// 实现:
//   - 每 key 一个 tokenBucket, 容量 = 允许的突发次数, 补充速率 = 容量 / 周期.
//   - 并发安全 (每桶自己 mu), 允许不同 key 并行.
//   - gcLoop 周期回收长期不活跃的桶, 防内存被无限新 key 吃爆.

import (
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type tokenBucket struct {
	mu       sync.Mutex
	rate     float64 // tokens/sec
	capacity float64
	tokens   float64
	last     time.Time
}

func (b *tokenBucket) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(b.last).Seconds()
	b.last = now
	b.tokens = math.Min(b.capacity, b.tokens+elapsed*b.rate)
	if b.tokens < 1.0 {
		return false
	}
	b.tokens--
	return true
}

type rateLimiter struct {
	rate     float64
	capacity float64
	ttl      time.Duration // 多久没访问就 GC 掉这个 key 的桶
	mu       sync.Mutex
	buckets  map[string]*tokenBucket
}

// newRateLimiter: 每 period 内允许 n 次 (突发也允许 n 次).
func newRateLimiter(n int, period time.Duration) *rateLimiter {
	return &rateLimiter{
		rate:     float64(n) / period.Seconds(),
		capacity: float64(n),
		ttl:      period * 2,
		buckets:  make(map[string]*tokenBucket),
	}
}

func (r *rateLimiter) allow(key string) bool {
	r.mu.Lock()
	b, ok := r.buckets[key]
	if !ok {
		b = &tokenBucket{
			rate:     r.rate,
			capacity: r.capacity,
			tokens:   r.capacity,
			last:     time.Now(),
		}
		r.buckets[key] = b
	}
	r.mu.Unlock()
	return b.allow()
}

// gcLoop 常驻 goroutine, 10 分钟扫一次, 清理 last 超出 ttl 的桶.
func (r *rateLimiter) gcLoop() {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for range t.C {
		cutoff := time.Now().Add(-r.ttl)
		r.mu.Lock()
		for k, b := range r.buckets {
			b.mu.Lock()
			stale := b.last.Before(cutoff)
			b.mu.Unlock()
			if stale {
				delete(r.buckets, k)
			}
		}
		r.mu.Unlock()
	}
}

// clientIP 从反代后面提取真实客户端 IP. Portal 只绑 127.0.0.1:28080,
// 所有请求都经 Nginx, 可信任 X-Real-IP / X-Forwarded-For.
// aaPanel 默认 Nginx 反代会填 X-Real-IP.
func clientIP(r *http.Request) string {
	if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" {
		return xri
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// 多级代理时 XFF 是逗号分隔列表, 最左边是原始客户端.
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
