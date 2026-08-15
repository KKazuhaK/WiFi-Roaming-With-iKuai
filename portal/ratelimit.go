package main

// ratelimit.go
// Failure counting and the helpers around it.
//
//   failCounter  Stores timestamp lists, supports counts within arbitrary windows, and resets on success.
//                Used by rule 1 (email dual windows) and rule 5 (MAC).
//
//   clientIP     Extracts the real client IP from reverse-proxy headers.
//                The portal normally binds 127.0.0.1 and all traffic arrives through a trusted proxy.
//
// What is deliberately NOT here any more is the ban list: cooldowns are shared
// through the database (store_ipban.go), because a ban only one instance knows
// about is not a ban.
//
// The counters below are still per-process, and that is a considered trade
// rather than an oversight. They are read and written on every failed attempt,
// which is the path an attacker controls the volume of, and moving them into the
// database would put a write there. The consequence is that with N instances an
// attacker spreading attempts evenly gets up to N times the threshold before a
// ban — but the ban that follows is global, and the permanent escalation that
// follows repeated bans has been shared from the start (banHistory). So the
// weakening is bounded and the enforcement is not.

import (
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// maxFailCounterEntries caps keys in one failCounter to prevent memory-growth DOS from many forged
// keys. When full, record prunes synchronously and then evicts the oldest key if still full.
const maxFailCounterEntries = 100000

// failCounter stores failure timestamps per key, supports countIn(key, window), and resets on success.
// gcLoop periodically prunes old timestamps and empty keys.
type failCounter struct {
	mu        sync.Mutex
	entries   map[string][]time.Time
	maxWindow time.Duration // GC cutoff: timestamps older than this are dropped.
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

// evictOldestLocked synchronously evicts old keys when capacity is reached. It first performs the
// same window prune as gcLoop, then evicts keys with the oldest latest-failure time down to 90%.
// Must be called with the lock held.
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

// countIn returns the number of failures for key within the recent window.
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

// resetAll clears every key. It is only used by the admin clear-all action.
func (c *failCounter) resetAll() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(c.entries)
	c.entries = make(map[string][]time.Time)
	return n
}

// FailSnapshot is for the admin panel: how many failures a key has within maxWindow.
type FailSnapshot struct {
	Key    string `json:"key"`
	Count  int    `json:"count"`
	Latest int64  `json:"latest_unix"` // Latest failure time as Unix seconds.
}

// snapshot returns every key with count > 0, sorted by Count descending.
// It uses maxWindow, which is wider than business short/long windows, so admins can see all relevant
// keys rather than only those currently triggering rate limits.
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
	// Count descending + Key ascending puts the hottest keys first with stable ties.
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

// banHistory records how many times each IP has been cooled down. It is non-persistent and does not
// escalate by default. If admins lower IPBanEscalateAt and enable persistence, it can still support
// escalation. It stores only {ip: count}, not accumulated failures, because clearing those on restart
// is friendlier to legitimate users.
//
// Persistence strategy: increment only marks dirty instead of writing synchronously. Under attack,
// syncing the whole ratelimit-state.json on every failure would serialize disk IO and slow every
// portal handler. A background flusher writes periodically and shutdown flushes once.
// usedStateSet records recently consumed OIDC states to prevent replay after cookie theft. The
// callback marks a state used immediately after validation; a second use is rejected. TTL matches
// sessionTTL, after which the cookie and state are both useless. maxUsedStates evicts oldest entries.
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

// markUsed records state and returns true if it was unused or expired; reused states return false.
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
		// Synchronously prune expired entries.
		for k, exp := range s.states {
			if now.After(exp) {
				delete(s.states, k)
			}
		}
		// If still full, drop the earliest expiry.
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

// PermanentBanUntil marks a "permanent" ban as a Unix time about 100 years in the future.
// It is large enough that normal expiry will not cross it, while still using normal time comparisons.
var PermanentBanUntil = time.Date(2125, 1, 1, 0, 0, 0, 0, time.UTC)

// IsPermanent reports whether an expiry time is the permanent marker.
func IsPermanent(t time.Time) bool {
	return t.After(time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC))
}

// trustProxyHeaders is injected by main from cfg.TrustProxy at startup. It defaults to true for
// reverse-proxy compatibility. When directly exposed, set TRUST_PROXY=false so clientIP only trusts
// r.RemoteAddr; otherwise attackers can spoof X-Real-IP / X-Forwarded-For.
var trustProxyHeaders = true

// clientIP returns the real client IP.
//
// trustProxyHeaders=true (default, reverse-proxy deployment):
//
//	X-Real-IP has priority. If absent, fall back to X-Forwarded-For and take the rightmost
//	valid IP because nginx $proxy_add_x_forwarded_for appends the previous hop to the end.
//	Attacker-supplied spoofed XFF values are pushed left, so taking leftmost reads attacker input.
//
//	Header values must pass net.ParseIP; invalid values are ignored to prevent proxy
//	misconfiguration from injecting arbitrary strings into failCounter/ipBans keys or event logs.
//	XFF is scanned right-to-left, skipping invalid segments until the first valid IP.
//
// trustProxyHeaders=false (direct public exposure):
//
//	Ignore headers entirely and use only r.RemoteAddr.
func clientIP(r *http.Request) string {
	if trustProxyHeaders {
		if xri := validIP(r.Header.Get("X-Real-IP")); xri != "" {
			return xri
		}
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			for i := len(parts) - 1; i >= 0; i-- {
				if ip := validIP(parts[i]); ip != "" {
					return ip
				}
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// validIP trims and validates with net.ParseIP. Valid input returns the normalized string; invalid
// input returns "". Callers use this to decide whether a header segment is trustworthy.
func validIP(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return ""
	}
	return ip.String()
}
