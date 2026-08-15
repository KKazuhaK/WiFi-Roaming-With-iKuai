package main

// store_ipban.go
// IP cooldowns, shared by every instance.
//
// This replaces a map behind a mutex. The map was correct for one process and
// silently wrong for two: an attacker cooled down on instance A was served
// normally by instance B on the very next request, because each held its own
// copy of a decision that is about the network, not about a process.
//
// The shape is a write-through cache rather than a query per request:
//
//   - isBanned is on the path of every portal hit, including the ones from
//     devices that are behaving. A database round trip there would put the
//     rate limiter in the way of the traffic it exists to protect.
//   - Bans are rare and expire on their own, so the working set is small and a
//     full refresh is cheap.
//   - A ban this instance issues is visible to it immediately, because the
//     write updates the cache too. A ban another instance issued becomes
//     visible within banCacheTTL. An attacker therefore gets at most a couple
//     of seconds of extra requests against the other instances, which is worth
//     the round trip saved on every legitimate one.
//
// The failure counters that decide when to ban are still per-process; see the
// note in ratelimit.go for what that means and why.

import (
	"log"
	"sort"
	"sync"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/kazuhahub/wifi-portal/internal/dbstore"
)

// banCacheTTL is how stale this instance's view of another instance's bans may
// be. Short enough that a ban propagates before an attacker can do much with the
// gap, long enough that a portal under load is not querying per request.
const banCacheTTL = 2 * time.Second

// maxCachedBans bounds a refresh. An attack from a large botnet could otherwise
// make each instance load an unbounded table into memory on a timer — which is
// the same denial of service the rate limiter is supposed to prevent, aimed at
// the portal instead of the login form.
const maxCachedBans = 50000

type ipBanList struct {
	db *dbstore.DB

	mu        sync.RWMutex
	cache     map[string]time.Time
	refreshed time.Time
	// truncated records that the last refresh hit the cap, so the log says so
	// once rather than on every request.
	truncated bool
}

func newIPBanList(db *dbstore.DB) *ipBanList {
	b := &ipBanList{db: db, cache: map[string]time.Time{}}
	b.refresh()
	return b
}

// refresh reloads the active bans.
func (b *ipBanList) refresh() {
	var rows []dbstore.IPBan
	// Ordered by expiry descending so that if the cap truncates, what survives
	// is the longest-lasting bans — the escalated ones an operator most wants
	// enforced.
	err := b.db.Where("until > ?", time.Now().UTC()).
		Order("until DESC").Limit(maxCachedBans).Find(&rows).Error
	if err != nil {
		// The previous cache is kept. Dropping every ban because one query
		// failed would turn a database hiccup into an open door.
		log.Printf("ip bans: refresh failed, serving the previous view: %v", err)
		return
	}

	next := make(map[string]time.Time, len(rows))
	for _, r := range rows {
		next[r.IP] = r.Until
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cache = next
	b.refreshed = time.Now()
	if len(rows) >= maxCachedBans {
		if !b.truncated {
			log.Printf("ip bans: more than %d active bans; only the longest-lasting are enforced in memory", maxCachedBans)
		}
		b.truncated = true
	} else {
		b.truncated = false
	}
}

// refreshIfStale reloads when the cached view has aged past banCacheTTL.
func (b *ipBanList) refreshIfStale() {
	b.mu.RLock()
	age := time.Since(b.refreshed)
	b.mu.RUnlock()
	if age > banCacheTTL {
		b.refresh()
	}
}

// ban puts an IP into cooldown for d, or extends an existing one.
func (b *ipBanList) ban(ip string, d time.Duration) {
	if ip == "" {
		return
	}
	until := time.Now().Add(d).UTC()
	err := b.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "ip"}},
		// GREATEST would be neater but PostgreSQL, MySQL and SQLite disagree on
		// its name and semantics; the comparison is done in the WHERE-less
		// assignment below by only ever moving the expiry forward.
		DoUpdates: clause.Assignments(map[string]any{
			"until":      gorm.Expr("CASE WHEN ip_ban.until > ? THEN ip_ban.until ELSE ? END", until, until),
			"updated_at": time.Now().UTC(),
		}),
	}).Create(&dbstore.IPBan{IP: ip, Until: until, UpdatedAt: time.Now().UTC()}).Error
	if err != nil {
		log.Printf("ip bans: recording a cooldown for %s failed: %v", ip, err)
		// Still cached locally: this instance enforces what it decided even if
		// the database refused it, which is strictly better than not banning.
	}

	b.mu.Lock()
	if prev, ok := b.cache[ip]; !ok || until.After(prev) {
		b.cache[ip] = until
	}
	b.mu.Unlock()
}

func (b *ipBanList) isBanned(ip string) bool {
	_, ok := b.expiryOf(ip)
	return ok
}

// expiryOf returns an IP's cooldown expiry. ok=false means it is not cooling
// down.
func (b *ipBanList) expiryOf(ip string) (time.Time, bool) {
	b.refreshIfStale()
	b.mu.RLock()
	exp, ok := b.cache[ip]
	b.mu.RUnlock()
	if !ok {
		return time.Time{}, false
	}
	if time.Now().After(exp) {
		// Expired since the last refresh. Dropped locally; the row is removed by
		// the sweep, not from a read path that may be running on ten instances
		// at once.
		b.mu.Lock()
		delete(b.cache, ip)
		b.mu.Unlock()
		return time.Time{}, false
	}
	return exp, true
}

// unban removes one cooldown and reports whether there was one.
func (b *ipBanList) unban(ip string) bool {
	res := b.db.Where("ip = ?", ip).Delete(&dbstore.IPBan{})
	if res.Error != nil {
		log.Printf("ip bans: unban %s failed: %v", ip, res.Error)
	}
	b.mu.Lock()
	_, cached := b.cache[ip]
	delete(b.cache, ip)
	b.mu.Unlock()
	return res.RowsAffected > 0 || cached
}

// unbanAll clears every cooldown, for the admin clear-all action.
func (b *ipBanList) unbanAll() int {
	var n int64
	if err := b.db.Model(&dbstore.IPBan{}).Where("until > ?", time.Now().UTC()).Count(&n).Error; err != nil {
		log.Printf("ip bans: counting before clear failed: %v", err)
	}
	if err := b.db.Where("1 = 1").Delete(&dbstore.IPBan{}).Error; err != nil {
		log.Printf("ip bans: clear failed: %v", err)
		return 0
	}
	b.mu.Lock()
	b.cache = map[string]time.Time{}
	b.refreshed = time.Now()
	b.mu.Unlock()
	return int(n)
}

// BanSnapshot is used by the admin panel.
type BanSnapshot struct {
	IP        string `json:"ip"`
	ExpiresAt int64  `json:"expires_unix"` // Ban expiry as Unix seconds.
}

// snapshot returns currently banned IPs, soonest expiry first.
//
// Read from the database rather than from the cache: this backs the admin page,
// where seeing every instance's bans is the whole point, and where being a
// couple of seconds stale would be visible as a ban that the operator just
// created not appearing.
func (b *ipBanList) snapshot() []BanSnapshot {
	var rows []dbstore.IPBan
	if err := b.db.Where("until > ?", time.Now().UTC()).
		Order("until ASC").Limit(maxCachedBans).Find(&rows).Error; err != nil {
		log.Printf("ip bans: snapshot failed: %v", err)
		return nil
	}
	out := make([]BanSnapshot, 0, len(rows))
	for _, r := range rows {
		out = append(out, BanSnapshot{IP: r.IP, ExpiresAt: r.Until.Unix()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ExpiresAt < out[j].ExpiresAt })
	return out
}

// gcLoop deletes expired rows and keeps this instance's view fresh.
func (b *ipBanList) gcLoop() {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for range t.C {
		if err := b.db.Where("until <= ?", time.Now().UTC()).Delete(&dbstore.IPBan{}).Error; err != nil {
			log.Printf("ip bans: sweeping expired cooldowns failed: %v", err)
		}
		b.refresh()
	}
}
