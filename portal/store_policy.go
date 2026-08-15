package main

// store_policy.go
// Database-backed iKuai allow-policy storage.
//
// Three rows, read on every successful authentication to decide the bandwidth
// and timeout written into the router's allow-list. Unlike the guest-code and
// denylist stores, this one keeps a cache — see the note on Get.

import (
	"errors"
	"fmt"
	"log"
	"sync/atomic"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/kazuhahub/wifi-portal/internal/dbstore"
)

type IKuaiPolicyStore struct {
	db       *dbstore.DB
	defaults map[IKuaiAuthProfile]IKuaiPolicy

	// cache holds the three policies, replaced wholesale on every write.
	//
	// This is the one store that keeps one, and the reasoning is specific: the
	// table has exactly three rows that change only when an administrator edits
	// them, while Get runs inside the redirect that puts a device on the network
	// — the most latency-sensitive moment in the whole flow, with a user staring
	// at a spinner. Staleness costs nothing here either: a second instance that
	// has not noticed a bandwidth change writes a slightly wrong rate limit for
	// one session, which is not comparable to admitting a banned device or
	// double-redeeming a single-use code.
	//
	// A multi-instance deployment refreshes on write locally and picks up another
	// instance's change on its next reload; Refresh exists for that.
	cache atomic.Pointer[map[IKuaiAuthProfile]IKuaiPolicy]
}

// newIKuaiPolicyStore loads the table, seeding any missing profile from the
// defaults so the admin page always renders three rows.
func newIKuaiPolicyStore(db *dbstore.DB, defaults map[IKuaiAuthProfile]IKuaiPolicy) (*IKuaiPolicyStore, error) {
	s := &IKuaiPolicyStore{db: db, defaults: defaults}
	if err := s.seedMissing(); err != nil {
		return nil, err
	}
	if err := s.Refresh(); err != nil {
		return nil, err
	}
	return s, nil
}

// seedMissing inserts any profile the table does not have yet, using the
// configured defaults. DO NOTHING means an existing row is never overwritten by
// a default, which matters on every restart after the first.
func (s *IKuaiPolicyStore) seedMissing() error {
	now := time.Now().UTC()
	rows := make([]dbstore.IKuaiPolicy, 0, len(allIKuaiProfiles))
	for _, profile := range allIKuaiProfiles {
		p := normalizeIKuaiPolicyForProfile(profile, s.defaults[profile])
		rows = append(rows, dbstore.IKuaiPolicy{
			Profile: string(profile), Upload: p.Upload, Download: p.Download,
			Timeout: p.Timeout, Comment: p.Comment, UpdatedAt: now,
		})
	}
	if err := s.db.Clauses(clause.OnConflict{DoNothing: true}).Create(&rows).Error; err != nil {
		return fmt.Errorf("iKuai policy: seeding defaults: %w", err)
	}
	return nil
}

// Refresh reloads the cache from the database.
func (s *IKuaiPolicyStore) Refresh() error {
	var rows []dbstore.IKuaiPolicy
	if err := s.db.Find(&rows).Error; err != nil {
		return fmt.Errorf("iKuai policy: load: %w", err)
	}
	next := make(map[IKuaiAuthProfile]IKuaiPolicy, len(rows))
	for _, r := range rows {
		next[IKuaiAuthProfile(r.Profile)] = IKuaiPolicy{
			Upload: r.Upload, Download: r.Download, Timeout: r.Timeout, Comment: r.Comment,
		}
	}
	s.cache.Store(&next)
	return nil
}

// Get returns the policy for a profile, falling back to the configured default
// for a profile that is somehow absent.
func (s *IKuaiPolicyStore) Get(profile IKuaiAuthProfile) IKuaiPolicy {
	if c := s.cache.Load(); c != nil {
		if p, ok := (*c)[profile]; ok {
			return p
		}
	}
	return s.defaults[profile]
}

// Set validates and stores one profile's policy.
func (s *IKuaiPolicyStore) Set(profile IKuaiAuthProfile, p IKuaiPolicy) error {
	if _, ok := parseIKuaiProfile(string(profile)); !ok {
		return fmt.Errorf("invalid_profile")
	}
	if err := validateIKuaiPolicy(p); err != nil {
		return err
	}
	p = normalizeIKuaiPolicyForProfile(profile, p)
	row := dbstore.IKuaiPolicy{
		Profile: string(profile), Upload: p.Upload, Download: p.Download,
		Timeout: p.Timeout, Comment: p.Comment, UpdatedAt: time.Now().UTC(),
	}
	err := s.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "profile"}},
		DoUpdates: clause.AssignmentColumns([]string{"upload", "download", "timeout", "comment", "updated_at"}),
	}).Create(&row).Error
	if err != nil {
		return fmt.Errorf("iKuai policy: save %s: %w", profile, err)
	}
	// Refresh rather than patching the cached map in place: the map behind the
	// atomic pointer is shared with in-flight readers and must never be mutated.
	if err := s.Refresh(); err != nil {
		log.Printf("iKuai policy: saved but cache reload failed, this instance keeps the previous values until restart: %v", err)
	}
	return nil
}

// List returns the three profiles in a fixed order for the admin table. The
// order is fixed rather than database-defined so the rows do not reshuffle
// between page loads.
func (s *IKuaiPolicyStore) List() []IKuaiPolicyRow {
	out := make([]IKuaiPolicyRow, 0, len(allIKuaiProfiles))
	for _, profile := range allIKuaiProfiles {
		p := s.Get(profile)
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

// --- ban history ---

// banHistory counts how many cooldowns each IP has accumulated, which drives
// permanent escalation.
//
// The file-backed version batched writes through a dirty flag and a 30-second
// flusher, on the reasoning that losing half a minute of escalation history
// during an attack was cheaper than a file write per offence. That trade does
// not survive multiple instances — a counter split across two processes reaches
// the escalation threshold at twice the intended attempt count, or never — so
// increments are now a single atomic UPSERT. It is one indexed write on a path
// that only runs when an IP has already failed enough times to be cooled down,
// which is rare by construction.
type banHistory struct {
	db *dbstore.DB
}

func newBanHistory(db *dbstore.DB) *banHistory {
	return &banHistory{db: db}
}

// increment records one cooldown and returns the IP's new total, starting at 1.
func (b *banHistory) increment(ip string) int {
	if ip == "" {
		return 0
	}
	now := time.Now().UTC()
	// An atomic read-modify-write in one statement. Doing it as SELECT then
	// UPDATE would let two instances cooling down the same attacker each read 3
	// and each write 4.
	err := b.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "ip"}},
		DoUpdates: clause.Assignments(map[string]any{
			"count":      gorm.Expr("ban_history.count + 1"),
			"updated_at": now,
		}),
	}).Create(&dbstore.BanHistory{IP: ip, Count: 1, UpdatedAt: now}).Error
	if err != nil {
		log.Printf("ban history: increment %q failed: %v", ip, err)
		return 0
	}
	return b.get(ip)
}

// get returns how many times an IP has been cooled down; 0 means never.
func (b *banHistory) get(ip string) int {
	if ip == "" {
		return 0
	}
	var row dbstore.BanHistory
	if err := b.db.Where("ip = ?", ip).First(&row).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			log.Printf("ban history: get %q failed: %v", ip, err)
		}
		return 0
	}
	return row.Count
}

// reset returns one IP to first-offence status.
func (b *banHistory) reset(ip string) {
	if ip == "" {
		return
	}
	if err := b.db.Where("ip = ?", ip).Delete(&dbstore.BanHistory{}).Error; err != nil {
		log.Printf("ban history: reset %q failed: %v", ip, err)
	}
}

// resetAll clears every counter and reports how many rows went.
func (b *banHistory) resetAll() int {
	res := b.db.Where("1 = 1").Delete(&dbstore.BanHistory{})
	if res.Error != nil {
		log.Printf("ban history: reset-all failed: %v", res.Error)
		return 0
	}
	return int(res.RowsAffected)
}

// snapshot returns {ip: count} for the admin rate-limit page.
func (b *banHistory) snapshot() map[string]int {
	var rows []dbstore.BanHistory
	if err := b.db.Find(&rows).Error; err != nil {
		log.Printf("ban history: snapshot failed: %v", err)
		return map[string]int{}
	}
	out := make(map[string]int, len(rows))
	for _, r := range rows {
		out[r.IP] = r.Count
	}
	return out
}

// shutdown exists so the caller's lifecycle code did not have to change. There
// is nothing left to flush — every increment is already durable — but keeping
// the call makes the removal of the flusher goroutine explicit rather than a
// silently dropped step.
func (b *banHistory) shutdown() error { return nil }
