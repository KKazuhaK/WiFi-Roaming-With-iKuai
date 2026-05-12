package main

// admin.go
// Guest code admin backend: data model, in-memory storage, optional JSON persistence, and random generation.
//
// Persistence: when newGuestCodeStore(path) receives a non-empty path, startup loads from disk and
// every mutation writes atomically (tmp + rename). An empty path means memory only, so data is lost on restart.
// Mount the directory containing path with a docker-compose volume to keep codes across container restarts.

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

// GuestCodeType is the selectable character set for batch generation.
type GuestCodeType string

const (
	CodeNumeric      GuestCodeType = "numeric"
	CodeAlpha        GuestCodeType = "alpha"
	CodeAlphaNumeric GuestCodeType = "alphanumeric"
)

// GuestCode is a single guest-code record.
// Design notes:
//   - ExpiresAt is an absolute expiration time. Zero means never expires.
//   - DurationMin is the iKuai allow-list duration after each successful use. 0 means unlimited.
//   - MaxUses limits how many successful uses the same code allows. 0 means unlimited.
//   - Note is an admin note and is only shown in the admin UI.
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
	GuestUPN string    `json:"guest_upn"` // e.g. Guest-abc12345
}

func (c *GuestCode) IsExpired() bool {
	if c.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(c.ExpiresAt)
}

// IsExhausted reports whether MaxUses has been reached (MaxUses=0 means unlimited).
func (c *GuestCode) IsExhausted() bool {
	return c.MaxUses > 0 && len(c.Uses) >= c.MaxUses
}

func (c *GuestCode) UseCount() int {
	return len(c.Uses)
}

// Status is used by the UI tabs. Any code used at least once is "used"; exhausted vs partially
// used is handled by IsActive. This keeps the existing admin.html tabs unchanged.
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

// IsActive reports whether the code can still be used now: not expired and not exhausted.
// This is distinct from Status: Status is for UI grouping, while IsActive drives business
// decisions such as DeleteInactive. C3 depends on partially used multi-use codes staying active.
func (c *GuestCode) IsActive() bool {
	return !c.IsExpired() && !c.IsExhausted()
}

// GuestCodeStore is a concurrency-safe in-memory store with optional disk persistence.
// An empty persistPath disables disk writes.
type GuestCodeStore struct {
	mu          sync.RWMutex
	codes       map[string]*GuestCode // key = strings.ToLower(Code)
	persistPath string
}

// newGuestCodeStore uses memory only when persistPath is empty; otherwise it loads from disk
// and returns any startup error instead of silently overwriting data.
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

// loadFromDisk is called once at startup and does not take the store lock.
func (s *GuestCodeStore) loadFromDisk() error {
	data, err := os.ReadFile(s.persistPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // First startup; the file does not exist yet.
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

// saveLocked must be called with the write lock held. It writes atomically (tmp -> rename).
// Failures are logged without rolling back memory state; the next mutation will retry the write,
// and this change is only lost if the process restarts first.
//
// Note: M12 was evaluated and intentionally left unchanged. Async writes risk goroutine
// scheduling reordering (a later write can hit disk first and lose data), while splitting locks
// is a larger change. Typical size (<1000 codes, ~150KB JSON) holds the lock for ~5ms, which is
// negligible next to the 100ms+ iKuai webauth call in handleGuestCode. Revisit for 10k+ code sets.
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

// List returns a deep copy sorted by CreatedAt descending; callers can read or modify it without
// affecting the store. Equal timestamps fall back to Code order for stable refreshes.
//
// Important: Validate appends to c.Uses while holding the lock. If List returned internal pointers,
// renderAdmin/buildDashboard would read c.Uses outside the lock and race with Validate. Deep copying
// the table is acceptable because List is normally used for admin rendering, not the hot path.
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

// copyGuestCode deep-copies a GuestCode, including the Uses slice. Uses elements are values, so copy is enough.
func copyGuestCode(c *GuestCode) *GuestCode {
	dup := *c
	if len(c.Uses) > 0 {
		dup.Uses = make([]CodeUse, len(c.Uses))
		copy(dup.Uses, c.Uses)
	}
	return &dup
}

// Add returns false for duplicate codes and never overwrites.
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

// AddMany inserts a batch under one lock and writes once. It returns inserted codes in input order,
// skipping empty and duplicate codes. This supports handleCodeBatch and avoids one saveLocked call
// per generated code, which would cause O(N^2) file writes.
//
// Callers often need to know which codes actually entered the store. Return []string instead of a
// count because skipped inputs may appear in the middle, not just at the end.
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

// DeleteMany deletes a batch under one lock and writes once. It returns the actual number removed;
// empty or missing codes are skipped. Like AddMany, this avoids O(N^2) writes.
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

// Edit updates mutable code metadata: expiration, duration, MaxUses, and note. Code itself cannot
// change because that is equivalent to delete-and-recreate. Missing codes return false. Used codes
// can still be edited; DurationMin only affects future allow-list entries, not already-online devices.
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

// DeleteInactive removes codes that can no longer be used: expired or exhausted.
// Partially used multi-use codes are retained because they are still useful admin assets.
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

// Validate records one use when a code exists, is not expired, and has not reached MaxUses.
// guestUPN is the user_id reported to iKuai and differs per connection. It returns a copy instead
// of an internal pointer so callers cannot race on Uses outside the lock.
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

// Stats computes UI and dashboard counters:
//
//	total   — all codes
//	used    — exhausted (IsExhausted) and not expired
//	unused  — still usable (IsActive), including never-used and partially used multi-use codes
//	expired — expired, regardless of use count
//
// M1 fix: the old implementation grouped by Status() and counted partially used multi-use codes
// as used, which disagreed with buildDashboard.ActiveGuestCodes. Stats.unused now matches the
// dashboard active count exactly.
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

// --- Random code generation ---

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
