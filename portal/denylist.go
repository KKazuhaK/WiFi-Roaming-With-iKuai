package main

// denylist.go
// Admin-maintained device denylist. It currently blocks MACs, not UPNs:
//   - SSO handles user identity security.
//   - The MAC denylist handles device-level operational blocks.
//   - IPs are only used for short cooldowns, not long-term identity.

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type DeniedMAC struct {
	MAC       string    `json:"mac"`
	Reason    string    `json:"reason,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by,omitempty"`
}

type denylistDisk struct {
	MACs map[string]DeniedMAC `json:"macs"`
}

type DenylistStore struct {
	mu          sync.RWMutex
	macs        map[string]DeniedMAC
	persistPath string
}

func newDenylistStore(persistPath string) (*DenylistStore, error) {
	s := &DenylistStore{
		macs:        make(map[string]DeniedMAC),
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

func (s *DenylistStore) loadFromDisk() error {
	data, err := os.ReadFile(s.persistPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read %s: %w", s.persistPath, err)
	}
	if len(data) == 0 {
		return nil
	}
	var disk denylistDisk
	if err := json.Unmarshal(data, &disk); err != nil {
		return fmt.Errorf("parse %s: %w", s.persistPath, err)
	}
	for mac, item := range disk.MACs {
		norm := normalizeMAC(mac)
		if norm == "" {
			continue
		}
		item.MAC = norm
		s.macs[norm] = item
	}
	log.Printf("MAC denylist: loaded %d entries from %s", len(s.macs), s.persistPath)
	return nil
}

func (s *DenylistStore) IsMACDenied(mac string) (DeniedMAC, bool) {
	norm := normalizeMAC(mac)
	s.mu.RLock()
	defer s.mu.RUnlock()
	item, ok := s.macs[norm]
	return item, ok
}

func (s *DenylistStore) AddMAC(mac, reason, createdBy string) (DeniedMAC, bool, error) {
	norm := normalizeMAC(mac)
	if !isNormalizedMAC(norm) {
		return DeniedMAC{}, false, fmt.Errorf("invalid_mac")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if item, ok := s.macs[norm]; ok {
		return item, false, nil
	}
	item := DeniedMAC{
		MAC:       norm,
		Reason:    strings.TrimSpace(reason),
		CreatedAt: time.Now(),
		CreatedBy: strings.TrimSpace(createdBy),
	}
	s.macs[norm] = item
	s.saveLocked()
	return item, true, nil
}

// MACInput is a batch input item for AddMACMany.
type MACInput struct {
	MAC       string
	Reason    string
	CreatedBy string
}

// AddMACMany inserts a batch under one lock and writes once. It returns added and skipped counts.
// It is used by handleDenylistImportCSV to avoid one saveLocked call per CSV row.
// Invalid MACs are skipped without error; the handler reports skipped counts to the user.
func (s *DenylistStore) AddMACMany(items []MACInput) (added, skipped int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for _, in := range items {
		norm := normalizeMAC(in.MAC)
		if !isNormalizedMAC(norm) {
			skipped++
			continue
		}
		if _, ok := s.macs[norm]; ok {
			skipped++
			continue
		}
		s.macs[norm] = DeniedMAC{
			MAC:       norm,
			Reason:    strings.TrimSpace(in.Reason),
			CreatedAt: now,
			CreatedBy: strings.TrimSpace(in.CreatedBy),
		}
		added++
	}
	if added > 0 {
		s.saveLocked()
	}
	return added, skipped
}

func (s *DenylistStore) DeleteMAC(mac string) bool {
	norm := normalizeMAC(mac)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.macs[norm]; !ok {
		return false
	}
	delete(s.macs, norm)
	s.saveLocked()
	return true
}

// DeleteAllMACs clears the entire MAC denylist and returns the number removed.
// It is used by the admin "clear all" action and does not touch rate-limit state.
func (s *DenylistStore) DeleteAllMACs() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.macs)
	if n == 0 {
		return 0
	}
	s.macs = make(map[string]DeniedMAC)
	s.saveLocked()
	return n
}

func (s *DenylistStore) ListMACs() []DeniedMAC {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]DeniedMAC, 0, len(s.macs))
	for _, item := range s.macs {
		out = append(out, item)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].MAC < out[j].MAC
	})
	return out
}

func (s *DenylistStore) saveLocked() {
	if s.persistPath == "" {
		return
	}
	disk := denylistDisk{MACs: s.macs}
	data, err := json.MarshalIndent(disk, "", "  ")
	if err != nil {
		log.Printf("MAC denylist: marshal failed: %v", err)
		return
	}
	dir := filepath.Dir(s.persistPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		log.Printf("MAC denylist: mkdir %s failed: %v", dir, err)
		return
	}
	tmp := s.persistPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		log.Printf("MAC denylist: write %s failed: %v", tmp, err)
		return
	}
	if err := os.Rename(tmp, s.persistPath); err != nil {
		log.Printf("MAC denylist: rename %s -> %s failed: %v", tmp, s.persistPath, err)
	}
}

func isNormalizedMAC(mac string) bool {
	if len(mac) != 17 {
		return false
	}
	for i, c := range mac {
		if i%3 == 2 {
			if c != ':' {
				return false
			}
			continue
		}
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
