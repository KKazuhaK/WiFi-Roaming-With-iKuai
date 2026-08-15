package main

// store_denylist.go
// Database-backed MAC denylist.
//
// Same method set as the file-backed store it replaces. The reason for the move
// is the same as for guest codes — two instances each holding their own map
// means a device banned on one is still admitted by the other — but the risk
// profile is different: this is a security control, so a stale copy does not
// merely inconvenience an operator, it silently readmits a device they banned.
//
// IsMACDenied runs on the portal's hot path, once per captive-portal hit. It is
// a primary-key lookup on a table that holds tens to hundreds of rows, which
// every supported backend answers from cache. Adding a local cache in front of
// it would reintroduce exactly the staleness this change removes.

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/kazuhahub/wifi-portal/internal/dbstore"
)

// DeniedMAC is the domain record. Retained here rather than using the dbstore
// row directly so the admin API's JSON shape does not follow the schema around.
type DeniedMAC struct {
	MAC       string    `json:"mac"`
	Reason    string    `json:"reason,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by,omitempty"`
}

type DenylistStore struct {
	db *dbstore.DB
}

func newDenylistStore(db *dbstore.DB) *DenylistStore {
	return &DenylistStore{db: db}
}

func toDomainMAC(r dbstore.DeniedMAC) DeniedMAC {
	return DeniedMAC{MAC: r.MAC, Reason: r.Reason, CreatedAt: r.CreatedAt, CreatedBy: r.CreatedBy}
}

// IsMACDenied reports whether a device is blocked.
//
// A database error is treated as "not denied", deliberately. The alternative is
// failing closed, which during a database blip would lock every guest off the
// network — including the administrator trying to reach the console to fix it.
// The denylist is an operational block on known-bad devices, not the mechanism
// keeping unauthenticated users out; that is SSO, and it does not depend on this
// table. The error is logged so the outage is visible.
func (s *DenylistStore) IsMACDenied(mac string) (DeniedMAC, bool) {
	norm := normalizeMAC(mac)
	if norm == "" {
		return DeniedMAC{}, false
	}
	var row dbstore.DeniedMAC
	if err := s.db.Where("mac = ?", norm).First(&row).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			log.Printf("denylist: lookup %q failed, treating the device as allowed: %v", norm, err)
		}
		return DeniedMAC{}, false
	}
	return toDomainMAC(row), true
}

// AddMAC bans a device. The bool reports whether this call created the entry, so
// the admin UI can distinguish "banned" from "already banned".
func (s *DenylistStore) AddMAC(mac, reason, createdBy string) (DeniedMAC, bool, error) {
	norm := normalizeMAC(mac)
	if !isNormalizedMAC(norm) {
		return DeniedMAC{}, false, fmt.Errorf("invalid_mac")
	}
	row := dbstore.DeniedMAC{
		MAC:       norm,
		Reason:    strings.TrimSpace(reason),
		CreatedAt: time.Now().UTC(),
		CreatedBy: strings.TrimSpace(createdBy),
	}
	res := s.db.Clauses(clause.OnConflict{DoNothing: true}).Create(&row)
	if res.Error != nil {
		return DeniedMAC{}, false, res.Error
	}
	if res.RowsAffected > 0 {
		return toDomainMAC(row), true, nil
	}
	// Already present: return the existing record, whose reason and author are
	// what the operator should see rather than the ones just submitted.
	var existing dbstore.DeniedMAC
	if err := s.db.Where("mac = ?", norm).First(&existing).Error; err != nil {
		return DeniedMAC{}, false, err
	}
	return toDomainMAC(existing), false, nil
}

// MACInput is one row of a bulk import.
type MACInput struct {
	MAC       string
	Reason    string
	CreatedBy string
}

// AddMACMany imports a batch, returning how many were added and how many were
// skipped as invalid or already present.
//
// One statement per row inside a transaction, for the same reason AddMany uses
// it for guest codes: the caller reports exact added/skipped counts back to the
// operator who uploaded the CSV, and a multi-row insert only yields a total.
func (s *DenylistStore) AddMACMany(items []MACInput) (added, skipped int) {
	now := time.Now().UTC()
	err := s.db.Transaction(func(tx *gorm.DB) error {
		for _, in := range items {
			norm := normalizeMAC(in.MAC)
			if !isNormalizedMAC(norm) {
				skipped++
				continue
			}
			row := dbstore.DeniedMAC{
				MAC:       norm,
				Reason:    strings.TrimSpace(in.Reason),
				CreatedAt: now,
				CreatedBy: strings.TrimSpace(in.CreatedBy),
			}
			res := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&row)
			if res.Error != nil {
				return res.Error
			}
			if res.RowsAffected > 0 {
				added++
			} else {
				skipped++
			}
		}
		return nil
	})
	if err != nil {
		log.Printf("denylist: bulk import failed after %d row(s): %v", added, err)
		// The transaction rolled back, so nothing was written.
		return 0, len(items)
	}
	return added, skipped
}

func (s *DenylistStore) DeleteMAC(mac string) bool {
	norm := normalizeMAC(mac)
	if norm == "" {
		return false
	}
	res := s.db.Where("mac = ?", norm).Delete(&dbstore.DeniedMAC{})
	if res.Error != nil {
		log.Printf("denylist: delete %q failed: %v", norm, res.Error)
		return false
	}
	return res.RowsAffected > 0
}

func (s *DenylistStore) DeleteAllMACs() int {
	// A bare Delete with no condition is refused by GORM's block-global-update
	// guard, which is a good default; the "1 = 1" is the explicit opt-in for the
	// one place that genuinely means every row.
	res := s.db.Where("1 = 1").Delete(&dbstore.DeniedMAC{})
	if res.Error != nil {
		log.Printf("denylist: clear failed: %v", res.Error)
		return 0
	}
	return int(res.RowsAffected)
}

// ListMACs returns the denylist, newest ban first.
//
// Still whole-table, and deliberately: the CSV export has to be complete, and
// the denylist is bounded by how many devices an operator has banned by hand.
// The admin table uses PageMACs instead.
func (s *DenylistStore) ListMACs() []DeniedMAC {
	var rows []dbstore.DeniedMAC
	if err := s.db.Order("created_at DESC, mac ASC").Find(&rows).Error; err != nil {
		log.Printf("denylist: list failed: %v", err)
		return nil
	}
	out := make([]DeniedMAC, 0, len(rows))
	for _, r := range rows {
		out = append(out, toDomainMAC(r))
	}
	return out
}

// PageMACs returns one page of the denylist plus the total matching the search.
func (s *DenylistStore) PageMACs(search string, offset, limit int) ([]DeniedMAC, int) {
	apply := func(q *gorm.DB) *gorm.DB {
		if s := strings.TrimSpace(search); s != "" {
			like := "%" + strings.ToLower(s) + "%"
			q = q.Where("mac LIKE ? OR LOWER(reason) LIKE ? OR LOWER(created_by) LIKE ?", like, like, like)
		}
		return q
	}

	var n int64
	if err := apply(s.db.Model(&dbstore.DeniedMAC{})).Count(&n).Error; err != nil {
		log.Printf("denylist: count failed: %v", err)
		return nil, 0
	}
	q := apply(s.db.Model(&dbstore.DeniedMAC{})).Order("created_at DESC, mac ASC")
	if limit > 0 {
		q = q.Limit(limit)
	}
	if offset > 0 {
		q = q.Offset(offset)
	}
	var rows []dbstore.DeniedMAC
	if err := q.Find(&rows).Error; err != nil {
		log.Printf("denylist: page failed: %v", err)
		return nil, int(n)
	}
	out := make([]DeniedMAC, 0, len(rows))
	for _, r := range rows {
		out = append(out, toDomainMAC(r))
	}
	return out, int(n)
}

// CountMACs is the dashboard's banned-device counter, without loading the rows.
func (s *DenylistStore) CountMACs() int {
	var n int64
	if err := s.db.Model(&dbstore.DeniedMAC{}).Count(&n).Error; err != nil {
		log.Printf("denylist: count failed: %v", err)
		return 0
	}
	return int(n)
}
