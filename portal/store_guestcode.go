package main

// store_guestcode.go
// Database-backed guest-code storage.
//
// The method set is unchanged from the file-backed store it replaces, so no
// caller had to be touched. What changed is where the data lives and, more
// importantly, how concurrency is handled.
//
// The file-backed store kept every code in a map behind a RWMutex and rewrote
// the whole JSON file on each mutation. That is correct for exactly one process.
// Running two — which is the point of supporting an external database — breaks
// it silently in the worst possible way: each instance holds its own map, so a
// single-use code redeemed on instance A is still unused on instance B, and the
// same code lets two devices onto the network. The lock protected memory that
// was never the shared resource.
//
// So reads go to the database rather than to a cache. Redemption in particular
// runs as one transaction with a row lock, which is the only construct that
// makes "check the code is usable and record the use" atomic across processes.
// The tables are small (hundreds of codes) and the queries are indexed, so the
// cost is a local round trip on a path that already talks to an OIDC provider
// and a router.

import (
	"errors"
	"fmt"
	"log"
	"sort"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/kazuhahub/wifi-portal/internal/dbstore"
)

// GuestCodeStore is the database-backed store.
type GuestCodeStore struct {
	db *dbstore.DB
}

func newGuestCodeStore(db *dbstore.DB) *GuestCodeStore {
	return &GuestCodeStore{db: db}
}

// normalizeCode delegates to the storage layer's definition, so the value this
// package queries by is by construction the one BeforeSave wrote.
func normalizeCode(code string) string { return dbstore.NormalizeCode(code) }

// rowLock returns the clause that makes a read-then-write atomic against other
// instances, or nothing on SQLite.
//
// SQLite has no SELECT ... FOR UPDATE, and does not need one: the pool is pinned
// to a single connection and its write transactions are serialised, so a
// transaction that reads and then writes cannot interleave with another. Sending
// the clause anyway would be a syntax error.
func (s *GuestCodeStore) rowLock() []clause.Expression {
	if s.db.Driver == dbstore.DriverSQLite {
		return nil
	}
	return []clause.Expression{clause.Locking{Strength: "UPDATE"}}
}

// toDomain converts a row plus its uses into the domain type the handlers and
// the admin API already speak.
func toDomainCode(row dbstore.GuestCode, uses []dbstore.GuestCodeUse) *GuestCode {
	c := &GuestCode{
		Code:        row.Code,
		CreatedAt:   row.CreatedAt,
		DurationMin: row.DurationMin,
		MaxUses:     row.MaxUses,
		Note:        row.Note,
	}
	if row.ExpiresAt != nil {
		c.ExpiresAt = *row.ExpiresAt
	}
	for _, u := range uses {
		c.Uses = append(c.Uses, CodeUse{At: u.At, MAC: u.MAC, IP: u.IP, GuestUPN: u.GuestUPN})
	}
	return c
}

// List returns every code, newest first, with its redemption history.
//
// Two queries rather than a join: a join multiplies each code by its use count
// and then has to be de-duplicated in Go, which for a code redeemed a thousand
// times means a thousand copies of its note crossing the wire.
func (s *GuestCodeStore) List() []*GuestCode {
	var rows []dbstore.GuestCode
	if err := s.db.Order("created_at DESC, code ASC").Find(&rows).Error; err != nil {
		// Returning an empty list rather than propagating: every caller renders
		// a table, and an admin page that shows nothing plus a logged error is
		// more useful than one that fails to render at all.
		log.Printf("guest codes: list failed: %v", err)
		return nil
	}
	if len(rows) == 0 {
		return nil
	}

	var uses []dbstore.GuestCodeUse
	if err := s.db.Order("at ASC").Find(&uses).Error; err != nil {
		log.Printf("guest codes: loading redemption history failed, codes shown without it: %v", err)
	}
	byCode := make(map[string][]dbstore.GuestCodeUse, len(rows))
	for _, u := range uses {
		byCode[u.Code] = append(byCode[u.Code], u)
	}

	out := make([]*GuestCode, 0, len(rows))
	for _, r := range rows {
		out = append(out, toDomainCode(r, byCode[r.Code]))
	}
	// The database ordering is authoritative, but timestamps imported from the
	// old JSON files can collide to the second; sort again so the order is
	// stable across page loads rather than whatever the engine returns.
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].Code < out[j].Code
	})
	return out
}

// Get returns one code with its uses, or nil.
func (s *GuestCodeStore) Get(code string) *GuestCode {
	k := normalizeCode(code)
	if k == "" {
		return nil
	}
	var row dbstore.GuestCode
	if err := s.db.Where("code_lower = ?", k).First(&row).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			log.Printf("guest codes: get %q failed: %v", k, err)
		}
		return nil
	}
	var uses []dbstore.GuestCodeUse
	s.db.Where("code = ?", row.Code).Order("at ASC").Find(&uses)
	return toDomainCode(row, uses)
}

func toRow(c *GuestCode) dbstore.GuestCode {
	row := dbstore.GuestCode{
		Code:        c.Code,
		CodeLower:   normalizeCode(c.Code),
		CreatedAt:   c.CreatedAt.UTC(),
		DurationMin: c.DurationMin,
		MaxUses:     c.MaxUses,
		Note:        c.Note,
	}
	if !c.ExpiresAt.IsZero() {
		t := c.ExpiresAt.UTC()
		row.ExpiresAt = &t
	}
	return row
}

// Add inserts a code, returning false if one with that spelling already exists.
//
// The duplicate check is the unique index on code_lower, not a prior SELECT.
// Two instances generating codes concurrently would both pass a SELECT and one
// would then overwrite the other; letting the constraint decide makes the race
// impossible rather than merely unlikely. DO NOTHING turns a collision into a
// zero-row insert, which is what RowsAffected reports on all three backends.
func (s *GuestCodeStore) Add(c *GuestCode) bool {
	if normalizeCode(c.Code) == "" {
		return false
	}
	var inserted bool
	err := s.db.Transaction(func(tx *gorm.DB) error {
		var err error
		inserted, err = insertCode(tx, c)
		return err
	})
	if err != nil {
		log.Printf("guest codes: add %q failed: %v", c.Code, err)
		return false
	}
	return inserted
}

// insertCode writes one code and any redemption history it arrives with.
//
// Carrying the uses matters even though the handlers always create fresh codes:
// GuestCode has a Uses field, so an insert that quietly ignored it would be a
// silent data loss waiting for the first caller that populates it — the legacy
// importer being the obvious candidate.
func insertCode(tx *gorm.DB, c *GuestCode) (bool, error) {
	row := toRow(c)
	res := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&row)
	if res.Error != nil {
		return false, res.Error
	}
	if res.RowsAffected == 0 {
		return false, nil // A code with this spelling already exists.
	}
	if len(c.Uses) == 0 {
		return true, nil
	}
	uses := make([]dbstore.GuestCodeUse, 0, len(c.Uses))
	for _, u := range c.Uses {
		uses = append(uses, dbstore.GuestCodeUse{
			Code: row.Code, At: u.At.UTC(), MAC: u.MAC, IP: u.IP, GuestUPN: u.GuestUPN,
		})
	}
	if err := tx.Create(&uses).Error; err != nil {
		return false, err
	}
	return true, nil
}

// AddMany inserts a batch and returns the codes that actually landed, in the
// order they were offered.
//
// One statement per code inside a single transaction, rather than a multi-row
// insert. A multi-row insert reports only a total, and the caller needs the
// list: it shows the generated codes to an administrator exactly once, and a
// code that collided with an existing one must not appear there — they would
// print it and hand out something that already belongs to someone else. The
// handler caps batches at 200, so the statement count is bounded.
func (s *GuestCodeStore) AddMany(codes []*GuestCode) []string {
	added := make([]string, 0, len(codes))
	seen := make(map[string]bool, len(codes))

	err := s.db.Transaction(func(tx *gorm.DB) error {
		for _, c := range codes {
			k := normalizeCode(c.Code)
			// De-duplicate within the batch too: the same key offered twice
			// would otherwise collide with itself.
			if k == "" || seen[k] {
				continue
			}
			seen[k] = true
			ok, err := insertCode(tx, c)
			if err != nil {
				return err
			}
			if ok {
				added = append(added, c.Code)
			}
		}
		return nil
	})
	if err != nil {
		log.Printf("guest codes: batch insert failed: %v", err)
		return nil
	}
	return added
}

func (s *GuestCodeStore) Delete(code string) bool {
	k := normalizeCode(code)
	if k == "" {
		return false
	}
	res := s.db.Where("code_lower = ?", k).Delete(&dbstore.GuestCode{})
	if res.Error != nil {
		log.Printf("guest codes: delete %q failed: %v", k, res.Error)
		return false
	}
	return res.RowsAffected > 0
}

// DeleteMany removes a batch in one statement and returns how many rows went.
func (s *GuestCodeStore) DeleteMany(codes []string) int {
	keys := make([]string, 0, len(codes))
	for _, c := range codes {
		if k := normalizeCode(c); k != "" {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return 0
	}
	res := s.db.Where("code_lower IN ?", keys).Delete(&dbstore.GuestCode{})
	if res.Error != nil {
		log.Printf("guest codes: bulk delete failed: %v", res.Error)
		return 0
	}
	return int(res.RowsAffected)
}

// Edit updates the mutable metadata. The code itself cannot change, because that
// is delete-and-recreate and would orphan the redemption history.
func (s *GuestCodeStore) Edit(code string, expiresAt time.Time, durationMin, maxUses int, note string) bool {
	k := normalizeCode(code)
	if k == "" {
		return false
	}
	updates := map[string]any{
		"duration_min": durationMin,
		"max_uses":     maxUses,
		"note":         note,
		// Explicitly nullable: clearing the expiry is how an admin makes a code
		// permanent, and a zero time would be stored as year 1 and read back as
		// "expired long ago".
		"expires_at": nil,
	}
	if !expiresAt.IsZero() {
		updates["expires_at"] = expiresAt.UTC()
	}
	res := s.db.Model(&dbstore.GuestCode{}).Where("code_lower = ?", k).Updates(updates)
	if res.Error != nil {
		log.Printf("guest codes: edit %q failed: %v", k, res.Error)
		return false
	}
	return res.RowsAffected > 0
}

// DeleteInactive removes codes that can no longer be used: expired, or with
// every permitted use consumed. Partially used multi-use codes stay, because
// they are still handed out.
//
// Expressed as SQL rather than by listing and filtering in Go: the exhaustion
// test needs a count of child rows, and doing that per code would be one query
// per code on the one operation an admin runs when the table is large.
func (s *GuestCodeStore) DeleteInactive() int {
	now := time.Now().UTC()
	const exhausted = `max_uses > 0 AND max_uses <= (
		SELECT COUNT(*) FROM guest_code_use WHERE guest_code_use.code = guest_code.code
	)`
	res := s.db.Where("(expires_at IS NOT NULL AND expires_at < ?) OR ("+exhausted+")", now).
		Delete(&dbstore.GuestCode{})
	if res.Error != nil {
		log.Printf("guest codes: delete-inactive failed: %v", res.Error)
		return 0
	}
	return int(res.RowsAffected)
}

// DeleteExpired is retained for older call sites; the admin action means
// "inactive", which is expired or exhausted.
func (s *GuestCodeStore) DeleteExpired() int { return s.DeleteInactive() }

// Validate redeems a code: it records one use if the code exists, has not
// expired and has uses left, and returns the resulting record.
//
// This is the one operation where correctness depends on the transaction. Read
// the code, count its uses, and insert — all under a row lock, so two devices
// racing on the last use of a single-use code cannot both win. The file-backed
// store's mutex gave this guarantee within one process and nothing across two,
// which is precisely the bug that would appear the day someone ran a second
// instance for redundancy.
func (s *GuestCodeStore) Validate(code, mac, ip, guestUPN string) *GuestCode {
	k := normalizeCode(code)
	if k == "" {
		return nil
	}

	var result *GuestCode
	err := s.db.Transaction(func(tx *gorm.DB) error {
		var row dbstore.GuestCode
		if err := tx.Clauses(s.rowLock()...).Where("code_lower = ?", k).First(&row).Error; err != nil {
			return err // Includes ErrRecordNotFound for an unknown code.
		}
		if row.ExpiresAt != nil && time.Now().After(*row.ExpiresAt) {
			return errCodeUnusable
		}
		var used int64
		if err := tx.Model(&dbstore.GuestCodeUse{}).Where("code = ?", row.Code).Count(&used).Error; err != nil {
			return err
		}
		if row.MaxUses > 0 && used >= int64(row.MaxUses) {
			return errCodeUnusable
		}
		use := dbstore.GuestCodeUse{
			Code: row.Code, At: time.Now().UTC(), MAC: mac, IP: ip, GuestUPN: guestUPN,
		}
		if err := tx.Create(&use).Error; err != nil {
			return err
		}
		var uses []dbstore.GuestCodeUse
		if err := tx.Where("code = ?", row.Code).Order("at ASC").Find(&uses).Error; err != nil {
			return err
		}
		result = toDomainCode(row, uses)
		return nil
	})
	if err != nil {
		if !errors.Is(err, errCodeUnusable) && !errors.Is(err, gorm.ErrRecordNotFound) {
			// A wrong or spent code is the common case and not worth logging on
			// every attempt; anything else is a real failure.
			log.Printf("guest codes: validating %q failed: %v", k, err)
		}
		return nil
	}
	return result
}

// errCodeUnusable rolls the redemption transaction back for an expired or
// exhausted code without conflating it with a database failure.
var errCodeUnusable = errors.New("guest code is expired or exhausted")

// Stats returns the counters the admin header shows.
//
//	total   — every code
//	used    — exhausted and not expired
//	unused  — still usable, including partly used multi-use codes
//	expired — expired, whatever its use count
//
// The definitions have to agree with buildDashboard's active-code count, which
// is derived from the same rows; they disagreed once and the header contradicted
// the table.
func (s *GuestCodeStore) Stats() (total, used, unused, expired int) {
	now := time.Now().UTC()
	count := func(where string, args ...any) int {
		var n int64
		q := s.db.Model(&dbstore.GuestCode{})
		if where != "" {
			q = q.Where(where, args...)
		}
		if err := q.Count(&n).Error; err != nil {
			log.Printf("guest codes: stats query failed: %v", err)
			return 0
		}
		return int(n)
	}
	const exhausted = `max_uses > 0 AND max_uses <= (
		SELECT COUNT(*) FROM guest_code_use WHERE guest_code_use.code = guest_code.code
	)`
	const notExpired = "(expires_at IS NULL OR expires_at >= ?)"

	total = count("")
	expired = count("expires_at IS NOT NULL AND expires_at < ?", now)
	used = count(notExpired+" AND ("+exhausted+")", now)
	unused = total - expired - used
	if unused < 0 {
		// Only reachable if the three queries straddled a concurrent write.
		// Clamping keeps the admin header from rendering a negative count.
		unused = 0
	}
	return total, used, unused, expired
}

// ensureGuestCodeSchema is a startup sanity check that the raw SQL above matches
// the table names GORM generated. The subselects are written by hand, so a model
// rename would leave them referring to a table that no longer exists — and the
// failure would surface as "delete used/expired removed nothing", not as an
// error.
func ensureGuestCodeSchema(db *dbstore.DB) error {
	if !db.Migrator().HasTable("guest_code") || !db.Migrator().HasTable("guest_code_use") {
		return fmt.Errorf("dbstore: expected tables guest_code and guest_code_use; " +
			"the hand-written subselects in store_guestcode.go need updating")
	}
	return nil
}
