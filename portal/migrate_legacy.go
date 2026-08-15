package main

// migrate_legacy.go
// One-time adoption of an installation that predates the database.
//
// Before this, everything lived in .env plus five JSON files under DataDir.
// Upgrading is "replace the binary and restart", so the import has to happen
// unprompted and has to be right the first time — an operator who restarts and
// finds their guest codes gone has no undo.
//
// Three rules make that safe:
//
//   - It runs only against an empty settings table. An operator who deletes
//     every guest code must not have them resurrected from a stale file on the
//     next restart, so emptiness is judged by settings, which the import always
//     writes.
//   - Nothing is deleted. Imported files are renamed to *.migrated rather than
//     removed, so a failed upgrade can be rolled back by restoring the old
//     binary and the old names.
//   - A file that cannot be parsed is reported and skipped, not fatal. A
//     corrupt ban-history file is not a reason to refuse to start; losing the
//     guest codes would be, and that case is loud.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"strings"
	"time"

	"github.com/kazuhahub/wifi-portal/internal/dbstore"
	"github.com/kazuhahub/wifi-portal/internal/settings"
)

// importLegacyState populates a fresh database from the environment and the
// JSON files, if there is anything to populate it from.
func importLegacyState(db *dbstore.DB, store *settings.Store, boot BootstrapConfig) error {
	empty, err := dbstore.IsEmpty(db)
	if err != nil {
		return err
	}
	if !empty {
		return nil
	}

	log.Printf("import: settings table is empty, adopting existing configuration")

	// Defaults first, so a key the environment does not set still lands in the
	// table and shows up populated on its settings page.
	for section, kv := range defaultSettingValues() {
		if err := store.Save(section, kv, "system:defaults"); err != nil {
			return fmt.Errorf("import defaults: %w", err)
		}
	}

	imported := importEnvSettings(store)
	if imported > 0 {
		log.Printf("import: adopted %d setting(s) from environment variables; "+
			"from now on they are edited in Admin -> Settings and the variables are ignored", imported)
	} else {
		log.Printf("import: no configuration environment variables set; starting with defaults. " +
			"Configure Entra SSO and the iKuai app key in Admin -> Settings.")
	}

	// The five JSON state files are NOT imported here yet, and that omission is
	// deliberate rather than unfinished business.
	//
	// importLegacyStateFiles renames each file to *.migrated once its contents
	// are in the database. The guest-code, denylist, policy, ban-history and
	// event stores still read those files, so running it now would move the data
	// somewhere nothing reads it from and leave the portal showing an empty
	// guest-code table after an upgrade — verified in an upgrade rehearsal,
	// which is exactly what it was for.
	//
	// The two halves have to land together: the state import runs from the same
	// change that switches those stores to the database. The code and its tests
	// are kept here so that change is a wiring change, not a rewrite.
	_ = boot
	return nil
}

// importEnvSettings copies every registry entry whose environment variable is
// set. Values are written per section so one bad section cannot abort the rest.
func importEnvSettings(store *settings.Store) int {
	bySection := map[string]map[string]string{}
	for _, d := range settingRegistry {
		if d.Env == "" {
			continue
		}
		v := strings.TrimSpace(os.Getenv(d.Env))
		if v == "" {
			continue
		}
		if bySection[d.Section] == nil {
			bySection[d.Section] = map[string]string{}
		}
		bySection[d.Section][d.Key] = v
	}

	count := 0
	for section, kv := range bySection {
		if err := store.Save(section, kv, "system:env-import"); err != nil {
			// Reported, not fatal: losing one section of settings is repairable
			// from the admin console, and refusing to start is not.
			log.Printf("import: section %s failed, configure it in Admin -> Settings: %v", section, err)
			continue
		}
		count += len(kv)
	}
	return count
}

// legacyCodeUse mirrors the on-disk shape of one redemption.
type legacyCodeUse struct {
	At       time.Time `json:"at"`
	MAC      string    `json:"mac"`
	IP       string    `json:"ip"`
	GuestUPN string    `json:"guest_upn"`
}

type legacyGuestCode struct {
	Code        string          `json:"code"`
	CreatedAt   time.Time       `json:"created_at"`
	ExpiresAt   time.Time       `json:"expires_at"`
	DurationMin int             `json:"duration_min"`
	MaxUses     int             `json:"max_uses"`
	Note        string          `json:"note"`
	Uses        []legacyCodeUse `json:"uses"`
}

type legacyDeniedMAC struct {
	MAC       string    `json:"mac"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
}

type legacyEvent struct {
	Time    time.Time `json:"time"`
	Kind    string    `json:"kind"`
	Subject string    `json:"subject"`
	Result  string    `json:"result"`
	Method  string    `json:"method"`
	MAC     string    `json:"mac"`
	IP      string    `json:"ip"`
	Detail  string    `json:"detail"`
}

// importLegacyStateFiles moves the five state files into their tables.
//
// Not yet called from importLegacyState — see the note there. It is complete and
// tested; what is missing is the store layer reading from these tables instead
// of from the files this function renames away.
func importLegacyStateFiles(db *dbstore.DB, paths dataPaths) {
	importGuestCodes(db, paths.GuestCodes)
	importDenylist(db, paths.Denylist)
	importIKuaiPolicy(db, paths.IKuaiPolicy)
	importBanHistory(db, paths.BanHistory)
	importEvents(db, paths.EventLog)
}

// readLegacyFile returns nil, nil when the file simply does not exist, which is
// the normal case for a fresh install.
func readLegacyFile(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return data, nil
}

// markMigrated renames an imported file instead of deleting it. The rename is
// what stops a second import if the settings table is ever cleared, and it
// leaves a rollback path for an operator who reverts the binary.
func markMigrated(path string) {
	if path == "" {
		return
	}
	if err := os.Rename(path, path+".migrated"); err != nil {
		log.Printf("import: could not rename %s (import succeeded; rename it by hand to avoid confusion): %v", path, err)
	}
}

func importGuestCodes(db *dbstore.DB, path string) {
	data, err := readLegacyFile(path)
	if err != nil {
		log.Printf("import: read %s failed, guest codes NOT imported: %v", path, err)
		return
	}
	if len(data) == 0 {
		return
	}
	var codes []legacyGuestCode
	if err := json.Unmarshal(data, &codes); err != nil {
		// The loudest failure in this file. Guest codes are handed out to real
		// people who are holding them right now.
		log.Printf("import: %s is not valid JSON, guest codes NOT imported — "+
			"the file is untouched, restore the previous binary to recover: %v", path, err)
		return
	}

	rows := make([]dbstore.GuestCode, 0, len(codes))
	uses := make([]dbstore.GuestCodeUse, 0)
	for _, c := range codes {
		row := dbstore.GuestCode{
			Code:        c.Code,
			CreatedAt:   c.CreatedAt.UTC(),
			DurationMin: c.DurationMin,
			MaxUses:     c.MaxUses,
			Note:        c.Note,
		}
		// A zero time meant "never expires" in the file format; the column is
		// nullable so that stays representable without a sentinel date.
		if !c.ExpiresAt.IsZero() {
			t := c.ExpiresAt.UTC()
			row.ExpiresAt = &t
		}
		rows = append(rows, row)
		for _, u := range c.Uses {
			uses = append(uses, dbstore.GuestCodeUse{
				Code: c.Code, At: u.At.UTC(), MAC: u.MAC, IP: u.IP, GuestUPN: u.GuestUPN,
			})
		}
	}
	if len(rows) > 0 {
		if err := db.CreateInBatches(&rows, 200).Error; err != nil {
			log.Printf("import: writing guest codes failed, they were NOT imported: %v", err)
			return
		}
	}
	if len(uses) > 0 {
		if err := db.CreateInBatches(&uses, 500).Error; err != nil {
			// The codes are in and usable; only their history is missing.
			log.Printf("import: guest codes imported but their use history was not: %v", err)
		}
	}
	log.Printf("import: %d guest code(s), %d redemption(s)", len(rows), len(uses))
	markMigrated(path)
}

func importDenylist(db *dbstore.DB, path string) {
	data, err := readLegacyFile(path)
	if err != nil || len(data) == 0 {
		if err != nil {
			log.Printf("import: read %s failed: %v", path, err)
		}
		return
	}
	var items []legacyDeniedMAC
	if err := json.Unmarshal(data, &items); err != nil {
		log.Printf("import: %s is not valid JSON, MAC denylist NOT imported: %v", path, err)
		return
	}
	rows := make([]dbstore.DeniedMAC, 0, len(items))
	for _, it := range items {
		rows = append(rows, dbstore.DeniedMAC{
			MAC: it.MAC, Reason: it.Reason, CreatedAt: it.CreatedAt.UTC(), CreatedBy: it.CreatedBy,
		})
	}
	if len(rows) > 0 {
		if err := db.CreateInBatches(&rows, 200).Error; err != nil {
			log.Printf("import: writing the MAC denylist failed, it was NOT imported: %v", err)
			return
		}
	}
	log.Printf("import: %d denied MAC(s)", len(rows))
	markMigrated(path)
}

func importIKuaiPolicy(db *dbstore.DB, path string) {
	data, err := readLegacyFile(path)
	if err != nil || len(data) == 0 {
		if err != nil {
			log.Printf("import: read %s failed: %v", path, err)
		}
		return
	}
	var policies map[string]IKuaiPolicy
	if err := json.Unmarshal(data, &policies); err != nil {
		log.Printf("import: %s is not valid JSON, iKuai policies NOT imported (defaults apply): %v", path, err)
		return
	}
	now := time.Now().UTC()
	rows := make([]dbstore.IKuaiPolicy, 0, len(policies))
	for profile, p := range policies {
		rows = append(rows, dbstore.IKuaiPolicy{
			Profile: profile, Upload: p.Upload, Download: p.Download,
			Timeout: p.Timeout, Comment: p.Comment, UpdatedAt: now,
		})
	}
	if len(rows) > 0 {
		if err := db.Create(&rows).Error; err != nil {
			log.Printf("import: writing iKuai policies failed: %v", err)
			return
		}
	}
	log.Printf("import: %d iKuai policy row(s)", len(rows))
	markMigrated(path)
}

func importBanHistory(db *dbstore.DB, path string) {
	data, err := readLegacyFile(path)
	if err != nil || len(data) == 0 {
		if err != nil {
			log.Printf("import: read %s failed: %v", path, err)
		}
		return
	}
	var counts map[string]int
	if err := json.Unmarshal(data, &counts); err != nil {
		log.Printf("import: %s is not valid JSON, ban history NOT imported: %v", path, err)
		return
	}
	now := time.Now().UTC()
	rows := make([]dbstore.BanHistory, 0, len(counts))
	for ip, n := range counts {
		rows = append(rows, dbstore.BanHistory{IP: ip, Count: n, UpdatedAt: now})
	}
	if len(rows) > 0 {
		if err := db.CreateInBatches(&rows, 500).Error; err != nil {
			log.Printf("import: writing ban history failed: %v", err)
			return
		}
	}
	log.Printf("import: %d ban-history entr(ies)", len(rows))
	markMigrated(path)
}

// importEvents reads events.jsonl. It is the only line-delimited file and by far
// the largest, so it is streamed in batches and a single malformed line is
// skipped rather than abandoning the whole audit trail.
func importEvents(db *dbstore.DB, path string) {
	data, err := readLegacyFile(path)
	if err != nil || len(data) == 0 {
		if err != nil {
			log.Printf("import: read %s failed: %v", path, err)
		}
		return
	}

	const batchSize = 1000
	batch := make([]dbstore.Event, 0, batchSize)
	total, skipped := 0, 0

	flush := func() bool {
		if len(batch) == 0 {
			return true
		}
		if err := db.Create(&batch).Error; err != nil {
			log.Printf("import: writing events failed after %d row(s): %v", total, err)
			return false
		}
		total += len(batch)
		batch = batch[:0]
		return true
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var ev legacyEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			skipped++
			continue
		}
		batch = append(batch, dbstore.Event{
			Time: ev.Time.UTC(), Kind: ev.Kind, Subject: ev.Subject, Result: ev.Result,
			Method: ev.Method, MAC: ev.MAC, IP: ev.IP, Detail: ev.Detail,
		})
		if len(batch) >= batchSize && !flush() {
			return
		}
	}
	if !flush() {
		return
	}
	if skipped > 0 {
		log.Printf("import: %d event(s), %d unparseable line(s) skipped", total, skipped)
	} else {
		log.Printf("import: %d event(s)", total)
	}
	markMigrated(path)
}
