// Package settings is the typed key-value store behind the admin Settings pages.
//
// It knows nothing about what any particular setting means — the registry that
// maps keys onto the portal's Config struct lives next to that struct, because
// the two have to change together and a package boundary between them would
// only hide the coupling. What lives here is the part worth isolating: reading
// and writing the setting table, deciding which keys are secret, and making
// sure a secret is encrypted on the way in and never handed back to an API
// response on the way out.
package settings

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kazuhahub/wifi-portal/internal/dbstore"
	"github.com/kazuhahub/wifi-portal/internal/secret"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// SecretKeys reports whether "section.key" holds a credential. Supplied by the
// caller's registry.
type SecretKeys func(section, key string) bool

// Store reads and writes settings.
type Store struct {
	db      *dbstore.DB
	keys    *secret.Keyring
	secrets SecretKeys
}

// New builds a Store. secrets may be nil, in which case nothing is encrypted —
// useful in tests that do not care about credentials.
func New(db *dbstore.DB, keys *secret.Keyring, secrets SecretKeys) *Store {
	if secrets == nil {
		secrets = func(string, string) bool { return false }
	}
	return &Store{db: db, keys: keys, secrets: secrets}
}

// Values is a decrypted snapshot, keyed "section.key".
//
// A flat map rather than nested sections: every consumer either wants one key
// or wants to build the whole Config, and nesting would make the second case
// walk two levels for no gain.
type Values map[string]string

// Key joins a section and key into the map's key form.
func Key(section, key string) string { return section + "." + key }

// LoadAll returns every stored setting with secrets decrypted.
//
// A decryption failure is fatal to the load rather than skipped. The alternative
// — dropping the unreadable key and carrying on — starts the portal with an
// empty OIDC client secret, which fails at the point a user tries to sign in,
// hours later and with nothing in the logs pointing at the encryption key.
func (s *Store) LoadAll() (Values, error) {
	var rows []dbstore.Setting
	if err := s.db.Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("settings: load: %w", err)
	}
	out := make(Values, len(rows))
	for _, r := range rows {
		v := r.Value
		if s.secrets(r.Section, r.Key) {
			plain, err := s.keys.Decrypt(r.Value)
			if err != nil {
				return nil, fmt.Errorf("settings: %s: %w", Key(r.Section, r.Key), err)
			}
			v = plain
		}
		out[Key(r.Section, r.Key)] = v
	}
	return out, nil
}

// LoadSection returns one section's decrypted values, keyed by bare key name.
func (s *Store) LoadSection(section string) (map[string]string, error) {
	var rows []dbstore.Setting
	if err := s.db.Where("section = ?", section).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("settings: load %s: %w", section, err)
	}
	out := make(map[string]string, len(rows))
	for _, r := range rows {
		v := r.Value
		if s.secrets(r.Section, r.Key) {
			plain, err := s.keys.Decrypt(r.Value)
			if err != nil {
				return nil, fmt.Errorf("settings: %s: %w", Key(r.Section, r.Key), err)
			}
			v = plain
		}
		out[r.Key] = v
	}
	return out, nil
}

// Save writes one section's values in a single transaction.
//
// Transactional because a settings page is saved as a unit: half-applied OIDC
// credentials — new tenant, old client secret — is a state no operator asked
// for and one that breaks sign-in until someone notices.
//
// Keys absent from values are left alone, so a page that renders a subset of a
// section does not blank the rest.
func (s *Store) Save(section string, values map[string]string, updatedBy string) error {
	if updatedBy == "" {
		updatedBy = "system"
	}
	now := time.Now().UTC()
	rows := make([]dbstore.Setting, 0, len(values))

	// Sorted so the statement order is deterministic — it makes a failed
	// transaction reproducible and keeps test assertions stable.
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		v := values[k]
		if s.secrets(section, k) {
			enc, err := s.keys.Encrypt(v)
			if err != nil {
				return fmt.Errorf("settings: encrypt %s: %w", Key(section, k), err)
			}
			v = enc
		}
		rows = append(rows, dbstore.Setting{
			Section:   section,
			Key:       k,
			Value:     v,
			UpdatedAt: now,
			UpdatedBy: updatedBy,
		})
	}
	if len(rows) == 0 {
		return nil
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		// Upsert on the composite primary key. Written as one statement per
		// batch rather than a select-then-insert so two admins saving different
		// sections concurrently cannot deadlock on a read lock.
		return tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "section"}, {Name: "key"}},
			DoUpdates: clause.AssignmentColumns([]string{"value", "updated_at", "updated_by"}),
		}).Create(&rows).Error
	})
}

// SetOne writes a single value. Convenience for the CLI and for the import.
func (s *Store) SetOne(section, key, value, updatedBy string) error {
	return s.Save(section, map[string]string{key: value}, updatedBy)
}

// Redact returns a copy of values with every secret replaced by a boolean-ish
// marker, for use in an API response.
//
// The admin UI never receives a stored credential. It receives the fact that
// one is set, which is all a form needs to render "leave blank to keep the
// current value" — and it means a read-only admin, a browser extension, or a
// proxy log never sees an OIDC client secret.
func (s *Store) Redact(section string, values map[string]string) (fields map[string]string, present map[string]bool) {
	fields = make(map[string]string, len(values))
	present = make(map[string]bool)
	for k, v := range values {
		if s.secrets(section, k) {
			present[k] = v != ""
			continue
		}
		fields[k] = v
	}
	return fields, present
}

// ApplySecretUpdates merges a submitted form into the stored values, honouring
// the "blank means unchanged" convention for secrets.
//
// Without this, saving the OIDC page after only changing the tenant ID would
// blank the client secret — the form never had it to send back.
func (s *Store) ApplySecretUpdates(section string, stored, submitted map[string]string) map[string]string {
	out := make(map[string]string, len(submitted))
	for k, v := range submitted {
		if s.secrets(section, k) && strings.TrimSpace(v) == "" {
			if prev, ok := stored[k]; ok {
				out[k] = prev
				continue
			}
		}
		out[k] = v
	}
	return out
}

// --- typed readers over a loaded snapshot ---
//
// These take a default rather than returning an error for a missing or
// malformed value. A settings table is written by validated forms and by the
// import, so a bad value means something already went wrong upstream; failing
// the portal's startup over one unparseable integer would turn a cosmetic bug
// into an outage. Callers that need strictness validate before saving.

func (v Values) String(section, key, def string) string {
	if s, ok := v[Key(section, key)]; ok && s != "" {
		return s
	}
	return def
}

func (v Values) Int(section, key string, def int) int {
	s, ok := v[Key(section, key)]
	if !ok || s == "" {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return def
	}
	return n
}

func (v Values) Bool(section, key string, def bool) bool {
	s, ok := v[Key(section, key)]
	if !ok || s == "" {
		return def
	}
	b, err := strconv.ParseBool(strings.TrimSpace(s))
	if err != nil {
		return def
	}
	return b
}

func (v Values) Duration(section, key string, def time.Duration) time.Duration {
	s, ok := v[Key(section, key)]
	if !ok || s == "" {
		return def
	}
	d, err := time.ParseDuration(strings.TrimSpace(s))
	if err != nil {
		return def
	}
	return d
}

// List splits a comma-separated value, trimming and dropping empties. This is
// the same shape the .env values had, so the import is a straight copy and an
// operator editing the field in the admin UI types what they used to type.
func (v Values) List(section, key string, def []string) []string {
	s, ok := v[Key(section, key)]
	if !ok || strings.TrimSpace(s) == "" {
		return def
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return def
	}
	return out
}
