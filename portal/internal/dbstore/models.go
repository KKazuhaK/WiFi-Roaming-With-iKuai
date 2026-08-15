package dbstore

import "time"

// The schema mirrors the JSON files it replaces, so the one-time import is a
// straight field copy and an operator reading the tables recognises what they
// are looking at.
//
// Three rules apply throughout:
//
//   - Timestamps are stored UTC and compared UTC. The old JSON files stored
//     RFC3339 with an offset and the admin panel formatted to local time at
//     render; keeping the storage layer UTC-only means a server that moves
//     timezone does not reinterpret its own history.
//   - Any column that can hold an encrypted secret is `type:text`, never a
//     sized varchar. An AES-GCM blob of a long client secret overruns
//     varchar(512), and the failure is silent truncation on non-strict MySQL —
//     the ciphertext then fails authentication on read and SSO breaks with no
//     obvious cause.
//   - Natural keys (the code itself, the MAC, the profile name) are the primary
//     key wherever the old file used them as a map key. Adding surrogate IDs
//     would have meant the import had to invent identities that nothing
//     references.

// Setting is one runtime configuration value.
//
// A key-value table rather than a column per setting: the portal has ~30 of
// them across unrelated concerns, they are read as a whole into one struct at
// startup, and adding one should not require a migration. Section groups keys
// for the admin UI and lets a page save its own fields without a read-modify-
// write of everything else.
type Setting struct {
	Section string `gorm:"primaryKey;size:64"`
	Key     string `gorm:"primaryKey;size:64"`
	// Value holds a string in every case; typed accessors in the settings
	// package parse it. Encrypted values carry the "enc:v1:" prefix.
	Value     string `gorm:"type:text"`
	UpdatedAt time.Time
	// UpdatedBy is the admin UPN that last wrote this key, or "system" for
	// values written by the import or by a default. The old .env had no audit
	// trail at all; moving settings into a UI makes "who changed the OIDC
	// tenant" a question worth being able to answer.
	UpdatedBy string `gorm:"size:255"`
}

// GuestCode replaces guest-codes.json.
type GuestCode struct {
	Code      string    `gorm:"primaryKey;size:64"`
	CreatedAt time.Time `gorm:"index"`
	// ExpiresAt zero means the code never expires. Stored as a nullable column
	// so "never" is representable without a sentinel date that sorting and
	// range queries would treat as a real timestamp.
	ExpiresAt   *time.Time `gorm:"index"`
	DurationMin int
	MaxUses     int
	Note        string `gorm:"size:256"`

	Uses []GuestCodeUse `gorm:"foreignKey:Code;references:Code;constraint:OnDelete:CASCADE"`
}

// GuestCodeUse is one redemption of a code.
//
// A child table rather than the JSON array it replaces: the admin panel only
// ever reads the most recent use for its "last used" column, and a code shared
// with a whole conference would otherwise re-serialise its entire history on
// every save.
type GuestCodeUse struct {
	ID   int64     `gorm:"primaryKey;autoIncrement"`
	Code string    `gorm:"size:64;index:idx_use_code_at,priority:1"`
	At   time.Time `gorm:"index:idx_use_code_at,priority:2,sort:desc"`
	MAC  string    `gorm:"size:32"`
	IP   string    `gorm:"size:64"`
	// GuestUPN is the synthetic identity issued for this redemption
	// (Guest-abc12345), which is what the event log records as the subject.
	GuestUPN string `gorm:"size:64"`
}

// DeniedMAC replaces denylist.json.
type DeniedMAC struct {
	MAC       string `gorm:"primaryKey;size:32"`
	Reason    string `gorm:"size:256"`
	CreatedAt time.Time
	CreatedBy string `gorm:"size:255"`
}

// IKuaiPolicy replaces ikuai-policy.json. Profile is the auth method
// ("sso", "duo", "guest").
type IKuaiPolicy struct {
	Profile   string `gorm:"primaryKey;size:32"`
	Upload    int
	Download  int
	Timeout   int
	Comment   string `gorm:"size:128"`
	UpdatedAt time.Time
}

// Event replaces events.jsonl.
//
// This is the highest-volume table by a wide margin — one row per login attempt
// plus one per admin action — so its indexes are chosen against the queries the
// panel actually issues rather than one per column:
//
//   - idx_event_time backs the default view and the retention sweep, both of
//     which are pure time ranges.
//   - idx_event_kind_time and idx_event_result_time back the kind and result
//     filters, which are always combined with a time window; a bare index on
//     kind would still leave the engine sorting the whole matching set.
//
// Subject is deliberately not indexed: its filter is a substring search, which
// no btree index can serve, and adding one would only slow every insert.
type Event struct {
	ID      int64     `gorm:"primaryKey;autoIncrement"`
	Time    time.Time `gorm:"index:idx_event_time,sort:desc;index:idx_event_kind_time,priority:2,sort:desc;index:idx_event_result_time,priority:2,sort:desc"`
	Kind    string    `gorm:"size:32;index:idx_event_kind_time,priority:1"`
	Subject string    `gorm:"size:255"`
	Result  string    `gorm:"size:32;index:idx_event_result_time,priority:1"`
	Method  string    `gorm:"size:32"`
	MAC     string    `gorm:"size:32"`
	IP      string    `gorm:"size:64"`
	Detail  string    `gorm:"type:text"`
}

// BanHistory replaces ratelimit-state.json: how many cooldowns an IP has
// accumulated, which drives permanent escalation.
type BanHistory struct {
	IP        string `gorm:"primaryKey;size:64"`
	Count     int
	UpdatedAt time.Time
}

// LocalAdmin is the break-glass account.
//
// Admin access is otherwise entirely Entra SSO, and the SSO configuration now
// lives in this same database, editable from the admin UI. Without a second way
// in, one bad tenant ID typed into that form locks every administrator out
// permanently with no recovery short of hand-editing the database.
//
// It is disabled by default and has to be created through the CLI
// (`wifi-portal admin add`), so a deployment that does not want a password on
// its admin surface never grows one.
type LocalAdmin struct {
	Username string `gorm:"primaryKey;size:64"`
	// PasswordHash is an argon2id encoded hash (its own salt and parameters are
	// embedded in the string), never a bare digest.
	PasswordHash string `gorm:"type:text"`
	Enabled      bool
	CreatedAt    time.Time
	LastLoginAt  *time.Time
	// FailedAttempts and LockedUntil throttle password guessing at the account
	// level. The portal's existing IP-based rate limiter protects the captive
	// portal endpoints; this surface needs its own, because an attacker with a
	// botnet has plenty of IPs and only one username worth guessing.
	FailedAttempts int
	LockedUntil    *time.Time
}

// AllModels is the AutoMigrate list. Order matters only for the foreign key
// from GuestCodeUse to GuestCode.
func AllModels() []any {
	return []any{
		&Setting{},
		&GuestCode{},
		&GuestCodeUse{},
		&DeniedMAC{},
		&IKuaiPolicy{},
		&Event{},
		&BanHistory{},
		&LocalAdmin{},
	}
}
