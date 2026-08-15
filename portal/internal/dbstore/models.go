package dbstore

import (
	"strings"
	"time"

	"gorm.io/gorm"
)

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
	Code string `gorm:"primaryKey;size:64"`
	// CodeLower is the lookup key, carrying a unique index.
	//
	// Redemption has always been case-insensitive (the file-backed store keyed
	// its map on strings.ToLower), and that cannot be delegated to the database:
	// MySQL's default collation compares case-insensitively, PostgreSQL's does
	// not, and SQLite's depends on the column. Relying on collation would mean a
	// code that works on one backend is rejected on another. An explicit column
	// makes the behaviour identical everywhere.
	CodeLower string    `gorm:"size:64;uniqueIndex"`
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

// NormalizeCode is the single definition of the redemption lookup key. Guests
// type these off a printed slip, so matching is case-insensitive and tolerates
// surrounding whitespace.
func NormalizeCode(code string) string {
	return strings.ToLower(strings.TrimSpace(code))
}

// BeforeSave derives CodeLower so no writer can forget it.
//
// This is a hook rather than a rule for callers because forgetting is silent in
// the worst way: the row inserts with an empty lookup key, the code cannot be
// redeemed, and the admin table still shows it as available. The legacy importer
// did exactly that, and the unique index turned it into a loud failure — which
// is the second half of the same defence.
func (g *GuestCode) BeforeSave(*gorm.DB) error {
	g.CodeLower = NormalizeCode(g.Code)
	// See GuestCodeUse.BeforeSave: a zero time is '0000-00-00' to MySQL, which
	// rejects it. ExpiresAt is deliberately not touched — it is a nullable
	// pointer precisely so that "never expires" needs no sentinel date.
	if g.CreatedAt.IsZero() {
		g.CreatedAt = time.Now().UTC()
	}
	return nil
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

// BeforeSave fills in a missing timestamp.
//
// A zero time.Time reaches MySQL as '0000-00-00', which its default strict mode
// rejects outright — so a legacy JSON file with a redemption that lost its
// timestamp, or any caller that builds a use without one, fails the whole insert
// on MySQL while inserting happily on SQLite and PostgreSQL. Normalising here
// rather than at each call site keeps the three engines behaving the same, which
// is the only way "MySQL is supported" can be true.
func (u *GuestCodeUse) BeforeSave(*gorm.DB) error {
	if u.At.IsZero() {
		u.At = time.Now().UTC()
	}
	return nil
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

// IPBan is an active cooldown, shared by every instance.
//
// It is in the database rather than in each process's memory for the reason the
// guest codes are: a ban that only one instance knows about is not a ban. Two
// portals behind a load balancer would each hold their own map, and an attacker
// cooled down on one would be served by the other on the next request.
//
// Rows are deleted when they expire rather than kept as history — that is what
// BanHistory is for, and it counts cooldowns rather than storing them.
// A permanent ban is a very distant Until rather than a separate flag, matching
// how the rate limiter has always represented it — two representations of the
// same fact is how they end up disagreeing.
type IPBan struct {
	IP        string    `gorm:"primaryKey;size:64"`
	Until     time.Time `gorm:"index"`
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

// Certificate is a TLS certificate the portal serves for its own listener.
//
// Single-row by convention (Domain is the key, and the portal serves one), but
// modelled as a table so a future multi-domain listener does not need a
// migration. The private key is encrypted at rest with the same keyring that
// protects the OIDC client secret — a certificate key in a database backup is
// exactly the material this whole encryption layer exists for.
type Certificate struct {
	Domain string `gorm:"primaryKey;size:255"`
	// Source is "acme" or "manual", which decides whether the renewal loop owns
	// this certificate or leaves it alone.
	Source string `gorm:"size:16"`
	// CertPEM is the full chain, leaf first. Not secret, but stored alongside
	// the key so the pair cannot be separated by a partial write.
	CertPEM string `gorm:"type:text"`
	// KeyPEM carries an enc:v1: AES-GCM blob.
	KeyPEM    string `gorm:"type:text"`
	NotBefore time.Time
	NotAfter  time.Time `gorm:"index"`
	UpdatedAt time.Time
	// LastError records why the most recent issuance or renewal failed, so the
	// TLS page can show it instead of an operator having to read the log.
	LastError    string `gorm:"type:text"`
	LastAttempt  *time.Time
	ACMEAccount  string `gorm:"type:text"` // Encrypted registration key.
	ACMEAccountU string `gorm:"size:255"`  // Account URL, not secret.
}

// BeforeSave fills in the validity window.
//
// Rows here are not always certificates: a failed issuance records its error
// against the domain, and the ACME account key is stored before any certificate
// exists. Those rows carry no dates, and a zero time.Time is '0000-00-00' to
// MySQL, which refuses the insert — so on MySQL a failing ACME challenge could
// not even record why it failed.
//
// Now is the honest filler for a row with no certificate in it: NotAfter in the
// past reads as "not valid", which is exactly right. Nothing depends on the
// value, because both Status and needsRenewal check CertPEM first.
func (c *Certificate) BeforeSave(*gorm.DB) error {
	now := time.Now().UTC()
	if c.NotBefore.IsZero() {
		c.NotBefore = now
	}
	if c.NotAfter.IsZero() {
		c.NotAfter = now
	}
	if c.UpdatedAt.IsZero() {
		c.UpdatedAt = now
	}
	return nil
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
		&IPBan{},
		&LocalAdmin{},
		&Certificate{},
	}
}
