// Package dbstore owns the portal's persistent storage.
//
// Before this package the portal kept everything in JSON files under DataDir:
// guest-codes.json, denylist.json, ikuai-policy.json, events.jsonl and
// ratelimit-state.json, plus ~30 runtime settings that could only be changed by
// editing .env and restarting. That works for one box and stops working for two:
// a second instance has its own guest codes, its own denylist and its own audit
// trail, and an operator has no way to change anything without shell access.
//
// Storage is SQLite by default — the same zero-configuration experience the JSON
// files gave — and MySQL or PostgreSQL when a DSN says so.
//
// The SQLite driver is glebarez/sqlite, which wraps modernc.org/sqlite: a pure
// Go translation of SQLite rather than a cgo binding. That choice is
// load-bearing, not incidental. The whole deployment story here rests on
// CGO_ENABLED=0 static binaries — scratch and distroless images, a single file
// dropped on a router-adjacent box — and mattn/go-sqlite3 would end that.
package dbstore

import (
	"errors"
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	gormschema "gorm.io/gorm/schema"
)

// Driver names the backend selected by the DSN.
type Driver string

const (
	DriverSQLite   Driver = "sqlite"
	DriverMySQL    Driver = "mysql"
	DriverPostgres Driver = "postgres"
)

// Options configures Open. Everything here comes from the bootstrap config file
// or its environment overrides — this is the layer that has to work before any
// database-backed setting can be read.
type Options struct {
	// DSN selects the backend. Empty means SQLite at <DataDir>/portal.db.
	//
	// Recognised forms:
	//   ""                                  -> sqlite at <DataDir>/portal.db
	//   "sqlite:./data/portal.db"           -> sqlite at an explicit path
	//   "file:/var/lib/wifi-portal/p.db"    -> sqlite (file: prefix)
	//   "postgres://user:pw@host/db"        -> PostgreSQL
	//   "postgresql://..."                  -> PostgreSQL
	//   "host=... user=... dbname=..."      -> PostgreSQL (libpq keyword form)
	//   "user:pw@tcp(host:3306)/db?..."     -> MySQL
	DSN string

	// DataDir is where the default SQLite file lives.
	DataDir string

	// MaxOpenConns caps the pool. Ignored for SQLite, which is pinned to 1 —
	// see the note in tune().
	MaxOpenConns int

	// SlowQueryThreshold logs statements slower than this. Zero disables.
	SlowQueryThreshold time.Duration

	// Debug logs every statement. Never enable in production: the portal writes
	// OIDC client secrets and iKuai app keys through this connection, and GORM's
	// statement log would put their plaintext in the process log.
	Debug bool
}

// DB wraps the GORM handle with the driver identity, which several call sites
// need because SQLite, MySQL and PostgreSQL disagree about upsert syntax and
// about what a "text" column is.
type DB struct {
	*gorm.DB
	Driver Driver
	// DSNRedacted is safe to log: credentials are stripped.
	DSNRedacted string
}

// detectDriver classifies a DSN. It deliberately does not accept an explicit
// driver name field: a single string is what an operator pastes from their
// database provider's console, and every form below is unambiguous.
func detectDriver(dsn string) (Driver, string) {
	s := strings.TrimSpace(dsn)
	switch {
	case s == "":
		return DriverSQLite, ""
	case strings.HasPrefix(s, "sqlite:"):
		return DriverSQLite, strings.TrimPrefix(s, "sqlite:")
	case strings.HasPrefix(s, "file:"):
		return DriverSQLite, s
	case strings.HasPrefix(s, "postgres://"), strings.HasPrefix(s, "postgresql://"):
		return DriverPostgres, s
	// libpq keyword form. "host=" is the only token that cannot appear at the
	// start of a MySQL DSN, which always begins with user[:pass]@.
	case strings.HasPrefix(s, "host="), strings.Contains(s, " host="):
		return DriverPostgres, s
	case strings.HasSuffix(s, ".db"), strings.HasSuffix(s, ".sqlite"), strings.HasSuffix(s, ".sqlite3"):
		return DriverSQLite, s
	default:
		return DriverMySQL, s
	}
}

// redactDSN removes the password so a DSN can be logged. Both the URL form and
// the MySQL user:pass@ form are handled; anything unrecognised is reported as
// the driver name alone rather than risking a leak.
func redactDSN(d Driver, dsn string) string {
	// Dispatch on the driver rather than probing the string, because the probes
	// overlap: url.Parse happily accepts a MySQL DSN like
	// "psp:hunter2@tcp(127.0.0.1:3306)/portal" — it reads "psp" as the scheme,
	// finds no userinfo, and hands back the password untouched.
	switch d {
	case DriverSQLite:
		// A file path carries no credentials, and it is the single most useful
		// line in the startup log for a file-backed deployment.
		return dsn

	case DriverMySQL:
		// user[:pass]@protocol(address)/dbname. The password ends at the last
		// '@' before the address; usernames may not contain '@' unescaped, but
		// passwords may, so scan from the right.
		at := strings.LastIndex(dsn, "@")
		if at <= 0 {
			return dsn
		}
		cred := dsn[:at]
		colon := strings.Index(cred, ":")
		if colon < 0 {
			return dsn // No password component.
		}
		return cred[:colon] + ":***" + dsn[at:]

	case DriverPostgres:
		if u, err := url.Parse(dsn); err == nil && u.Scheme != "" {
			if u.User != nil {
				u.User = url.User(u.User.Username())
			}
			return u.String()
		}
		// libpq keyword form: host=... password=... dbname=...
		fields := strings.Fields(dsn)
		for i, f := range fields {
			if strings.HasPrefix(f, "password=") {
				fields[i] = "password=***"
			}
		}
		return strings.Join(fields, " ")

	default:
		// Unknown shape: say nothing rather than risk printing a secret.
		return string(d) + " (dsn redacted)"
	}
}

// sqliteDSN builds the connection string for the embedded database.
//
// The pragmas are not optional decoration:
//
//   - WAL lets the event-log writer and the admin panel's readers proceed
//     concurrently. Under the default rollback journal a single insert blocks
//     every reader, and this database is written on every login attempt.
//   - busy_timeout turns "database is locked" — which SQLite returns
//     immediately by default — into a bounded wait. Without it, two goroutines
//     racing on a write surface as a user-visible error.
//   - foreign_keys is off by default in SQLite, which would silently let a
//     guest_code_uses row outlive its parent code.
//   - synchronous=NORMAL is the documented safe pairing with WAL: it survives
//     application crashes, and trades only power-loss durability of the last
//     transactions for a large write speedup.
func sqliteDSN(path string) string {
	return path + "?" +
		"_pragma=journal_mode(WAL)" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=foreign_keys(1)" +
		"&_pragma=synchronous(NORMAL)"
}

// Open connects, verifies the connection, and applies the schema.
func Open(opts Options) (*DB, error) {
	driver, dsn := detectDriver(opts.DSN)

	if driver == DriverSQLite && dsn == "" {
		if opts.DataDir == "" {
			return nil, errors.New("dbstore: DataDir is required when no DSN is set")
		}
		dsn = strings.TrimRight(opts.DataDir, "/") + "/portal.db"
	}

	gcfg := &gorm.Config{
		// The portal's own tables are singular and explicit (setting, guest_code);
		// GORM's default pluralisation would rename them behind our backs.
		NamingStrategy: gormschema.NamingStrategy{SingularTable: true},
		// Every write in this codebase is a single statement or an explicit
		// transaction, so GORM's default per-call transaction is pure overhead.
		SkipDefaultTransaction: true,
		Logger:                 newGormLogger(opts),
	}

	var (
		gdb *gorm.DB
		err error
	)
	switch driver {
	case DriverSQLite:
		gdb, err = gorm.Open(sqlite.Open(sqliteDSN(dsn)), gcfg)
	case DriverMySQL:
		gdb, err = gorm.Open(mysql.Open(dsn), gcfg)
	case DriverPostgres:
		gdb, err = gorm.Open(postgres.Open(dsn), gcfg)
	default:
		return nil, fmt.Errorf("dbstore: unsupported driver %q", driver)
	}
	redacted := redactDSN(driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("dbstore: connect %s (%s): %w", driver, redacted, err)
	}

	db := &DB{DB: gdb, Driver: driver, DSNRedacted: redacted}
	if err := db.tune(opts); err != nil {
		return nil, err
	}
	// gorm.Open is lazy for the network drivers: a wrong password surfaces on
	// first query, which would otherwise be some unrelated handler minutes later.
	if err := db.ping(); err != nil {
		return nil, fmt.Errorf("dbstore: ping %s (%s): %w", driver, redacted, err)
	}
	return db, nil
}

func (db *DB) tune(opts Options) error {
	sqlDB, err := db.DB.DB()
	if err != nil {
		return fmt.Errorf("dbstore: sql handle: %w", err)
	}
	switch db.Driver {
	case DriverSQLite:
		// One writer, deliberately. SQLite serialises writes anyway, and a pool
		// larger than one converts that serialisation into SQLITE_BUSY errors
		// racing against busy_timeout. A single connection makes the queueing
		// happen in Go, where it is fair and cannot fail.
		sqlDB.SetMaxOpenConns(1)
		sqlDB.SetMaxIdleConns(1)
		// Never expire it: reopening costs a fresh WAL handshake for nothing.
		sqlDB.SetConnMaxLifetime(0)
	default:
		max := opts.MaxOpenConns
		if max <= 0 {
			max = 25
		}
		sqlDB.SetMaxOpenConns(max)
		idle := max / 4
		if idle < 2 {
			idle = 2
		}
		sqlDB.SetMaxIdleConns(idle)
		// Managed MySQL and PgBouncer both cut idle connections server-side;
		// recycling first turns "unexpected EOF" on a borrowed connection into a
		// non-event.
		sqlDB.SetConnMaxLifetime(30 * time.Minute)
		sqlDB.SetConnMaxIdleTime(5 * time.Minute)
	}
	return nil
}

func (db *DB) ping() error {
	sqlDB, err := db.DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Ping()
}

// Close releases the pool.
func (db *DB) Close() error {
	sqlDB, err := db.DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// newGormLogger routes GORM's output through the standard logger the rest of the
// portal uses, at a volume suited to an appliance: errors and slow queries only.
func newGormLogger(opts Options) logger.Interface {
	level := logger.Warn
	if opts.Debug {
		level = logger.Info
	}
	slow := opts.SlowQueryThreshold
	if slow <= 0 {
		slow = 300 * time.Millisecond
	}
	return logger.New(log.Default(), logger.Config{
		SlowThreshold: slow,
		LogLevel:      level,
		// A settings lookup for a section that has never been written is a
		// normal miss, not an event worth a log line on every request.
		IgnoreRecordNotFoundError: true,
		// GORM cannot know which of our columns hold an encrypted OIDC secret,
		// so the only safe setting is to never print bound parameters.
		ParameterizedQueries: true,
		Colorful:             false,
	})
}
