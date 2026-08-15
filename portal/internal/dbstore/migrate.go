package dbstore

import (
	"fmt"
	"log"
	"time"
)

// Migrate brings the schema up to date.
//
// GORM's AutoMigrate rather than versioned SQL migrations. The trade is
// deliberate: AutoMigrate adds tables, columns and indexes but never drops or
// narrows anything, which is exactly the safe subset for an appliance that an
// operator upgrades by replacing a binary and restarting. Versioned migrations
// would buy destructive changes and precise ordering — neither of which this
// schema has needed — at the cost of a migration runner, a version table, and a
// failure mode where a half-applied migration leaves an operator with no portal
// and no obvious way back.
//
// The one thing AutoMigrate cannot do is change a column's meaning. If that ever
// becomes necessary, it needs a real migration and this comment should stop
// being true.
func Migrate(db *DB) error {
	start := time.Now()
	if err := db.AutoMigrate(AllModels()...); err != nil {
		return fmt.Errorf("dbstore: migrate: %w", err)
	}
	log.Printf("dbstore: schema ready (%s, %s) in %s", db.Driver, db.DSNRedacted, time.Since(start).Round(time.Millisecond))
	return nil
}

// IsEmpty reports whether this looks like a fresh install — no settings and no
// guest codes. The one-time import from .env and the JSON files keys off this,
// so it must stay cheap and must not treat "an operator deleted every guest
// code" as a fresh install; the settings table is what makes it reliable, since
// the import always writes at least one row there.
func IsEmpty(db *DB) (bool, error) {
	var settings int64
	if err := db.Model(&Setting{}).Count(&settings).Error; err != nil {
		return false, fmt.Errorf("dbstore: count settings: %w", err)
	}
	return settings == 0, nil
}
