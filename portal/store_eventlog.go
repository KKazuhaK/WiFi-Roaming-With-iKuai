package main

// store_eventlog.go
// Database-backed event log.
//
// This is the highest-volume table: one row per login attempt plus one per admin
// action. The file-backed version it replaces kept every event in a slice and
// answered queries by scanning it, which was fast and had two properties that do
// not survive the move to multiple instances or to real retention windows:
//
//   - The whole history sat in RAM. A year of a busy site is millions of rows,
//     and the process paid for all of them on every restart.
//   - Each instance saw only its own events, so the audit trail an operator
//     reads depended on which instance answered their request.
//
// Queries are now SQL against the indexes declared on dbstore.Event, which were
// chosen for exactly these access patterns: a time range for the default view
// and the retention sweep, and kind or result always combined with a time range
// for the filters.

import (
	"fmt"
	"log"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/kazuhahub/wifi-portal/internal/dbstore"
)

type EventLog struct {
	db        *dbstore.DB
	retention time.Duration
}

func newEventLog(db *dbstore.DB, retention time.Duration) *EventLog {
	return &EventLog{db: db, retention: retention}
}

// Append records one event.
//
// Failures are logged and swallowed, which is the same contract the file-backed
// version had and is deliberate: this is called from the middle of a sign-in, and
// an audit-log write must never be what stops a user getting onto the network.
// The failure is visible in the process log, where an operator watching for
// database trouble will already be looking.
func (e *EventLog) Append(ev Event) {
	row := dbstore.Event{
		Time: ev.Time.UTC(), Kind: ev.Kind, Subject: ev.Subject, Result: ev.Result,
		Method: ev.Method, MAC: ev.MAC, IP: ev.IP, Detail: ev.Detail,
	}
	if row.Time.IsZero() {
		row.Time = time.Now().UTC()
	}
	if err := e.db.Create(&row).Error; err != nil {
		log.Printf("event log: append failed (the request itself was not affected): %v", err)
	}
}

// applyFilter translates an EventQueryFilter into SQL.
//
// Subject is a case-insensitive substring match, which is what the admin UI's
// free-text box means. It cannot use an index and is left unindexed on purpose;
// it is always combined with a time window, which is what bounds the scan.
func (e *EventLog) applyFilter(q *gorm.DB, f EventQueryFilter) *gorm.DB {
	if f.Kind != "" {
		q = q.Where("kind = ?", f.Kind)
	}
	if f.Method != "" {
		q = q.Where("method = ?", f.Method)
	}
	if f.Result != "" {
		q = q.Where("result = ?", f.Result)
	}
	if s := strings.TrimSpace(f.Subject); s != "" {
		// LOWER on both sides rather than ILIKE or a collation assumption:
		// PostgreSQL's LIKE is case-sensitive, MySQL's default collation is not,
		// and SQLite's depends on the column. Normalising explicitly makes the
		// filter behave the same on all three.
		q = q.Where("LOWER(subject) LIKE ?", "%"+strings.ToLower(s)+"%")
	}
	if !f.Since.IsZero() {
		q = q.Where("time >= ?", f.Since.UTC())
	}
	if !f.Until.IsZero() {
		q = q.Where("time <= ?", f.Until.UTC())
	}
	return q
}

// Query returns matching events, newest first.
func (e *EventLog) Query(f EventQueryFilter) []Event {
	q := e.applyFilter(e.db.Model(&dbstore.Event{}), f)
	// Tie-break on id so pagination and repeated loads are stable: events
	// recorded in the same second would otherwise come back in whatever order
	// the engine chose that time.
	q = q.Order("time DESC, id DESC")
	if f.Limit > 0 {
		q = q.Limit(f.Limit)
	}
	var rows []dbstore.Event
	if err := q.Find(&rows).Error; err != nil {
		log.Printf("event log: query failed: %v", err)
		return nil
	}
	out := make([]Event, 0, len(rows))
	for _, r := range rows {
		out = append(out, Event{
			Time: r.Time, Kind: r.Kind, Subject: r.Subject, Result: r.Result,
			Method: r.Method, MAC: r.MAC, IP: r.IP, Detail: r.Detail,
		})
	}
	return out
}

// Count returns how many events match, ignoring Limit.
func (e *EventLog) Count(f EventQueryFilter) int {
	var n int64
	if err := e.applyFilter(e.db.Model(&dbstore.Event{}), f).Count(&n).Error; err != nil {
		log.Printf("event log: count failed: %v", err)
		return 0
	}
	return int(n)
}

// MultiCount answers several counts for the dashboard.
//
// The file-backed version existed to scan the in-memory slice once under a
// single lock instead of five times. Against a database the equivalent win is
// smaller — each of these is an index range scan — so it stays a loop rather
// than a hand-built UNION, which would be harder to read for a saving that does
// not show up on a page rendered once per admin visit.
func (e *EventLog) MultiCount(filters []EventQueryFilter) []int {
	out := make([]int, len(filters))
	for i, f := range filters {
		out[i] = e.Count(f)
	}
	return out
}

// Prune deletes events past the retention window and returns how many went.
func (e *EventLog) Prune() int {
	if e.retention <= 0 {
		return 0
	}
	cutoff := time.Now().UTC().Add(-e.retention)
	res := e.db.Where("time < ?", cutoff).Delete(&dbstore.Event{})
	if res.Error != nil {
		log.Printf("event log: prune failed: %v", res.Error)
		return 0
	}
	if res.RowsAffected > 0 {
		log.Printf("event log: pruned %d event(s) older than %s", res.RowsAffected, e.retention)
	}
	return int(res.RowsAffected)
}

// gcLoop prunes hourly. Started as a goroutine by main.
func (e *EventLog) gcLoop() {
	if e.retention <= 0 {
		return
	}
	// One sweep at startup catches the backlog after a long outage or a
	// shortened retention window, without waiting an hour for the first tick.
	e.Prune()
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for range t.C {
		e.Prune()
	}
}

// Close exists so the caller's shutdown path did not change. There is no file
// handle left to flush; every append is already committed.
func (e *EventLog) Close() error { return nil }

// ensureEventSchema is the startup counterpart to ensureGuestCodeSchema.
func ensureEventSchema(db *dbstore.DB) error {
	if !db.Migrator().HasTable("event") {
		return fmt.Errorf("dbstore: expected table event")
	}
	return nil
}
