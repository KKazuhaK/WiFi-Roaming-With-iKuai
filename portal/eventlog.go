package main

// eventlog.go
// Structured event log for logins and admin actions. Events are kept in memory for fast queries
// and optionally written to JSONL for restart persistence and tail -f debugging.
//
// Storage policy:
//   - Append(): lock, append to the memory slice, and write one JSON line with O_APPEND.
//     File-write failures are logged and do not block the business path.
//   - Query(): return matching events in reverse chronological order with a limit.
//   - Prune(): delete entries older than retention and rewrite the file on the hourly cold path.
//   - persistPath == "" means memory-only mode.

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Event is one structured event.
type Event struct {
	Time    time.Time `json:"time"`
	Kind    string    `json:"kind"`    // See Kind constants.
	Subject string    `json:"subject"` // user UPN / Guest-xxxxx / admin UPN / "(guest)" / "(unknown)"
	Result  string    `json:"result"`  // started / success / denied / rate_limited / error
	Method  string    `json:"method"`  // sso / duo / guest_code / admin
	MAC     string    `json:"mac,omitempty"`
	IP      string    `json:"ip,omitempty"`
	Detail  string    `json:"detail,omitempty"`
}

const (
	KindLogin       = "login"
	KindAdminAction = "admin_action"

	ResultStarted     = "started"
	ResultSuccess     = "success"
	ResultDenied      = "denied"
	ResultRateLimited = "rate_limited"
	ResultError       = "error"

	MethodSSO       = "sso"
	MethodDuo       = "duo"
	MethodGuestCode = "guest_code"
	MethodAdmin     = "admin"
)

// EventQueryFilter is a query filter. Empty strings mean no filtering for that dimension.
type EventQueryFilter struct {
	Kind    string
	Method  string
	Result  string
	Subject string
	Since   time.Time // Inclusive.
	Until   time.Time // Inclusive.
	Limit   int       // 0 or negative means unlimited.
}

// EventLog stores events in memory with optional JSONL persistence.
//
// A single lock protects both in-memory events and file writes. This is the key C2 fix: the old
// implementation wrote to disk after releasing mu, allowing Prune and Append disk writes to
// interleave and duplicate events in the file. Append and Prune now complete disk writes while
// holding mu, so they are strictly serialized.
//
// Performance: each Append spends about 0.5ms writing through the OS cache, which is sufficient
// for sub-1k-QPS captive-portal traffic. H4 open/close overhead is removed with a long-lived file
// handle opened at startup and replaced after Prune rewrites.
type EventLog struct {
	mu          sync.Mutex
	events      []Event
	persistPath string
	retention   time.Duration
	logFile     *os.File // Long-lived O_APPEND handle, reused to avoid open/close per Append.
}

// newEventLog constructs an EventLog. persistPath == "" means memory-only.
// Startup loads JSONL and opens the long-lived file handle (H4).
func newEventLog(persistPath string, retention time.Duration) (*EventLog, error) {
	e := &EventLog{
		persistPath: persistPath,
		retention:   retention,
	}
	if persistPath == "" {
		return e, nil
	}
	if err := e.loadFromDisk(); err != nil {
		return nil, err
	}
	if err := e.openLogFile(); err != nil {
		return nil, fmt.Errorf("open log file: %w", err)
	}
	return e, nil
}

// openLogFile opens the long-lived O_APPEND handle. Call with mu held.
func (e *EventLog) openLogFile() error {
	if e.persistPath == "" {
		return nil
	}
	dir := filepath.Dir(e.persistPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	f, err := os.OpenFile(e.persistPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open %s: %w", e.persistPath, err)
	}
	e.logFile = f
	return nil
}

// Close closes the file handle during shutdown.
func (e *EventLog) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.logFile != nil {
		err := e.logFile.Close()
		e.logFile = nil
		return err
	}
	return nil
}

func (e *EventLog) loadFromDisk() error {
	f, err := os.Open(e.persistPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("open %s: %w", e.persistPath, err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	loaded := 0
	broken := 0
	cutoff := e.retentionCutoff()
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var ev Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			broken++
			continue
		}
		if !cutoff.IsZero() && ev.Time.Before(cutoff) {
			continue
		}
		e.events = append(e.events, ev)
		loaded++
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read %s: %w", e.persistPath, err)
	}
	sort.SliceStable(e.events, func(i, j int) bool {
		return e.events[i].Time.Before(e.events[j].Time)
	})
	log.Printf("event log: loaded %d entries from %s (skipped %d malformed)", loaded, e.persistPath, broken)
	return nil
}

func (e *EventLog) retentionCutoff() time.Time {
	if e.retention <= 0 {
		return time.Time{}
	}
	return time.Now().Add(-e.retention)
}

// maxEventsInMemory caps in-memory events to avoid OOM during attacks with a 7-day retention.
// Oldest entries are dropped when exceeded. The on-disk file is only pruned by time.
const maxEventsInMemory = 100000

// Append adds one event. Memory update and disk write happen under the same mu and exclude Prune,
// preventing C2 duplicates. Disk failures are logged and do not block the business path.
func (e *EventLog) Append(ev Event) {
	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append(e.events, ev)
	if len(e.events) > maxEventsInMemory {
		// Drop the oldest 10% in one slice operation instead of shifting O(n) on every Append.
		drop := len(e.events) - maxEventsInMemory*9/10
		e.events = append([]Event(nil), e.events[drop:]...)
	}
	if e.logFile == nil {
		return
	}
	if err := e.appendToDiskLocked(ev); err != nil {
		log.Printf("event log: write failed: %v", err)
	}
}

// appendToDiskLocked must be called with mu held. It uses the long-lived logFile handle.
func (e *EventLog) appendToDiskLocked(ev Event) error {
	data, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	data = append(data, '\n')
	if _, err := e.logFile.Write(data); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return nil
}

// Query returns events matching the filter, newest first.
//
// M6: do not rely on e.events being monotonic. NTP moving backward can make appended events
// out of order. The old reverse scan with early break could apply Limit too soon and miss newer
// events. Now it scans all events, collects matches, sorts by Time descending, and applies Limit.
func (e *EventLog) Query(f EventQueryFilter) []Event {
	subjectLower := strings.ToLower(f.Subject)
	e.mu.Lock()
	defer e.mu.Unlock()
	matched := make([]Event, 0)
	for _, ev := range e.events {
		if matchEvent(ev, f, subjectLower) {
			matched = append(matched, ev)
		}
	}
	sort.Slice(matched, func(i, j int) bool {
		return matched[i].Time.After(matched[j].Time)
	})
	if f.Limit > 0 && len(matched) > f.Limit {
		matched = matched[:f.Limit]
	}
	return matched
}

// matchEvent is the shared predicate for Query and Count. subjectLower is f.Subject lowered once
// before the loop to avoid repeated ToLower calls; the 100k-event benchmark difference is visible.
func matchEvent(ev Event, f EventQueryFilter, subjectLower string) bool {
	if f.Kind != "" && ev.Kind != f.Kind {
		return false
	}
	if f.Method != "" && ev.Method != f.Method {
		return false
	}
	if f.Result != "" && ev.Result != f.Result {
		return false
	}
	if subjectLower != "" {
		if !strings.Contains(strings.ToLower(ev.Subject), subjectLower) {
			return false
		}
	}
	if !f.Since.IsZero() && ev.Time.Before(f.Since) {
		return false
	}
	if !f.Until.IsZero() && ev.Time.After(f.Until) {
		return false
	}
	return true
}

// Count returns the total number of matching events, ignoring Limit.
func (e *EventLog) Count(f EventQueryFilter) int {
	subjectLower := strings.ToLower(f.Subject)
	e.mu.Lock()
	defer e.mu.Unlock()
	n := 0
	for _, ev := range e.events {
		if matchEvent(ev, f, subjectLower) {
			n++
		}
	}
	return n
}

// MultiCount scans the table once and counts several filters. It is used by buildDashboard for
// groups such as {LoginsToday, LoginsWeek, FailedDenied7d, ...}, replacing N full Count scans.
// For 100k events and N=5 this makes /admin load tens of milliseconds faster.
//
// H6 fix. The returned slice has the same length and order as the input filters.
func (e *EventLog) MultiCount(filters []EventQueryFilter) []int {
	subjectLowers := make([]string, len(filters))
	for i, f := range filters {
		subjectLowers[i] = strings.ToLower(f.Subject)
	}
	counts := make([]int, len(filters))
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, ev := range e.events {
		for i, f := range filters {
			if matchEvent(ev, f, subjectLowers[i]) {
				counts[i]++
			}
		}
	}
	return counts
}

// Prune removes entries older than cutoff, rewrites the file, and returns the removed count.
// It holds mu throughout so Append cannot O_APPEND an event already included in the rewrite (C2).
func (e *EventLog) Prune() int {
	cutoff := e.retentionCutoff()
	if cutoff.IsZero() {
		return 0
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	kept := make([]Event, 0, len(e.events))
	removed := 0
	for _, ev := range e.events {
		if ev.Time.Before(cutoff) {
			removed++
			continue
		}
		kept = append(kept, ev)
	}
	e.events = kept
	if removed > 0 && e.persistPath != "" {
		if err := e.rewriteFileLocked(kept); err != nil {
			log.Printf("event log: prune rewrite failed: %v", err)
		}
	}
	return removed
}

// rewriteFileLocked must be called with mu held. It closes the old handle, tmp+renames, then reopens.
func (e *EventLog) rewriteFileLocked(events []Event) error {
	// Close the old handle before rename for conservative cross-platform behavior. Reopen may get a
	// new inode, but OS path resolution stays consistent.
	if e.logFile != nil {
		_ = e.logFile.Close()
		e.logFile = nil
	}
	dir := filepath.Dir(e.persistPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	tmp := e.persistPath + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		// Failing to reopen logFile is non-fatal; the next Append still nil-checks it.
		_ = e.openLogFile()
		return fmt.Errorf("open %s: %w", tmp, err)
	}
	w := bufio.NewWriter(f)
	for _, ev := range events {
		data, err := json.Marshal(ev)
		if err != nil {
			f.Close()
			os.Remove(tmp)
			_ = e.openLogFile()
			return fmt.Errorf("marshal: %w", err)
		}
		if _, err := w.Write(data); err != nil {
			f.Close()
			os.Remove(tmp)
			_ = e.openLogFile()
			return fmt.Errorf("write: %w", err)
		}
		if err := w.WriteByte('\n'); err != nil {
			f.Close()
			os.Remove(tmp)
			_ = e.openLogFile()
			return fmt.Errorf("write: %w", err)
		}
	}
	if err := w.Flush(); err != nil {
		f.Close()
		os.Remove(tmp)
		_ = e.openLogFile()
		return fmt.Errorf("flush: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		_ = e.openLogFile()
		return fmt.Errorf("close: %w", err)
	}
	if err := os.Rename(tmp, e.persistPath); err != nil {
		_ = e.openLogFile()
		return fmt.Errorf("rename: %w", err)
	}
	// Rename succeeded; reopen the long-lived handle against the new file.
	return e.openLogFile()
}

// gcLoop runs Prune hourly.
func (e *EventLog) gcLoop() {
	if e.retention <= 0 {
		return
	}
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for range t.C {
		e.Prune()
	}
}

// --- CSV export ---

// sanitizeCSVCell protects against CSV formula injection. Excel/LibreOffice/Numbers evaluate cells
// starting with = + - @ Tab CR as formulas; attackers can use values such as =WEBSERVICE(...) or
// =cmd|'/c calc'!A0 for exfiltration or RCE. Prefixing a single quote forces plain text.
//
// Only the first character matters. An @ in the middle, such as alice@example.com, is safe.
func sanitizeCSVCell(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

// writeCSVRowSafe sanitizes every cell before writing so callers do not repeat that logic.
// Headers are not filtered because they are hard-coded constants.
func writeCSVRowSafe(cw *csv.Writer, cells []string) error {
	safe := make([]string, len(cells))
	for i, c := range cells {
		safe[i] = sanitizeCSVCell(c)
	}
	return cw.Write(safe)
}

// WriteEventsCSV writes events as CSV with a UTF-8 BOM.
// The BOM keeps Excel from misdetecting UTF-8.
//
// L9 fix: do not `defer cw.Flush()` and then `return cw.Error()`, because defer runs after return
// and loses IO errors from Flush. Explicit Flush + Error checks reliably capture all write errors.
//
// Every data cell passes through sanitizeCSVCell to neutralize formula injection.
func WriteEventsCSV(w http.ResponseWriter, events []Event) error {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="events.csv"`)
	w.Header().Set("Cache-Control", "no-store")
	// UTF-8 BOM
	if _, err := w.Write([]byte{0xEF, 0xBB, 0xBF}); err != nil {
		return err
	}
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"Time", "Kind", "Subject", "Method", "Result", "MAC", "IP", "Detail"}); err != nil {
		return err
	}
	for _, ev := range events {
		if err := writeCSVRowSafe(cw, []string{
			ev.Time.Local().Format("2006-01-02 15:04:05"),
			eventKindLabel(ev.Kind),
			ev.Subject,
			eventMethodLabel(ev.Method),
			eventResultLabel(ev.Result),
			ev.MAC,
			ev.IP,
			ev.Detail,
		}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func eventKindLabel(k string) string {
	switch k {
	case KindLogin:
		return "login"
	case KindAdminAction:
		return "admin"
	default:
		return k
	}
}

func eventMethodLabel(m string) string {
	switch m {
	case MethodSSO:
		return "SSO"
	case MethodDuo:
		return "Duo"
	case MethodGuestCode:
		return "guest_code"
	case MethodAdmin:
		return "admin_console"
	default:
		return m
	}
}

func eventResultLabel(r string) string {
	switch r {
	case ResultStarted:
		return "started"
	case ResultSuccess:
		return "success"
	case ResultDenied:
		return "denied"
	case ResultRateLimited:
		return "rate_limited"
	case ResultError:
		return "error"
	default:
		return r
	}
}

// logLogin is a convenience wrapper for appending login events.
func (a *App) logLogin(subject, result, method, mac, ip, detail string) {
	if a.eventLog == nil {
		return
	}
	a.eventLog.Append(Event{
		Kind:    KindLogin,
		Subject: subject,
		Result:  result,
		Method:  method,
		MAC:     mac,
		IP:      ip,
		Detail:  detail,
	})
}

// logAdminAction is a convenience wrapper for appending admin-action events.
// ip is the admin's current client IP, preserving an audit trail of where changes came from.
// Call sites already have *http.Request and pass clientIP(r) directly.
func (a *App) logAdminAction(adminUPN, ip, result, detail string) {
	if a.eventLog == nil {
		return
	}
	a.eventLog.Append(Event{
		Kind:    KindAdminAction,
		Subject: adminUPN,
		Result:  result,
		Method:  MethodAdmin,
		IP:      ip,
		Detail:  detail,
	})
}
