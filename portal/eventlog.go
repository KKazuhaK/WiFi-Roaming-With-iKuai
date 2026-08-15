package main

// eventlog.go
// Event record type, constants, query filter, and CSV export.
//
// Storage lives in store_eventlog.go. What stays here is the vocabulary the rest
// of the portal logs against and the export the admin page downloads.

import (
	"encoding/csv"
	"net/http"
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
