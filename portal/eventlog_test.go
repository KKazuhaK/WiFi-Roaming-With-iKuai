package main

// eventlog_test.go
// Core event-log semantics:
//   - Append writes memory and disk.
//   - Query returns newest first with filters.
//   - Prune trims by retention.
//   - JSONL persistence round-trip.
//   - maxEventsInMemory cap (H3 regression).
//   - Sensitive-data avoidance is caller-owned; these tests check wrapper forwarding only.

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testCSVResponseWriter is a minimal http.ResponseWriter for CSV tests and collects body into bytes.Buffer.
type testCSVResponseWriter struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func newTestCSVResponseWriter() *testCSVResponseWriter {
	return &testCSVResponseWriter{header: make(http.Header)}
}

func (w *testCSVResponseWriter) Header() http.Header       { return w.header }
func (w *testCSVResponseWriter) Write(b []byte) (int, error) { return w.body.Write(b) }
func (w *testCSVResponseWriter) WriteHeader(code int)        { w.status = code }

func TestEventLog_AppendAndQuery(t *testing.T) {
	e, _ := newEventLog("", time.Hour)
	now := time.Now()
	e.Append(Event{Time: now, Kind: KindLogin, Subject: "a", Result: ResultSuccess, Method: MethodSSO})
	e.Append(Event{Time: now.Add(time.Second), Kind: KindLogin, Subject: "b", Result: ResultDenied, Method: MethodSSO})

	got := e.Query(EventQueryFilter{})
	if len(got) != 2 {
		t.Fatalf("Query all = %d, want 2", len(got))
	}
	// Newest first.
	if got[0].Subject != "b" {
		t.Errorf("first event subject = %q, want b (newest)", got[0].Subject)
	}
}

func TestEventLog_QueryFilters(t *testing.T) {
	e, _ := newEventLog("", time.Hour)
	now := time.Now()
	e.Append(Event{Time: now, Kind: KindLogin, Subject: "alice@x", Result: ResultSuccess, Method: MethodSSO})
	e.Append(Event{Time: now, Kind: KindLogin, Subject: "bob@x", Result: ResultDenied, Method: MethodDuo})
	e.Append(Event{Time: now, Kind: KindAdminAction, Subject: "admin@x", Result: ResultSuccess, Method: MethodAdmin})

	cases := []struct {
		name string
		f    EventQueryFilter
		want int
	}{
		{"by Kind", EventQueryFilter{Kind: KindLogin}, 2},
		{"by Result", EventQueryFilter{Result: ResultSuccess}, 2},
		{"by Method", EventQueryFilter{Method: MethodDuo}, 1},
		{"by Subject substring", EventQueryFilter{Subject: "alice"}, 1},
		{"by Subject case-insensitive", EventQueryFilter{Subject: "ALICE"}, 1},
		{"limit 1", EventQueryFilter{Limit: 1}, 1},
		{"compound", EventQueryFilter{Kind: KindLogin, Result: ResultSuccess}, 1},
		{"no match", EventQueryFilter{Subject: "ghost"}, 0},
	}
	for _, c := range cases {
		if got := e.Query(c.f); len(got) != c.want {
			t.Errorf("%s: got %d, want %d", c.name, len(got), c.want)
		}
	}
}

func TestEventLog_QueryTimeRange(t *testing.T) {
	e, _ := newEventLog("", time.Hour)
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		e.Append(Event{Time: t0.Add(time.Duration(i) * time.Hour), Kind: KindLogin, Subject: "u"})
	}
	got := e.Query(EventQueryFilter{
		Since: t0.Add(time.Hour),
		Until: t0.Add(3 * time.Hour),
	})
	if len(got) != 3 { // hour 1, 2, 3
		t.Errorf("time-range filter got %d, want 3", len(got))
	}
}

func TestEventLog_Count(t *testing.T) {
	e, _ := newEventLog("", time.Hour)
	for i := 0; i < 10; i++ {
		e.Append(Event{Kind: KindLogin, Result: ResultSuccess})
	}
	for i := 0; i < 3; i++ {
		e.Append(Event{Kind: KindLogin, Result: ResultDenied})
	}
	if n := e.Count(EventQueryFilter{Result: ResultSuccess}); n != 10 {
		t.Errorf("Count success = %d, want 10", n)
	}
	if n := e.Count(EventQueryFilter{Result: ResultDenied}); n != 3 {
		t.Errorf("Count denied = %d, want 3", n)
	}
}

func TestEventLog_PruneByRetention(t *testing.T) {
	e, _ := newEventLog("", time.Hour)
	now := time.Now()
	e.Append(Event{Time: now.Add(-2 * time.Hour), Kind: KindLogin, Subject: "old"})
	e.Append(Event{Time: now.Add(-30 * time.Minute), Kind: KindLogin, Subject: "fresh"})
	e.Append(Event{Time: now, Kind: KindLogin, Subject: "newest"})

	removed := e.Prune()
	if removed != 1 {
		t.Errorf("Prune removed %d, want 1", removed)
	}
	got := e.Query(EventQueryFilter{})
	for _, ev := range got {
		if ev.Subject == "old" {
			t.Errorf("old event survived prune: %+v", ev)
		}
	}
}

func TestEventLog_PruneNoOpWithoutRetention(t *testing.T) {
	e, _ := newEventLog("", 0) // retention=0 means no pruning.
	e.Append(Event{Time: time.Now().Add(-1000 * time.Hour), Kind: KindLogin})
	if removed := e.Prune(); removed != 0 {
		t.Errorf("Prune with retention=0 removed %d, want 0", removed)
	}
}

// TestEventLog_PersistRoundTrip ensures JSONL write and restart load are consistent.
// Audit logs must not lose recorded events across restart.
func TestEventLog_PersistRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")

	{
		e, err := newEventLog(path, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		e.Append(Event{Kind: KindLogin, Subject: "alice", Result: ResultSuccess, Method: MethodSSO,
			MAC: "aa:bb", IP: "1.1.1.1", Detail: "ok"})
		e.Append(Event{Kind: KindAdminAction, Subject: "admin@x", Result: ResultSuccess, Method: MethodAdmin,
			Detail: "ban mac=xx"})
	}
	{
		e2, err := newEventLog(path, time.Hour)
		if err != nil {
			t.Fatalf("reload: %v", err)
		}
		got := e2.Query(EventQueryFilter{})
		if len(got) != 2 {
			t.Fatalf("reload count = %d, want 2", len(got))
		}
	}
}

func TestEventLog_PersistFileMode(t *testing.T) {
	// events.jsonl contains UPN/IP/MAC, so file mode is 0600.
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	e, err := newEventLog(path, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	e.Append(Event{Kind: KindLogin, Subject: "u"})
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Errorf("events.jsonl mode = %o, want no group/other", info.Mode().Perm())
	}
}

// TestEventLog_MaxInMemoryCap is the H3 regression: memory events must not grow without bound.
// Attack traffic plus a 7-day retention could otherwise accumulate millions of events and OOM.
func TestEventLog_MaxInMemoryCap(t *testing.T) {
	e, _ := newEventLog("", 0)
	for i := 0; i < maxEventsInMemory+5000; i++ {
		e.Append(Event{Kind: KindLogin, Subject: "u"})
	}
	got := e.Query(EventQueryFilter{Limit: 0})
	if len(got) > maxEventsInMemory {
		t.Errorf("in-memory events overflowed cap: %d > %d", len(got), maxEventsInMemory)
	}
}

func TestEventLog_LoadSkipsBrokenLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	// Write mixed JSONL: valid + empty + broken + valid.
	content := `{"time":"2026-05-08T00:00:00Z","kind":"login","subject":"a","result":"success"}
this-is-not-json
{"time":"2026-05-08T00:00:01Z","kind":"login","subject":"b","result":"success"}

`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := newEventLog(path, 365*24*time.Hour)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	got := e.Query(EventQueryFilter{})
	if len(got) != 2 {
		t.Errorf("loaded %d events, want 2 (broken line should be skipped, not fatal)", len(got))
	}
}

// --- logLogin / logAdminAction forwarding ---

func TestLogLogin_PreservesFields(t *testing.T) {
	app := &App{
		eventLog: func() *EventLog {
			e, _ := newEventLog("", time.Hour)
			return e
		}(),
	}
	app.logLogin("user@x", ResultSuccess, MethodGuestCode, "aa:bb", "1.1.1.1", "code-suffix=1234")
	got := app.eventLog.Query(EventQueryFilter{})
	if len(got) != 1 {
		t.Fatalf("expected 1 event, got %d", len(got))
	}
	ev := got[0]
	if ev.Kind != KindLogin || ev.Subject != "user@x" || ev.Method != MethodGuestCode ||
		ev.MAC != "aa:bb" || ev.IP != "1.1.1.1" || ev.Detail != "code-suffix=1234" {
		t.Errorf("event fields wrong: %+v", ev)
	}
}

// --- CSV formula injection defense (audit #3) ---

// sanitizeCSVCell: fields starting with = + - @ Tab CR are parsed as formulas by spreadsheet apps.
// Prefix a single quote before writing CSV to force plain text.
func TestSanitizeCSVCell_NeutralizesFormulaPrefixes(t *testing.T) {
	dangerous := []string{
		"=1+1",
		"=cmd|'/c calc'!A0",
		"+1",
		"-1",
		"@SUM(A1:A10)",
		"\t=1+1",
		"\r=1+1",
	}
	for _, in := range dangerous {
		got := sanitizeCSVCell(in)
		if got == in {
			t.Errorf("sanitizeCSVCell(%q) returned unchanged %q, want '-prefix", in, got)
		}
		if !strings.HasPrefix(got, "'") {
			t.Errorf("sanitizeCSVCell(%q) = %q, want leading single quote", in, got)
		}
	}
}

func TestSanitizeCSVCell_PassesThroughSafeText(t *testing.T) {
	safe := []string{
		"",
		"alice@example.com", // @ in the middle is a valid email and should not change.
		"aa:bb:cc:dd:ee:ff",
		"some note",
		"123",
		"normal text",
	}
	for _, in := range safe {
		got := sanitizeCSVCell(in)
		if got != in {
			t.Errorf("sanitizeCSVCell(%q) = %q, want unchanged", in, got)
		}
	}
}

func TestWriteEventsCSV_SanitizesFormulaInjection(t *testing.T) {
	rec := newTestCSVResponseWriter()
	events := []Event{
		{
			Time:    time.Unix(1700000000, 0),
			Kind:    KindLogin,
			Subject: "=BAD()",         // Attacker-controlled subject.
			Result:  ResultSuccess,
			Method:  MethodSSO,
			MAC:     "aa:bb:cc:dd:ee:ff",
			IP:      "1.1.1.1",
			Detail:  "+evil",
		},
	}
	if err := WriteEventsCSV(rec, events); err != nil {
		t.Fatalf("WriteEventsCSV: %v", err)
	}
	body := rec.body.String()
	// Attack cells must be prefixed and cannot keep leading = / +.
	if strings.Contains(body, ",=BAD()") || strings.Contains(body, ",+evil") {
		t.Errorf("CSV body did not sanitize formula prefix: %s", body)
	}
	// Legitimate email-shaped IP/MAC/time fields are unaffected.
	if !strings.Contains(body, "aa:bb:cc:dd:ee:ff") {
		t.Errorf("MAC missing from CSV: %s", body)
	}
}

// TestLogLogin_NoFullCodeInDetail is the H2 regression: callers must pass only code suffixes, not
// full codes. This simulates correct usage and asserts Detail does not contain the full code.
func TestLogLogin_NoFullCodeInDetail(t *testing.T) {
	app := &App{
		eventLog: func() *EventLog {
			e, _ := newEventLog("", time.Hour)
			return e
		}(),
	}
	fullCode := "1234567890abcdef"
	suffix := tailN(fullCode, 4)
	// This matches the real call pattern after the main.go fix.
	app.logLogin("guest-1", ResultSuccess, MethodGuestCode, "aa:bb", "1.1.1.1", "code-suffix="+suffix)
	got := app.eventLog.Query(EventQueryFilter{})
	if len(got) != 1 {
		t.Fatalf("want 1 event")
	}
	if strings.Contains(got[0].Detail, fullCode) {
		t.Errorf("Detail leaked full code: %q", got[0].Detail)
	}
	if !strings.Contains(got[0].Detail, "cdef") {
		t.Errorf("Detail should contain suffix 'cdef', got %q", got[0].Detail)
	}
}
