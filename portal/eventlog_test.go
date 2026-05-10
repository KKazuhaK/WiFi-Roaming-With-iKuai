package main

// eventlog_test.go
// 事件日志的核心语义:
//   - Append → 内存 + 落盘
//   - Query 倒序 + 各种过滤
//   - Prune 按 retention 裁剪
//   - JSONL 持久化 round-trip
//   - maxEventsInMemory 容量上限 (H3 回归)
//   - 不记录敏感数据 — 由调用方保证, 这里只测便捷函数转发正确

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEventLog_AppendAndQuery(t *testing.T) {
	e, _ := newEventLog("", time.Hour)
	now := time.Now()
	e.Append(Event{Time: now, Kind: KindLogin, Subject: "a", Result: ResultSuccess, Method: MethodSSO})
	e.Append(Event{Time: now.Add(time.Second), Kind: KindLogin, Subject: "b", Result: ResultDenied, Method: MethodSSO})

	got := e.Query(EventQueryFilter{})
	if len(got) != 2 {
		t.Fatalf("Query all = %d, want 2", len(got))
	}
	// 倒序 — 最新的在前
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
	e, _ := newEventLog("", 0) // retention=0 = 不裁剪
	e.Append(Event{Time: time.Now().Add(-1000 * time.Hour), Kind: KindLogin})
	if removed := e.Prune(); removed != 0 {
		t.Errorf("Prune with retention=0 removed %d, want 0", removed)
	}
}

// TestEventLog_PersistRoundTrip 保证 JSONL 写入 + 重启加载 的一致性,
// 这是审计日志的基本契约 — 重启不能丢已记录事件.
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
	// events.jsonl 含 UPN / IP / MAC, 文件权限 0600
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

// TestEventLog_MaxInMemoryCap: H3 回归. 内存事件不能无限增长.
// 攻击下 + 7 天保留期可能堆百万事件 → OOM.
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
	// 写一份混杂 JSONL: 合法 + 空行 + 损坏行 + 合法
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

// --- logLogin / logAdminAction 转发 ---

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

// TestLogLogin_NoFullCodeInDetail: H2 关键回归 — 调用方必须只传 code-suffix,
// 不能传完整 code. 这里我们模拟正确的调用并断言 Detail 里没出现完整码.
func TestLogLogin_NoFullCodeInDetail(t *testing.T) {
	app := &App{
		eventLog: func() *EventLog {
			e, _ := newEventLog("", time.Hour)
			return e
		}(),
	}
	fullCode := "1234567890abcdef"
	suffix := tailN(fullCode, 4)
	// main.go 修复后这就是真实调用方式
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
