package main

// eventlog.go
// 结构化事件日志 (登录 + admin 操作). 所有事件同时保留在内存 (供快速查询) 和
// 可选 JSONL 文件 (跨重启保留 + 支持 tail -f 排错).
//
// 存储策略:
//   - Append(): 加锁追加到内存 slice + 一次 O_APPEND 写一条 JSON 行到文件.
//     写文件失败只 log, 不阻塞业务路径.
//   - Query(): 按过滤条件倒序返回, 带 limit.
//   - Prune(): 根据保留期删旧条目, 重写全文件 (cold path, 每小时一次).
//   - persistPath == "" → 纯内存模式.

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

// Event 一条结构化事件.
type Event struct {
	Time    time.Time `json:"time"`
	Kind    string    `json:"kind"`    // 见 Kind 常量
	Subject string    `json:"subject"` // user UPN / guest-xxxxx / admin UPN / "(guest)" / "(unknown)"
	Result  string    `json:"result"`  // success / denied / rate_limited / error
	Method  string    `json:"method"`  // sso / duo / guest_code / admin
	MAC     string    `json:"mac,omitempty"`
	IP      string    `json:"ip,omitempty"`
	Detail  string    `json:"detail,omitempty"`
}

const (
	KindLogin       = "login"
	KindAdminAction = "admin_action"

	ResultSuccess     = "success"
	ResultDenied      = "denied"
	ResultRateLimited = "rate_limited"
	ResultError       = "error"

	MethodSSO       = "sso"
	MethodDuo       = "duo"
	MethodGuestCode = "guest_code"
	MethodAdmin     = "admin"
)

// EventQueryFilter 查询过滤器. 空字符串视为不过滤该维度.
type EventQueryFilter struct {
	Kind    string
	Method  string
	Result  string
	Subject string
	Since   time.Time // 包含
	Until   time.Time // 包含
	Limit   int       // 0 或负数视为不限
}

// EventLog 内存事件存储 + 可选 JSONL 持久化.
type EventLog struct {
	mu          sync.Mutex
	events      []Event
	persistPath string
	retention   time.Duration
}

// newEventLog 构造一个 EventLog. persistPath == "" → 纯内存.
// 启动时会尝试从 JSONL 加载, 格式错只 log 不 fatal — 事件日志不是关键路径.
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
	return e, nil
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
	log.Printf("event log: loaded %d entries from %s (skipped %d malformed)", e.persistPath, loaded, broken)
	return nil
}

func (e *EventLog) retentionCutoff() time.Time {
	if e.retention <= 0 {
		return time.Time{}
	}
	return time.Now().Add(-e.retention)
}

// Append 追加一条事件. 写文件失败只 log.
func (e *EventLog) Append(ev Event) {
	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}
	e.mu.Lock()
	e.events = append(e.events, ev)
	e.mu.Unlock()
	if e.persistPath == "" {
		return
	}
	if err := e.appendToDisk(ev); err != nil {
		log.Printf("event log: write failed: %v", err)
	}
}

func (e *EventLog) appendToDisk(ev Event) error {
	dir := filepath.Dir(e.persistPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	f, err := os.OpenFile(e.persistPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open %s: %w", e.persistPath, err)
	}
	defer f.Close()
	data, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	data = append(data, '\n')
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return nil
}

// Query 按过滤条件倒序 (最新在前) 返回事件.
func (e *EventLog) Query(f EventQueryFilter) []Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Event, 0, len(e.events))
	// 倒序遍历拿最新的在前
	for i := len(e.events) - 1; i >= 0; i-- {
		ev := e.events[i]
		if !matchEvent(ev, f) {
			continue
		}
		out = append(out, ev)
		if f.Limit > 0 && len(out) >= f.Limit {
			break
		}
	}
	return out
}

func matchEvent(ev Event, f EventQueryFilter) bool {
	if f.Kind != "" && ev.Kind != f.Kind {
		return false
	}
	if f.Method != "" && ev.Method != f.Method {
		return false
	}
	if f.Result != "" && ev.Result != f.Result {
		return false
	}
	if f.Subject != "" {
		if !strings.Contains(strings.ToLower(ev.Subject), strings.ToLower(f.Subject)) {
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

// Count 返回匹配过滤条件的事件总数 (不受 Limit 限制).
func (e *EventLog) Count(f EventQueryFilter) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	n := 0
	for _, ev := range e.events {
		if matchEvent(ev, f) {
			n++
		}
	}
	return n
}

// Prune 删除早于 cutoff 的条目, 重写整个文件. 返回删了多少条.
func (e *EventLog) Prune() int {
	cutoff := e.retentionCutoff()
	if cutoff.IsZero() {
		return 0
	}
	e.mu.Lock()
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
	needsRewrite := removed > 0 && e.persistPath != ""
	eventsCopy := append([]Event(nil), kept...)
	e.mu.Unlock()

	if needsRewrite {
		if err := e.rewriteFile(eventsCopy); err != nil {
			log.Printf("event log: prune rewrite failed: %v", err)
		}
	}
	return removed
}

func (e *EventLog) rewriteFile(events []Event) error {
	dir := filepath.Dir(e.persistPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	tmp := e.persistPath + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open %s: %w", tmp, err)
	}
	w := bufio.NewWriter(f)
	for _, ev := range events {
		data, err := json.Marshal(ev)
		if err != nil {
			f.Close()
			os.Remove(tmp)
			return fmt.Errorf("marshal: %w", err)
		}
		if _, err := w.Write(data); err != nil {
			f.Close()
			os.Remove(tmp)
			return fmt.Errorf("write: %w", err)
		}
		if err := w.WriteByte('\n'); err != nil {
			f.Close()
			os.Remove(tmp)
			return fmt.Errorf("write: %w", err)
		}
	}
	if err := w.Flush(); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("flush: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("close: %w", err)
	}
	if err := os.Rename(tmp, e.persistPath); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// gcLoop 每小时跑一次 Prune.
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

// --- CSV 导出 ---

// WriteCSV 把 events 以 UTF-8 BOM + 中文列头的 CSV 格式写到 w.
// BOM 是为了 Excel 不乱码 (Excel 判断 UTF-8 唯一的稳定信号).
func WriteEventsCSV(w http.ResponseWriter, events []Event) error {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="events.csv"`)
	w.Header().Set("Cache-Control", "no-store")
	// UTF-8 BOM
	if _, err := w.Write([]byte{0xEF, 0xBB, 0xBF}); err != nil {
		return err
	}
	cw := csv.NewWriter(w)
	defer cw.Flush()
	if err := cw.Write([]string{"Time", "Kind", "Subject", "Method", "Result", "MAC", "IP", "Detail"}); err != nil {
		return err
	}
	for _, ev := range events {
		if err := cw.Write([]string{
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

// logLogin 登录事件便捷 Append.
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

// logAdminAction admin 操作事件便捷 Append.
// ip 是 admin 当下操作所在的 client IP — 留下"管理员从哪里改的"审计痕迹.
// 调用点都能拿到 *http.Request, 直接 clientIP(r) 传进来.
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
