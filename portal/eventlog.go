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
//
// 单锁 (mu): 同时保护内存 events + 文件写入. C2 修复关键: Append 释放 mu 之后
// 才写盘的旧实现会让 Prune (在 Append 之后入 mu, copy 内存, 释放 mu, rewrite 全量)
// 和 Append 的 disk write 互相穿插, 造成事件在文件里被重复落盘. 现在 Append/Prune
// 在持 mu 期间一并完成 disk write, 二者必然顺序串行.
//
// 性能上: 每条 Append 多花 ~0.5ms 写盘 (磁盘缓存命中) — captive portal 负载不到
// 1k QPS, 完全够用. open/close 开销 (H4) 通过 long-lived file handle 消除:
// 启动时一次 OpenFile, Prune rewrite 时关旧 handle / 开新 handle.
type EventLog struct {
	mu          sync.Mutex
	events      []Event
	persistPath string
	retention   time.Duration
	logFile     *os.File // long-lived O_APPEND handle, 复用以避免每条 Append 都 open/close
}

// newEventLog 构造一个 EventLog. persistPath == "" → 纯内存.
// 启动时会尝试从 JSONL 加载 + 打开长期 file handle (H4).
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

// openLogFile 打开 long-lived O_APPEND handle. 持 mu 时调.
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

// Close 关闭 file handle. shutdown 时调用.
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

// maxEventsInMemory 内存里事件最大条数. 防攻击下事件爆炸 + 7 天保留期间内 OOM.
// 超过则丢最老的. 落盘文件不受这个限制 (Prune 按时间裁剪).
const maxEventsInMemory = 100000

// Append 追加一条事件. 内存 + 写盘在同一把 mu 内完成, 跟 Prune 互斥, 防 C2 dup.
// 写盘失败只 log, 不阻塞 — 事件日志不是关键业务路径.
func (e *EventLog) Append(ev Event) {
	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append(e.events, ev)
	if len(e.events) > maxEventsInMemory {
		// 砍最老的 10%, 一次性切 — 比每次 Append 都 shift O(n) 划算
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

// appendToDiskLocked: 必须持 mu 调用. 用 long-lived logFile 句柄, 不再每条 open/close.
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

// Query 按过滤条件倒序 (最新在前) 返回事件.
//
// M6: 不再依赖 e.events 的时间单调递增 — NTP 跳回时, Append 后切片可能乱序.
// 旧实现倒序扫 + early break, 在乱序场景会 limit 提前截断漏算最新事件.
// 现改为完整扫 → 收集 match → 按 Time 倒序排序 → 取前 Limit 条.
// 100k events 时多花 ~10ms, admin 操作可接受.
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

// matchEvent 是 Query / Count 共用的过滤判定. subjectLower 是 f.Subject 提前 lower
// 一次的结果 — 避免在循环里每次都 ToLower(f.Subject). 100k 事件 × 1 次的差异是
// real benchmark 可观察的 (M5 修复).
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

// Count 返回匹配过滤条件的事件总数 (不受 Limit 限制).
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

// MultiCount 一次扫表对多个过滤条件分别计数. 用于 buildDashboard 这种要拿
// {LoginsToday, LoginsWeek, FailedDenied7d, ...} 多组数字的场景 — 取代 N 次
// Count 的 N 次全表扫. 100k 事件 × N=5 → N=1, 实测 admin /admin 加载快几十 ms.
//
// H6 修复. 返回 slice 长度跟入参一致, 顺序对应.
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

// Prune 删除早于 cutoff 的条目, 重写整个文件. 返回删了多少条.
// 全程持 mu — 避免 Append 在锁外把刚被 rewrite 包含的事件再 O_APPEND 一遍 (C2).
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

// rewriteFileLocked: 必须持 mu. 关旧 handle, tmp+rename, 重开新 handle.
func (e *EventLog) rewriteFileLocked(events []Event) error {
	// 关旧 handle 后才能安全 rename — Linux 上其实可以 rename 已打开文件,
	// macOS 也行, 但保险起见先关. 重开后 inode 可能换, 但 OS 路径解析一致.
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
		// 重开 logFile 失败不致命 — 下次 Append 仍会 nil-check
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
	// rename 成功, 重开 long-lived handle 指向新文件
	return e.openLogFile()
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

// sanitizeCSVCell: CSV 注入防护. Excel/LibreOffice/Numbers 会把以
//   = + - @ Tab CR
// 起头的 cell 当公式求值, 攻击者可构造 =WEBSERVICE(...) / =cmd|'/c calc'!A0
// 之类做 RCE 或外联. 我们在前面塞一个单引号把 cell 强制成纯文本.
//
// 注意: 只看首字符. 中段的 @ (如 alice@example.com) 不算.
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

// writeCSVRowSafe 把每个 cell 过一遍 sanitizeCSVCell 再写, 避免每个 caller
// 都得手动包一遍. 列头不过滤 — 列头是我们硬编码的常量, 不可能命中.
func writeCSVRowSafe(cw *csv.Writer, cells []string) error {
	safe := make([]string, len(cells))
	for i, c := range cells {
		safe[i] = sanitizeCSVCell(c)
	}
	return cw.Write(safe)
}

// WriteCSV 把 events 以 UTF-8 BOM + 中文列头的 CSV 格式写到 w.
// BOM 是为了 Excel 不乱码 (Excel 判断 UTF-8 唯一的稳定信号).
//
// L9 修复: 不能 `defer cw.Flush()` 后 `return cw.Error()` — defer 在 return 之后跑,
// Flush 内部的 IO 错误丢失. 显式 Flush + 检查 Error 才能可靠拿到所有写错误.
//
// 每行数据 cell 走 sanitizeCSVCell 中和公式注入.
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
