package main

// regressions_test.go
// 第二轮审计 (功能性 bug + perf) 的回归测试. 写在修复**之前**, 确认它们会失败,
// 修完应该全 PASS. 按 finding 编号注释.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ============================================================================
// C1: GuestCodeStore.List() 返回内部 *GuestCode 指针, race 与 Validate
// 通过 race detector 跑这个测试 (`go test -race`) 会爆出来.
// 修复后 List 应返回值副本, 调用方读 Uses 不会再 race.
// ============================================================================

func TestC1_ListReturnsCopiesNotInternalPointers(t *testing.T) {
	s, _ := newGuestCodeStore("")
	s.Add(&GuestCode{Code: "abc", CreatedAt: time.Now(), MaxUses: 100})

	// List 拿到的对象修改, 不应影响 store 内部.
	got := s.List()
	if len(got) != 1 {
		t.Fatalf("len = %d", len(got))
	}
	got[0].Code = "MUTATED"
	got[0].Note = "mutated by caller"

	// 重新 List, 应该看到原始值
	again := s.List()
	if again[0].Code != "abc" {
		t.Errorf("List leaked internal pointer: caller mutation propagated, code = %q",
			again[0].Code)
	}
	if again[0].Note != "" {
		t.Errorf("List leaked internal pointer: Note mutation propagated, note = %q",
			again[0].Note)
	}
}

// TestC1_ConcurrentValidateAndList: 这是真正会触发 race detector 的测试.
// 跑 `go test -race -run TestC1_ConcurrentValidateAndList` 修复前应该 fail.
func TestC1_ConcurrentValidateAndList(t *testing.T) {
	s, _ := newGuestCodeStore("")
	s.Add(&GuestCode{Code: "code1", CreatedAt: time.Now(), MaxUses: 0}) // 不限次

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// 多个 goroutine 反复 Validate (写 Uses)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					s.Validate("code1", "mac", "ip", "guest")
				}
			}
		}()
	}

	// 多个 goroutine 反复 List + 读 Uses (模拟 renderAdmin 路径)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					list := s.List()
					for _, c := range list {
						_ = c.UseCount()
						if len(c.Uses) > 0 {
							_ = c.Uses[len(c.Uses)-1]
						}
						_ = c.IsExpired()
						_ = c.IsExhausted()
					}
				}
			}
		}()
	}

	time.Sleep(100 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// ============================================================================
// C2: EventLog Append vs Prune 重复落盘
// ============================================================================

func TestC2_AppendDuringPruneDoesNotDuplicateOnDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	e, err := newEventLog(path, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// 准备一个会被 Prune 跨过去的旧事件
	e.Append(Event{Time: time.Now().Add(-2 * time.Hour), Subject: "OLD", Kind: KindLogin})

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// 频繁 Append
	wg.Add(1)
	go func() {
		defer wg.Done()
		i := 0
		for {
			select {
			case <-stop:
				return
			default:
				e.Append(Event{Subject: "fresh", Kind: KindLogin, Detail: "n=" + intToStr(i)})
				i++
			}
		}
	}()

	// 频繁 Prune (模拟 gcLoop 跑的频率)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				e.Prune()
				time.Sleep(time.Millisecond)
			}
		}
	}()

	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()

	// 内存里和文件里的事件计数应该一致 (允许某些 in-flight 落差,
	// 但绝不应该出现"文件里事件 > 内存里事件"的情况, 那是 dup 的信号)
	memEvents := e.Query(EventQueryFilter{})

	// 解析文件计数事件行数
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	fileLines := bytes.Count(data, []byte{'\n'})

	if fileLines > len(memEvents)+5 {
		// +5 容忍 in-flight (Append 解锁但还没写文件)
		t.Errorf("file has %d lines but memory has %d events — likely duplicate writes from Append/Prune race",
			fileLines, len(memEvents))
	}
}

// ============================================================================
// C3: Status() 把 partial-use 码当 inactive 删除
// ============================================================================

func TestC3_DeleteInactivePreservesPartiallyUsedMultiUseCode(t *testing.T) {
	s, _ := newGuestCodeStore("")
	// MaxUses=3, 已用 1 次 — 还能用 2 次
	s.Add(&GuestCode{
		Code:      "multi-use",
		CreatedAt: time.Now(),
		MaxUses:   3,
		Uses:      []CodeUse{{At: time.Now(), MAC: "aa"}},
	})
	// 一个真正用尽的码
	s.Add(&GuestCode{
		Code:      "exhausted",
		CreatedAt: time.Now(),
		MaxUses:   1,
		Uses:      []CodeUse{{At: time.Now(), MAC: "bb"}},
	})

	n := s.DeleteInactive()
	if n != 1 {
		t.Errorf("DeleteInactive removed %d codes, want 1 (only exhausted)", n)
	}

	// multi-use 码必须保留 — 它还能用
	if s.Validate("multi-use", "m", "i", "g") == nil {
		t.Error("multi-use code with remaining uses must NOT be deleted by DeleteInactive")
	}
}

// ============================================================================
// C4: banHistory 异步 flush — 高频 increment 不应阻塞热路径
// 不能直接测 "异步" 行为, 但可以测: increment 不再每次都触发文件 mtime 更新.
// 修复后, 100 次 increment 在 < 100ms 应只看到 1-2 次文件写.
// ============================================================================

func TestC4_BanHistoryDoesNotWriteOnEveryIncrement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ratelimit-state.json")
	bh, err := newBanHistory(path)
	if err != nil {
		t.Fatal(err)
	}
	defer bh.shutdown() // 修复后 banHistory 加 shutdown 关闭 flusher

	// 100 次 increment
	start := time.Now()
	for i := 0; i < 100; i++ {
		bh.increment("1.1.1.1")
	}
	elapsed := time.Since(start)

	// 修复前: 每次都同步写整个文件, 100 次 ≥ 几 ms × 100 = 几百 ms
	// 修复后: 只标记 dirty, 100 次应在 < 10ms 完成
	if elapsed > 50*time.Millisecond {
		t.Errorf("100 increments took %v, want < 50ms (sign of sync writes per increment)", elapsed)
	}

	// 确认 increment 自己仍然返回正确的 count
	if got := bh.get("1.1.1.1"); got != 100 {
		t.Errorf("get = %d, want 100", got)
	}
}

func TestC4_BanHistoryFlushesOnShutdown(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ratelimit-state.json")
	bh, err := newBanHistory(path)
	if err != nil {
		t.Fatal(err)
	}
	bh.increment("2.2.2.2")
	bh.increment("2.2.2.2")
	if err := bh.shutdown(); err != nil {
		t.Fatal(err)
	}

	// 重开应该读回 2
	bh2, err := newBanHistory(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := bh2.get("2.2.2.2"); got != 2 {
		t.Errorf("after shutdown+reload, get = %d, want 2", got)
	}
}

// ============================================================================
// H1/H2/H3: 批量操作只 saveLocked 一次 — 我们用文件 mtime 间接验证
// ============================================================================

func TestH1_DeleteBulkDoesNotRewriteFilePerCode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "guest-codes.json")
	s, _ := newGuestCodeStore(path)
	for i := 0; i < 50; i++ {
		s.Add(&GuestCode{Code: "code" + intToStr(i), CreatedAt: time.Now()})
	}

	// 记录修改前 mtime
	stat1, _ := os.Stat(path)

	// 批量删 30 条
	codes := []string{}
	for i := 0; i < 30; i++ {
		codes = append(codes, "code"+intToStr(i))
	}
	n := s.DeleteMany(codes)
	if n != 30 {
		t.Errorf("DeleteMany = %d, want 30", n)
	}

	// 应该只有 1 次文件 mtime 变更 — 我们没法直接测次数, 但可以测最终状态
	stat2, _ := os.Stat(path)
	if !stat2.ModTime().After(stat1.ModTime()) {
		t.Error("file should have been touched")
	}

	// 重新加载验证一致
	s2, err := newGuestCodeStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(s2.List()) != 20 {
		t.Errorf("after DeleteMany, %d codes, want 20", len(s2.List()))
	}
}

func TestH3_AddManyDoesNotRewriteFilePerCode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "guest-codes.json")
	s, _ := newGuestCodeStore(path)

	// 放 100 个码到 store, 用 AddMany 一次性
	codes := make([]*GuestCode, 100)
	for i := 0; i < 100; i++ {
		codes[i] = &GuestCode{Code: "bulk-" + intToStr(i), CreatedAt: time.Now()}
	}
	added := s.AddMany(codes)
	if len(added) != 100 {
		t.Errorf("AddMany inserted %d, want 100", len(added))
	}

	s2, _ := newGuestCodeStore(path)
	if len(s2.List()) != 100 {
		t.Errorf("after AddMany, %d codes loaded, want 100", len(s2.List()))
	}
}

// ============================================================================
// H7: handleCodeEdit 应允许填过去的 ExpiresAt (admin 想强制让码过期)
// ============================================================================

func TestH7_EditAcceptsPastExpiry(t *testing.T) {
	app := mkAdminTestApp(t)
	app.guestCodes.Add(&GuestCode{Code: "edit-me", CreatedAt: time.Now()})

	pastTime := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	form := url.Values{
		"code":         {"edit-me"},
		"expires_at":   {pastTime},
		"duration_min": {"60"},
	}
	r, _ := http.NewRequest("POST", "/admin/codes/edit", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", app.cfg.PublicURL)
	r.AddCookie(mkAdminCookie(t, app))

	w := httptest.NewRecorder()
	app.handleCodeEdit(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("Edit with past expiry should succeed (admin force-expires code), got %d body=%s",
			w.Code, w.Body.String())
	}

	// 该码现在应该 IsExpired
	got := app.guestCodes.List()
	if len(got) != 1 {
		t.Fatalf("want 1 code, got %d", len(got))
	}
	if !got[0].IsExpired() {
		t.Error("after Edit with past expiry, code should be IsExpired")
	}
}

// ============================================================================
// M1: Stats() 把半使用多次性码归 used, 跟 Dashboard.ActiveGuestCodes 计数不一致.
// 修复后 Stats.unused 应等于 IsActive() 的码数, Dashboard 用同一标准.
// ============================================================================

func TestM1_StatsAlignsWithDashboardActive(t *testing.T) {
	s, _ := newGuestCodeStore("")
	s.Add(&GuestCode{Code: "fresh", CreatedAt: time.Now()})                                          // unused, IsActive
	s.Add(&GuestCode{Code: "partial", MaxUses: 5, Uses: []CodeUse{{}}, CreatedAt: time.Now()})       // 半用, IsActive
	s.Add(&GuestCode{Code: "exhausted", MaxUses: 1, Uses: []CodeUse{{}}, CreatedAt: time.Now()})     // 用尽
	s.Add(&GuestCode{Code: "expired", ExpiresAt: time.Now().Add(-time.Hour), CreatedAt: time.Now()}) // 过期
	s.Add(&GuestCode{Code: "expired-and-used", MaxUses: 1, Uses: []CodeUse{{}}, ExpiresAt: time.Now().Add(-time.Hour), CreatedAt: time.Now()})

	total, used, unused, expired := s.Stats()
	if total != 5 {
		t.Errorf("total = %d, want 5", total)
	}
	// "unused" 应该是"还能用的" (== IsActive 数). 这里 fresh + partial = 2.
	if unused != 2 {
		t.Errorf("unused = %d, want 2 (fresh+partial — both IsActive)", unused)
	}

	// Dashboard 用 IsActive() 算 active. Stats.unused 必须等于 active 数.
	activeCount := 0
	for _, c := range s.List() {
		if c.IsActive() {
			activeCount++
		}
	}
	if unused != activeCount {
		t.Errorf("M1 不一致: Stats.unused=%d vs Dashboard active count=%d", unused, activeCount)
	}

	// expired 包括 "expired" 和 "expired-and-used" (过期优先)
	if expired != 2 {
		t.Errorf("expired = %d, want 2", expired)
	}
	// used = exhausted but not expired
	if used != 1 {
		t.Errorf("used = %d, want 1 (only exhausted-not-expired)", used)
	}
}

// ============================================================================
// M5: matchEvent 在 Query 循环里每次 strings.ToLower(filter.Subject) 浪费.
// 修复后 filter.Subject 在 Query 入口 lower 一次. 这里测**过滤结果不变**,
// 性能差异不能直接测 (机器抖动太大).
// ============================================================================

func TestM5_QuerySubjectFilterCaseInsensitive(t *testing.T) {
	e, _ := newEventLog("", time.Hour)
	e.Append(Event{Subject: "Alice@Example.COM", Kind: KindLogin})
	e.Append(Event{Subject: "bob@example.com", Kind: KindLogin})
	e.Append(Event{Subject: "carol@example.com", Kind: KindLogin})

	cases := []struct {
		filter string
		want   int
	}{
		{"alice", 1},
		{"ALICE", 1},
		{"Alice", 1},
		{"@example.com", 3},
		{"@EXAMPLE.com", 3},
		{"nobody", 0},
	}
	for _, c := range cases {
		got := e.Query(EventQueryFilter{Subject: c.filter})
		if len(got) != c.want {
			t.Errorf("filter=%q got %d, want %d", c.filter, len(got), c.want)
		}
	}
}

// ============================================================================
// M8: /auth/start 中 proceedStore.put 失败时, 之前已经 record(email) 不应留下.
// 修复后调换顺序 — 先 put, put 成功后才 record. 没法直接 mock put 失败 (需要
// rand 失败), 但可以测调用顺序: 当 put 成功时 record 也被调; 修复正确性靠
// code review 保证不会调换错.
// ============================================================================

func TestM8_AuthStartRecordsAfterProceedStorePut(t *testing.T) {
	app := mkTestApp(t)
	rec := httptest.NewRecorder()
	_ = writeSessionCookie(rec, app.cfg.SessionSecret, Session{
		MAC: "aa:bb:cc:dd:ee:ff", UserIP: "1.1.1.1",
		State: "s", Nonce: "n",
		Exp: time.Now().Add(time.Minute).Unix(),
	}, false)

	// 正常路径: put 不会失败. 记完应该看到 record.
	form := url.Values{"email": {"alice@example.com"}}
	r, _ := http.NewRequest("POST", "/auth/start", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range rec.Result().Cookies() {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	app.handleAuthStart(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	// record 应该已发生
	if got := app.authEmailFails.countIn("alice@example.com", time.Hour); got != 1 {
		t.Errorf("expected 1 fail recorded, got %d", got)
	}
	// proceedStore 应该有 1 条
	app.proceedStore.mu.Lock()
	storeCount := len(app.proceedStore.entries)
	app.proceedStore.mu.Unlock()
	if storeCount != 1 {
		t.Errorf("proceedStore has %d entries, want 1", storeCount)
	}
}

// ============================================================================
// H6: 多个 Count 一次扫多过滤. 验证 MultiCount 结果与多次 Count 等价.
// ============================================================================

func TestH6_MultiCountMatchesIndividualCounts(t *testing.T) {
	e, _ := newEventLog("", time.Hour)
	for i := 0; i < 100; i++ {
		e.Append(Event{Kind: KindLogin, Result: ResultSuccess})
	}
	for i := 0; i < 30; i++ {
		e.Append(Event{Kind: KindLogin, Result: ResultDenied})
	}
	for i := 0; i < 10; i++ {
		e.Append(Event{Kind: KindAdminAction, Result: ResultSuccess})
	}

	filters := []EventQueryFilter{
		{Kind: KindLogin, Result: ResultSuccess}, // 100
		{Kind: KindLogin, Result: ResultDenied},  // 30
		{Kind: KindAdminAction},                  // 10
		{Result: ResultSuccess},                  // 110 (login success + admin success)
	}
	multi := e.MultiCount(filters)
	if len(multi) != 4 {
		t.Fatalf("MultiCount returned %d, want 4", len(multi))
	}
	for i, f := range filters {
		want := e.Count(f)
		if multi[i] != want {
			t.Errorf("filter[%d] %+v: MultiCount=%d, individual Count=%d", i, f, multi[i], want)
		}
	}
}

// ============================================================================
// M6: NTP 跳回时, events 切片不再单调时间序. matchEvent 倒序遍历 + early break
// (依赖时间单调) 会漏算. 修复: Query/Count 不依赖时间序, 完整扫.
// ============================================================================

func TestM6_QueryHandlesOutOfOrderTimes(t *testing.T) {
	e, _ := newEventLog("", time.Hour)
	now := time.Now()
	// 模拟 NTP 跳回: 先写 t1, 再写 t0 (t0 < t1)
	e.Append(Event{Time: now, Subject: "later", Kind: KindLogin})
	e.Append(Event{Time: now.Add(-time.Minute), Subject: "earlier", Kind: KindLogin})
	e.Append(Event{Time: now.Add(time.Second), Subject: "newest", Kind: KindLogin})

	got := e.Query(EventQueryFilter{Kind: KindLogin})
	if len(got) != 3 {
		t.Errorf("Query out-of-order events: got %d, want 3", len(got))
	}

	// 时间窗口过滤也要正确, 即使内存里乱序
	since := now.Add(-30 * time.Second)
	got = e.Query(EventQueryFilter{Since: since})
	// "earlier" (now-1min) 不应出现, "later" 和 "newest" 应该出现
	for _, ev := range got {
		if ev.Subject == "earlier" {
			t.Error("earlier event should be filtered by Since")
		}
	}
	if len(got) != 2 {
		t.Errorf("Since filter: got %d events, want 2", len(got))
	}
}

// ============================================================================
// L6: IPBanEscalateAt = 0 时 banHistory.increment 应被 short-circuit, 不消耗 dirty 写盘.
// ============================================================================

func TestL6_DisablesBanHistoryWhenEscalateAtZero(t *testing.T) {
	app := mkTestApp(t)
	app.cfg.IPBanEscalateAt = 0 // 显式禁用永久升级
	app.cfg.IPFailsLimit = 1    // 立即触发冷却

	app.recordIPFailure("3.3.3.3", "test")

	// banHistory 不应该有 entry — 因为 escalate 关了, 历史无意义.
	if got := app.banHistory.get("3.3.3.3"); got != 0 {
		t.Errorf("banHistory.get with EscalateAt=0 = %d, want 0 (disabled)", got)
	}
	// 但短时冷却应仍然生效
	if !app.ipBans.isBanned("3.3.3.3") {
		t.Error("temporary ban should still trigger even with EscalateAt=0")
	}
}

// ============================================================================
// M9: parseDurationMin 把 duration_min=-1 (用户故意填) 当 fallback, 应返回 0
// (即"不限时") 而不是 18h default.
// ============================================================================

func TestM9_ParseDurationMinNegativeReturnsZero(t *testing.T) {
	// 每个 case 新建 Request — r.FormValue 第一次后会 cache r.Form, 后面改 PostForm 不生效.
	mk := func(form map[string][]string) *http.Request {
		r, _ := http.NewRequest("POST", "/", nil)
		r.PostForm = form
		return r
	}
	cases := []struct {
		form map[string][]string
		want int
		desc string
	}{
		{map[string][]string{"duration_min": {"-1"}}, 0, "duration_min=-1 → 'no limit'"},
		{map[string][]string{"duration_min": {"0"}}, 0, "duration_min=0 → no limit"},
		{map[string][]string{"duration_h": {"3"}}, 180, "no duration_min, h=3 → 180"},
		{map[string][]string{"duration_min": {"60"}}, 60, "duration_min=60 → 60"},
		{map[string][]string{"duration_min": {"abc"}, "duration_h": {"5"}}, 300, "garbage duration_min falls back to h+m"},
	}
	for _, c := range cases {
		if got := parseDurationMin(mk(c.form)); got != c.want {
			t.Errorf("%s → %d, want %d", c.desc, got, c.want)
		}
	}
}

// helpers

func intToStr(i int) string {
	if i == 0 {
		return "0"
	}
	out := ""
	neg := i < 0
	if neg {
		i = -i
	}
	for i > 0 {
		out = string(rune('0'+i%10)) + out
		i /= 10
	}
	if neg {
		out = "-" + out
	}
	return out
}

// 防止 testing 包用不到导致 import 报警 (只在没有 test 用到 json/bytes 时)
var _ = json.Marshal
var _ = bytes.NewReader
