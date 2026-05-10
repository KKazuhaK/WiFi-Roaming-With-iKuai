package main

// ratelimit_test.go
// 失败计数 / 冷却 / 永久封禁 升级 的核心语义. 重点测:
//   - failCounter 窗口边界
//   - failCounter reset / resetAll 行为
//   - ipBanList 自动过期
//   - banHistory increment / reset
//   - clearSuccessfulAuthState **不**清 banHistory (M3 修复回归)
//   - recordIPFailure 触发冷却 / 触发永久升级
//   - usedStateSet TTL 自动过期

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// --- failCounter ---

func TestFailCounter_WindowBoundary(t *testing.T) {
	c := newFailCounter(time.Minute)

	c.record("a")
	c.record("a")
	c.record("a")

	if got := c.countIn("a", time.Minute); got != 3 {
		t.Errorf("countIn 1m = %d, want 3", got)
	}
	// 远超的 0 长度窗口应该返回 0.
	if got := c.countIn("a", time.Nanosecond); got != 0 {
		t.Errorf("countIn 1ns = %d, want 0 (timestamps are older)", got)
	}
	// 不同 key 不串.
	if got := c.countIn("b", time.Minute); got != 0 {
		t.Errorf("unrelated key counted as %d, want 0", got)
	}
}

func TestFailCounter_ResetClearsKey(t *testing.T) {
	c := newFailCounter(time.Minute)
	c.record("a")
	c.record("a")
	c.reset("a")
	if got := c.countIn("a", time.Minute); got != 0 {
		t.Errorf("after reset want 0 got %d", got)
	}
}

func TestFailCounter_ResetAllClearsEverything(t *testing.T) {
	c := newFailCounter(time.Minute)
	c.record("a")
	c.record("b")
	c.record("c")
	if n := c.resetAll(); n != 3 {
		t.Errorf("resetAll returned %d, want 3", n)
	}
	if got := c.countIn("a", time.Minute); got != 0 {
		t.Errorf("after resetAll, key a should be empty, got %d", got)
	}
}

func TestFailCounter_OldEntriesIgnoredByCount(t *testing.T) {
	c := newFailCounter(time.Hour)
	c.mu.Lock()
	c.entries["k"] = []time.Time{
		time.Now().Add(-30 * time.Minute), // 30 分钟前
		time.Now().Add(-2 * time.Minute),  // 2 分钟前
		time.Now(),
	}
	c.mu.Unlock()
	if got := c.countIn("k", 5*time.Minute); got != 2 {
		t.Errorf("countIn 5m = %d, want 2 (only last 2 are within window)", got)
	}
}

// --- ipBanList ---

func TestIPBanList_AutoExpire(t *testing.T) {
	b := newIPBanList()
	b.ban("1.1.1.1", time.Millisecond)
	if !b.isBanned("1.1.1.1") {
		t.Fatal("just banned, must be banned")
	}
	time.Sleep(5 * time.Millisecond)
	if b.isBanned("1.1.1.1") {
		t.Fatal("after expiry, must not be banned")
	}
}

func TestIPBanList_ExpiryOfRespectsExpiry(t *testing.T) {
	b := newIPBanList()
	b.ban("1.1.1.1", time.Hour)
	exp, ok := b.expiryOf("1.1.1.1")
	if !ok {
		t.Fatal("expiryOf must report banned")
	}
	if !exp.After(time.Now()) {
		t.Errorf("expiry %v should be in future", exp)
	}
	// 不在列表里时
	if _, ok := b.expiryOf("2.2.2.2"); ok {
		t.Error("expiryOf for unbanned IP must return ok=false")
	}
}

func TestIPBanList_UnbanReturnsWhetherWasBanned(t *testing.T) {
	b := newIPBanList()
	if b.unban("never-banned") {
		t.Error("unban of never-banned should return false")
	}
	b.ban("x", time.Hour)
	if !b.unban("x") {
		t.Error("unban of banned IP should return true")
	}
	if b.isBanned("x") {
		t.Error("after unban, should not be banned")
	}
}

// --- banHistory ---

func TestBanHistory_IncrementCounts(t *testing.T) {
	bh, err := newBanHistory("") // 内存模式不落盘
	if err != nil {
		t.Fatal(err)
	}
	if bh.increment("ip-a") != 1 {
		t.Error("first increment must return 1")
	}
	if bh.increment("ip-a") != 2 {
		t.Error("second increment must return 2")
	}
	if bh.increment("ip-b") != 1 {
		t.Error("different ip starts from 1")
	}
	if bh.get("ip-a") != 2 {
		t.Errorf("get ip-a = %d, want 2", bh.get("ip-a"))
	}
}

func TestBanHistory_ResetClearsOnlyTarget(t *testing.T) {
	bh, _ := newBanHistory("")
	bh.increment("a")
	bh.increment("a")
	bh.increment("b")
	bh.reset("a")
	if bh.get("a") != 0 {
		t.Errorf("reset(a) failed: %d", bh.get("a"))
	}
	if bh.get("b") != 1 {
		t.Errorf("reset(a) leaked into b: %d", bh.get("b"))
	}
}

// --- M3 关键回归: clearSuccessfulAuthState 不应清 banHistory ---

func TestClearSuccessfulAuthState_PreservesBanHistory(t *testing.T) {
	// 这是 M3 核心场景: 攻击者积累了 IP 封禁历史 (banHistory),
	// 一次合法登录就把历史归零 → 升级永久永远到不了. 修复后必须保留.
	app := mkTestApp(t)
	const ip = "5.5.5.5"
	const email = "alice@example.com"

	// 模拟该 IP 之前已经被冷却过 3 次, 冷却次数累积在 banHistory.
	app.banHistory.increment(ip)
	app.banHistory.increment(ip)
	app.banHistory.increment(ip)
	if app.banHistory.get(ip) != 3 {
		t.Fatalf("setup: banHistory should be 3, got %d", app.banHistory.get(ip))
	}

	// 同时模拟当前还有失败计数 + 冷却中.
	app.ipFails.record(ip)
	app.ipFails.record(ip)
	app.ipBans.ban(ip, time.Hour)
	app.authEmailFails.record(email)

	// 该 IP 现在合法登录 (eg 用真账号). clearSuccessfulAuthState 应该:
	//   - 清 ipFails
	//   - 解 ipBans 当前冷却
	//   - **保留** banHistory 历史 — 这是 M3 修复的核心点
	r, _ := http.NewRequest("GET", "/", nil)
	r.RemoteAddr = ip + ":12345"
	prev := trustProxyHeaders
	trustProxyHeaders = false
	defer func() { trustProxyHeaders = prev }()
	sess := Session{Email: email, MAC: "aa:bb:cc:dd:ee:ff", UserIP: ip}

	app.clearSuccessfulAuthState(r, sess)

	if got := app.banHistory.get(ip); got != 3 {
		t.Errorf("banHistory MUST be preserved across legit login, got %d, want 3", got)
	}
	if app.ipBans.isBanned(ip) {
		t.Error("current cooldown should be cleared")
	}
	if app.ipFails.countIn(ip, time.Hour) != 0 {
		t.Error("ipFails should be cleared")
	}
	if app.authEmailFails.countIn(email, time.Hour) != 0 {
		t.Error("authEmailFails should be cleared")
	}
}

// --- recordIPFailure: 阈值触发冷却 / 升级永久 ---

func TestRecordIPFailure_TriggersCooldownAtThreshold(t *testing.T) {
	app := mkTestApp(t)
	app.cfg.IPFailsLimit = 3
	app.cfg.IPFailsWindow = time.Hour
	app.cfg.IPBanDuration = time.Minute
	app.cfg.IPBanEscalateAt = 999999

	const ip = "7.7.7.7"
	app.recordIPFailure(ip, "test")
	app.recordIPFailure(ip, "test")
	if app.ipBans.isBanned(ip) {
		t.Error("at 2 fails (< limit 3) should not be banned yet")
	}
	app.recordIPFailure(ip, "test")
	if !app.ipBans.isBanned(ip) {
		t.Error("at 3 fails (== limit) should trigger cooldown")
	}
}

func TestRecordIPFailure_EscalatesToPermanent(t *testing.T) {
	app := mkTestApp(t)
	app.cfg.IPFailsLimit = 1
	app.cfg.IPFailsWindow = time.Hour
	app.cfg.IPBanDuration = time.Minute
	app.cfg.IPBanEscalateAt = 3 // 第 3 次冷却 = 永久

	const ip = "8.8.8.8"

	// 第 1 次: 触发短时冷却, banHistory=1.
	app.recordIPFailure(ip, "test")
	exp, _ := app.ipBans.expiryOf(ip)
	if IsPermanent(exp) {
		t.Error("first ban must be temporary")
	}
	if app.banHistory.get(ip) != 1 {
		t.Errorf("banHistory after 1st = %d, want 1", app.banHistory.get(ip))
	}

	// 模拟冷却到期. 攻击者再发一次失败.
	app.ipBans.unban(ip)
	app.recordIPFailure(ip, "test")
	if app.banHistory.get(ip) != 2 {
		t.Errorf("banHistory after 2nd = %d, want 2", app.banHistory.get(ip))
	}

	// 第 3 次: 触发永久封禁.
	app.ipBans.unban(ip)
	app.recordIPFailure(ip, "test")
	exp3, ok := app.ipBans.expiryOf(ip)
	if !ok {
		t.Fatal("third trigger should ban")
	}
	if !IsPermanent(exp3) {
		t.Errorf("third ban should be PERMANENT, got expiry %v", exp3)
	}
}

func TestRecordIPFailure_DoesNotRebanWhileCooling(t *testing.T) {
	// 已经冷却中, 又来 N 次失败 — banHistory 不应该再升一次, 也不该续冷却.
	app := mkTestApp(t)
	app.cfg.IPFailsLimit = 1
	app.cfg.IPBanDuration = time.Hour
	app.cfg.IPBanEscalateAt = 5

	const ip = "9.9.9.9"
	app.recordIPFailure(ip, "test")
	if app.banHistory.get(ip) != 1 {
		t.Fatalf("setup: banHistory should be 1, got %d", app.banHistory.get(ip))
	}

	// 已经在封了, 再 record 一堆.
	for i := 0; i < 5; i++ {
		app.recordIPFailure(ip, "test")
	}
	if app.banHistory.get(ip) != 1 {
		t.Errorf("banHistory should stay at 1 while cooling, got %d", app.banHistory.get(ip))
	}
}

// --- usedStateSet ---

func TestUsedStateSet_TTLAutoRefreshAfterExpiry(t *testing.T) {
	s := newUsedStateSet(20 * time.Millisecond)
	if !s.markUsed("abc") {
		t.Fatal("first markUsed must succeed")
	}
	if s.markUsed("abc") {
		t.Fatal("immediate second markUsed must fail")
	}
	time.Sleep(40 * time.Millisecond)
	if !s.markUsed("abc") {
		t.Fatal("after TTL expiry, same state should be re-acceptable")
	}
}

// --- requestIPKeys ---

func TestRequestIPKeys_DeduplicatesClientAndSessionIP(t *testing.T) {
	prev := trustProxyHeaders
	trustProxyHeaders = false
	defer func() { trustProxyHeaders = prev }()

	r, _ := http.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.1.1.1:1111"

	// session IP 跟 client IP 相同 → 只返回一个
	keys := requestIPKeys(r, &Session{UserIP: "1.1.1.1"})
	if len(keys) != 1 || keys[0] != "1.1.1.1" {
		t.Errorf("identical client/session IPs should dedupe, got %v", keys)
	}

	// session IP 不同 → 都包含 (限流要双向覆盖, 反代 IP + iKuai 上报 IP)
	keys = requestIPKeys(r, &Session{UserIP: "2.2.2.2"})
	if len(keys) != 2 {
		t.Errorf("different IPs should both appear, got %v", keys)
	}

	// 没 session
	keys = requestIPKeys(r, nil)
	if len(keys) != 1 || keys[0] != "1.1.1.1" {
		t.Errorf("no session: only client IP, got %v", keys)
	}
}

// --- proceedTokenStore ---

func TestProceedTokenStore_OneTimeConsumption(t *testing.T) {
	s := newProceedTokenStore(time.Minute)
	tok, err := s.put("/somewhere", "state-x", "u@x")
	if err != nil {
		t.Fatal(err)
	}
	e, ok := s.take(tok)
	if !ok {
		t.Fatal("first take must succeed")
	}
	if e.URL != "/somewhere" {
		t.Errorf("URL mismatch: %q", e.URL)
	}
	// 第二次必须失败
	if _, ok := s.take(tok); ok {
		t.Fatal("second take of same token must fail (one-time)")
	}
}

func TestProceedTokenStore_ExpiredRejected(t *testing.T) {
	s := newProceedTokenStore(time.Millisecond)
	tok, _ := s.put("/x", "s", "u@x")
	time.Sleep(5 * time.Millisecond)
	if _, ok := s.take(tok); ok {
		t.Fatal("expired token must not be accepted")
	}
}

// --- H4 回归: admin POST 必须被同源校验拦截 ---

func TestRequireAdmin_BlocksCrossOriginPOST(t *testing.T) {
	app := mkTestApp(t)
	app.cfg.AdminEmails = []string{"admin@example.com"}

	// 即使带着合法的 admin cookie, 跨站 Origin 应该被拦截.
	rec := httptest.NewRecorder()
	_ = writeAdminCookie(rec, app.cfg.SessionSecret, AdminSession{
		UPN: "admin@example.com",
		Exp: time.Now().Add(time.Hour).Unix(),
	}, false)

	r, _ := http.NewRequest("POST", "/admin/codes/delete-bulk",
		strings.NewReader("codes=1234"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://evil.example.com")
	for _, c := range rec.Result().Cookies() {
		r.AddCookie(c)
	}

	w := httptest.NewRecorder()
	_, ok := app.requireAdmin(w, r, true)
	if ok {
		t.Fatal("requireAdmin must reject cross-origin POST even with valid cookie")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestRequireAdmin_AllowsSameOriginPOST(t *testing.T) {
	app := mkTestApp(t)
	app.cfg.AdminEmails = []string{"admin@example.com"}

	rec := httptest.NewRecorder()
	_ = writeAdminCookie(rec, app.cfg.SessionSecret, AdminSession{
		UPN: "admin@example.com",
		Exp: time.Now().Add(time.Hour).Unix(),
	}, false)

	r, _ := http.NewRequest("POST", "/admin/codes/delete-bulk",
		strings.NewReader("codes=1234"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", app.cfg.PublicURL)
	for _, c := range rec.Result().Cookies() {
		r.AddCookie(c)
	}

	w := httptest.NewRecorder()
	_, ok := app.requireAdmin(w, r, true)
	if !ok {
		t.Errorf("requireAdmin must allow same-origin POST, got status %d", w.Code)
	}
}

func TestRequireAdmin_BlocksPOSTWithoutOriginHeader(t *testing.T) {
	// 防御深度: 浏览器现在 form POST 都会带 Origin/Referer. 缺失通常是 curl /
	// 伪造客户端 / 老浏览器 — 拒掉.
	app := mkTestApp(t)
	app.cfg.AdminEmails = []string{"admin@example.com"}

	rec := httptest.NewRecorder()
	_ = writeAdminCookie(rec, app.cfg.SessionSecret, AdminSession{
		UPN: "admin@example.com",
		Exp: time.Now().Add(time.Hour).Unix(),
	}, false)

	r, _ := http.NewRequest("POST", "/admin/codes/delete-bulk",
		strings.NewReader("codes=1234"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range rec.Result().Cookies() {
		r.AddCookie(c)
	}

	w := httptest.NewRecorder()
	_, ok := app.requireAdmin(w, r, true)
	if ok {
		t.Fatal("requireAdmin must reject POST without Origin/Referer")
	}
}

func TestRequireAdmin_AllowsGETWithoutOrigin(t *testing.T) {
	// GET (页面渲染 / status 查询) 不强制 Origin — 浏览器很多 GET 不发 Origin.
	app := mkTestApp(t)
	app.cfg.AdminEmails = []string{"admin@example.com"}

	rec := httptest.NewRecorder()
	_ = writeAdminCookie(rec, app.cfg.SessionSecret, AdminSession{
		UPN: "admin@example.com",
		Exp: time.Now().Add(time.Hour).Unix(),
	}, false)

	r, _ := http.NewRequest("GET", "/admin/ratelimit/status", nil)
	for _, c := range rec.Result().Cookies() {
		r.AddCookie(c)
	}

	w := httptest.NewRecorder()
	_, ok := app.requireAdmin(w, r, true)
	if !ok {
		t.Errorf("GET without Origin should pass, got %d", w.Code)
	}
}

// --- handleAuthProceed: state 不匹配应拒绝 ---

func TestHandleAuthProceed_StateMismatchRejected(t *testing.T) {
	app := mkTestApp(t)

	// 浏览器 cookie 里 session.State = "session-state"
	rec := httptest.NewRecorder()
	sess := Session{
		State: "session-state",
		Nonce: "n",
		MAC:   "aa:bb:cc:dd:ee:ff",
		Exp:   time.Now().Add(time.Minute).Unix(),
	}
	if err := writeSessionCookie(rec, app.cfg.SessionSecret, sess, false); err != nil {
		t.Fatal(err)
	}

	// proceed token 绑的是另一个 state — 模拟攻击者拿到他人的 token 试图重放.
	tok, _ := app.proceedStore.put("/login?hint=victim@example.com",
		"OTHER-STATE", "victim@example.com")

	r, _ := http.NewRequest("GET", "/auth/proceed?token="+tok, nil)
	for _, c := range rec.Result().Cookies() {
		r.AddCookie(c)
	}
	rec2 := httptest.NewRecorder()
	app.handleAuthProceed(rec2, r)
	if rec2.Code != http.StatusBadRequest {
		t.Errorf("state mismatch should return 400, got %d", rec2.Code)
	}
	// 不能 302 到 token 内的真 URL
	if loc := rec2.Header().Get("Location"); strings.Contains(loc, "victim@example.com") {
		t.Errorf("must not redirect to mismatched URL: %q", loc)
	}
}

// --- clientIP / 反代信任边界 (H1 修复) ---

func TestClientIP_RightmostXFFWhenProxied(t *testing.T) {
	prev := trustProxyHeaders
	trustProxyHeaders = true
	defer func() { trustProxyHeaders = prev }()

	r, _ := http.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:54321"
	// 攻击者伪造的 XFF + 反代 (nginx $proxy_add_x_forwarded_for) append 的真客户端 IP
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8, 9.9.9.9")

	got := clientIP(r)
	if got != "9.9.9.9" {
		t.Fatalf("clientIP = %q, want %q (rightmost — nginx-appended real client)", got, "9.9.9.9")
	}
}

func TestClientIP_XRealIPWinsOverXFF(t *testing.T) {
	prev := trustProxyHeaders
	trustProxyHeaders = true
	defer func() { trustProxyHeaders = prev }()

	r, _ := http.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:54321"
	r.Header.Set("X-Real-IP", "10.0.0.1")
	r.Header.Set("X-Forwarded-For", "1.2.3.4")

	if got := clientIP(r); got != "10.0.0.1" {
		t.Fatalf("clientIP = %q, want X-Real-IP value 10.0.0.1", got)
	}
}

func TestClientIP_TrustProxyFalseIgnoresHeaders(t *testing.T) {
	prev := trustProxyHeaders
	trustProxyHeaders = false
	defer func() { trustProxyHeaders = prev }()

	r, _ := http.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.5:11111"
	r.Header.Set("X-Real-IP", "1.2.3.4")
	r.Header.Set("X-Forwarded-For", "5.6.7.8, 9.9.9.9")

	if got := clientIP(r); got != "203.0.113.5" {
		t.Fatalf("clientIP = %q, want RemoteAddr host 203.0.113.5 (headers should be ignored)", got)
	}
}

// --- usedStateSet (M2 OIDC state 重放防护) ---

func TestUsedStateSet_BlocksReplay(t *testing.T) {
	s := newUsedStateSet(10 * time.Second)

	if !s.markUsed("abc") {
		t.Fatal("first markUsed should return true (fresh)")
	}
	if s.markUsed("abc") {
		t.Fatal("second markUsed for same state must return false (replay)")
	}
	if !s.markUsed("def") {
		t.Fatal("different state should still be accepted")
	}
}

func TestUsedStateSet_EmptyStateRejected(t *testing.T) {
	s := newUsedStateSet(time.Minute)
	if s.markUsed("") {
		t.Fatal("empty state must not be accepted")
	}
}

// --- failCounter 容量上限 (H3 内存增长 DOS) ---

func TestFailCounterCapacity(t *testing.T) {
	c := newFailCounter(time.Hour)
	for i := 0; i < maxFailCounterEntries+100; i++ {
		c.record(uniqKey(i))
	}
	c.mu.Lock()
	n := len(c.entries)
	c.mu.Unlock()
	if n > maxFailCounterEntries {
		t.Fatalf("failCounter exceeded cap: %d > %d", n, maxFailCounterEntries)
	}
}

func uniqKey(i int) string {
	const alpha = "0123456789abcdef"
	buf := make([]byte, 8)
	for j := 0; j < 8; j++ {
		buf[j] = alpha[(i>>(4*j))&0xf]
	}
	return string(buf)
}

// --- helpers ---

// mkTestApp 构造一个最小可用的 *App, 适合限流 / 中间件路径测试.
// 不启动 gcLoop, 不连 OIDC, 不写盘. 模板 + i18n 用真实文件加载,
// 这样 renderError 不会 nil panic.
func mkTestApp(t *testing.T) *App {
	t.Helper()
	loadTranslations()
	cfg := Config{
		SessionSecret: testSecret(t),
		PublicURL:     "https://wifi.test",
		// 限流默认值, 单测里大多数会覆盖这些.
		AuthEmailFailsShort:  5,
		AuthEmailWindowShort: 3 * time.Minute,
		AuthEmailFailsLong:   20,
		AuthEmailWindowLong:  time.Hour,
		GuestCodeMacFails:    6,
		GuestCodeMacWindow:   30 * time.Minute,
		IPFailsLimit:         20,
		IPFailsWindow:        5 * time.Minute,
		IPBanDuration:        2 * time.Minute,
		IPBanEscalateAt:      999999,
		AuthProceedTTL:       5 * time.Minute,
		TrustProxy:           true,
	}
	bh, err := newBanHistory("")
	if err != nil {
		t.Fatal(err)
	}
	dl, err := newDenylistStore("")
	if err != nil {
		t.Fatal(err)
	}
	tmpl, err := template.New("").Funcs(template.FuncMap{
		"T":        T,
		"jsonI18N": jsonI18N,
	}).ParseFS(templateFS, "templates/*.html")
	if err != nil {
		t.Fatal(err)
	}
	return &App{
		cfg:            cfg,
		denylist:       dl,
		templates:      tmpl,
		authEmailFails: newFailCounter(cfg.AuthEmailWindowLong),
		guestCodeFails: newFailCounter(cfg.GuestCodeMacWindow),
		ipFails:        newFailCounter(cfg.IPFailsWindow),
		ipBans:         newIPBanList(),
		banHistory:     bh,
		proceedStore:   newProceedTokenStore(cfg.AuthProceedTTL),
		usedStates:     newUsedStateSet(sessionTTL),
	}
}
