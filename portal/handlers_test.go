package main

// handlers_test.go
// HTTP handler 端到端测试. 测的是真实路径上的安全契约:
//   - handleCodeCreate: 用户自填 code 长度上限 (M7 回归)
//   - handleCodeCreate: 审计 detail 里只有 code-suffix, 没有完整码 (H2 回归)
//   - handleCodeDelete / handleCodeEdit: 同样脱敏审计
//   - handleAuthStart: 账号枚举防护 — 所有 email 响应一致
//   - handleAuthStart: 邮箱失败计数双窗口
//   - handlePortal: MAC 在 denylist 里直接拒
//
// 这里不打 OIDC, 不调 Duo — 把这些 client 设为 nil 走 fallback 分支.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func mkAdminCookie(t *testing.T, app *App) *http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	if err := writeAdminCookie(rec, app.cfg.SessionSecret, AdminSession{
		UPN: "admin@example.com",
		Exp: time.Now().Add(time.Hour).Unix(),
	}, false); err != nil {
		t.Fatal(err)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("want 1 cookie, got %d", len(cookies))
	}
	return cookies[0]
}

func mkAdminTestApp(t *testing.T) *App {
	t.Helper()
	app := mkTestApp(t)
	app.cfg.AdminEmails = []string{"admin@example.com"}
	gc, err := newGuestCodeStore("")
	if err != nil {
		t.Fatal(err)
	}
	app.guestCodes = gc
	policies, err := newIKuaiPolicyStore(map[IKuaiAuthProfile]IKuaiPolicy{
		IKuaiProfileSSO: {}, IKuaiProfileDuo: {}, IKuaiProfileGuest: {},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	app.ikuaiPolicies = policies
	app.eventLog, _ = newEventLog("", time.Hour)
	return app
}

// adminPOST 拼装一个带合法 admin cookie + 同源 Origin 的 POST 请求.
func adminPOST(t *testing.T, app *App, path string, form url.Values) *http.Request {
	t.Helper()
	r, _ := http.NewRequest("POST", path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", app.cfg.PublicURL)
	r.AddCookie(mkAdminCookie(t, app))
	return r
}

// --- handleCodeCreate ---

func TestHandleCodeCreate_RejectsLongCode(t *testing.T) {
	// M7 回归: 用户自填 code 不能超过 64 字符.
	app := mkAdminTestApp(t)
	form := url.Values{
		"code": {strings.Repeat("a", 65)},
	}
	w := httptest.NewRecorder()
	app.handleCodeCreate(w, adminPOST(t, app, "/admin/codes/create", form))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for over-long code", w.Code)
	}
}

// TestHandleCodeCreate_RejectsShortCode: 审计 #9.
// admin 自填的 code 太短 (< 6 字符) 时, tailN(code, 4) 几乎等于完整码,
// 等于把"短码"完整持久化进事件日志. 服务端拒掉, 强制 admin 用至少 6 位
// (跟批量生成的 length 下限对齐).
func TestHandleCodeCreate_RejectsShortCode(t *testing.T) {
	app := mkAdminTestApp(t)
	for _, short := range []string{"1", "12", "123", "1234", "12345"} {
		form := url.Values{"code": {short}}
		w := httptest.NewRecorder()
		app.handleCodeCreate(w, adminPOST(t, app, "/admin/codes/create", form))
		if w.Code != http.StatusBadRequest {
			t.Errorf("short code %q: status = %d, want 400", short, w.Code)
		}
	}
	// 6 字符及以上接受
	form := url.Values{"code": {"abcdef"}}
	w := httptest.NewRecorder()
	app.handleCodeCreate(w, adminPOST(t, app, "/admin/codes/create", form))
	if w.Code != http.StatusOK {
		t.Errorf("6-char code: status = %d, want 200, body=%s", w.Code, w.Body.String())
	}
}

// TestHandleCodeCreate_AuditDoesNotLeakFullCode: H2 关键回归.
// admin 创建访客码时, 审计 detail 不能写完整码 — 备份 / SIEM 泄露后等于身份信息.
func TestHandleCodeCreate_AuditDoesNotLeakFullCode(t *testing.T) {
	app := mkAdminTestApp(t)
	const myCode = "VERY-SECRET-CODE-1234"
	form := url.Values{
		"code":         {myCode},
		"duration_min": {"60"},
	}
	w := httptest.NewRecorder()
	app.handleCodeCreate(w, adminPOST(t, app, "/admin/codes/create", form))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	events := app.eventLog.Query(EventQueryFilter{Kind: KindAdminAction})
	if len(events) != 1 {
		t.Fatalf("want 1 admin event, got %d", len(events))
	}
	detail := events[0].Detail
	if strings.Contains(detail, myCode) {
		t.Errorf("audit detail leaked full code: %q", detail)
	}
	// 应该有 code-suffix 字样
	if !strings.Contains(detail, "code-suffix=") {
		t.Errorf("detail missing 'code-suffix=': %q", detail)
	}
	// 末 4 位 (1234) 应该出现
	if !strings.Contains(detail, "1234") {
		t.Errorf("detail missing last 4 chars: %q", detail)
	}
}

func TestHandleCodeDelete_AuditUsesSuffix(t *testing.T) {
	// H2 回归: 删除审计也只留末 4 位.
	app := mkAdminTestApp(t)
	app.guestCodes.Add(&GuestCode{
		Code:      "AAAA-BBBB-CCCC-DDDD",
		CreatedAt: time.Now(),
	})
	form := url.Values{"code": {"AAAA-BBBB-CCCC-DDDD"}}
	w := httptest.NewRecorder()
	app.handleCodeDelete(w, adminPOST(t, app, "/admin/codes/delete", form))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	events := app.eventLog.Query(EventQueryFilter{Kind: KindAdminAction})
	if len(events) != 1 {
		t.Fatalf("want 1 event, got %d", len(events))
	}
	if strings.Contains(events[0].Detail, "AAAA-BBBB") {
		t.Errorf("delete audit leaked full code: %q", events[0].Detail)
	}
	if !strings.Contains(events[0].Detail, "DDDD") {
		t.Errorf("delete audit missing suffix DDDD: %q", events[0].Detail)
	}
}

// --- handleAuthStart 账号枚举防护 ---

func TestHandleAuthStart_OpaqueResponseRegardlessOfDuoStatus(t *testing.T) {
	// 关键设计: /auth/start 对所有合法邮箱响应一致 (返回 opaque token), 攻击者
	// 没法靠响应差异判断哪个 email 在 Duo 注册. 这里 duo=nil 走 SSO fallback,
	// 仅验返回结构稳定.
	app := mkTestApp(t)

	// 走 /auth/start 需要先有合法 wifi session cookie
	rec := httptest.NewRecorder()
	sess := Session{
		MAC:    "aa:bb:cc:dd:ee:ff",
		UserIP: "192.168.1.10",
		State:  "s", Nonce: "n",
		Lang: "en",
		Exp:  time.Now().Add(time.Minute).Unix(),
	}
	if err := writeSessionCookie(rec, app.cfg.SessionSecret, sess, false); err != nil {
		t.Fatal(err)
	}

	bodyOf := func(email string) (int, string) {
		form := url.Values{"email": {email}}
		r, _ := http.NewRequest("POST", "/auth/start", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for _, c := range rec.Result().Cookies() {
			r.AddCookie(c)
		}
		w := httptest.NewRecorder()
		app.handleAuthStart(w, r)
		body, _ := io.ReadAll(w.Result().Body)
		return w.Code, string(body)
	}

	for _, email := range []string{"alice@example.com", "bob@example.com", "anyone@test.org"} {
		code, body := bodyOf(email)
		if code != http.StatusOK {
			t.Errorf("email=%q got status %d, body=%s", email, code, body)
			continue
		}
		// 响应里只有 redirect 字段,不能含邮箱信息或 deny 信号
		if !strings.Contains(body, "/auth/proceed?token=") {
			t.Errorf("email=%q response missing opaque token: %s", email, body)
		}
		if strings.Contains(body, "duo") || strings.Contains(body, "deny") {
			t.Errorf("email=%q response leaked Duo/deny signal: %s", email, body)
		}
	}
}

func TestHandleAuthStart_RejectsInvalidEmail(t *testing.T) {
	app := mkTestApp(t)
	rec := httptest.NewRecorder()
	_ = writeSessionCookie(rec, app.cfg.SessionSecret, Session{
		MAC: "aa", UserIP: "1.1.1.1",
		State: "s", Nonce: "n",
		Exp: time.Now().Add(time.Minute).Unix(),
	}, false)

	cases := []string{
		"",
		"not-an-email",
		"two@@at.com",
		"with space@x.com",
		strings.Repeat("a", 300) + "@x.com",
	}
	for _, email := range cases {
		form := url.Values{"email": {email}}
		r, _ := http.NewRequest("POST", "/auth/start", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for _, c := range rec.Result().Cookies() {
			r.AddCookie(c)
		}
		w := httptest.NewRecorder()
		app.handleAuthStart(w, r)
		if w.Code != http.StatusBadRequest {
			t.Errorf("email=%q got %d, want 400", email, w.Code)
		}
	}
}

func TestHandleAuthStart_RejectsGET(t *testing.T) {
	app := mkTestApp(t)
	r, _ := http.NewRequest("GET", "/auth/start", nil)
	w := httptest.NewRecorder()
	app.handleAuthStart(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET should be 405, got %d", w.Code)
	}
}

// --- handlePortal MAC denylist ---

func TestHandlePortal_BlocksDeniedMAC(t *testing.T) {
	app := mkTestApp(t)
	app.denylist.AddMAC("aa:bb:cc:dd:ee:ff", "abuse", "admin")

	// 模拟 iKuai 跳过来 + cookie 已带这个 MAC
	rec := httptest.NewRecorder()
	_ = writeSessionCookie(rec, app.cfg.SessionSecret, Session{
		MAC:    "aa:bb:cc:dd:ee:ff",
		UserIP: "192.168.1.10",
		State:  "s", Nonce: "n",
		Exp: time.Now().Add(time.Minute).Unix(),
	}, false)

	r, _ := http.NewRequest("GET", "/portal", nil)
	for _, c := range rec.Result().Cookies() {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	app.handlePortal(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("denied MAC should get 403, got %d", w.Code)
	}
}

// --- handleAdminLoginStart M6 回归 ---

// --- 纯函数 / helper 单测 (M1, M7, L3 修复路径) ---

func TestCapLen(t *testing.T) {
	cases := []struct {
		in   string
		n    int
		want string
	}{
		{"", 5, ""},
		{"abc", 5, "abc"},
		{"abcdef", 3, "abc"},
		{"abc", 3, "abc"},
	}
	for _, c := range cases {
		if got := capLen(c.in, c.n); got != c.want {
			t.Errorf("capLen(%q, %d) = %q, want %q", c.in, c.n, got, c.want)
		}
	}
}

func TestIsLoopbackListen(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:28080", true},
		{"localhost:28080", true},
		{"[::1]:28080", true},
		{"0.0.0.0:28080", false},
		{":28080", false},
		{"203.0.113.5:28080", false},
		{"not_an_addr", false},
	}
	for _, c := range cases {
		if got := isLoopbackListen(c.addr); got != c.want {
			t.Errorf("isLoopbackListen(%q) = %v, want %v", c.addr, got, c.want)
		}
	}
}

func TestIsSameOriginRequest(t *testing.T) {
	app := &App{cfg: Config{PublicURL: "https://wifi.example.com"}}

	cases := []struct {
		name    string
		origin  string
		referer string
		want    bool
	}{
		{"matching Origin", "https://wifi.example.com", "", true},
		{"matching Origin trailing slash", "https://wifi.example.com/", "", true},
		{"foreign Origin", "https://evil.com", "", false},
		{"http vs https", "http://wifi.example.com", "", false},
		{"matching Referer", "", "https://wifi.example.com/admin", true},
		{"foreign Referer", "", "https://evil.com/x", false},
		{"both missing → reject", "", "", false},
		{"Origin overrides Referer", "https://wifi.example.com", "https://evil.com/x", true},
		{"foreign Origin even with good Referer", "https://evil.com", "https://wifi.example.com/admin", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, _ := http.NewRequest("POST", "/admin/codes/create", nil)
			if c.origin != "" {
				r.Header.Set("Origin", c.origin)
			}
			if c.referer != "" {
				r.Header.Set("Referer", c.referer)
			}
			if got := app.isSameOriginRequest(r); got != c.want {
				t.Errorf("origin=%q referer=%q → %v, want %v", c.origin, c.referer, got, c.want)
			}
		})
	}
}

func TestParseDurationMinClamp(t *testing.T) {
	r, _ := http.NewRequest("POST", "/", nil)
	r.PostForm = map[string][]string{
		"duration_h": {"99999999999"}, // 远超合理值
		"duration_m": {"0"},
	}
	got := parseDurationMin(r)
	if got < 0 || got > maxDurationMin {
		t.Fatalf("parseDurationMin overflow / out of range: got %d, expected 0..%d", got, maxDurationMin)
	}
}

// --- DATA_DIR / init 子命令 (模式 D 裸二进制部署) ---

func TestMakeDataPaths_DefaultData(t *testing.T) {
	p := makeDataPaths("/data")
	if p.GuestCodes != "/data/guest-codes.json" {
		t.Errorf("guest path: %q", p.GuestCodes)
	}
	if p.EventLog != "/data/events.jsonl" {
		t.Errorf("event log path: %q", p.EventLog)
	}
}

func TestMakeDataPaths_OverrideDir(t *testing.T) {
	p := makeDataPaths("/var/lib/wifi-portal")
	wants := map[string]string{
		"guest":    "/var/lib/wifi-portal/guest-codes.json",
		"denylist": "/var/lib/wifi-portal/denylist.json",
		"policy":   "/var/lib/wifi-portal/ikuai-policy.json",
		"banhist":  "/var/lib/wifi-portal/ratelimit-state.json",
		"events":   "/var/lib/wifi-portal/events.jsonl",
	}
	got := map[string]string{
		"guest":    p.GuestCodes,
		"denylist": p.Denylist,
		"policy":   p.IKuaiPolicy,
		"banhist":  p.BanHistory,
		"events":   p.EventLog,
	}
	for k, want := range wants {
		if got[k] != want {
			t.Errorf("%s = %q, want %q", k, got[k], want)
		}
	}
}

func TestRunInit_RejectsPositional(t *testing.T) {
	dir := t.TempDir()
	if err := runInit([]string{dir}); err == nil {
		t.Error("positional arg should be rejected with clear error")
	}
}

func TestRunInit_CustomPathsFlowIntoUnit(t *testing.T) {
	dir := t.TempDir()
	if err := runInit([]string{
		"--out-dir", dir,
		"--conf-dir", "/etc/wifi-portal",
		"--data-dir", "/srv/wifi-portal",
		"--bin-path", "/opt/wp/bin",
	}); err != nil {
		t.Fatal(err)
	}
	unit, _ := os.ReadFile(dir + "/wifi-portal.service")
	s := string(unit)
	for _, want := range []string{
		"EnvironmentFile=/etc/wifi-portal/wifi-portal.env",
		"ReadWritePaths=/srv/wifi-portal",
		"ExecStart=/opt/wp/bin",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("systemd unit missing %q\n--- unit ---\n%s", want, s)
		}
	}
	env, _ := os.ReadFile(dir + "/wifi-portal.env")
	if !strings.Contains(string(env), "DATA_DIR=/srv/wifi-portal") {
		t.Error(".env should set DATA_DIR matching --data-dir")
	}
}

func TestRunInit_WritesFiles(t *testing.T) {
	dir := t.TempDir()
	if err := runInit([]string{"--out-dir", dir}); err != nil {
		t.Fatal(err)
	}

	// .env 应存在,权限 0600 (因含 secret)
	envPath := dir + "/wifi-portal.env"
	info, err := os.Stat(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Errorf(".env mode = %o, want no group/other access", info.Mode().Perm())
	}
	// 内容应包含 .env.example 内容 + init header
	data, _ := os.ReadFile(envPath)
	if !strings.Contains(string(data), "wifi-portal init") {
		t.Error(".env missing init header")
	}
	if !strings.Contains(string(data), "TENANT_ID") {
		t.Error(".env missing embedded template (TENANT_ID)")
	}

	// systemd unit 应存在,权限 0644 (system 可读)
	servicePath := dir + "/wifi-portal.service"
	info, err = os.Stat(servicePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf(".service mode = %o, want 0644", info.Mode().Perm())
	}
	data, _ = os.ReadFile(servicePath)
	if !strings.Contains(string(data), "[Unit]") || !strings.Contains(string(data), "[Service]") {
		t.Errorf(".service file missing systemd sections")
	}
}

func TestLooksUninitialized(t *testing.T) {
	keys := []string{"TENANT_ID", "CLIENT_ID", "CLIENT_SECRET", "IKUAI_APPKEY", "PUBLIC_URL", "SESSION_SECRET"}

	// 备份 + 清空所有关键 env
	saved := map[string]string{}
	for _, k := range keys {
		saved[k] = os.Getenv(k)
		os.Unsetenv(k)
	}
	defer func() {
		for k, v := range saved {
			if v == "" {
				os.Unsetenv(k)
			} else {
				os.Setenv(k, v)
			}
		}
	}()

	// 全空 → uninitialized
	if !looksUninitialized() {
		t.Error("all empty env should report uninitialized")
	}

	// 只设一个 → 已视为 initialized (mustEnv 会报具体缺哪个)
	os.Setenv("TENANT_ID", "xxx")
	if looksUninitialized() {
		t.Error("partial env should NOT trigger first-run (mustEnv reports specific missing key)")
	}
	os.Unsetenv("TENANT_ID")

	// 空格不算设
	os.Setenv("PUBLIC_URL", "   ")
	if !looksUninitialized() {
		t.Error("whitespace-only env should still be considered empty")
	}
}

func TestRunInit_DoesNotOverwriteExisting(t *testing.T) {
	dir := t.TempDir()
	envPath := dir + "/wifi-portal.env"
	if err := os.WriteFile(envPath, []byte("MY-EXISTING-CONFIG=xxx\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runInit([]string{"--out-dir", dir}); err != nil {
		t.Fatal(err)
	}
	// .env 应该保持原内容
	data, _ := os.ReadFile(envPath)
	if string(data) != "MY-EXISTING-CONFIG=xxx\n" {
		t.Errorf("existing .env was overwritten: %q", string(data))
	}
	// systemd unit 没存在过, 应被写入
	if _, err := os.Stat(dir + "/wifi-portal.service"); err != nil {
		t.Error(".service should be written when missing")
	}
}

func TestHandleAdminLoginStart_RejectsGET(t *testing.T) {
	// M6 回归: GET 不能写 cookie. 限定 POST 后, GET 应直接 405.
	app := mkAdminTestApp(t)
	r, _ := http.NewRequest("GET", "/admin/login/start", nil)
	w := httptest.NewRecorder()
	app.handleAdminLoginStart(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET to /admin/login/start should be 405, got %d", w.Code)
	}
	// 不应该有 cookie 被写
	if len(w.Result().Cookies()) > 0 {
		t.Error("GET must not set any cookie")
	}
}
