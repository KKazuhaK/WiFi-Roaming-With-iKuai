package main

// main.go
// HTTP 路由 + 启动逻辑。业务逻辑散在其它文件里:
//   config.go  - 环境变量 → Config
//   session.go - 签名 cookie (wifi + admin 两种)
//   oidc.go    - Entra 授权 + id_token 校验
//   ikuai.go   - 设备识别 + iKuai 放行 URL
//   duo.go     - Duo Auth API v2 客户端
//   admin.go   - 访客码数据 + 内存存储 + 随机生成
//   i18n.go    - 三语字符串
//
// 端点:
//   GET  /healthz                       健康检查
//   GET  /portal                        iKuai 302 未认证设备到这里
//   GET  /login                         SSO 路径: 点按钮 → Entra
//   GET  /auth/callback                 Entra 回调, 按 session.Purpose 分流
//   POST /auth/duo-start                Duo 免密: 提交邮箱
//   GET  /auth/duo-status               Duo 免密: 轮询状态
//   GET  /auth/duo-finish               Duo 免密: 批准后放行
//   POST /auth/guest-code               访客码登录
//   GET  /admin                         访客码管理主页 (Entra 保护)
//   GET  /admin/login                   启动 admin OIDC 流
//   POST /admin/logout                  清 admin cookie
//   POST /admin/codes/create            单条添加
//   POST /admin/codes/batch             批量生成
//   POST /admin/codes/delete            删单条
//   POST /admin/codes/delete-expired    删所有失效
//   GET  /static/*                      logo / 头像

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

type App struct {
	cfg        Config
	oidc       *OIDCClient
	duo        *DuoClient      // nil 表示 Duo 未启用
	guestCodes *GuestCodeStore // 访客码内存存储
	templates  *template.Template
}

func main() {
	cfg := loadConfig()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	oidcClient, err := newOIDCClient(ctx, cfg)
	if err != nil {
		log.Fatalf("OIDC 初始化失败: %v", err)
	}

	var duoClient *DuoClient
	if cfg.IsDuoEnabled() {
		duoClient = newDuoClient(cfg)
		log.Printf("Duo 免密推送: 已启用, API host=%s, 允许域名=%v",
			cfg.DuoAPIHost, cfg.AllowedEmailDomains)
	} else {
		log.Printf("Duo 免密推送: 未启用")
	}

	if cfg.IsAdminEnabled() {
		log.Printf("访客码 admin 后台: 已启用, admin=%v", cfg.AdminEmails)
	} else {
		log.Printf("访客码 admin 后台: 未启用 (ADMIN_EMAILS 未配置)")
	}

	tmpl, err := template.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		log.Fatalf("模板加载失败: %v", err)
	}

	app := &App{
		cfg:        cfg,
		oidc:       oidcClient,
		duo:        duoClient,
		guestCodes: newGuestCodeStore(),
		templates:  tmpl,
	}

	staticSub, err := fs.Sub(staticFS, "static")
	if err != nil {
		log.Fatalf("静态目录加载失败: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", app.healthz)
	mux.HandleFunc("/portal", app.handlePortal)
	mux.HandleFunc("/login", app.handleLogin)
	mux.HandleFunc("/auth/callback", app.handleCallback)
	mux.HandleFunc("/auth/duo-start", app.handleDuoStart)
	mux.HandleFunc("/auth/duo-status", app.handleDuoStatus)
	mux.HandleFunc("/auth/duo-finish", app.handleDuoFinish)
	mux.HandleFunc("/auth/guest-code", app.handleGuestCode)
	mux.HandleFunc("/admin", app.handleAdmin)
	mux.HandleFunc("/admin/login", app.handleAdminLogin)
	mux.HandleFunc("/admin/logout", app.handleAdminLogout)
	mux.HandleFunc("/admin/codes/create", app.handleCodeCreate)
	mux.HandleFunc("/admin/codes/batch", app.handleCodeBatch)
	mux.HandleFunc("/admin/codes/delete", app.handleCodeDelete)
	mux.HandleFunc("/admin/codes/delete-expired", app.handleCodeDeleteExpired)
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           securityHeaders(logRequests(mux)),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("Portal 启动, 监听 %s, public URL: %s", cfg.ListenAddr, cfg.PublicURL)
	log.Fatal(srv.ListenAndServe())
}

// --- 中间件 ---

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data: https:; frame-ancestors 'none'")
		h.ServeHTTP(w, r)
	})
}

func logRequests(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lrw := &logRespWriter{ResponseWriter: w, status: 200}
		h.ServeHTTP(lrw, r)
		log.Printf("%s %s -> %d (%s) ua=%q",
			r.Method, r.URL.Path, lrw.status, time.Since(start), r.UserAgent())
	})
}

type logRespWriter struct {
	http.ResponseWriter
	status int
}

func (w *logRespWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// --- 通用 handlers ---

func (a *App) healthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

// --- WiFi 登录流程 ---

func (a *App) handlePortal(w http.ResponseWriter, r *http.Request) {
	lang := pickLang(r)
	dev, ok := extractDeviceInfo(r, a.cfg)
	if !ok {
		a.renderError(w, r, lang, lang.s().SessionLostMsg, http.StatusBadRequest)
		return
	}
	sess, err := newSession(dev.IP, dev.MAC, string(lang))
	if err != nil {
		log.Printf("newSession 失败: %v", err)
		a.renderError(w, r, lang, lang.s().ErrorGenericMsg, http.StatusInternalServerError)
		return
	}
	if err := writeSessionCookie(w, a.cfg.SessionSecret, sess, true); err != nil {
		log.Printf("写 cookie 失败: %v", err)
		a.renderError(w, r, lang, lang.s().ErrorGenericMsg, http.StatusInternalServerError)
		return
	}
	a.renderLogin(w, r, lang, dev)
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	lang := pickLang(r)
	sess, err := readSessionCookie(r, a.cfg.SessionSecret)
	if err != nil {
		a.renderError(w, r, lang, lang.s().SessionLostMsg, http.StatusBadRequest)
		return
	}
	authURL := a.oidc.AuthURL(sess.State, sess.Nonce)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleCallback: 按 session.Purpose 分流.
//   wifi  → iKuai 放行 (成员/访客身份)
//   admin → 验证 UPN 在 ADMIN_EMAILS, 写 admin cookie, 跳 /admin
func (a *App) handleCallback(w http.ResponseWriter, r *http.Request) {
	lang := pickLang(r)
	sess, err := readSessionCookie(r, a.cfg.SessionSecret)
	if err != nil {
		a.renderError(w, r, lang, lang.s().SessionLostMsg, http.StatusBadRequest)
		return
	}
	if sess.Lang != "" {
		lang = Lang(sess.Lang)
	}

	if errParam := r.URL.Query().Get("error"); errParam != "" {
		log.Printf("Entra 返回错误: %s - %s", errParam, r.URL.Query().Get("error_description"))
		a.renderError(w, r, lang, lang.s().ErrorGenericMsg, http.StatusBadRequest)
		return
	}
	if got := r.URL.Query().Get("state"); got != sess.State {
		log.Printf("state 不匹配")
		a.renderError(w, r, lang, lang.s().ErrorGenericMsg, http.StatusBadRequest)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		a.renderError(w, r, lang, lang.s().ErrorGenericMsg, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	user, err := a.oidc.Exchange(ctx, a.cfg, code, sess.Nonce)
	if err != nil {
		log.Printf("OIDC Exchange 失败: %v", err)
		a.renderError(w, r, lang, lang.s().ErrorGenericMsg, http.StatusUnauthorized)
		return
	}

	if sess.Purpose == "admin" {
		a.finishAdminLogin(w, r, lang, user)
		return
	}

	// 默认走 wifi 路径
	if user.IsGuest() {
		log.Printf("拒绝 Guest 账号登录: %s", user.UPN)
		a.renderError(w, r, lang, lang.s().GuestBlockedMsg, http.StatusForbidden)
		return
	}
	log.Printf("放行成员(SSO): upn=%s name=%q ip=%s mac=%s",
		user.UPN, user.Name, sess.UserIP, sess.MAC)
	ikuaiURL := buildWebAuthURL(a.cfg, DeviceInfo{IP: sess.UserIP, MAC: sess.MAC}, user.UPN)
	clearSessionCookie(w, true)
	http.Redirect(w, r, ikuaiURL, http.StatusFound)
}

// --- Duo 免密 ---

func (a *App) handleDuoStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	if a.duo == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "duo_disabled"})
		return
	}
	sess, err := readSessionCookie(r, a.cfg.SessionSecret)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "session_lost"})
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	if !isValidEmail(email) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_email"})
		return
	}
	if !isAllowedDomain(email, a.cfg.AllowedEmailDomains) {
		log.Printf("拒绝域名不在白名单的邮箱: %s", email)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_domain"})
		return
	}
	pre, err := a.duo.Preauth(email)
	if err != nil {
		log.Printf("Duo preauth error for %s: %v", email, err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "duo_unavailable"})
		return
	}
	log.Printf("Duo preauth for %s: result=%s", email, pre.Result)

	switch pre.Result {
	case "auth":
		if !pre.HasPushCapable() {
			log.Printf("%s 无 push 设备, 回落 SSO", email)
			writeJSON(w, http.StatusOK, map[string]string{"mode": "sso"})
			return
		}
		pushInfo := url.Values{}
		pushInfo.Set("SSID", "Kazuha Hub Roaming")
		pushInfo.Set("Device-IP", sess.UserIP)
		pushInfo.Set("Purpose", "WiFi Login")
		txid, err := a.duo.AuthPushAsync(email, pushInfo.Encode())
		if err != nil {
			log.Printf("Duo push failed for %s: %v", email, err)
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "push_failed"})
			return
		}
		sess.Email = email
		sess.DuoTxID = txid
		if err := writeSessionCookie(w, a.cfg.SessionSecret, sess, true); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cookie_write"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"mode": "push", "timeout": a.cfg.DuoPushTimeoutSec,
		})
	case "enroll":
		writeJSON(w, http.StatusOK, map[string]string{"mode": "sso"})
	case "deny":
		log.Printf("Duo 拒绝账号: %s (%s)", email, pre.StatusMsg)
		writeJSON(w, http.StatusOK, map[string]string{"mode": "deny"})
	case "allow":
		writeJSON(w, http.StatusOK, map[string]string{"mode": "sso"})
	default:
		log.Printf("未知 preauth result: %s, 回落 SSO", pre.Result)
		writeJSON(w, http.StatusOK, map[string]string{"mode": "sso"})
	}
}

func (a *App) handleDuoStatus(w http.ResponseWriter, r *http.Request) {
	if a.duo == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"state": "error"})
		return
	}
	sess, err := readSessionCookie(r, a.cfg.SessionSecret)
	if err != nil || sess.DuoTxID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"state": "error"})
		return
	}
	status, err := a.duo.AuthStatus(sess.DuoTxID)
	if err != nil {
		log.Printf("Duo status error: %v", err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"state": "error"})
		return
	}
	resp := map[string]string{}
	switch status.Result {
	case "waiting":
		resp["state"] = "waiting"
	case "allow":
		resp["state"] = "approved"
	case "deny":
		resp["state"] = "denied"
		resp["reason"] = status.Status
	default:
		resp["state"] = "waiting"
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *App) handleDuoFinish(w http.ResponseWriter, r *http.Request) {
	lang := pickLang(r)
	if a.duo == nil {
		a.renderError(w, r, lang, lang.s().ErrorGenericMsg, http.StatusServiceUnavailable)
		return
	}
	sess, err := readSessionCookie(r, a.cfg.SessionSecret)
	if err != nil || sess.DuoTxID == "" || sess.Email == "" {
		a.renderError(w, r, lang, lang.s().SessionLostMsg, http.StatusBadRequest)
		return
	}
	if sess.Lang != "" {
		lang = Lang(sess.Lang)
	}
	status, err := a.duo.AuthStatus(sess.DuoTxID)
	if err != nil {
		a.renderError(w, r, lang, lang.s().ErrorGenericMsg, http.StatusBadGateway)
		return
	}
	if status.Result != "allow" {
		a.renderError(w, r, lang, lang.s().ErrorGenericMsg, http.StatusUnauthorized)
		return
	}
	log.Printf("放行成员(Duo免密): upn=%s ip=%s mac=%s", sess.Email, sess.UserIP, sess.MAC)
	ikuaiURL := buildWebAuthURL(a.cfg, DeviceInfo{IP: sess.UserIP, MAC: sess.MAC}, sess.Email)
	clearSessionCookie(w, true)
	http.Redirect(w, r, ikuaiURL, http.StatusFound)
}

// --- 访客码登录 ---

func (a *App) handleGuestCode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	if !a.cfg.IsAdminEnabled() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "guest_disabled"})
		return
	}
	sess, err := readSessionCookie(r, a.cfg.SessionSecret)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "session_lost"})
		return
	}
	code := strings.TrimSpace(r.FormValue("code"))
	guestID, err := randomHex(4)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "random_failed"})
		return
	}
	upn := "guest-" + guestID
	c := a.guestCodes.Validate(code, sess.MAC, sess.UserIP, upn)
	if c == nil {
		log.Printf("拒绝访客码 (失败或过期) ip=%s mac=%s", sess.UserIP, sess.MAC)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_code"})
		return
	}
	log.Printf("放行访客: upn=%s code-suffix=%s ip=%s mac=%s",
		upn, tailN(c.Code, 4), sess.UserIP, sess.MAC)
	ikuaiURL := buildWebAuthURL(a.cfg, DeviceInfo{IP: sess.UserIP, MAC: sess.MAC}, upn)
	clearSessionCookie(w, true)
	writeJSON(w, http.StatusOK, map[string]string{"redirect": ikuaiURL})
}

// --- admin 流程 ---

func (a *App) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	lang := pickLang(r)
	if !a.cfg.IsAdminEnabled() {
		a.renderError(w, r, lang, "Admin 后台未配置 (ADMIN_EMAILS)", http.StatusNotFound)
		return
	}
	sess, err := newAdminPreloginSession(string(lang))
	if err != nil {
		a.renderError(w, r, lang, lang.s().ErrorGenericMsg, http.StatusInternalServerError)
		return
	}
	if err := writeSessionCookie(w, a.cfg.SessionSecret, sess, true); err != nil {
		a.renderError(w, r, lang, lang.s().ErrorGenericMsg, http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, a.oidc.AuthURL(sess.State, sess.Nonce), http.StatusFound)
}

// finishAdminLogin 在 callback 里被调用, Entra 已验证通过.
func (a *App) finishAdminLogin(w http.ResponseWriter, r *http.Request, lang Lang, user *UserInfo) {
	if user.IsGuest() || !a.cfg.IsAdminEmail(user.UPN) {
		log.Printf("admin 登录被拒: upn=%s (不在 ADMIN_EMAILS)", user.UPN)
		a.renderError(w, r, lang, "你的账号不在 admin 列表, 请联系管理员。", http.StatusForbidden)
		return
	}
	adminSess := AdminSession{
		UPN: user.UPN,
		Exp: time.Now().Add(adminSessionTTL).Unix(),
	}
	if err := writeAdminCookie(w, a.cfg.SessionSecret, adminSess, true); err != nil {
		a.renderError(w, r, lang, lang.s().ErrorGenericMsg, http.StatusInternalServerError)
		return
	}
	clearSessionCookie(w, true)
	log.Printf("admin 登录成功: upn=%s", user.UPN)
	http.Redirect(w, r, "/admin", http.StatusFound)
}

func (a *App) handleAdminLogout(w http.ResponseWriter, r *http.Request) {
	clearAdminCookie(w, true)
	http.Redirect(w, r, "/admin/login", http.StatusFound)
}

// requireAdmin 是所有 /admin/* 路由的守门员.
// 通过则返回 AdminSession, 否则写 302/401 响应并返回 ok=false.
func (a *App) requireAdmin(w http.ResponseWriter, r *http.Request, apiMode bool) (AdminSession, bool) {
	if !a.cfg.IsAdminEnabled() {
		if apiMode {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "admin_disabled"})
		} else {
			http.Error(w, "Admin 后台未配置", http.StatusNotFound)
		}
		return AdminSession{}, false
	}
	sess, err := readAdminCookie(r, a.cfg.SessionSecret)
	if err != nil {
		if apiMode {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not_logged_in"})
		} else {
			http.Redirect(w, r, "/admin/login", http.StatusFound)
		}
		return AdminSession{}, false
	}
	if !a.cfg.IsAdminEmail(sess.UPN) {
		// 账号被从 ADMIN_EMAILS 里删了, 失效
		clearAdminCookie(w, true)
		if apiMode {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "not_admin"})
		} else {
			http.Redirect(w, r, "/admin/login", http.StatusFound)
		}
		return AdminSession{}, false
	}
	return sess, true
}

func (a *App) handleAdmin(w http.ResponseWriter, r *http.Request) {
	sess, ok := a.requireAdmin(w, r, false)
	if !ok {
		return
	}
	a.renderAdmin(w, r, sess)
}

// --- admin API: 码 CRUD ---

// /admin/codes/create  POST
// fields:
//   code           可留空 (留空 = 自动生成 10 位数字)
//   expires_at     RFC3339 字符串, 可留空
//   duration_min   整数, 单位分钟. 用 expires_at 时忽略. 默认 120.
//   note           可选
func (a *App) handleCodeCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	if _, ok := a.requireAdmin(w, r, true); !ok {
		return
	}

	code := strings.TrimSpace(r.FormValue("code"))
	if code == "" {
		g, err := generateCode(CodeNumeric, 10)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "rand_failed"})
			return
		}
		code = g
	}

	gc := &GuestCode{
		Code:      code,
		CreatedAt: time.Now(),
		Note:      strings.TrimSpace(r.FormValue("note")),
	}
	if err := parseExpiry(r, gc); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if !a.guestCodes.Add(gc) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "duplicate_code"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":   true,
		"code": gc.Code,
	})
}

// /admin/codes/batch  POST
// fields:
//   code_type       numeric | alpha | alphanumeric  (默认 numeric)
//   count           整数 (默认 10, 上限 200)
//   length          整数 (默认 15, 范围 6-32)
//   expires_at / duration_min / note  同上
func (a *App) handleCodeBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	if _, ok := a.requireAdmin(w, r, true); !ok {
		return
	}
	codeType := GuestCodeType(strings.TrimSpace(r.FormValue("code_type")))
	if codeType != CodeAlpha && codeType != CodeAlphaNumeric {
		codeType = CodeNumeric
	}
	count := parseIntDefault(r.FormValue("count"), 10)
	if count < 1 {
		count = 1
	}
	if count > 200 {
		count = 200
	}
	length := parseIntDefault(r.FormValue("length"), 15)
	if length < 6 {
		length = 6
	}
	if length > 32 {
		length = 32
	}
	note := strings.TrimSpace(r.FormValue("note"))

	// 预算过期时间一次, 所有码用同一份
	baseProbe := &GuestCode{CreatedAt: time.Now()}
	if err := parseExpiry(r, baseProbe); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	generated := make([]string, 0, count)
	for i := 0; i < count; i++ {
		raw, err := generateCode(codeType, length)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "rand_failed"})
			return
		}
		gc := &GuestCode{
			Code:      raw,
			CreatedAt: baseProbe.CreatedAt,
			ExpiresAt: baseProbe.ExpiresAt,
			Note:      note,
		}
		if !a.guestCodes.Add(gc) {
			// 撞码了, 重试一次
			i--
			continue
		}
		generated = append(generated, raw)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":    true,
		"count": len(generated),
		"codes": generated,
	})
}

func (a *App) handleCodeDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	if _, ok := a.requireAdmin(w, r, true); !ok {
		return
	}
	code := strings.TrimSpace(r.FormValue("code"))
	if code == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing_code"})
		return
	}
	ok := a.guestCodes.Delete(code)
	writeJSON(w, http.StatusOK, map[string]any{"ok": ok})
}

func (a *App) handleCodeDeleteExpired(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	if _, ok := a.requireAdmin(w, r, true); !ok {
		return
	}
	n := a.guestCodes.DeleteExpired()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "deleted": n})
}

// parseExpiry: 从 form 里读 expires_at 或 duration_min, 赋值给 gc.ExpiresAt.
func parseExpiry(r *http.Request, gc *GuestCode) error {
	exp := strings.TrimSpace(r.FormValue("expires_at"))
	if exp != "" {
		t, err := time.Parse(time.RFC3339, exp)
		if err != nil {
			// 尝试 datetime-local 格式 "2006-01-02T15:04"
			t2, err2 := time.ParseInLocation("2006-01-02T15:04", exp, time.Local)
			if err2 != nil {
				return fmt.Errorf("expires_at 格式错误 (需要 RFC3339 或 YYYY-MM-DDTHH:MM): %v", err)
			}
			t = t2
		}
		if t.Before(time.Now()) {
			return fmt.Errorf("expires_at 不能是过去时间")
		}
		gc.ExpiresAt = t
		return nil
	}
	dur := parseIntDefault(r.FormValue("duration_min"), 120)
	if dur < 1 {
		dur = 1
	}
	gc.ExpiresAt = gc.CreatedAt.Add(time.Duration(dur) * time.Minute)
	return nil
}

// --- 渲染 ---

type pageData struct {
	Lang               string
	S                  Strings
	Brand              brandData
	DeviceIP           string
	DeviceMAC          string
	Account            string
	Message            string
	NowYear            int
	DuoEnabled         bool
	GuestEnabled       bool
	AllowedDomainsHint string
	PushTimeout        int
}

type brandData struct {
	Name    string
	Color   string
	LogoURL string
	Initial string
}

func (a *App) makeBrand() brandData {
	initial := "?"
	for _, r := range a.cfg.BrandName {
		initial = string(r)
		break
	}
	return brandData{
		Name:    a.cfg.BrandName,
		Color:   a.cfg.BrandColor,
		LogoURL: a.cfg.BrandLogoURL,
		Initial: initial,
	}
}

func (a *App) firstAllowedDomain() string {
	if len(a.cfg.AllowedEmailDomains) > 0 {
		return a.cfg.AllowedEmailDomains[0]
	}
	return "example.com"
}

func (a *App) renderLogin(w http.ResponseWriter, r *http.Request, lang Lang, dev DeviceInfo) {
	data := pageData{
		Lang:               string(lang),
		S:                  lang.s(),
		Brand:              a.makeBrand(),
		DeviceIP:           dev.IP,
		DeviceMAC:          dev.MAC,
		NowYear:            time.Now().Year(),
		DuoEnabled:         a.cfg.IsDuoEnabled(),
		GuestEnabled:       a.cfg.IsAdminEnabled(),
		AllowedDomainsHint: a.firstAllowedDomain(),
		PushTimeout:        a.cfg.DuoPushTimeoutSec,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := a.templates.ExecuteTemplate(w, "login.html", data); err != nil {
		log.Printf("模板渲染失败: %v", err)
	}
}

func (a *App) renderError(w http.ResponseWriter, r *http.Request, lang Lang, msg string, code int) {
	data := pageData{
		Lang:    string(lang),
		S:       lang.s(),
		Brand:   a.makeBrand(),
		Message: msg,
		NowYear: time.Now().Year(),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	if err := a.templates.ExecuteTemplate(w, "error.html", data); err != nil {
		log.Printf("模板渲染失败: %v", err)
	}
}

// adminPageData: /admin 模板数据.
type adminPageData struct {
	Brand     brandData
	AdminUPN  string
	NowYear   int
	Codes     []adminCodeRow
	Total     int
	Used      int
	Unused    int
	Expired   int
}

// adminCodeRow: UI 列表里一行.
type adminCodeRow struct {
	Code         string
	CreatedAt    string
	ExpiresAt    string
	Duration     string // 显示用, "2 小时" / "30 分钟" / 如果定了绝对时间就显示 "-"
	Status       string // unused / used / expired
	UseCount     int
	LastUsedAt   string
	LastUsedMAC  string
	LastUsedIP   string
	Note         string
}

func (a *App) renderAdmin(w http.ResponseWriter, r *http.Request, admin AdminSession) {
	raw := a.guestCodes.List()
	total, used, unused, expired := a.guestCodes.Stats()
	rows := make([]adminCodeRow, 0, len(raw))
	for _, c := range raw {
		row := adminCodeRow{
			Code:      c.Code,
			CreatedAt: c.CreatedAt.Local().Format("2006-01-02 15:04"),
			ExpiresAt: c.ExpiresAt.Local().Format("2006-01-02 15:04"),
			Status:    c.Status(),
			UseCount:  c.UseCount(),
			Note:      c.Note,
		}
		d := c.ExpiresAt.Sub(c.CreatedAt)
		hours := int(d.Hours())
		mins := int(d.Minutes()) - hours*60
		row.Duration = formatDuration(hours, mins)
		if len(c.Uses) > 0 {
			u := c.Uses[len(c.Uses)-1]
			row.LastUsedAt = u.At.Local().Format("2006-01-02 15:04")
			row.LastUsedMAC = u.MAC
			row.LastUsedIP = u.IP
		}
		rows = append(rows, row)
	}
	data := adminPageData{
		Brand:    a.makeBrand(),
		AdminUPN: admin.UPN,
		NowYear:  time.Now().Year(),
		Codes:    rows,
		Total:    total,
		Used:     used,
		Unused:   unused,
		Expired:  expired,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := a.templates.ExecuteTemplate(w, "admin.html", data); err != nil {
		log.Printf("admin 模板渲染失败: %v", err)
	}
}

// --- 小工具 ---

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("writeJSON encode: %v", err)
	}
}

func isValidEmail(s string) bool {
	if s == "" || len(s) > 254 {
		return false
	}
	at := strings.Index(s, "@")
	if at <= 0 || at >= len(s)-1 {
		return false
	}
	if strings.Count(s, "@") != 1 {
		return false
	}
	for _, c := range s {
		if !(c == '@' || c == '.' || c == '-' || c == '_' || c == '+' ||
			(c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

func isAllowedDomain(email string, allowed []string) bool {
	if len(allowed) == 0 {
		return false
	}
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return false
	}
	domain := strings.ToLower(email[at+1:])
	for _, d := range allowed {
		if strings.ToLower(strings.TrimSpace(d)) == domain {
			return true
		}
	}
	return false
}

func parseIntDefault(s string, def int) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

func tailN(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[len(r)-n:])
}

func formatDuration(hours, mins int) string {
	switch {
	case hours > 0 && mins > 0:
		return strconv.Itoa(hours) + "h" + strconv.Itoa(mins) + "m"
	case hours > 0:
		return strconv.Itoa(hours) + " 小时"
	case mins > 0:
		return strconv.Itoa(mins) + " 分钟"
	default:
		return "-"
	}
}
