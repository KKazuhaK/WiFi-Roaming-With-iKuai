package main

// main.go
// HTTP 路由 + 启动逻辑。业务逻辑拆在其它文件里.
//
// 端点:
//   GET  /healthz                  健康检查
//   GET  /portal                   iKuai 302 未认证设备到这里
//   POST /auth/start               用户输入邮箱 → 服务端 preauth → 返回 { redirect }
//                                    有 Duo → Duo Universal Prompt URL
//                                    否则 → /login?hint=... (Entra SSO)
//   GET  /login                    跳 Entra (带 login_hint)
//   GET  /auth/callback            Entra 回调, 按 session.Purpose 分流 (wifi / admin)
//   GET  /auth/duo-callback        Duo Universal Prompt 回调, 拿 id_token → 放行
//   POST /auth/guest-code          访客码验证 → 放行
//   /admin*                        后台管理 (Entra 保护)
//   GET  /static/*                 静态资源
//
// 安全:
//   - Portal 只绑 127.0.0.1, Nginx 反代负责 TLS
//   - Cookie Secure + HttpOnly + SameSite=Lax
//   - Entra + Duo 都验 state (CSRF), Entra 额外验 nonce, tid, iss, aud
//   - Guest (UPN 含 #EXT#) 拒绝
//   - 邮箱域名白名单防外部域名在 Duo 上触发推送

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
	cfg          Config
	oidc         *OIDCClient
	duo          *DuoClient          // Duo Auth API, 仅 preauth 用
	duoUniversal *DuoUniversalClient // Duo Universal Prompt (OIDC)
	guestCodes   *GuestCodeStore
	templates    *template.Template
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
	var duoUni *DuoUniversalClient
	if cfg.IsDuoEnabled() {
		duoClient = newDuoClient(cfg)
		duoUni = newDuoUniversalClient(cfg)
		log.Printf("Duo: 已启用 (Auth API + Universal Prompt), host=%s, 允许域名=%v",
			cfg.DuoAPIHost, cfg.AllowedEmailDomains)
	} else {
		log.Printf("Duo: 未启用")
	}

	if cfg.IsAdminEnabled() {
		log.Printf("访客码 admin 后台: 已启用, admin=%v", cfg.AdminEmails)
	} else {
		log.Printf("访客码 admin 后台: 未启用")
	}

	tmpl, err := template.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		log.Fatalf("模板加载失败: %v", err)
	}

	app := &App{
		cfg:          cfg,
		oidc:         oidcClient,
		duo:          duoClient,
		duoUniversal: duoUni,
		guestCodes:   newGuestCodeStore(),
		templates:    tmpl,
	}

	staticSub, err := fs.Sub(staticFS, "static")
	if err != nil {
		log.Fatalf("静态目录加载失败: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", app.healthz)
	mux.HandleFunc("/portal", app.handlePortal)
	mux.HandleFunc("/auth/start", app.handleAuthStart)
	mux.HandleFunc("/login", app.handleLogin)
	mux.HandleFunc("/auth/callback", app.handleCallback)
	mux.HandleFunc("/auth/duo-callback", app.handleDuoCallback)
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

// --- 通用 ---

func (a *App) healthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

// --- WiFi 登录 ---

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

// handleAuthStart: 邮箱输入后的分流入口.
// 有 Duo 且用户在 Duo → 返回 Duo Universal Prompt URL
// 其它情况 → 返回 /login?hint=<email> (走 Entra SSO 预填邮箱)
func (a *App) handleAuthStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
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
	// 只有启用 Duo 时才强制域名白名单;
	// 不用 Duo 的场景, Entra 自己会做域名 / 租户过滤.
	if a.cfg.IsDuoEnabled() && !isAllowedDomain(email, a.cfg.AllowedEmailDomains) {
		log.Printf("拒绝域名不在白名单: %s", email)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_domain"})
		return
	}

	// 把邮箱记进 session, 供后续 handler 使用
	sess.Email = email
	if err := writeSessionCookie(w, a.cfg.SessionSecret, sess, true); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cookie_write"})
		return
	}

	ssoURL := "/login?hint=" + url.QueryEscape(email)

	// Duo 未启用 → 直接走 Entra
	if a.duo == nil || a.duoUniversal == nil {
		writeJSON(w, http.StatusOK, map[string]string{"redirect": ssoURL})
		return
	}

	// preauth 探测用户在 Duo 的状态
	pre, err := a.duo.Preauth(email)
	if err != nil {
		log.Printf("Duo preauth 失败 for %s: %v, fallback 到 SSO", email, err)
		writeJSON(w, http.StatusOK, map[string]string{"redirect": ssoURL})
		return
	}
	log.Printf("Duo preauth for %s: result=%s devices=%d", email, pre.Result, len(pre.Devices))

	switch pre.Result {
	case "auth":
		if !pre.HasUniversalPromptCapable() {
			log.Printf("%s 无任何 Duo 设备, fallback SSO", email)
			writeJSON(w, http.StatusOK, map[string]string{"redirect": ssoURL})
			return
		}
		duoURL, err := a.duoUniversal.AuthURL(email, sess.State)
		if err != nil {
			log.Printf("Duo AuthURL 构造失败: %v, fallback SSO", err)
			writeJSON(w, http.StatusOK, map[string]string{"redirect": ssoURL})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"redirect": duoURL})

	case "enroll", "allow":
		// 没在 Duo 注册, 或被标记跳过 MFA → 正常走 Entra
		writeJSON(w, http.StatusOK, map[string]string{"redirect": ssoURL})

	case "deny":
		log.Printf("Duo 拒绝账号: %s (%s)", email, pre.StatusMsg)
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "account_denied"})

	default:
		log.Printf("未知 Duo preauth result: %s, fallback SSO", pre.Result)
		writeJSON(w, http.StatusOK, map[string]string{"redirect": ssoURL})
	}
}

// handleLogin: 跳 Entra, 如有 ?hint=email 作为 login_hint 预填.
// 如果没 hint 但 session 里有 email 也用.
func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	lang := pickLang(r)
	sess, err := readSessionCookie(r, a.cfg.SessionSecret)
	if err != nil {
		a.renderError(w, r, lang, lang.s().SessionLostMsg, http.StatusBadRequest)
		return
	}
	hint := strings.TrimSpace(r.URL.Query().Get("hint"))
	if hint == "" {
		hint = sess.Email
	}
	http.Redirect(w, r, a.oidc.AuthURL(sess.State, sess.Nonce, hint), http.StatusFound)
}

// handleCallback: Entra 回调. 按 session.Purpose 分流.
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
		log.Printf("Entra state 不匹配")
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
	if user.IsGuest() {
		log.Printf("拒绝 Guest: %s", user.UPN)
		a.renderError(w, r, lang, lang.s().GuestBlockedMsg, http.StatusForbidden)
		return
	}
	log.Printf("放行成员(SSO): upn=%s name=%q ip=%s mac=%s",
		user.UPN, user.Name, sess.UserIP, sess.MAC)
	ikuaiURL := buildWebAuthURL(a.cfg, DeviceInfo{IP: sess.UserIP, MAC: sess.MAC}, user.UPN)
	clearSessionCookie(w, true)
	http.Redirect(w, r, ikuaiURL, http.StatusFound)
}

// handleDuoCallback: Duo Universal Prompt 回调. ?state, ?duo_code.
// 验 state → 换 code → 得 username → 放行.
func (a *App) handleDuoCallback(w http.ResponseWriter, r *http.Request) {
	lang := pickLang(r)
	if a.duoUniversal == nil {
		a.renderError(w, r, lang, lang.s().ErrorGenericMsg, http.StatusServiceUnavailable)
		return
	}
	sess, err := readSessionCookie(r, a.cfg.SessionSecret)
	if err != nil {
		a.renderError(w, r, lang, lang.s().SessionLostMsg, http.StatusBadRequest)
		return
	}
	if sess.Lang != "" {
		lang = Lang(sess.Lang)
	}
	if got := r.URL.Query().Get("state"); got != sess.State {
		log.Printf("Duo state 不匹配")
		a.renderError(w, r, lang, lang.s().ErrorGenericMsg, http.StatusBadRequest)
		return
	}
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		log.Printf("Duo 返回错误: %s", errParam)
		a.renderError(w, r, lang, lang.s().ErrorGenericMsg, http.StatusBadRequest)
		return
	}
	duoCode := r.URL.Query().Get("duo_code")
	if duoCode == "" {
		a.renderError(w, r, lang, lang.s().ErrorGenericMsg, http.StatusBadRequest)
		return
	}
	if sess.Email == "" {
		log.Printf("Duo callback: session 里没 email")
		a.renderError(w, r, lang, lang.s().SessionLostMsg, http.StatusBadRequest)
		return
	}
	username, err := a.duoUniversal.Exchange(duoCode, sess.Email)
	if err != nil {
		log.Printf("Duo Exchange 失败 for %s: %v", sess.Email, err)
		a.renderError(w, r, lang, lang.s().ErrorGenericMsg, http.StatusUnauthorized)
		return
	}
	log.Printf("放行成员(Duo快捷): upn=%s ip=%s mac=%s", username, sess.UserIP, sess.MAC)
	ikuaiURL := buildWebAuthURL(a.cfg, DeviceInfo{IP: sess.UserIP, MAC: sess.MAC}, username)
	clearSessionCookie(w, true)
	http.Redirect(w, r, ikuaiURL, http.StatusFound)
}

// --- 访客码 ---

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
		log.Printf("拒绝访客码 ip=%s mac=%s", sess.UserIP, sess.MAC)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_code"})
		return
	}
	log.Printf("放行访客: upn=%s code-suffix=%s ip=%s mac=%s",
		upn, tailN(c.Code, 4), sess.UserIP, sess.MAC)
	ikuaiURL := buildWebAuthURL(a.cfg, DeviceInfo{IP: sess.UserIP, MAC: sess.MAC}, upn)
	clearSessionCookie(w, true)
	writeJSON(w, http.StatusOK, map[string]string{"redirect": ikuaiURL})
}

// --- admin ---

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
	// admin 登录不预填邮箱
	http.Redirect(w, r, a.oidc.AuthURL(sess.State, sess.Nonce, ""), http.StatusFound)
}

func (a *App) finishAdminLogin(w http.ResponseWriter, r *http.Request, lang Lang, user *UserInfo) {
	if user.IsGuest() || !a.cfg.IsAdminEmail(user.UPN) {
		log.Printf("admin 登录被拒: upn=%s", user.UPN)
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
		MaxUses:   parseMaxUses(r.FormValue("max_uses")),
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
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "code": gc.Code})
}

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
	maxUses := parseMaxUses(r.FormValue("max_uses"))
	// baseProbe 只用来复用 parseExpiry 的过期计算; 每个码的 CreatedAt 用各自
	// 的 time.Now(), 保证 List 排序时不会因时间戳相同而顺序抖动.
	baseProbe := &GuestCode{CreatedAt: time.Now()}
	if err := parseExpiry(r, baseProbe); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	// 如果用户填了绝对过期时间, 所有码共用; 否则按 "创建时间 + 时长" 给每个码算.
	absoluteExpiry := strings.TrimSpace(r.FormValue("expires_at")) != ""
	duration := baseProbe.ExpiresAt.Sub(baseProbe.CreatedAt)
	generated := make([]string, 0, count)
	for i := 0; i < count; i++ {
		raw, err := generateCode(codeType, length)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "rand_failed"})
			return
		}
		createdAt := time.Now()
		expiresAt := baseProbe.ExpiresAt
		if !absoluteExpiry {
			expiresAt = createdAt.Add(duration)
		}
		gc := &GuestCode{
			Code:      raw,
			CreatedAt: createdAt,
			ExpiresAt: expiresAt,
			MaxUses:   maxUses,
			Note:      note,
		}
		if !a.guestCodes.Add(gc) {
			i-- // 撞码了, 重试
			continue
		}
		generated = append(generated, raw)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "count": len(generated), "codes": generated,
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
	writeJSON(w, http.StatusOK, map[string]any{"ok": a.guestCodes.Delete(code)})
}

func (a *App) handleCodeDeleteExpired(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	if _, ok := a.requireAdmin(w, r, true); !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "deleted": a.guestCodes.DeleteExpired()})
}

func parseExpiry(r *http.Request, gc *GuestCode) error {
	exp := strings.TrimSpace(r.FormValue("expires_at"))
	if exp != "" {
		t, err := time.Parse(time.RFC3339, exp)
		if err != nil {
			t2, err2 := time.ParseInLocation("2006-01-02T15:04", exp, time.Local)
			if err2 != nil {
				return fmt.Errorf("expires_at 格式错误: %v", err)
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
	Message            string
	NowYear            int
	GuestEnabled       bool
	AllowedDomainsHint string // email input placeholder 用第一个允许域名
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
		NowYear:            time.Now().Year(),
		GuestEnabled:       a.cfg.IsAdminEnabled(),
		AllowedDomainsHint: a.firstAllowedDomain(),
	}
	_ = dev // IP/MAC 不再显示, 但 handlePortal 仍会校验存在性
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

type adminPageData struct {
	Brand    brandData
	AdminUPN string
	NowYear  int
	Codes    []adminCodeRow
	Total    int
	Used     int
	Unused   int
	Expired  int
}

type adminCodeRow struct {
	Code        string
	CreatedAt   string
	ExpiresAt   string
	Duration    string
	Status      string
	UseCount    int
	MaxUses     int // 0 = 不限
	LastUsedAt  string
	LastUsedMAC string
	LastUsedIP  string
	Note        string
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
			MaxUses:   c.MaxUses,
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

// parseMaxUses: 空 / 0 / 负数 → 0 (不限); 否则原值.
func parseMaxUses(s string) int {
	n := parseIntDefault(s, 0)
	if n < 0 {
		return 0
	}
	return n
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
