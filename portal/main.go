package main

// main.go
// HTTP 路由 + 启动逻辑。业务逻辑散在其它文件里:
//   config.go  - 环境变量 → Config
//   session.go - 签名 cookie (OIDC / Duo 流程的短命状态)
//   oidc.go    - Entra 授权 + id_token 校验
//   ikuai.go   - 设备识别 + iKuai 放行 URL
//   duo.go     - Duo Auth API v2 客户端 (免密推送)
//   i18n.go    - 三语字符串 (简体/繁體/英文)
//
// 端点:
//   GET  /healthz              给 aaPanel / docker healthcheck 用
//   GET  /portal               iKuai 路由器把用户 302 到这里 (带 user_ip + mac)
//   GET  /login                Entra SSO 路径: 用户点"使用 SSO 登录"后跳 Entra
//   GET  /auth/callback        Entra 登录完回跳这里
//   POST /auth/duo-start       Duo 免密路径: 提交邮箱, 服务器调 Duo preauth + auth
//   GET  /auth/duo-status      轮询 Duo 推送状态 (waiting/approved/denied)
//   GET  /auth/duo-finish      Duo 批准后最终放行 → 302 到 iKuai
//   GET  /static/*             logo/HeadPicture 等图片
//
// 安全约束:
//   - ListenAddr 默认只绑 127.0.0.1, 永远不直接面对公网; Nginx 反代负责 TLS
//   - 所有涉及写 Set-Cookie 的响应 Secure=true
//   - OIDC round-trip 用 state + nonce 防 CSRF 和重放
//   - tid claim 必须匹配, 防跨 tenant 攻击
//   - Duo 免密流程依赖邮箱域名白名单防推送滥发

import (
	"context"
	"embed"
	"encoding/json"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

type App struct {
	cfg       Config
	oidc      *OIDCClient
	duo       *DuoClient // 可能 nil (Duo 未配置)
	templates *template.Template
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
		log.Printf("Duo 免密推送: 未启用 (DUO_IKEY/SKEY/API_HOST 任一为空)")
	}

	tmpl, err := template.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		log.Fatalf("模板加载失败: %v", err)
	}

	app := &App{
		cfg:       cfg,
		oidc:      oidcClient,
		duo:       duoClient,
		templates: tmpl,
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

// --- handlers ---

func (a *App) healthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

// handlePortal: iKuai 302 未认证用户到这里, query 带 user_ip + mac.
// 我们:
//   1. 扒出 IP + MAC
//   2. 生成 session (含 state + nonce + 设备信息), 写 cookie
//   3. 渲染登录页 (两个按钮: SSO / Duo 免密)
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

// handleLogin: 用户点了 "使用 SSO 登录"。
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

// handleCallback: Entra 跳回这里。
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
		desc := r.URL.Query().Get("error_description")
		log.Printf("Entra 返回错误: %s - %s", errParam, desc)
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

// --- Duo 免密流程 ---

// handleDuoStart: 前端提交邮箱, 后端调 Duo preauth, 根据结果分流:
//   - 用户在 Duo 且有 push 设备 → 发推送, 返回 {mode: "push"}
//   - 用户不在 Duo (enroll)     → 让前端重定向到 /login (Entra SSO)
//   - 用户被 Duo 拒               → {mode: "deny"}
//   - 其它 (allow/异常)           → fallback SSO
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
			// 这个 Duo 用户没绑 push 能力 (可能只有硬件 token), 降级走 SSO
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
			log.Printf("写 Duo session 失败: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cookie_write"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"mode":    "push",
			"timeout": a.cfg.DuoPushTimeoutSec,
		})

	case "enroll":
		// 用户不在 Duo, 走 Entra SSO 路径
		writeJSON(w, http.StatusOK, map[string]string{"mode": "sso"})

	case "deny":
		log.Printf("Duo 拒绝账号: %s (%s)", email, pre.StatusMsg)
		writeJSON(w, http.StatusOK, map[string]string{"mode": "deny"})

	case "allow":
		// Duo 说这人免 MFA, 但我们仍要 Entra 确认是 Member
		writeJSON(w, http.StatusOK, map[string]string{"mode": "sso"})

	default:
		log.Printf("未知 preauth result: %s, 回落 SSO", pre.Result)
		writeJSON(w, http.StatusOK, map[string]string{"mode": "sso"})
	}
}

// handleDuoStatus: 前端每秒轮询, 返回 Duo 当前状态.
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

// handleDuoFinish: 前端看到 approved 后跳过来. 服务端再核一次 Duo 状态,
// 通过则构造 iKuai 放行 URL 并 302.
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
		log.Printf("Duo finish status error: %v", err)
		a.renderError(w, r, lang, lang.s().ErrorGenericMsg, http.StatusBadGateway)
		return
	}
	if status.Result != "allow" {
		log.Printf("Duo finish 状态非 allow: result=%s status=%s", status.Result, status.Status)
		a.renderError(w, r, lang, lang.s().ErrorGenericMsg, http.StatusUnauthorized)
		return
	}

	log.Printf("放行成员(Duo免密): upn=%s ip=%s mac=%s",
		sess.Email, sess.UserIP, sess.MAC)

	ikuaiURL := buildWebAuthURL(a.cfg, DeviceInfo{IP: sess.UserIP, MAC: sess.MAC}, sess.Email)
	clearSessionCookie(w, true)
	http.Redirect(w, r, ikuaiURL, http.StatusFound)
}

// --- 渲染 ---

type pageData struct {
	Lang                 string
	S                    Strings
	Brand                brandData
	DeviceIP             string
	DeviceMAC            string
	Account              string
	Message              string
	NowYear              int
	DuoEnabled           bool
	AllowedDomainsHint   string // 第一个允许域名, 用作 input placeholder
	PushTimeout          int    // Duo 推送超时秒数
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

// --- 小工具 ---

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("writeJSON encode: %v", err)
	}
}

// isValidEmail: 极简格式校验 (不要跑正则表达式试图覆盖 RFC 5322 全集).
// 只要有 @, 前后都有东西, 长度合理就通过. Duo preauth 会替我们进一步验证存在性.
func isValidEmail(s string) bool {
	if s == "" || len(s) > 254 {
		return false
	}
	at := strings.Index(s, "@")
	if at <= 0 || at >= len(s)-1 {
		return false
	}
	// 禁止多个 @, 或 @ 在最后一位
	if strings.Count(s, "@") != 1 {
		return false
	}
	// 简单字符白名单
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

