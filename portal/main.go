package main

// main.go
// HTTP 路由 + 启动逻辑。业务逻辑散在其它文件里:
//   config.go  - 环境变量 → Config
//   session.go - 签名 cookie (OIDC round-trip 状态)
//   oidc.go    - Entra 授权 + id_token 校验
//   ikuai.go   - 设备识别 + iKuai 放行 URL
//   i18n.go    - 中英双语字符串
//
// 端点:
//   GET  /portal           iKuai 路由器把用户 302 到这里 (带 user_ip + mac)
//   GET  /login            用户点 "Sign in" 后, 跳到 Entra
//   GET  /auth/callback    Entra 登录完回跳这里
//   GET  /healthz          给 aaPanel / docker healthcheck 用
//
// 安全约束:
//   - ListenAddr 默认只绑 127.0.0.1, 永远不直接面对公网; Nginx 反代负责 TLS
//   - 所有涉及写 Set-Cookie 的响应 Secure=true (因为对外永远是 https)
//   - OIDC round-trip 用 state + nonce 防 CSRF 和重放
//   - tid claim 必须匹配, 防跨 tenant 攻击

import (
	"context"
	"embed"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"time"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

type App struct {
	cfg       Config
	oidc      *OIDCClient
	templates *template.Template
}

func main() {
	cfg := loadConfig()

	// Entra discovery 带一个大超时, 容器启动时如果 Entra 临时抽风至少能报错退出
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	oidcClient, err := newOIDCClient(ctx, cfg)
	if err != nil {
		log.Fatalf("OIDC 初始化失败: %v", err)
	}

	tmpl, err := template.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		log.Fatalf("模板加载失败: %v", err)
	}

	app := &App{
		cfg:       cfg,
		oidc:      oidcClient,
		templates: tmpl,
	}

	// 静态资源 (logo fallback 等). 只在 mux 上挂一次.
	staticSub, err := fs.Sub(staticFS, "static")
	if err != nil {
		log.Fatalf("静态目录加载失败: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", app.healthz)
	mux.HandleFunc("/portal", app.handlePortal)
	mux.HandleFunc("/login", app.handleLogin)
	mux.HandleFunc("/auth/callback", app.handleCallback)
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

// securityHeaders 给所有响应加基础安全头.
// Captive Portal 暴露面很窄但也要防止万一被当成 iframe 套进去做钓鱼.
func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 拒绝被 iframe 嵌套
		w.Header().Set("X-Frame-Options", "DENY")
		// 阻止 MIME 嗅探
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// 不带 Referer 去 Entra (它也不需要)
		w.Header().Set("Referrer-Policy", "no-referrer")
		// CSP: 只允许同源, 允许内联 style (我们模板里用了 inline CSS)
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; frame-ancestors 'none'")
		// HSTS 是 Nginx 那层加的, 这里不重复
		h.ServeHTTP(w, r)
	})
}

// logRequests 打印每个请求的简要信息。
// 不打 cookie, 不打 code, 避免敏感信息进日志。
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

// healthz 简单的存活探针。给 docker healthcheck / Nginx upstream check 用。
func (a *App) healthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

// handlePortal: iKuai 路由器把未认证用户 302 到这里, query 带 user_ip + mac。
// 我们:
//   1. 扒出 IP + MAC
//   2. 生成 session (含 state + nonce + 设备信息), 写 cookie
//   3. 渲染登录页, 按钮指向 /login
func (a *App) handlePortal(w http.ResponseWriter, r *http.Request) {
	lang := pickLang(r)

	dev, ok := extractDeviceInfo(r, a.cfg)
	if !ok {
		// 没识别到设备, 通常是有人直接访问 Portal 域名 (不是从 WiFi 跳进来的)
		// 返回一个说明页, 不继续流程
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

// handleLogin: 用户点了登录按钮。
// 前提: /portal 已经写好 session cookie。如果没有 (直接访问 /login), 拒绝。
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
// 流程:
//   1. 验 state (从 query 里取, 和 cookie 里存的比对)
//   2. code → token → id_token 验签 + nonce 校验 → UserInfo
//   3. 查 Guest (UPN 含 #EXT#), 有则拒
//   4. 构造 iKuai 放行 URL, 302 过去
//   5. 清掉 session cookie
func (a *App) handleCallback(w http.ResponseWriter, r *http.Request) {
	lang := pickLang(r)

	// 1. 取并验 session
	sess, err := readSessionCookie(r, a.cfg.SessionSecret)
	if err != nil {
		a.renderError(w, r, lang, lang.s().SessionLostMsg, http.StatusBadRequest)
		return
	}
	// session 里记了用户选的语言, 跨 Entra 之后沿用
	if sess.Lang != "" {
		lang = Lang(sess.Lang)
	}

	// 2. Entra 报错时不会带 code, 而是带 error 参数
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		desc := r.URL.Query().Get("error_description")
		log.Printf("Entra 返回错误: %s - %s", errParam, desc)
		a.renderError(w, r, lang, lang.s().ErrorGenericMsg, http.StatusBadRequest)
		return
	}

	// 3. state 校验
	if got := r.URL.Query().Get("state"); got != sess.State {
		log.Printf("state 不匹配: cookie=%s, query=%s", sess.State, got)
		a.renderError(w, r, lang, lang.s().ErrorGenericMsg, http.StatusBadRequest)
		return
	}

	// 4. code 换 token + id_token 校验
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

	// 5. Guest 拦截
	if user.IsGuest() {
		log.Printf("拒绝 Guest 账号登录: %s", user.UPN)
		a.renderError(w, r, lang, lang.s().GuestBlockedMsg, http.StatusForbidden)
		return
	}

	log.Printf("放行成员: upn=%s name=%q ip=%s mac=%s",
		user.UPN, user.Name, sess.UserIP, sess.MAC)

	// 6. 生成 iKuai 放行 URL, 302
	ikuaiURL := buildWebAuthURL(a.cfg, DeviceInfo{IP: sess.UserIP, MAC: sess.MAC})

	// 清 session cookie, 用完就扔
	clearSessionCookie(w, true)

	http.Redirect(w, r, ikuaiURL, http.StatusFound)
}

// --- 渲染 ---

type pageData struct {
	Lang      string // 从 Lang 类型 cast 过来, 便于模板里 {{ if eq .Lang "en" }} 比较
	S         Strings
	Brand     brandData
	DeviceIP  string
	DeviceMAC string
	Account   string
	Message   string
	NowYear   int
}

type brandData struct {
	Name    string
	Color   string
	LogoURL string
	Initial string // Name 的首字符, 支持多字节 (中文) 正确截取
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

func (a *App) renderLogin(w http.ResponseWriter, r *http.Request, lang Lang, dev DeviceInfo) {
	data := pageData{
		Lang:      string(lang),
		S:         lang.s(),
		Brand:     a.makeBrand(),
		DeviceIP:  dev.IP,
		DeviceMAC: dev.MAC,
		NowYear:   time.Now().Year(),
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
