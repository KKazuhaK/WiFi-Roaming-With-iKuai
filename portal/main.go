package main

// main.go
// HTTP 路由 + 启动逻辑。业务逻辑拆在其它文件里.
//
// 端点:
//   GET  /healthz                  健康检查
//   GET  /portal                   iKuai 302 未认证设备到这里
//   POST /auth/start               用户输入邮箱 → 服务端 preauth → 返回 opaque token
//                                    响应对所有邮箱一致 (防账号枚举), 浏览器再访问:
//   GET  /auth/proceed?token=...   查 token → 302 到真正目的 (Duo Universal / Entra)
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

	// --- 限流 / 防滥用 ---
	// 规则 1: /auth/start 按邮箱失败计数, 双窗口, 成功回调清零. 防 MFA 轰炸.
	authEmailFails *failCounter
	// 规则 5: /auth/guest-code 按 MAC 失败计数, 成功清零. 防暴力猜码.
	guestCodeFails *failCounter
	// 规则 6: 单 IP 跨端点累计失败, 超限封禁. 防同 IP 广撒网.
	ipFails    *failCounter
	ipBans     *ipBanList
	banHistory *banHistory // IP 被封过几次 (持久化), 用于升级到永久封禁

	// 账号枚举防护: /auth/start 返回 opaque token, /auth/proceed 才 302.
	proceedStore *proceedTokenStore
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

	guestStore, err := newGuestCodeStore(cfg.GuestCodesPath)
	if err != nil {
		log.Fatalf("访客码存储初始化失败: %v", err)
	}
	if cfg.GuestCodesPath != "" {
		log.Printf("访客码持久化: 已启用, path=%s", cfg.GuestCodesPath)
	} else {
		log.Printf("访客码持久化: 未启用 (纯内存, 容器重启数据丢)")
	}

	tmpl, err := template.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		log.Fatalf("模板加载失败: %v", err)
	}

	banHist, err := newBanHistory(cfg.RatelimitStatePath)
	if err != nil {
		log.Fatalf("ban history 初始化失败: %v", err)
	}

	app := &App{
		cfg:            cfg,
		oidc:           oidcClient,
		duo:            duoClient,
		duoUniversal:   duoUni,
		guestCodes:     guestStore,
		templates:      tmpl,
		authEmailFails: newFailCounter(cfg.AuthEmailWindowLong),
		guestCodeFails: newFailCounter(cfg.GuestCodeMacWindow),
		ipFails:        newFailCounter(cfg.IPFailsWindow),
		ipBans:         newIPBanList(),
		banHistory:     banHist,
		proceedStore:   newProceedTokenStore(cfg.AuthProceedTTL),
	}
	go app.authEmailFails.gcLoop()
	go app.guestCodeFails.gcLoop()
	go app.ipFails.gcLoop()
	go app.ipBans.gcLoop()
	go app.proceedStore.gcLoop()
	log.Printf("限流: email %d/%s + %d/%s, MAC %d/%s, IP %d/%s → 首次封禁 %s, 第 %d 次起永久",
		cfg.AuthEmailFailsShort, cfg.AuthEmailWindowShort,
		cfg.AuthEmailFailsLong, cfg.AuthEmailWindowLong,
		cfg.GuestCodeMacFails, cfg.GuestCodeMacWindow,
		cfg.IPFailsLimit, cfg.IPFailsWindow, cfg.IPBanDuration, cfg.IPBanEscalateAt)
	if cfg.RatelimitStatePath != "" {
		log.Printf("ban history 持久化: 已启用, path=%s", cfg.RatelimitStatePath)
	}

	staticSub, err := fs.Sub(staticFS, "static")
	if err != nil {
		log.Fatalf("静态目录加载失败: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", app.healthz)
	mux.HandleFunc("/robots.txt", app.robotsTxt)
	mux.HandleFunc("/portal", app.handlePortal)
	mux.HandleFunc("/auth/start", app.handleAuthStart)
	mux.HandleFunc("/auth/proceed", app.handleAuthProceed)
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
	mux.HandleFunc("/admin/ratelimit/status", app.handleRateLimitStatus)
	mux.HandleFunc("/admin/ratelimit/reset", app.handleRateLimitReset)
	mux.HandleFunc("/admin/ratelimit/reset-all", app.handleRateLimitResetAll)
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

// robotsTxt: 挡正经爬虫. 恶意爬虫不理 robots, 那一层交给限流.
// 模板里也打了 <meta name="robots" content="noindex, nofollow">, 这里是第二道.
func (a *App) robotsTxt(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write([]byte("User-agent: *\nDisallow: /\n"))
}

// --- WiFi 登录 ---

func (a *App) handlePortal(w http.ResponseWriter, r *http.Request) {
	lang := pickLang(r)
	dev, ok := extractDeviceInfo(r, a.cfg)
	if !ok {
		// 语言切换 / 刷新等二次访问 query 里没 iKuai 字段, 回退用已有 cookie.
		// 只要 cookie 有效且存了 IP/MAC, 就不当 session lost.
		if existing, err := readSessionCookie(r, a.cfg.SessionSecret); err == nil &&
			existing.UserIP != "" && existing.MAC != "" {
			dev = DeviceInfo{IP: existing.UserIP, MAC: existing.MAC}
			ok = true
		}
	}
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
//
// 关键安全设计:
//  1. 入口先查 IP 封禁 (规则 6) 和邮箱失败计数 (规则 1), 都过了再走真实分流.
//  2. 分流决定 (Duo vs Entra vs deny) 不直接暴露在响应里 — 放进 proceedStore
//     生成 opaque token, 浏览器访问 /auth/proceed?token=X 时才 302 到真正 URL.
//     这样所有有效邮箱的 /auth/start 响应看起来一模一样, 攻击者没法靠响应差异
//     枚举谁在 Duo / 谁被 deny.
//  3. 此处 record 邮箱 "pending attempt", 在 /auth/callback 或 /auth/duo-callback
//     成功时 reset — legit 用户一次成功就清零, 攻击者一直发不回调就爬满被拦.
func (a *App) handleAuthStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}

	// 规则 6 入口: IP 是否在封禁期.
	ip := clientIP(r)
	if a.ipBans.isBanned(ip) {
		a.writeRateLimited(w, "ip_ban", ip)
		return
	}

	sess, err := readSessionCookie(r, a.cfg.SessionSecret)
	if err != nil {
		a.recordIPFailure(ip, "session_lost")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "session_lost"})
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	if !isValidEmail(email) {
		a.recordIPFailure(ip, "invalid_email")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_email"})
		return
	}
	// 只有启用 Duo 时才强制域名白名单;
	// 不用 Duo 的场景, Entra 自己会做域名 / 租户过滤.
	if a.cfg.IsDuoEnabled() && !isAllowedDomain(email, a.cfg.AllowedEmailDomains) {
		log.Printf("拒绝域名不在白名单: %s", email)
		a.recordIPFailure(ip, "invalid_domain")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_domain"})
		return
	}

	// 规则 1: 检查该邮箱的失败计数 (双窗口).
	shortN := a.authEmailFails.countIn(email, a.cfg.AuthEmailWindowShort)
	longN := a.authEmailFails.countIn(email, a.cfg.AuthEmailWindowLong)
	if shortN >= a.cfg.AuthEmailFailsShort || longN >= a.cfg.AuthEmailFailsLong {
		log.Printf("auth/start 邮箱限流: %s short=%d long=%d ip=%s",
			email, shortN, longN, ip)
		a.recordIPFailure(ip, "rate_limited_email")
		// 哪个窗口先满选哪个的 retry_after
		rule := "email_long"
		if shortN >= a.cfg.AuthEmailFailsShort {
			rule = "email_short"
		}
		// 如果 recordIPFailure 这次刚好触发了 IP 封禁, 优先告诉客户端那个 (更严重).
		if a.ipBans.isBanned(ip) {
			rule = "ip_ban"
		}
		a.writeRateLimited(w, rule, ip)
		return
	}

	// 把邮箱记进 session, 供后续 handler 使用.
	sess.Email = email
	if err := writeSessionCookie(w, a.cfg.SessionSecret, sess, true); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cookie_write"})
		return
	}

	// 计算真实目的 URL 和分类 (稍后打进 opaque token, 不在响应里暴露).
	ssoURL := "/login?hint=" + url.QueryEscape(email)
	var (
		realURL string
		kind    proceedKind
	)
	if a.duo == nil || a.duoUniversal == nil {
		realURL, kind = ssoURL, proceedEntra
	} else {
		pre, perr := a.duo.Preauth(email)
		if perr != nil {
			log.Printf("Duo preauth 失败 for %s: %v, fallback 到 SSO", email, perr)
			realURL, kind = ssoURL, proceedEntra
		} else {
			log.Printf("Duo preauth for %s: result=%s devices=%d",
				email, pre.Result, len(pre.Devices))
			switch pre.Result {
			case "auth":
				if pre.HasUniversalPromptCapable() {
					duoURL, derr := a.duoUniversal.AuthURL(email, sess.State)
					if derr != nil {
						log.Printf("Duo AuthURL 构造失败: %v, fallback SSO", derr)
						realURL, kind = ssoURL, proceedEntra
					} else {
						realURL, kind = duoURL, proceedDuo
					}
				} else {
					log.Printf("%s 无任何 Duo 设备, fallback SSO", email)
					realURL, kind = ssoURL, proceedEntra
				}
			case "enroll", "allow":
				realURL, kind = ssoURL, proceedEntra
			case "deny":
				// 不在响应里告诉攻击者 "被拒" — 一律丢给 Entra, Entra 自己拒.
				log.Printf("Duo 拒绝账号: %s (%s), 仍走 Entra 不暴露 deny 信号",
					email, pre.StatusMsg)
				realURL, kind = ssoURL, proceedDeny
			default:
				log.Printf("未知 Duo preauth result: %s, fallback SSO", pre.Result)
				realURL, kind = ssoURL, proceedEntra
			}
		}
	}

	// 记一次 pending 失败 — 回调成功会清零.
	a.authEmailFails.record(email)

	token, err := a.proceedStore.put(realURL, sess.State, email, kind)
	if err != nil {
		log.Printf("proceedStore.put 失败: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"redirect": "/auth/proceed?token=" + token})
}

// writeRateLimited 发 429 响应, 带足以让前端渲染"稍后再试"/"联系管理员"的信息:
//   - rule: ip_ban / email_short / email_long / mac
//   - retry_after_seconds: 建议重试等待秒数
//   - permanent: true 时前端显示联系管理员, 不显示倒计时
//   - unban_at_unix: 解封 unix 时间 (仅 ip_ban 用)
func (a *App) writeRateLimited(w http.ResponseWriter, rule, ip string) {
	body := map[string]any{
		"error": "rate_limited",
		"rule":  rule,
	}
	switch rule {
	case "ip_ban":
		if exp, ok := a.ipBans.expiryOf(ip); ok {
			if IsPermanent(exp) {
				body["permanent"] = true
			} else {
				body["retry_after_seconds"] = int(time.Until(exp).Seconds())
				body["unban_at_unix"] = exp.Unix()
			}
		}
	case "email_short":
		body["retry_after_seconds"] = int(a.cfg.AuthEmailWindowShort.Seconds())
	case "email_long":
		body["retry_after_seconds"] = int(a.cfg.AuthEmailWindowLong.Seconds())
	case "mac":
		body["retry_after_seconds"] = int(a.cfg.GuestCodeMacWindow.Seconds())
	}
	writeJSON(w, http.StatusTooManyRequests, body)
}

// recordIPFailure 累加 IP 失败计数, 触发阈值就封禁.
// 升级模型: 第 1 次到 (IPBanEscalateAt-1) 次封禁 → IPBanDuration 时长;
// 第 IPBanEscalateAt 次及以上 → 永久封禁 (要 admin 手动解).
// reason 只进日志, 便于排查.
func (a *App) recordIPFailure(ip, reason string) {
	a.ipFails.record(ip)
	n := a.ipFails.countIn(ip, a.cfg.IPFailsWindow)
	if n < a.cfg.IPFailsLimit {
		return
	}
	// 已经在封了就别重复封 (避免每次请求都续期 + 计数乱升级).
	if a.ipBans.isBanned(ip) {
		return
	}
	banCount := a.banHistory.increment(ip)
	var duration time.Duration
	if banCount >= a.cfg.IPBanEscalateAt {
		duration = time.Until(PermanentBanUntil) // 算出到"永久"标记点的时长
		a.ipBans.ban(ip, duration)
		log.Printf("IP 失败超限, **永久封禁** (第 %d 次): %s (累计=%d 窗口=%s 原因=%s)",
			banCount, ip, n, a.cfg.IPFailsWindow, reason)
	} else {
		duration = a.cfg.IPBanDuration
		a.ipBans.ban(ip, duration)
		log.Printf("IP 失败超限, 封禁 %s (第 %d 次): %s (累计=%d 窗口=%s 原因=%s)",
			duration, banCount, ip, n, a.cfg.IPFailsWindow, reason)
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
	// 规则 1 清零: 走完 Entra 成功 = 这个邮箱是真人, 把 pending 失败抹掉.
	// 同时清 session.Email (用户输入的) 和 user.UPN (Entra 返回的) 两个 key,
	// 兜底 case-sensitivity 和 UPN != email 的边界情况.
	if sess.Email != "" {
		a.authEmailFails.reset(strings.ToLower(sess.Email))
	}
	a.authEmailFails.reset(strings.ToLower(user.UPN))
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
	// Duo Universal Prompt 回调参数名在不同版本 / 租户不一致:
	// 早期版本返 duo_code, OIDC-compliant 的新版本返 code. 两个都认.
	duoCode := r.URL.Query().Get("duo_code")
	if duoCode == "" {
		duoCode = r.URL.Query().Get("code")
	}
	if duoCode == "" {
		log.Printf("Duo callback 缺 code/duo_code 参数, query=%q", r.URL.RawQuery)
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
	// 规则 1 清零: Duo 2FA 过 = 这个邮箱是真人, 把 pending 失败抹掉.
	if sess.Email != "" {
		a.authEmailFails.reset(strings.ToLower(sess.Email))
	}
	a.authEmailFails.reset(strings.ToLower(username))
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
	ip := clientIP(r)
	if a.ipBans.isBanned(ip) {
		a.writeRateLimited(w, "ip_ban", ip)
		return
	}
	sess, err := readSessionCookie(r, a.cfg.SessionSecret)
	if err != nil {
		a.recordIPFailure(ip, "session_lost")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "session_lost"})
		return
	}
	// 规则 5: 按 session 里的 MAC 查失败计数. MAC 是从 /portal 签进 cookie 的,
	// 攻击者改不了, 所以比按 IP 更稳.
	if a.guestCodeFails.countIn(sess.MAC, a.cfg.GuestCodeMacWindow) >= a.cfg.GuestCodeMacFails {
		log.Printf("guest-code 按 MAC 限流: mac=%s ip=%s", sess.MAC, ip)
		a.recordIPFailure(ip, "rate_limited_mac")
		rule := "mac"
		if a.ipBans.isBanned(ip) {
			rule = "ip_ban"
		}
		a.writeRateLimited(w, rule, ip)
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
		a.guestCodeFails.record(sess.MAC)
		a.recordIPFailure(ip, "invalid_guest_code")
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_code"})
		return
	}
	log.Printf("放行访客: upn=%s code-suffix=%s ip=%s mac=%s",
		upn, tailN(c.Code, 4), sess.UserIP, sess.MAC)
	// 成功 → MAC 失败计数清零.
	a.guestCodeFails.reset(sess.MAC)
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
	if user.IsGuest() || !user.IsAdmin(a.cfg) {
		log.Printf("admin 登录被拒: upn=%s groups=%v", user.UPN, user.Groups)
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
	log.Printf("admin 登录成功: upn=%s via=%s", user.UPN, adminGrantReason(a.cfg, user))
	http.Redirect(w, r, "/admin", http.StatusFound)
}

// adminGrantReason 只给日志用, 说明这次 admin 通过靠的是 UPN 白名单还是组成员.
func adminGrantReason(cfg Config, u *UserInfo) string {
	if cfg.IsAdminEmail(u.UPN) {
		return "email_list"
	}
	return "group"
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
	// 签名 cookie 说明这个用户登录时通过了 IsAdmin 检查 (UPN 白名单 或 Entra 组).
	// 这里不再每次请求都 re-check UPN 是否在 ADMIN_EMAILS — 否则靠组准入的 admin
	// 会被立刻踢出, 且组变更无法在请求期检查 (id_token 在登录时一次性签). 撤销 admin
	// 的生效周期 = cookie TTL (4h); 要立刻踢就清了这人的 cookie, 或改 SessionSecret
	// 让所有 cookie 失效.
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

// handleRateLimitStatus GET /admin/ratelimit/status
// 返回当前限流状态快照 (被封 IP + 邮箱 / MAC 失败计数), 供 admin UI 渲染.
func (a *App) handleRateLimitStatus(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdmin(w, r, true); !ok {
		return
	}
	// 把 ban history 的计数合并到 ip_bans 快照里, 让前端直接在一行里显示 "第 N 次".
	// 对当前封禁中的 IP, 也顺手标出是不是"永久".
	bans := a.ipBans.snapshot()
	banCounts := a.banHistory.snapshot()
	type enrichedBan struct {
		IP          string `json:"ip"`
		ExpiresAt   int64  `json:"expires_unix"`
		BanCount    int    `json:"ban_count"`
		Permanent   bool   `json:"permanent"`
	}
	enriched := make([]enrichedBan, 0, len(bans))
	for _, b := range bans {
		t := time.Unix(b.ExpiresAt, 0)
		enriched = append(enriched, enrichedBan{
			IP:        b.IP,
			ExpiresAt: b.ExpiresAt,
			BanCount:  banCounts[b.IP],
			Permanent: IsPermanent(t),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":              true,
		"ip_bans":         enriched,
		"ban_history":     banCounts, // 包含所有曾经被封过的 IP (包括当前没在封的)
		"email_fails":     a.authEmailFails.snapshot(),
		"guest_mac_fails": a.guestCodeFails.snapshot(),
		"ip_fails":        a.ipFails.snapshot(),
		"now_unix":        time.Now().Unix(),
		"thresholds": map[string]any{
			"email_short":      a.cfg.AuthEmailFailsShort,
			"email_short_s":    int(a.cfg.AuthEmailWindowShort.Seconds()),
			"email_long":       a.cfg.AuthEmailFailsLong,
			"email_long_s":     int(a.cfg.AuthEmailWindowLong.Seconds()),
			"mac":              a.cfg.GuestCodeMacFails,
			"mac_s":            int(a.cfg.GuestCodeMacWindow.Seconds()),
			"ip":               a.cfg.IPFailsLimit,
			"ip_s":             int(a.cfg.IPFailsWindow.Seconds()),
			"ip_ban_s":         int(a.cfg.IPBanDuration.Seconds()),
			"ip_ban_escalate":  a.cfg.IPBanEscalateAt,
		},
	})
}

// handleRateLimitReset POST /admin/ratelimit/reset
// form: type=ip_ban|ip_fails|email|mac, key=<value>
// 对应清除 / 解封该 key 的限流状态.
func (a *App) handleRateLimitReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	admin, ok := a.requireAdmin(w, r, true)
	if !ok {
		return
	}
	t := strings.TrimSpace(r.FormValue("type"))
	key := strings.TrimSpace(r.FormValue("key"))
	if key == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing_key"})
		return
	}
	switch t {
	case "ip_ban":
		a.ipBans.unban(key)
		a.ipFails.reset(key)       // 同时清 IP 累计计数, 避免刚解封又立刻触发
		a.banHistory.reset(key)    // 清除历史封禁次数, 不然下次失败直接进 "永久" 分支
	case "ip_fails":
		a.ipFails.reset(key)
	case "email":
		a.authEmailFails.reset(strings.ToLower(key))
	case "mac":
		a.guestCodeFails.reset(key)
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_type"})
		return
	}
	log.Printf("admin %s 清除限流: type=%s key=%s", admin.UPN, t, key)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleRateLimitResetAll POST /admin/ratelimit/reset-all
// 一键清空所有限流状态: 所有 IP 封禁 + 所有邮箱 / MAC / IP 失败计数 + 封禁历史.
// 用于大面积误伤时快速救场, 或攻击消退后整体归零. 操作进日志.
func (a *App) handleRateLimitResetAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	admin, ok := a.requireAdmin(w, r, true)
	if !ok {
		return
	}
	cleared := map[string]int{
		"ip_bans":         a.ipBans.unbanAll(),
		"ban_history":     a.banHistory.resetAll(),
		"email_fails":     a.authEmailFails.resetAll(),
		"guest_mac_fails": a.guestCodeFails.resetAll(),
		"ip_fails":        a.ipFails.resetAll(),
	}
	log.Printf("admin %s 一键清除所有限流状态: %+v", admin.UPN, cleared)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "cleared": cleared})
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
