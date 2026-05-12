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
	"crypto/subtle"
	"embed"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

// 内嵌的部署模板文件 — `wifi-portal init <dir>` 子命令把它们写到磁盘,
// 让裸二进制部署不需要再去 git clone 拿样板. //go:embed 在 build 时把
// 文件内容打进 binary, 路径相对 go 源码所在目录.
//
//go:embed .env.example
var embeddedEnvExample []byte

//go:embed embed/wifi-portal.service
var embeddedSystemdUnit []byte

// dataPaths 是从 cfg.DataDir 算出来的所有持久化文件位置. 在 main() 里构造一次
// 后整个进程复用. 文件名固定 (不暴露成各自的 env), 只目录可改:
//   - 容器场景: cfg.DataDir = /data (默认), docker-compose bind-mount /data → ./data
//   - 裸二进制 + systemd: 通常 /var/lib/wifi-portal
type dataPaths struct {
	GuestCodes  string
	Denylist    string
	IKuaiPolicy string
	BanHistory  string
	EventLog    string
}

func makeDataPaths(dataDir string) dataPaths {
	return dataPaths{
		GuestCodes:  filepath.Join(dataDir, "guest-codes.json"),
		Denylist:    filepath.Join(dataDir, "denylist.json"),
		IKuaiPolicy: filepath.Join(dataDir, "ikuai-policy.json"),
		BanHistory:  filepath.Join(dataDir, "ratelimit-state.json"),
		EventLog:    filepath.Join(dataDir, "events.jsonl"),
	}
}

// isSameOriginRequest 校验请求是从 cfg.PublicURL 同源发起.
// 优先 Origin (浏览器 fetch / form POST 都会发); fallback Referer.
// 两个都没有 → 拒绝 (现代浏览器 form POST 默认带 Referer; 缺失通常是 curl / 伪造客户端).
func (a *App) isSameOriginRequest(r *http.Request) bool {
	expected := strings.TrimRight(a.cfg.PublicURL, "/")
	if origin := r.Header.Get("Origin"); origin != "" {
		// Origin 是 scheme+host[:port], 不带 path — 直接比.
		return strings.TrimRight(origin, "/") == expected
	}
	if referer := r.Header.Get("Referer"); referer != "" {
		ref, err := url.Parse(referer)
		if err != nil || ref.Scheme == "" || ref.Host == "" {
			return false
		}
		// 重组成 scheme://host[:port] 后比.
		got := ref.Scheme + "://" + ref.Host
		return got == expected
	}
	return false
}

// isLoopbackListen 判断 LISTEN_ADDR 是否只绑 loopback 接口.
// host 部分为空 (":28080") 视为 0.0.0.0 — 监听所有接口, 不算 loopback.
func isLoopbackListen(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func ensureDataDirWritable(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create data dir %s: %w", dir, err)
	}
	f, err := os.CreateTemp(dir, ".write-test-*")
	if err != nil {
		return fmt.Errorf("write test in %s: %w", dir, err)
	}
	name := f.Name()
	if err := f.Close(); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("close write test %s: %w", name, err)
	}
	if err := os.Remove(name); err != nil {
		return fmt.Errorf("remove write test %s: %w", name, err)
	}
	return nil
}

type App struct {
	cfg           Config
	oidc          *OIDCClient
	duo           *DuoClient          // Duo Auth API, 仅 preauth 用
	duoUniversal  *DuoUniversalClient // Duo Universal Prompt (OIDC)
	guestCodes    *GuestCodeStore
	denylist      *DenylistStore
	ikuaiPolicies *IKuaiPolicyStore
	templates     *template.Template

	// --- 限流 / 防滥用 ---
	// 规则 1: /auth/start 按邮箱失败计数, 双窗口, 成功回调清零. 防 MFA 轰炸.
	authEmailFails *failCounter
	// 规则 5: /auth/guest-code 按 MAC 失败计数, 成功清零. 防暴力猜码.
	guestCodeFails *failCounter
	// 规则 6: 单 IP 跨端点累计失败, 超限短时冷却. 防同 IP 广撒网.
	ipFails    *failCounter
	ipBans     *ipBanList
	banHistory *banHistory // IP 被冷却过几次; 默认不持久化, 不升级永久

	// 账号枚举防护: /auth/start 返回 opaque token, /auth/proceed 才 302.
	proceedStore *proceedTokenStore

	// usedStates 防 OIDC state 被重放: callback 验完 state 立刻 markUsed, 同 state 第
	// 二次到达直接拒. 攻击者偷到 cookie 后即使在 15 分钟 TTL 内也只能 round-trip 一次.
	usedStates *usedStateSet

	// --- 可观测性 ---
	eventLog *EventLog
}

// runInit 处理 `wifi-portal init [dir]` 子命令: 把内嵌的 .env.example +
// systemd unit 写到指定目录, 让裸二进制部署不需要 git clone 拿样板.
//
// 已存在的目标文件不覆盖, 防止误删用户改过的配置. 返回非 nil 表示需要 exit 1.
func runInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	outDir := fs.String("out-dir", ".", "把 wifi-portal.env 和 wifi-portal.service 写到哪里 (本地编辑用)")
	confDir := fs.String("conf-dir", "", "systemd unit 里 EnvironmentFile 指向的目录 (default: 等于 --out-dir)")
	dataDir := fs.String("data-dir", "/var/lib/wifi-portal", "运行时数据目录, systemd unit 的 ReadWritePaths + .env 的 DATA_DIR")
	binPath := fs.String("bin-path", "/usr/local/bin/wifi-portal", "wifi-portal 二进制最终位置, systemd unit 的 ExecStart")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("意外的 positional 参数 %q. 所有路径都用 flag 指定: --out-dir / --conf-dir / --data-dir / --bin-path", fs.Arg(0))
	}
	absOut, err := filepath.Abs(*outDir)
	if err != nil {
		return fmt.Errorf("resolve %q: %w", *outDir, err)
	}
	if *confDir == "" {
		*confDir = absOut
	}
	if err := os.MkdirAll(absOut, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", absOut, err)
	}

	// .env header: 反映实际部署路径, 用户填好后能直接拷到 conf-dir + systemctl start.
	// 同时把 DATA_DIR= 设好, 跟 systemd unit 的 ReadWritePaths 自动对齐.
	envHeader := fmt.Sprintf(`# 由 `+"`"+`wifi-portal init`+"`"+` 生成. 实际部署路径 (本 .env 自身已对齐):
#
#   配置文件        %s/wifi-portal.env       (systemd EnvironmentFile=)
#   数据目录        %s     (DATA_DIR + systemd ReadWritePaths=)
#   二进制          %s   (systemd ExecStart=)
#
# 想换路径下次跑 init 时改 flag:
#   wifi-portal init --conf-dir <path> --data-dir <path> --bin-path <path> --out-dir <path>
#
# 关键 override (裸二进制 / systemd 场景):
#   LISTEN_ADDR=127.0.0.1:28080    # loopback, 反代访问
#   DATA_DIR=%s    # 已默认设, 跟 systemd ReadWritePaths 一致
#   TZ=UTC
#   TRUST_PROXY=true               # 反代终结连接时设
# ----------------------------------------------------------------------

DATA_DIR=%s
`, *confDir, *dataDir, *binPath, *dataDir, *dataDir)
	envContent := append([]byte(envHeader), embeddedEnvExample...)

	// systemd unit: 替换 3 个 placeholder.
	unitContent := strings.ReplaceAll(string(embeddedSystemdUnit), "__CONF_DIR__", *confDir)
	unitContent = strings.ReplaceAll(unitContent, "__DATA_DIR__", *dataDir)
	unitContent = strings.ReplaceAll(unitContent, "__BIN_PATH__", *binPath)

	items := []struct {
		name    string
		content []byte
		mode    os.FileMode
	}{
		{"wifi-portal.env", envContent, 0o600},
		{"wifi-portal.service", []byte(unitContent), 0o644},
	}
	for _, it := range items {
		dst := filepath.Join(absOut, it.name)
		if _, err := os.Stat(dst); err == nil {
			fmt.Fprintf(os.Stderr, "skip %s (already exists, not overwriting)\n", dst)
			continue
		}
		if err := os.WriteFile(dst, it.content, it.mode); err != nil {
			return fmt.Errorf("write %s: %w", dst, err)
		}
		fmt.Fprintf(os.Stderr, "wrote %s\n", dst)
	}
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "下一步:")
	fmt.Fprintf(os.Stderr, "  1. 编辑 %s/wifi-portal.env, 填 TENANT_ID / CLIENT_ID / 等\n", absOut)
	fmt.Fprintln(os.Stderr, "  2. systemd 部署:")
	fmt.Fprintf(os.Stderr, "       sudo useradd -r -s /usr/sbin/nologin -d %s wifi-portal\n", *dataDir)
	if *confDir != absOut {
		fmt.Fprintf(os.Stderr, "       sudo mkdir -p %s %s\n", *dataDir, *confDir)
		fmt.Fprintf(os.Stderr, "       sudo chown wifi-portal:wifi-portal %s\n", *dataDir)
		fmt.Fprintf(os.Stderr, "       sudo cp %s/wifi-portal.env %s/\n", absOut, *confDir)
	} else {
		fmt.Fprintf(os.Stderr, "       sudo mkdir -p %s\n", *dataDir)
		fmt.Fprintf(os.Stderr, "       sudo chown wifi-portal:wifi-portal %s\n", *dataDir)
		fmt.Fprintf(os.Stderr, "       # wifi-portal.env 已在 conf-dir (%s) 里, 不用再 cp\n", *confDir)
	}
	fmt.Fprintf(os.Stderr, "       sudo cp %s/wifi-portal.service /etc/systemd/system/\n", absOut)
	fmt.Fprintf(os.Stderr, "       sudo cp wifi-portal %s   # 二进制本体\n", *binPath)
	fmt.Fprintln(os.Stderr, "       sudo systemctl daemon-reload")
	fmt.Fprintln(os.Stderr, "       sudo systemctl enable --now wifi-portal")
	fmt.Fprintln(os.Stderr, "  3. 反代终结 TLS (Nginx / Caddy), 转发到 127.0.0.1:28080")
	return nil
}

// looksUninitialized: 关键 env *一个都没设* 时, 大概率是用户第一次裸跑二进制
// 还没 source .env / 没接 systemd EnvironmentFile=. 这种情况下进 first-run init
// 流程 — 自动生成配置模板而不是抛 mustEnv fatal.
//
// 只有"全部为空"才触发, 部分空仍走 mustEnv 报具体缺哪个 (用户已经填到一半的
// 配置不应被误判成 first-run).
func looksUninitialized() bool {
	keys := []string{"TENANT_ID", "CLIENT_ID", "CLIENT_SECRET", "IKUAI_APPKEY", "PUBLIC_URL", "SESSION_SECRET"}
	for _, k := range keys {
		if strings.TrimSpace(os.Getenv(k)) != "" {
			return false
		}
	}
	return true
}

func main() {
	// 显式 init 子命令 — 可指定目录, 适合 ops "我想 init 到 /etc/wifi-portal"
	if len(os.Args) > 1 && os.Args[1] == "init" {
		if err := runInit(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "init error:", err)
			os.Exit(1)
		}
		return
	}

	// First-run auto init: 关键 env 全空 = 用户裸跑还没配, 自动生成模板到当前目录.
	// 跳过条件: 容器场景 / systemd EnvironmentFile= 场景 — env 已设, 直接走启动.
	if looksUninitialized() {
		fmt.Fprintln(os.Stderr, "wifi-portal: 检测到关键 env 未设, 进入 first-run 配置流程")
		fmt.Fprintln(os.Stderr, "(若想 init 到其它目录用 `wifi-portal init <dir>`; 已设 env 时本步跳过)")
		fmt.Fprintln(os.Stderr, "")
		if err := runInit(nil); err != nil {
			fmt.Fprintln(os.Stderr, "init error:", err)
			os.Exit(1)
		}
		return
	}

	loadTranslations()

	cfg := loadConfig()

	// 注入到 ratelimit.go 的 package var. 必须在任何 clientIP 调用之前.
	trustProxyHeaders = cfg.TrustProxy
	if !cfg.TrustProxy {
		log.Printf("TRUST_PROXY=false: 忽略 X-Real-IP / X-Forwarded-For, 仅按 r.RemoteAddr 计客户端 IP")
	} else if !isLoopbackListen(cfg.ListenAddr) {
		log.Printf("warning: LISTEN_ADDR=%s 不是 loopback 且 TRUST_PROXY=true. 若 Portal 端口直接暴露公网, 攻击者可伪造 X-Real-IP/X-Forwarded-For 绕过 IP 限流; 务必让反代终结连接, 或显式 TRUST_PROXY=false",
			cfg.ListenAddr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	oidcClient, err := newOIDCClient(ctx, cfg)
	if err != nil {
		log.Fatalf("OIDC init failed: %v", err)
	}

	var duoClient *DuoClient
	var duoUni *DuoUniversalClient
	if cfg.IsDuoEnabled() {
		duoClient = newDuoClient(cfg)
		duoUni = newDuoUniversalClient(cfg)
		log.Printf("Duo: enabled (Auth API + Universal Prompt), host=%s, allowed_domains=%v",
			cfg.DuoAPIHost, cfg.AllowedEmailDomains)
	} else {
		log.Printf("Duo: disabled")
	}

	if cfg.IsAdminEnabled() {
		log.Printf("admin console: enabled, admin=%v", cfg.AdminEmails)
	} else {
		log.Printf("admin console: disabled")
	}

	paths := makeDataPaths(cfg.DataDir)
	if err := ensureDataDirWritable(cfg.DataDir); err != nil {
		log.Fatalf("data dir is not writable: %v", err)
	}

	guestStore, err := newGuestCodeStore(paths.GuestCodes)
	if err != nil {
		log.Fatalf("guest codes store init failed: %v", err)
	}

	denylistStore, err := newDenylistStore(paths.Denylist)
	if err != nil {
		log.Fatalf("MAC denylist init failed: %v", err)
	}

	ikuaiPolicyStore, err := newIKuaiPolicyStore(cfg.IKuaiPolicyDefaults, paths.IKuaiPolicy)
	if err != nil {
		log.Fatalf("iKuai policy init failed: %v", err)
	}

	tmpl, err := template.New("").Funcs(template.FuncMap{
		"T":        T,
		"jsonI18N": jsonI18N,
	}).ParseFS(templateFS, "templates/*.html")
	if err != nil {
		log.Fatalf("template load failed: %v", err)
	}

	banHist, err := newBanHistory(paths.BanHistory)
	if err != nil {
		log.Fatalf("ban history init failed: %v", err)
	}

	eventLog, err := newEventLog(paths.EventLog, cfg.EventLogRetention)
	if err != nil {
		log.Fatalf("event log init failed: %v", err)
	}
	log.Printf("data dir: %s (guest codes, MAC denylist, iKuai policy, ban history, event log; event retention %s)",
		cfg.DataDir, cfg.EventLogRetention)

	app := &App{
		cfg:            cfg,
		oidc:           oidcClient,
		duo:            duoClient,
		duoUniversal:   duoUni,
		guestCodes:     guestStore,
		denylist:       denylistStore,
		ikuaiPolicies:  ikuaiPolicyStore,
		templates:      tmpl,
		authEmailFails: newFailCounter(cfg.AuthEmailWindowLong),
		guestCodeFails: newFailCounter(cfg.GuestCodeMacWindow),
		ipFails:        newFailCounter(cfg.IPFailsWindow),
		ipBans:         newIPBanList(),
		banHistory:     banHist,
		proceedStore:   newProceedTokenStore(cfg.AuthProceedTTL),
		usedStates:     newUsedStateSet(sessionTTL),
		eventLog:       eventLog,
	}
	go app.authEmailFails.gcLoop()
	go app.guestCodeFails.gcLoop()
	go app.ipFails.gcLoop()
	go app.ipBans.gcLoop()
	go app.proceedStore.gcLoop()
	go app.usedStates.gcLoop()
	go app.eventLog.gcLoop()
	if cfg.IPBanEscalateAt >= 999999 {
		log.Printf("ratelimit: email %d/%s + %d/%s, MAC %d/%s, IP %d/%s -> cooldown %s, no permanent escalation",
			cfg.AuthEmailFailsShort, cfg.AuthEmailWindowShort,
			cfg.AuthEmailFailsLong, cfg.AuthEmailWindowLong,
			cfg.GuestCodeMacFails, cfg.GuestCodeMacWindow,
			cfg.IPFailsLimit, cfg.IPFailsWindow, cfg.IPBanDuration)
	} else {
		log.Printf("ratelimit: email %d/%s + %d/%s, MAC %d/%s, IP %d/%s -> first ban %s, permanent at attempt %d",
			cfg.AuthEmailFailsShort, cfg.AuthEmailWindowShort,
			cfg.AuthEmailFailsLong, cfg.AuthEmailWindowLong,
			cfg.GuestCodeMacFails, cfg.GuestCodeMacWindow,
			cfg.IPFailsLimit, cfg.IPFailsWindow, cfg.IPBanDuration, cfg.IPBanEscalateAt)
	}

	staticSub, err := fs.Sub(staticFS, "static")
	if err != nil {
		log.Fatalf("static dir load failed: %v", err)
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
	mux.HandleFunc("/admin/login/start", app.handleAdminLoginStart)
	mux.HandleFunc("/admin/logout", app.handleAdminLogout)
	mux.HandleFunc("/admin/codes/create", app.handleCodeCreate)
	mux.HandleFunc("/admin/codes/batch", app.handleCodeBatch)
	mux.HandleFunc("/admin/codes/delete", app.handleCodeDelete)
	mux.HandleFunc("/admin/codes/delete-bulk", app.handleCodeDeleteBulk)
	mux.HandleFunc("/admin/codes/delete-inactive", app.handleCodeDeleteInactive)
	mux.HandleFunc("/admin/codes/delete-expired", app.handleCodeDeleteInactive) // compatibility
	mux.HandleFunc("/admin/codes/edit", app.handleCodeEdit)
	mux.HandleFunc("/admin/ratelimit/status", app.handleRateLimitStatus)
	mux.HandleFunc("/admin/ratelimit/reset", app.handleRateLimitReset)
	mux.HandleFunc("/admin/ratelimit/reset-all", app.handleRateLimitResetAll)
	mux.HandleFunc("/admin/denylist/macs/create", app.handleDenyMACCreate)
	mux.HandleFunc("/admin/denylist/macs/delete", app.handleDenyMACDelete)
	mux.HandleFunc("/admin/denylist/macs/delete-all", app.handleDenyMACDeleteAll)
	mux.HandleFunc("/admin/ikuai-policy/update", app.handleIKuaiPolicyUpdate)
	mux.HandleFunc("/admin/events/query", app.handleEventsQuery)
	mux.HandleFunc("/admin/events/export.csv", app.handleEventsExportCSV)
	mux.HandleFunc("/admin/denylist/export.csv", app.handleDenylistExportCSV)
	mux.HandleFunc("/admin/denylist/import", app.handleDenylistImportCSV)
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           securityHeaders(app.logRequests(mux)),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("Portal started, listening on %s, public URL: %s", cfg.ListenAddr, cfg.PublicURL)

	// Graceful shutdown: 捕 SIGINT/SIGTERM 后停 server, 然后 flush banHistory +
	// 关 EventLog file handle. 没这步的话 SIGTERM 直接 kill, banHistory 异步 flusher
	// 还没到下一个 tick 就丢一段窗口的 ip 冷却历史 (虽然 IPBanEscalateAt 默认 999999
	// 不太关键, 但优雅退出对运维仪表盘 / 分析日志一致性都更好).
	stopCh := make(chan os.Signal, 1)
	signal.Notify(stopCh, os.Interrupt, syscall.SIGTERM)
	srvErr := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			srvErr <- err
		}
		close(srvErr)
	}()
	select {
	case sig := <-stopCh:
		log.Printf("got signal %s, shutting down...", sig)
	case err := <-srvErr:
		if err != nil {
			log.Fatalf("ListenAndServe: %v", err)
		}
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("server shutdown: %v", err)
	}
	if err := banHist.shutdown(); err != nil {
		log.Printf("ban history shutdown: %v", err)
	}
	if err := eventLog.Close(); err != nil {
		log.Printf("event log close: %v", err)
	}
	log.Printf("clean exit")
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

func (a *App) logRequests(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lrw := &logRespWriter{ResponseWriter: w, status: 200}
		h.ServeHTTP(lrw, r)
		client := clientIP(r)
		userIP, mac := "-", "-"
		if sess, err := readSessionCookie(r, a.cfg.SessionSecret); err == nil {
			if sess.UserIP != "" {
				userIP = sess.UserIP
			}
			if sess.MAC != "" {
				mac = sess.MAC
			}
		}
		log.Printf("%s %s -> %d (%s) client_ip=%s user_ip=%s mac=%s ua=%q",
			r.Method, r.URL.Path, lrw.status, time.Since(start), client, userIP, mac, r.UserAgent())
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
		a.renderError(w, r, lang, T(lang, "errors.sessionLost"), http.StatusBadRequest)
		return
	}
	if _, denied := a.denylist.IsMACDenied(dev.MAC); denied {
		log.Printf("deny banned MAC at /portal: mac=%s ip=%s", dev.MAC, dev.IP)
		a.renderError(w, r, lang, T(lang, "errors.rateLimitedPermanent"), http.StatusForbidden)
		return
	}
	sess, err := newSession(dev.IP, dev.MAC, string(lang))
	if err != nil {
		log.Printf("newSession failed: %v", err)
		a.renderError(w, r, lang, T(lang, "errors.generic"), http.StatusInternalServerError)
		return
	}
	if err := writeSessionCookie(w, a.cfg.SessionSecret, sess, true); err != nil {
		log.Printf("write cookie failed: %v", err)
		a.renderError(w, r, lang, T(lang, "errors.generic"), http.StatusInternalServerError)
		return
	}
	a.renderLogin(w, r, lang, dev)
}

// handleAuthStart: 邮箱输入后的分流入口.
//
// 关键安全设计:
//  1. 入口先查 IP 冷却 (规则 6) 和邮箱失败计数 (规则 1), 都过了再走真实分流.
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

	sess, err := readSessionCookie(r, a.cfg.SessionSecret)
	if err != nil {
		if bannedIP, ok := a.bannedIPForRequest(r, nil); ok {
			a.writeRateLimited(w, "ip_ban", bannedIP)
			return
		}
		a.recordRequestFailure(r, nil, "session_lost")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "session_lost"})
		return
	}
	ip := clientIP(r)
	if bannedIP, ok := a.bannedIPForRequest(r, &sess); ok {
		a.writeRateLimited(w, "ip_ban", bannedIP)
		return
	}
	if _, denied := a.denylist.IsMACDenied(sess.MAC); denied {
		log.Printf("deny banned MAC at /auth/start: mac=%s ip=%s", sess.MAC, ip)
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error":     "rate_limited",
			"permanent": true,
		})
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	if !isValidEmail(email) {
		a.recordRequestFailure(r, &sess, "invalid_email")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_email"})
		return
	}
	// 只有启用 Duo 时才强制域名白名单;
	// 不用 Duo 的场景, Entra 自己会做域名 / 租户过滤.
	if a.cfg.IsDuoEnabled() && !isAllowedDomain(email, a.cfg.AllowedEmailDomains) {
		log.Printf("deny domain not in allowlist: %q", email)
		a.recordRequestFailure(r, &sess, "invalid_domain")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_domain"})
		return
	}

	// 规则 1: 检查该邮箱的失败计数 (双窗口).
	shortN := a.authEmailFails.countIn(email, a.cfg.AuthEmailWindowShort)
	longN := a.authEmailFails.countIn(email, a.cfg.AuthEmailWindowLong)
	if shortN >= a.cfg.AuthEmailFailsShort || longN >= a.cfg.AuthEmailFailsLong {
		log.Printf("/auth/start email ratelimit: %q short=%d long=%d ip=%s",
			email, shortN, longN, ip)
		a.recordRequestFailure(r, &sess, "rate_limited_email")
		// 哪个窗口先满选哪个的 retry_after
		rule := "email_long"
		if shortN >= a.cfg.AuthEmailFailsShort {
			rule = "email_short"
		}
		// 如果 recordIPFailure 这次刚好触发了 IP 冷却, 优先告诉客户端那个.
		if bannedIP, ok := a.bannedIPForRequest(r, &sess); ok {
			rule = "ip_ban"
			ip = bannedIP
		}
		a.logLogin(email, ResultRateLimited, MethodSSO, sess.MAC, ip, rule)
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
			log.Printf("Duo preauth failed for %s: %v, falling back to SSO", email, perr)
			realURL, kind = ssoURL, proceedEntra
		} else {
			log.Printf("Duo preauth for %s: result=%s devices=%d",
				email, pre.Result, len(pre.Devices))
			switch pre.Result {
			case "auth":
				if pre.HasUniversalPromptCapable() {
					duoURL, derr := a.duoUniversal.AuthURL(email, sess.State)
					if derr != nil {
						log.Printf("Duo AuthURL build failed: %v, falling back to SSO", derr)
						realURL, kind = ssoURL, proceedEntra
					} else {
						realURL, kind = duoURL, proceedDuo
					}
				} else {
					log.Printf("%s has no Duo devices, falling back to SSO", email)
					realURL, kind = ssoURL, proceedEntra
				}
			case "enroll", "allow":
				realURL, kind = ssoURL, proceedEntra
			case "deny":
				// 不在响应里告诉攻击者 "被拒" — 一律丢给 Entra, Entra 自己拒.
				log.Printf("Duo denied account: %s (%s), routing to Entra anyway to hide deny signal",
					email, pre.StatusMsg)
				realURL, kind = ssoURL, proceedDeny
			default:
				log.Printf("unknown Duo preauth result: %s, falling back to SSO", pre.Result)
				realURL, kind = ssoURL, proceedEntra
			}
		}
	}

	// 先 put proceed token, 再 record pending 失败 — M8 修复: put 失败时不污染计数.
	// (put 唯一可能失败的路径是 rand.Reader 失败, 极罕见; 但既然成本是调换两行,
	// 干脆让计数永远跟 token 创建保持一致.)
	token, err := a.proceedStore.put(realURL, sess.State, email)
	if err != nil {
		log.Printf("proceedStore.put failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	a.authEmailFails.record(email)
	method := MethodSSO
	if kind == proceedDuo {
		method = MethodDuo
	}
	a.logLogin(email, ResultStarted, method, sess.MAC, sess.UserIP, "auth_start")
	writeJSON(w, http.StatusOK, map[string]string{"redirect": "/auth/proceed?token=" + token})
}

// writeRateLimited 发 429 响应, 带足以让前端渲染"稍后再试"/"联系管理员"的信息.
// 具体命中的内部规则不返回给前端, 避免向用户暴露封禁类型:
//   - retry_after_seconds: 建议重试等待秒数
//   - permanent: true 时前端显示联系管理员, 不显示倒计时
//   - unban_at_unix: 解封 unix 时间 (仅 ip_ban 用)
func (a *App) writeRateLimited(w http.ResponseWriter, rule, ip string) {
	body := map[string]any{
		"error": "rate_limited",
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

func uniqueNonEmpty(values ...string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func requestIPKeys(r *http.Request, sess *Session) []string {
	if sess == nil {
		return uniqueNonEmpty(clientIP(r))
	}
	return uniqueNonEmpty(clientIP(r), sess.UserIP)
}

func (a *App) bannedIPForRequest(r *http.Request, sess *Session) (string, bool) {
	for _, ip := range requestIPKeys(r, sess) {
		if a.ipBans.isBanned(ip) {
			return ip, true
		}
	}
	return "", false
}

func (a *App) recordRequestFailure(r *http.Request, sess *Session, reason string) {
	for _, ip := range requestIPKeys(r, sess) {
		a.recordIPFailure(ip, reason)
	}
}

func (a *App) clearSuccessfulAuthState(r *http.Request, sess Session, emails ...string) {
	emailKeys := make([]string, 0, len(emails)+1)
	if sess.Email != "" {
		emailKeys = append(emailKeys, sess.Email)
	}
	emailKeys = append(emailKeys, emails...)
	for _, email := range uniqueNonEmpty(emailKeys...) {
		a.authEmailFails.reset(strings.ToLower(email))
	}

	if sess.MAC != "" {
		a.guestCodeFails.reset(sess.MAC)
	}

	for _, ip := range requestIPKeys(r, &sess) {
		a.ipFails.reset(ip)
		a.ipBans.unban(ip)
		// 不要 reset banHistory — 一次合法登录不能洗白长期可疑 IP 的封禁历史.
		// 否则攻击者只要单次成功认证 (自己的真账号 / 一个合法访客码) 就能把所有
		// 累计的 banHistory 清零, 让升级永久封禁 (IPBanEscalateAt) 永远到不了.
		// admin 主动 /admin/ratelimit/reset (type=ip_ban) 仍会清 banHistory, 见 1234 行.
	}
}

// recordIPFailure 累加 IP 失败计数, 触发阈值就短时冷却.
// 升级模型仍保留为可配置兜底: 第 1 次到 (IPBanEscalateAt-1) 次 → IPBanDuration 时长;
// 第 IPBanEscalateAt 次及以上 → 永久封禁 (要 admin 手动解).
// IPBanEscalateAt <= 0 时显式禁用永久升级 + banHistory 完全短路 (L6).
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
	// L6: 升级模型禁用时不记 banHistory — 历史无意义, 还省一次锁 + dirty.
	if a.cfg.IPBanEscalateAt <= 0 {
		a.ipBans.ban(ip, a.cfg.IPBanDuration)
		log.Printf("IP fail-limit reached, cooldown %s: %s (count=%d window=%s reason=%s, escalation disabled)",
			a.cfg.IPBanDuration, ip, n, a.cfg.IPFailsWindow, reason)
		return
	}
	banCount := a.banHistory.increment(ip)
	var duration time.Duration
	if banCount >= a.cfg.IPBanEscalateAt {
		duration = time.Until(PermanentBanUntil) // 算出到"永久"标记点的时长
		a.ipBans.ban(ip, duration)
		log.Printf("IP fail-limit reached, **permanent ban** (attempt %d): %s (count=%d window=%s reason=%s)",
			banCount, ip, n, a.cfg.IPFailsWindow, reason)
	} else {
		duration = a.cfg.IPBanDuration
		a.ipBans.ban(ip, duration)
		log.Printf("IP fail-limit reached, cooldown %s (attempt %d): %s (count=%d window=%s reason=%s)",
			duration, banCount, ip, n, a.cfg.IPFailsWindow, reason)
	}
}

// handleLogin: 跳 Entra, 如有 ?hint=email 作为 login_hint 预填.
// 如果没 hint 但 session 里有 email 也用.
func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	lang := pickLang(r)
	sess, err := readSessionCookie(r, a.cfg.SessionSecret)
	if err != nil {
		a.renderError(w, r, lang, T(lang, "errors.sessionLost"), http.StatusBadRequest)
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
		a.renderError(w, r, lang, T(lang, "errors.sessionLost"), http.StatusBadRequest)
		return
	}
	if sess.Lang != "" {
		lang = Lang(sess.Lang)
	}
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		log.Printf("Entra returned error: %q - %q", errParam, r.URL.Query().Get("error_description"))
		a.renderError(w, r, lang, T(lang, "errors.generic"), http.StatusBadRequest)
		return
	}
	got := r.URL.Query().Get("state")
	if subtle.ConstantTimeCompare([]byte(got), []byte(sess.State)) != 1 {
		log.Printf("Entra state mismatch")
		a.renderError(w, r, lang, T(lang, "errors.generic"), http.StatusBadRequest)
		return
	}
	// 一次性消费 state, 防 cookie 被偷后重放. 第二次同 state 到达直接拒.
	if !a.usedStates.markUsed(sess.State) {
		log.Printf("Entra state replay rejected: state-prefix=%s", sess.State[:8])
		a.renderError(w, r, lang, T(lang, "errors.generic"), http.StatusBadRequest)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		a.renderError(w, r, lang, T(lang, "errors.generic"), http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	user, err := a.oidc.Exchange(ctx, a.cfg, code, sess.Nonce)
	if err != nil {
		log.Printf("OIDC Exchange failed: %v", err)
		a.renderError(w, r, lang, T(lang, "errors.generic"), http.StatusUnauthorized)
		return
	}
	if sess.Purpose == "admin" {
		a.finishAdminLogin(w, r, lang, user)
		return
	}
	if user.IsGuest() {
		log.Printf("deny Guest: %s", user.UPN)
		a.logLogin(user.UPN, ResultDenied, MethodSSO, sess.MAC, sess.UserIP, "guest_blocked")
		a.renderError(w, r, lang, T(lang, "errors.guestBlocked"), http.StatusForbidden)
		return
	}
	if _, denied := a.denylist.IsMACDenied(sess.MAC); denied {
		log.Printf("deny banned MAC at SSO grant: upn=%s mac=%s ip=%s", user.UPN, sess.MAC, sess.UserIP)
		a.logLogin(user.UPN, ResultDenied, MethodSSO, sess.MAC, sess.UserIP, "mac_denylist")
		a.renderError(w, r, lang, T(lang, "errors.rateLimitedPermanent"), http.StatusForbidden)
		return
	}
	log.Printf("grant member (SSO): upn=%s name=%q client_ip=%s user_ip=%s mac=%s",
		user.UPN, user.Name, clientIP(r), sess.UserIP, sess.MAC)
	a.logLogin(user.UPN, ResultSuccess, MethodSSO, sess.MAC, sess.UserIP, "")
	// 成功认证后清理同一邮箱 / 设备 / IP 的临时失败状态.
	a.clearSuccessfulAuthState(r, sess, user.UPN)
	ikuaiURL := buildWebAuthURL(a.cfg, DeviceInfo{IP: sess.UserIP, MAC: sess.MAC}, user.UPN,
		IKuaiProfileSSO, a.ikuaiPolicies.Get(IKuaiProfileSSO))
	clearSessionCookie(w, true)
	http.Redirect(w, r, ikuaiURL, http.StatusFound)
}

// handleDuoCallback: Duo Universal Prompt 回调. ?state, ?duo_code.
// 验 state → 换 code → 得 username → 放行.
func (a *App) handleDuoCallback(w http.ResponseWriter, r *http.Request) {
	lang := pickLang(r)
	if a.duoUniversal == nil {
		a.renderError(w, r, lang, T(lang, "errors.generic"), http.StatusServiceUnavailable)
		return
	}
	sess, err := readSessionCookie(r, a.cfg.SessionSecret)
	if err != nil {
		a.renderError(w, r, lang, T(lang, "errors.sessionLost"), http.StatusBadRequest)
		return
	}
	if sess.Lang != "" {
		lang = Lang(sess.Lang)
	}
	got := r.URL.Query().Get("state")
	if subtle.ConstantTimeCompare([]byte(got), []byte(sess.State)) != 1 {
		log.Printf("Duo state mismatch")
		a.renderError(w, r, lang, T(lang, "errors.generic"), http.StatusBadRequest)
		return
	}
	if !a.usedStates.markUsed(sess.State) {
		log.Printf("Duo state replay rejected: state-prefix=%s", sess.State[:8])
		a.renderError(w, r, lang, T(lang, "errors.generic"), http.StatusBadRequest)
		return
	}
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		log.Printf("Duo returned error: %q", errParam)
		a.renderError(w, r, lang, T(lang, "errors.generic"), http.StatusBadRequest)
		return
	}
	// Duo Universal Prompt 回调参数名在不同版本 / 租户不一致:
	// 早期版本返 duo_code, OIDC-compliant 的新版本返 code. 两个都认.
	duoCode := r.URL.Query().Get("duo_code")
	if duoCode == "" {
		duoCode = r.URL.Query().Get("code")
	}
	if duoCode == "" {
		log.Printf("Duo callback missing code/duo_code param, query=%q", r.URL.RawQuery)
		a.renderError(w, r, lang, T(lang, "errors.generic"), http.StatusBadRequest)
		return
	}
	if sess.Email == "" {
		log.Printf("Duo callback: no email in session")
		a.renderError(w, r, lang, T(lang, "errors.sessionLost"), http.StatusBadRequest)
		return
	}
	username, err := a.duoUniversal.Exchange(duoCode, sess.Email)
	if err != nil {
		log.Printf("Duo Exchange failed for %s: %v", sess.Email, err)
		a.renderError(w, r, lang, T(lang, "errors.generic"), http.StatusUnauthorized)
		return
	}
	if _, denied := a.denylist.IsMACDenied(sess.MAC); denied {
		log.Printf("deny banned MAC at Duo grant: upn=%s mac=%s ip=%s", username, sess.MAC, sess.UserIP)
		a.logLogin(username, ResultDenied, MethodDuo, sess.MAC, sess.UserIP, "mac_denylist")
		a.renderError(w, r, lang, T(lang, "errors.rateLimitedPermanent"), http.StatusForbidden)
		return
	}
	log.Printf("grant member (Duo): upn=%s client_ip=%s user_ip=%s mac=%s",
		username, clientIP(r), sess.UserIP, sess.MAC)
	a.logLogin(username, ResultSuccess, MethodDuo, sess.MAC, sess.UserIP, "")
	// 成功认证后清理同一邮箱 / 设备 / IP 的临时失败状态.
	a.clearSuccessfulAuthState(r, sess, username)
	ikuaiURL := buildWebAuthURL(a.cfg, DeviceInfo{IP: sess.UserIP, MAC: sess.MAC}, username,
		IKuaiProfileDuo, a.ikuaiPolicies.Get(IKuaiProfileDuo))
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
		if bannedIP, ok := a.bannedIPForRequest(r, nil); ok {
			a.writeRateLimited(w, "ip_ban", bannedIP)
			return
		}
		a.recordRequestFailure(r, nil, "session_lost")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "session_lost"})
		return
	}
	ip := clientIP(r)
	if bannedIP, ok := a.bannedIPForRequest(r, &sess); ok {
		a.writeRateLimited(w, "ip_ban", bannedIP)
		return
	}
	if _, denied := a.denylist.IsMACDenied(sess.MAC); denied {
		log.Printf("deny banned MAC at guest-code: mac=%s ip=%s", sess.MAC, ip)
		a.logLogin("(guest)", ResultDenied, MethodGuestCode, sess.MAC, ip, "mac_denylist")
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error":     "rate_limited",
			"permanent": true,
		})
		return
	}
	// 规则 5: 按 session 里的 MAC 查失败计数. MAC 是从 /portal 签进 cookie 的,
	// 攻击者改不了, 所以比按 IP 更稳.
	if a.guestCodeFails.countIn(sess.MAC, a.cfg.GuestCodeMacWindow) >= a.cfg.GuestCodeMacFails {
		log.Printf("guest-code ratelimited by MAC: mac=%s ip=%s", sess.MAC, ip)
		a.recordRequestFailure(r, &sess, "rate_limited_mac")
		a.logLogin("(guest)", ResultRateLimited, MethodGuestCode, sess.MAC, ip, "mac")
		rule := "mac"
		if bannedIP, ok := a.bannedIPForRequest(r, &sess); ok {
			rule = "ip_ban"
			ip = bannedIP
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
	upn := "Guest-" + guestID
	c := a.guestCodes.Validate(code, sess.MAC, sess.UserIP, upn)
	if c == nil {
		log.Printf("deny guest code ip=%s mac=%s", sess.UserIP, sess.MAC)
		a.guestCodeFails.record(sess.MAC)
		a.recordRequestFailure(r, &sess, "invalid_guest_code")
		a.logLogin("(guest)", ResultDenied, MethodGuestCode, sess.MAC, sess.UserIP, "invalid_code")
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_code"})
		return
	}
	log.Printf("grant guest: upn=%s code-suffix=%s client_ip=%s user_ip=%s mac=%s",
		upn, tailN(c.Code, 4), clientIP(r), sess.UserIP, sess.MAC)
	// 事件日志只记码尾 4 位, 与终端日志一致. /data/events.jsonl 可能被备份 / 日志聚合
	// 系统读到, 不能写完整码 — 否则就算码已用完, 历史码列表本身仍是身份信息泄漏面.
	a.logLogin(upn, ResultSuccess, MethodGuestCode, sess.MAC, sess.UserIP,
		"code-suffix="+tailN(c.Code, 4))
	// 成功 → 清理同一设备 / IP 的临时失败状态.
	a.clearSuccessfulAuthState(r, sess)
	policy := a.ikuaiPolicies.Get(IKuaiProfileGuest)
	policy.Timeout = c.DurationMin
	ikuaiURL := buildWebAuthURL(a.cfg, DeviceInfo{IP: sess.UserIP, MAC: sess.MAC}, upn,
		IKuaiProfileGuest, policy)
	clearSessionCookie(w, true)
	writeJSON(w, http.StatusOK, map[string]string{"redirect": ikuaiURL})
}

// --- admin ---

func (a *App) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	lang := pickLang(r)
	if !a.cfg.IsAdminEnabled() {
		a.renderError(w, r, lang, T(lang, "errors.adminDisabled"), http.StatusNotFound)
		return
	}
	if _, err := readAdminCookie(r, a.cfg.SessionSecret); err == nil {
		http.Redirect(w, r, "/admin", http.StatusFound)
		return
	}
	a.renderAdminLogin(w, r, lang)
}

func (a *App) handleAdminLoginStart(w http.ResponseWriter, r *http.Request) {
	lang := pickLang(r)
	if !a.cfg.IsAdminEnabled() {
		a.renderError(w, r, lang, T(lang, "errors.adminDisabled"), http.StatusNotFound)
		return
	}
	// 只接 POST: GET 写 cookie 违反幂等性, 也方便 <img src=...> 之类被动触发.
	// admin_login.html 已用 <form method="post">.
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	sess, err := newAdminPreloginSession(string(lang))
	if err != nil {
		a.renderError(w, r, lang, T(lang, "errors.generic"), http.StatusInternalServerError)
		return
	}
	if err := writeSessionCookie(w, a.cfg.SessionSecret, sess, true); err != nil {
		a.renderError(w, r, lang, T(lang, "errors.generic"), http.StatusInternalServerError)
		return
	}
	// admin 登录不预填邮箱
	http.Redirect(w, r, a.oidc.AuthURL(sess.State, sess.Nonce, ""), http.StatusFound)
}

func (a *App) finishAdminLogin(w http.ResponseWriter, r *http.Request, lang Lang, user *UserInfo) {
	if user.IsGuest() || !user.IsAdmin(a.cfg) {
		log.Printf("admin login denied: upn=%s groups=%v", user.UPN, user.Groups)
		a.logAdminAction(user.UPN, clientIP(r), ResultDenied, "admin login rejected (not in allow-list)")
		a.renderError(w, r, lang, T(lang, "errors.notAdminMember"), http.StatusForbidden)
		return
	}
	adminSess := AdminSession{
		UPN: user.UPN,
		Exp: time.Now().Add(adminSessionTTL).Unix(),
	}
	if err := writeAdminCookie(w, a.cfg.SessionSecret, adminSess, true); err != nil {
		a.renderError(w, r, lang, T(lang, "errors.generic"), http.StatusInternalServerError)
		return
	}
	clearSessionCookie(w, true)
	log.Printf("admin login success: upn=%s via=%s", user.UPN, adminGrantReason(a.cfg, user))
	a.logAdminAction(user.UPN, clientIP(r), ResultSuccess, "admin login via="+adminGrantReason(a.cfg, user))
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
			http.Error(w, "Admin console not configured", http.StatusNotFound)
		}
		return AdminSession{}, false
	}
	// CSRF 防护: 状态变更请求必须从同源发起. admin cookie 已经是 SameSite=Strict,
	// 这里再加 Origin/Referer 校验做双保险 — 同源策略 + 显式头校验.
	// GET 请求 (页面渲染 / status 查询) 不强制, 因为浏览器很多场景不发 Origin.
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		if !a.isSameOriginRequest(r) {
			log.Printf("admin CSRF block: method=%s path=%s origin=%q referer=%q",
				r.Method, r.URL.Path, r.Header.Get("Origin"), r.Header.Get("Referer"))
			if apiMode {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross_origin"})
			} else {
				http.Error(w, "cross-origin request blocked", http.StatusForbidden)
			}
			return AdminSession{}, false
		}
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
	// 的生效周期 = cookie TTL (1h); 要立刻踢就清了这人的 cookie, 或改 SessionSecret
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
	admin, ok := a.requireAdmin(w, r, true)
	if !ok {
		return
	}
	code := strings.TrimSpace(r.FormValue("code"))
	userProvidedCode := code != ""
	if code == "" {
		g, err := generateCode(CodeNumeric, 10)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "rand_failed"})
			return
		}
		code = g
	}
	gc := &GuestCode{
		Code:        code,
		CreatedAt:   time.Now(),
		DurationMin: parseDurationMin(r),
		MaxUses:     parseMaxUses(r.FormValue("max_uses")),
		Note:        capLen(strings.TrimSpace(r.FormValue("note")), 256),
	}
	// 用户自填的 code 也限长, 防 1MB code 灌进 events.jsonl.
	// 同时强制下限 6 字符: tailN(code, 4) 用作审计 suffix, 5 字符以下相当于全码裸暴露,
	// 跟 batch 生成的 length 下限对齐 (admin.go: generateCode 也是 length<6 强抬到 6).
	if userProvidedCode {
		if len(gc.Code) > 64 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "code_too_long"})
			return
		}
		if len(gc.Code) < 6 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "code_too_short"})
			return
		}
	}
	if err := parseExpiry(r, gc, false); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if !a.guestCodes.Add(gc) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "duplicate_code"})
		return
	}
	// 审计日志不记完整码 — 创建那一刻 UI 已把码值返回给 admin 浏览器, 一次性看见即可.
	// 长期审计只需"创建过这条"的痕迹 + 末 4 位帮排查.
	suffix := tailN(gc.Code, 4)
	detail := "add auto-gen code-suffix=" + suffix
	if userProvidedCode {
		detail = "add code-suffix=" + suffix
	}
	if gc.Note != "" {
		detail += " note=" + capLen(gc.Note, 64)
	}
	a.logAdminAction(admin.UPN, clientIP(r), ResultSuccess, detail)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "code": gc.Code})
}

func (a *App) handleCodeBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	admin, ok := a.requireAdmin(w, r, true)
	if !ok {
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
	note := capLen(strings.TrimSpace(r.FormValue("note")), 256)
	durationMin := parseDurationMin(r)
	maxUses := parseMaxUses(r.FormValue("max_uses"))
	// baseProbe 只用来复用 parseExpiry 的过期计算. 每个码的 CreatedAt 用各自
	// 的 time.Now(), 保证 List 排序时不会因时间戳相同而顺序抖动.
	baseProbe := &GuestCode{CreatedAt: time.Now()}
	if err := parseExpiry(r, baseProbe, false); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	// 撞码上限 — 防止 admin 误填 length=4 numeric 且空间几乎堆满时无限循环.
	maxAttempts := count * 50
	if maxAttempts < 200 {
		maxAttempts = 200
	}
	// 先 generate 候选 code 列表 (随机性来自 crypto/rand, 同批内撞码概率极低),
	// 再一次性 AddMany — 避免 N 次 saveLocked 重写整个 guest-codes.json. (H3)
	pending := make([]*GuestCode, 0, count)
	pendingSet := make(map[string]struct{}, count)
	for attempts := 0; len(pending) < count && attempts < maxAttempts; attempts++ {
		raw, err := generateCode(codeType, length)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "rand_failed"})
			return
		}
		k := strings.ToLower(strings.TrimSpace(raw))
		if _, exists := pendingSet[k]; exists {
			continue
		}
		pendingSet[k] = struct{}{}
		pending = append(pending, &GuestCode{
			Code:        raw,
			CreatedAt:   time.Now(),
			ExpiresAt:   baseProbe.ExpiresAt,
			DurationMin: durationMin,
			MaxUses:     maxUses,
			Note:        note,
		})
	}
	generated := a.guestCodes.AddMany(pending)
	if len(generated) < count {
		log.Printf("batch code-gen: 仅生成 %d/%d 条 (%d 次尝试后码空间已满 / 大量撞码), type=%s len=%d",
			len(generated), count, maxAttempts, codeType, length)
	}
	a.logAdminAction(admin.UPN, clientIP(r), ResultSuccess,
		fmt.Sprintf("batch count=%d type=%s len=%d", len(generated), codeType, length))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "count": len(generated), "codes": generated,
	})
}

func (a *App) handleCodeDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	admin, ok := a.requireAdmin(w, r, true)
	if !ok {
		return
	}
	code := strings.TrimSpace(r.FormValue("code"))
	if code == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing_code"})
		return
	}
	deleted := a.guestCodes.Delete(code)
	if deleted {
		a.logAdminAction(admin.UPN, clientIP(r), ResultSuccess, "delete code-suffix="+tailN(code, 4))
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": deleted})
}

func (a *App) handleCodeDeleteInactive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	admin, ok := a.requireAdmin(w, r, true)
	if !ok {
		return
	}
	n := a.guestCodes.DeleteInactive()
	a.logAdminAction(admin.UPN, clientIP(r), ResultSuccess, fmt.Sprintf("delete-inactive deleted=%d", n))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "deleted": n})
}

// handleCodeDeleteBulk: POST /admin/codes/delete-bulk
// form: codes=<逗号分隔的码列表>
// 一次删多个访客码. 写一条审计 (count + 抽样几个码尾 4 位), 不为每条单独写, 防日志噪音.
func (a *App) handleCodeDeleteBulk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	admin, ok := a.requireAdmin(w, r, true)
	if !ok {
		return
	}
	raw := r.FormValue("codes")
	if strings.TrimSpace(raw) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing_codes"})
		return
	}
	codes := strings.Split(raw, ",")
	deleted := a.guestCodes.DeleteMany(codes)
	skipped := 0
	for _, c := range codes {
		if strings.TrimSpace(c) != "" {
			skipped++
		}
	}
	skipped -= deleted
	a.logAdminAction(admin.UPN, clientIP(r), ResultSuccess,
		fmt.Sprintf("delete-bulk deleted=%d skipped=%d", deleted, skipped))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "deleted": deleted, "skipped": skipped,
	})
}

// handleCodeEdit: POST /admin/codes/edit
// form: code=<existing>, expires_at, duration_min, max_uses, note
// 改一个已存在码的 ExpiresAt / DurationMin / MaxUses / Note. Code 本身不能改 (要改就删了重建).
// 已经使用过的码也允许编辑, 但已经在线的设备的 iKuai timeout 改不了 — 仅影响后续放行.
func (a *App) handleCodeEdit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	admin, ok := a.requireAdmin(w, r, true)
	if !ok {
		return
	}
	code := strings.TrimSpace(r.FormValue("code"))
	if code == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing_code"})
		return
	}
	// 复用 parseExpiry: 它读 expires_at, 写到一个临时 GuestCode 上.
	probe := &GuestCode{CreatedAt: time.Now()}
	// Edit 路径允许过去时间, 让 admin 能强制让一个码立即失效 (H7).
	if err := parseExpiry(r, probe, true); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	durationMin := parseDurationMin(r)
	maxUses := parseMaxUses(r.FormValue("max_uses"))
	note := capLen(strings.TrimSpace(r.FormValue("note")), 256)
	if !a.guestCodes.Edit(code, probe.ExpiresAt, durationMin, maxUses, note) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
		return
	}
	a.logAdminAction(admin.UPN, clientIP(r), ResultSuccess,
		"edit code-suffix="+tailN(code, 4))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
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
		IP        string `json:"ip"`
		ExpiresAt int64  `json:"expires_unix"`
		BanCount  int    `json:"ban_count"`
		Permanent bool   `json:"permanent"`
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
			"email_short":     a.cfg.AuthEmailFailsShort,
			"email_short_s":   int(a.cfg.AuthEmailWindowShort.Seconds()),
			"email_long":      a.cfg.AuthEmailFailsLong,
			"email_long_s":    int(a.cfg.AuthEmailWindowLong.Seconds()),
			"mac":             a.cfg.GuestCodeMacFails,
			"mac_s":           int(a.cfg.GuestCodeMacWindow.Seconds()),
			"ip":              a.cfg.IPFailsLimit,
			"ip_s":            int(a.cfg.IPFailsWindow.Seconds()),
			"ip_ban_s":        int(a.cfg.IPBanDuration.Seconds()),
			"ip_ban_escalate": a.cfg.IPBanEscalateAt,
		},
	})
}

// handleRateLimitReset POST /admin/ratelimit/reset
// form: type=ip_ban|ip_fails|email|mac, key=<value>
// 对应清除 / 解封该 key 的限流状态. ip_ban 在默认配置下表示 IP 短时冷却.
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
		a.ipFails.reset(key)    // 同时清 IP 累计计数, 避免刚解封又立刻触发
		a.banHistory.reset(key) // 清除历史封禁次数, 不然下次失败直接进 "永久" 分支
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
	log.Printf("admin %s reset ratelimit: type=%s key=%s", admin.UPN, t, key)
	a.logAdminAction(admin.UPN, clientIP(r), ResultSuccess, fmt.Sprintf("reset type=%s key=%s", t, key))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleRateLimitResetAll POST /admin/ratelimit/reset-all
// 一键清空所有限流状态: 所有 IP 冷却 + 所有邮箱 / MAC / IP 失败计数 + 冷却历史.
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
	log.Printf("admin %s reset-all ratelimit state: %+v", admin.UPN, cleared)
	a.logAdminAction(admin.UPN, clientIP(r), ResultSuccess, fmt.Sprintf("reset-all %+v", cleared))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "cleared": cleared})
}

func (a *App) handleDenyMACCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	admin, ok := a.requireAdmin(w, r, true)
	if !ok {
		return
	}
	mac := strings.TrimSpace(r.FormValue("mac"))
	reason := capLen(strings.TrimSpace(r.FormValue("reason")), 256)
	item, created, err := a.denylist.AddMAC(mac, reason, admin.UPN)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	a.guestCodeFails.reset(item.MAC)
	log.Printf("admin %s ban MAC: mac=%s created=%v reason=%q", admin.UPN, item.MAC, created, item.Reason)
	if created {
		a.logAdminAction(admin.UPN, clientIP(r), ResultSuccess, "mac="+item.MAC+" ban reason="+item.Reason)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"created": created,
		"mac":     item.MAC,
	})
}

func (a *App) handleDenyMACDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	admin, ok := a.requireAdmin(w, r, true)
	if !ok {
		return
	}
	mac := strings.TrimSpace(r.FormValue("mac"))
	if mac == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing_mac"})
		return
	}
	norm := normalizeMAC(mac)
	deleted := a.denylist.DeleteMAC(norm)
	log.Printf("admin %s unban MAC: mac=%s deleted=%v", admin.UPN, norm, deleted)
	if deleted {
		a.logAdminAction(admin.UPN, clientIP(r), ResultSuccess, "mac="+norm+" unban")
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "deleted": deleted})
}

// handleDenyMACDeleteAll: 一键清空整个 MAC 封禁列表. 只动 denylist, 不碰限流.
// 跟 /admin/ratelimit/reset-all 是两个独立动作, 各管各的.
func (a *App) handleDenyMACDeleteAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	admin, ok := a.requireAdmin(w, r, true)
	if !ok {
		return
	}
	n := a.denylist.DeleteAllMACs()
	log.Printf("admin %s unban-all MAC: cleared=%d", admin.UPN, n)
	a.logAdminAction(admin.UPN, clientIP(r), ResultSuccess, fmt.Sprintf("mac unban-all cleared=%d", n))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "cleared": n})
}

func (a *App) handleIKuaiPolicyUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	admin, ok := a.requireAdmin(w, r, true)
	if !ok {
		return
	}
	profile, ok := parseIKuaiProfile(r.FormValue("profile"))
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_profile"})
		return
	}
	policy := IKuaiPolicy{
		Upload:   parseIntDefault(r.FormValue("upload"), 0),
		Download: parseIntDefault(r.FormValue("download"), 0),
		Timeout:  parseIntDefault(r.FormValue("timeout"), 0),
		Comment:  capLen(strings.TrimSpace(r.FormValue("comment")), 128),
	}
	if profile == IKuaiProfileGuest {
		policy.Timeout = 0
	}
	old := a.ikuaiPolicies.Get(profile)
	if err := a.ikuaiPolicies.Set(profile, policy); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	log.Printf("admin %s update iKuai policy: profile=%s upload=%d download=%d timeout=%d comment=%q",
		admin.UPN, profile, policy.Upload, policy.Download, policy.Timeout, policy.Comment)
	a.logAdminAction(admin.UPN, clientIP(r), ResultSuccess, ikuaiPolicyDiff(profile, old, policy))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ikuaiPolicyDiff 生成 "policy <profile>: upload 100→200, timeout 60→120" 这种可读的 diff,
// 只列真的变了的字段. 字段都没变时返回全量快照, 至少 detail 不为空.
func ikuaiPolicyDiff(profile IKuaiAuthProfile, old, cur IKuaiPolicy) string {
	parts := []string{}
	if old.Upload != cur.Upload {
		parts = append(parts, fmt.Sprintf("upload %d->%d", old.Upload, cur.Upload))
	}
	if old.Download != cur.Download {
		parts = append(parts, fmt.Sprintf("download %d->%d", old.Download, cur.Download))
	}
	if old.Timeout != cur.Timeout {
		parts = append(parts, fmt.Sprintf("timeout %d->%d", old.Timeout, cur.Timeout))
	}
	if old.Comment != cur.Comment {
		parts = append(parts, fmt.Sprintf("comment %q->%q", old.Comment, cur.Comment))
	}
	if len(parts) == 0 {
		return fmt.Sprintf("policy %s: (unchanged)", profile)
	}
	return fmt.Sprintf("policy %s: %s", profile, strings.Join(parts, ", "))
}

// --- 事件日志 / denylist CSV ---

// parseEventFilter 从 URL query 里抓过滤条件. 不校验字段值合法性 —
// 不认识的值会过滤后返回空结果, 不 500.
func parseEventFilter(r *http.Request) EventQueryFilter {
	q := r.URL.Query()
	f := EventQueryFilter{
		Kind:    strings.TrimSpace(q.Get("kind")),
		Method:  strings.TrimSpace(q.Get("method")),
		Result:  strings.TrimSpace(q.Get("result")),
		Subject: strings.TrimSpace(q.Get("subject")),
	}
	if s := strings.TrimSpace(q.Get("since")); s != "" {
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			f.Since = time.Unix(n, 0)
		}
	}
	if s := strings.TrimSpace(q.Get("until")); s != "" {
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			f.Until = time.Unix(n, 0)
		}
	}
	if s := strings.TrimSpace(q.Get("limit")); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			f.Limit = n
		}
	}
	return f
}

func (a *App) handleEventsQuery(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdmin(w, r, true); !ok {
		return
	}
	f := parseEventFilter(r)
	if f.Limit <= 0 || f.Limit > 2000 {
		f.Limit = 500
	}
	events := a.eventLog.Query(f)
	// 为前端渲染整理一下 — 附带每条的可读时间戳 (Unix 秒 + ISO8601 都给, 前端自己选)
	type row struct {
		Time    int64  `json:"time_unix"`
		TimeISO string `json:"time_iso"`
		Kind    string `json:"kind"`
		Subject string `json:"subject"`
		Result  string `json:"result"`
		Method  string `json:"method"`
		MAC     string `json:"mac,omitempty"`
		IP      string `json:"ip,omitempty"`
		Detail  string `json:"detail,omitempty"`
	}
	out := make([]row, 0, len(events))
	for _, ev := range events {
		out = append(out, row{
			Time:    ev.Time.Unix(),
			TimeISO: ev.Time.Local().Format("2006-01-02 15:04:05"),
			Kind:    ev.Kind,
			Subject: ev.Subject,
			Result:  ev.Result,
			Method:  ev.Method,
			MAC:     ev.MAC,
			IP:      ev.IP,
			Detail:  ev.Detail,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"events": out,
		"count":  len(out),
	})
}

func (a *App) handleEventsExportCSV(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdmin(w, r, false); !ok {
		return
	}
	f := parseEventFilter(r)
	if f.Limit <= 0 {
		f.Limit = 100000 // 导出不截断, 给个大数就行
	}
	events := a.eventLog.Query(f)
	if err := WriteEventsCSV(w, events); err != nil {
		log.Printf("event log CSV export failed: %v", err)
	}
}

func (a *App) handleDenylistExportCSV(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdmin(w, r, false); !ok {
		return
	}
	items := a.denylist.ListMACs()
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="denylist.csv"`)
	w.Header().Set("Cache-Control", "no-store")
	if _, err := w.Write([]byte{0xEF, 0xBB, 0xBF}); err != nil {
		return
	}
	cw := csv.NewWriter(w)
	// L10 修复: 显式 Flush + 检查 Error, 不用 defer cw.Flush(). Flush 错误是 IO 写
	// 失败 (客户端断开 / 磁盘满), 失败时只 log — handler 这里没 return error 路径.
	if err := cw.Write([]string{"mac", "reason", "banned_by", "banned_at"}); err != nil {
		log.Printf("denylist CSV header write: %v", err)
		return
	}
	for _, item := range items {
		// 数据行过 sanitizeCSVCell 中和 Excel 公式注入 (CSV 注入防护).
		if err := writeCSVRowSafe(cw, []string{
			item.MAC,
			item.Reason,
			item.CreatedBy,
			item.CreatedAt.Local().Format("2006-01-02 15:04:05"),
		}); err != nil {
			log.Printf("denylist CSV row write: %v", err)
			return
		}
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		log.Printf("denylist CSV flush: %v", err)
	}
}

func (a *App) handleDenylistImportCSV(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	admin, ok := a.requireAdmin(w, r, true)
	if !ok {
		return
	}
	// 限 1MB, 够 10k 行
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_multipart"})
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing_file"})
		return
	}
	defer file.Close()
	reader := csv.NewReader(file)
	reader.FieldsPerRecord = -1 // 容忍列数不一致
	rows, err := reader.ReadAll()
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "parse_failed"})
		return
	}
	// 先把所有合法行转成 MACInput 数组, 再一次性 AddMACMany. 避免每行 saveLocked
	// → 10k 行 CSV 在原实现下要 10k 次重写整个 denylist.json (H2). 现在 1 次.
	inputs := make([]MACInput, 0, len(rows))
	errs := []string{}
	for idx, row := range rows {
		if len(row) == 0 {
			continue
		}
		// 跳过表头 (第一列恰好是 "mac" 字样, 容忍 UTF-8 BOM).
		// "\ufeff" 是 escape 而非字面 BOM 字符 — Go 源文件中间不允许有 BOM.
		first := strings.TrimSpace(strings.TrimPrefix(row[0], "\ufeff"))
		if idx == 0 && strings.EqualFold(first, "mac") {
			continue
		}
		mac := first
		if mac == "" {
			continue
		}
		reason := ""
		if len(row) > 1 {
			reason = capLen(strings.TrimSpace(row[1]), 256)
		}
		// 安全: 始终用当前 admin.UPN 作为 createdBy. CSV 第三列 (banned_by) 是导出的
		// 信息字段, 不能让导入方任意指定他人 UPN — 否则审计追责被弱化, 任何 admin
		// 都能伪造"是 alice 封的"的历史记录.
		inputs = append(inputs, MACInput{MAC: mac, Reason: reason, CreatedBy: admin.UPN})
	}
	imported, skipped := a.denylist.AddMACMany(inputs)
	a.logAdminAction(admin.UPN, clientIP(r), ResultSuccess,
		fmt.Sprintf("denylist import imported=%d skipped=%d", imported, skipped))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"imported": imported,
		"skipped":  skipped,
		"errors":   errs,
	})
}

// parseExpiry 解析 expires_at 表单字段. allowPast=true 时不强制未来 — Edit 路径用,
// admin 想让一个还在用的码立即过期得能填过去时间; Create 路径仍强制未来防误填.
func parseExpiry(r *http.Request, gc *GuestCode, allowPast bool) error {
	exp := strings.TrimSpace(r.FormValue("expires_at"))
	if exp == "" {
		gc.ExpiresAt = time.Time{}
		return nil
	}
	t, err := time.Parse(time.RFC3339, exp)
	if err != nil {
		t2, err2 := time.ParseInLocation("2006-01-02T15:04", exp, time.Local)
		if err2 != nil {
			return fmt.Errorf("expires_at format error: %v", err)
		}
		t = t2
	}
	if !allowPast && t.Before(time.Now()) {
		return fmt.Errorf("expires_at must not be in the past")
	}
	gc.ExpiresAt = t
	return nil
}

// parseDurationMin 上限取 365*24*60 (一年, 分钟). 防 admin 误填巨值 →
// h*60+m 整数溢出 → 负数下发到 iKuai (timeout 字段语义错乱).
//
// duration_min 字段语义 (M9 修复):
//
//	提供且非负 → 直接用, clamp 到 [0, maxDurationMin]
//	提供且为负 (用户故意填 -1) → 视为 0 = "不限时", 而非 silent fallback 到 18h default
//	空 (字段未提交)        → 走 duration_h / duration_m default 18:00
const maxDurationMin = 365 * 24 * 60

func parseDurationMin(r *http.Request) int {
	rawMin := strings.TrimSpace(r.FormValue("duration_min"))
	if rawMin != "" {
		mins, err := strconv.Atoi(rawMin)
		if err != nil {
			// 输入垃圾走默认分支
		} else {
			if mins < 0 {
				return 0
			}
			if mins > maxDurationMin {
				return maxDurationMin
			}
			return mins
		}
	}
	h := parseIntDefault(r.FormValue("duration_h"), 18)
	m := parseIntDefault(r.FormValue("duration_m"), 0)
	if h < 0 {
		h = 0
	}
	if h > maxDurationMin/60 {
		h = maxDurationMin / 60
	}
	if m < 0 {
		m = 0
	}
	if m > 60*24*7 { // 一周分钟数, 已经远超合理输入
		m = 60 * 24 * 7
	}
	total := h*60 + m
	if total > maxDurationMin {
		total = maxDurationMin
	}
	return total
}

// --- 渲染 ---

type pageData struct {
	Lang               Lang
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
		Lang:               lang,
		Brand:              a.makeBrand(),
		NowYear:            time.Now().Year(),
		GuestEnabled:       a.cfg.IsAdminEnabled(),
		AllowedDomainsHint: a.firstAllowedDomain(),
	}
	_ = dev // IP/MAC 不再显示, 但 handlePortal 仍会校验存在性
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := a.templates.ExecuteTemplate(w, "login.html", data); err != nil {
		log.Printf("template render failed: %v", err)
	}
}

func (a *App) renderAdminLogin(w http.ResponseWriter, r *http.Request, lang Lang) {
	data := pageData{
		Lang:    lang,
		Brand:   a.makeBrand(),
		NowYear: time.Now().Year(),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := a.templates.ExecuteTemplate(w, "admin_login.html", data); err != nil {
		log.Printf("admin login template render failed: %v", err)
	}
}

func (a *App) renderError(w http.ResponseWriter, r *http.Request, lang Lang, msg string, code int) {
	data := pageData{
		Lang:    lang,
		Brand:   a.makeBrand(),
		Message: msg,
		NowYear: time.Now().Year(),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	if err := a.templates.ExecuteTemplate(w, "error.html", data); err != nil {
		log.Printf("template render failed: %v", err)
	}
}

type adminPageData struct {
	Lang          Lang
	Brand         brandData
	AdminUPN      string
	NowYear       int
	Codes         []adminCodeRow
	DeniedMACs    []adminDeniedMACRow
	IKuaiPolicies []IKuaiPolicyRow
	Total         int
	Used          int
	Unused        int
	Expired       int
	Dashboard     DashboardStats
}

// DashboardStats 顶部 summary 卡片. 所有字段都在内存可得, 渲染时一次 snapshot.
type DashboardStats struct {
	LoginsToday      int
	LoginsWeek       int
	FailedRatePct    int // 0..100, 最近 7 天失败占比
	FailedCount7d    int
	ActiveGuestCodes int
	BannedIPs        int
	BannedMACs       int
}

type adminCodeRow struct {
	Code           string
	CreatedAt      string
	ExpiresAt      string // 显示用 "2006-01-02 15:04"
	ExpiresAtInput string // datetime-local input 用 "2006-01-02T15:04"
	Duration       string
	DurationMin    int
	Status         string
	UseCount       int
	MaxUses        int // 0 = 不限
	LastUsedAt     string
	LastUsedMAC    string
	LastUsedIP     string
	Note           string
}

type adminDeniedMACRow struct {
	MAC       string
	Reason    string
	CreatedAt string
	CreatedBy string
}

func (a *App) renderAdmin(w http.ResponseWriter, r *http.Request, admin AdminSession) {
	lang := pickLang(r)
	raw := a.guestCodes.List()
	total, used, unused, expired := a.guestCodes.Stats()
	rows := make([]adminCodeRow, 0, len(raw))
	for _, c := range raw {
		row := adminCodeRow{
			Code:        c.Code,
			CreatedAt:   c.CreatedAt.Local().Format("2006-01-02 15:04"),
			Status:      c.Status(),
			UseCount:    c.UseCount(),
			DurationMin: c.DurationMin,
			MaxUses:     c.MaxUses,
			Note:        c.Note,
		}
		row.Duration = formatDurationMin(c.DurationMin, lang)
		if c.ExpiresAt.IsZero() {
			row.ExpiresAt = T(lang, "admin.codes.neverExpires")
		} else {
			row.ExpiresAt = c.ExpiresAt.Local().Format("2006-01-02 15:04")
			row.ExpiresAtInput = c.ExpiresAt.Local().Format("2006-01-02T15:04")
		}
		if len(c.Uses) > 0 {
			u := c.Uses[len(c.Uses)-1]
			row.LastUsedAt = u.At.Local().Format("2006-01-02 15:04")
			row.LastUsedMAC = u.MAC
			row.LastUsedIP = u.IP
		}
		rows = append(rows, row)
	}
	denied := a.denylist.ListMACs()
	deniedRows := make([]adminDeniedMACRow, 0, len(denied))
	for _, item := range denied {
		deniedRows = append(deniedRows, adminDeniedMACRow{
			MAC:       item.MAC,
			Reason:    item.Reason,
			CreatedAt: item.CreatedAt.Local().Format("2006-01-02 15:04"),
			CreatedBy: item.CreatedBy,
		})
	}
	data := adminPageData{
		Lang:          lang,
		Brand:         a.makeBrand(),
		AdminUPN:      admin.UPN,
		NowYear:       time.Now().Year(),
		Codes:         rows,
		DeniedMACs:    deniedRows,
		IKuaiPolicies: a.ikuaiPolicies.List(),
		Total:         total,
		Used:          used,
		Unused:        unused,
		Expired:       expired,
		Dashboard:     a.buildDashboard(raw),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := a.templates.ExecuteTemplate(w, "admin.html", data); err != nil {
		log.Printf("admin template render failed: %v", err)
	}
}

// buildDashboard 计算 /admin 首页顶部 summary 卡片的数字.
//   - 登录统计从 eventLog 的 KindLogin 事件推导
//   - 访客码 / 封禁状态从各 store 直接拿
//   - 当前在线设备数请直接到 iKuai 后台查, Portal 不重复造轮子
func (a *App) buildDashboard(allCodes []*GuestCode) DashboardStats {
	now := time.Now()
	stats := DashboardStats{
		BannedMACs: len(a.denylist.ListMACs()),
		BannedIPs:  len(a.ipBans.snapshot()),
	}
	// 当前有效访客码 = 未过期 且 未用完 (跟 Validate 判断一致, 比 Stats().Unused 更严格)
	validCodes := 0
	for _, c := range allCodes {
		if c.IsExpired() || c.IsExhausted() {
			continue
		}
		validCodes++
	}
	stats.ActiveGuestCodes = validCodes

	if a.eventLog == nil {
		return stats
	}
	dayAgo := now.Add(-24 * time.Hour)
	weekAgo := now.Add(-7 * 24 * time.Hour)

	// H6 修复: MultiCount 一次锁内扫多过滤. 旧实现 5 次 Count = 5 次锁 + 5 次全表扫,
	// 100k 事件场景下 admin 刷新 /admin 慢 50-100ms + 阻塞 logLogin.
	counts := a.eventLog.MultiCount([]EventQueryFilter{
		{Kind: KindLogin, Result: ResultSuccess, Since: dayAgo},
		{Kind: KindLogin, Result: ResultSuccess, Since: weekAgo},
		{Kind: KindLogin, Result: ResultDenied, Since: weekAgo},
		{Kind: KindLogin, Result: ResultRateLimited, Since: weekAgo},
		{Kind: KindLogin, Result: ResultError, Since: weekAgo},
	})
	stats.LoginsToday = counts[0]
	stats.LoginsWeek = counts[1]
	failedWeek := counts[2] + counts[3] + counts[4]
	stats.FailedCount7d = failedWeek
	terminalWeek := stats.LoginsWeek + failedWeek
	if terminalWeek > 0 {
		stats.FailedRatePct = int(float64(failedWeek) * 100 / float64(terminalWeek))
	}
	return stats
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

// parseMaxUses: 空 / 0 / 负数 → 0 (不限); 否则原值. 上限 1e6 防滥配 / 整数溢出后续计算.
func parseMaxUses(s string) int {
	n := parseIntDefault(s, 0)
	if n < 0 {
		return 0
	}
	if n > 1_000_000 {
		n = 1_000_000
	}
	return n
}

// capLen 字符级截断到 n 字节, 防 admin 输入超长字段被持久化爆磁盘 / 事件日志 OOM.
// 走字节截断不切 UTF-8 多字节序列, 调用方约定输入主要是 ASCII (note/reason/comment/mac).
func capLen(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
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
		return strconv.Itoa(hours) + " h"
	case mins > 0:
		return strconv.Itoa(mins) + " min"
	default:
		return "-"
	}
}

func formatDurationMin(totalMin int, lang Lang) string {
	if totalMin <= 0 {
		return T(lang, "admin.codes.noSessionLimit")
	}
	hours := totalMin / 60
	mins := totalMin % 60
	return formatDuration(hours, mins)
}
