package main

// main.go
// HTTP routing and startup logic. Business logic lives in other files.
//
// Endpoints:
//   GET  /healthz                  health check
//   GET  /portal                   iKuai redirects unauthenticated devices here
//   POST /auth/start               user submits email -> server preauth -> opaque token
//                                   response is identical for all emails; browser then visits:
//   GET  /auth/proceed?token=...   consume token -> 302 to real target (Duo Universal / Entra)
//   GET  /login                    redirect to Entra with login_hint
//   GET  /auth/callback            Entra callback, routed by session.Purpose (wifi / admin)
//   GET  /auth/duo-callback        Duo Universal Prompt callback, exchange id_token -> allow-list
//   POST /auth/guest-code          validate guest code -> allow-list
//   /admin*                        admin console protected by Entra
//   GET  /static/*                 static assets
//
// Security:
//   - Portal binds only 127.0.0.1; Nginx reverse proxy terminates TLS.
//   - Cookie Secure + HttpOnly + SameSite=Lax
//   - Entra and Duo both verify state (CSRF); Entra additionally verifies nonce, tid, iss, aud.
//   - Guests with #EXT# in UPN are rejected.
//   - Email-domain allowlist prevents external domains from triggering Duo prompts.

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

// Embedded deployment templates. The `wifi-portal init <dir>` subcommand writes them to disk so
// bare-binary deployments do not need git clone for examples. //go:embed packs file contents into
// the binary at build time, with paths relative to the Go source directory.
//
//go:embed .env.example
var embeddedEnvExample []byte

//go:embed embed/wifi-portal.service
var embeddedSystemdUnit []byte

// dataPaths contains every persistent file path derived from cfg.DataDir. It is built once in main()
// and reused for the process lifetime. File names are fixed; only the directory is configurable:
//   - Container: cfg.DataDir = /data by default, docker-compose bind-mounts /data to ./data.
//   - Bare binary + systemd: usually /var/lib/wifi-portal.
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

// isSameOriginRequest verifies that a request comes from the same origin as cfg.PublicURL.
// Prefer Origin, then fall back to Referer. Reject when both are missing; modern form POSTs normally
// include Referer, so missing headers are usually curl or forged clients.
func (a *App) isSameOriginRequest(r *http.Request) bool {
	expected := strings.TrimRight(a.cfg.PublicURL, "/")
	if origin := r.Header.Get("Origin"); origin != "" {
		// Origin is scheme+host[:port] without path, so compare directly.
		return strings.TrimRight(origin, "/") == expected
	}
	if referer := r.Header.Get("Referer"); referer != "" {
		ref, err := url.Parse(referer)
		if err != nil || ref.Scheme == "" || ref.Host == "" {
			return false
		}
		// Reconstruct scheme://host[:port] before comparing.
		got := ref.Scheme + "://" + ref.Host
		return got == expected
	}
	return false
}

// isLoopbackListen reports whether LISTEN_ADDR binds only a loopback interface.
// An empty host such as ":28080" means 0.0.0.0, which listens on all interfaces and is not loopback.
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
	duo           *DuoClient          // Duo Auth API, preauth only.
	duoUniversal  *DuoUniversalClient // Duo Universal Prompt (OIDC)
	guestCodes    *GuestCodeStore
	denylist      *DenylistStore
	ikuaiPolicies *IKuaiPolicyStore
	templates     *template.Template

	// --- Rate limiting / abuse prevention ---
	// Rule 1: /auth/start counts email failures with two windows and resets on successful callback.
	authEmailFails *failCounter
	// Rule 5: /auth/guest-code counts failures by MAC and resets on success.
	guestCodeFails *failCounter
	// Rule 6: one IP accumulates failures across endpoints and gets a short cooldown when over limit.
	ipFails    *failCounter
	ipBans     *ipBanList
	banHistory *banHistory // How many times an IP has been cooled down; non-persistent by default.

	// Account-enumeration defense: /auth/start returns an opaque token; /auth/proceed performs the 302.
	proceedStore *proceedTokenStore

	// usedStates prevents OIDC state replay: callback marks state used immediately after validation,
	// and a second arrival with the same state is rejected.
	usedStates *usedStateSet

	// --- Observability ---
	eventLog *EventLog
}

// runInit handles `wifi-portal init [dir]`: write embedded .env.example and systemd unit templates
// to the target directory so bare-binary deployments do not need git clone for examples.
//
// Existing files are not overwritten to avoid deleting user edits. A non-nil return means exit 1.
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

	// .env header: reflect actual deployment paths so users can copy it to conf-dir and systemctl start.
	// DATA_DIR is set to match the systemd unit ReadWritePaths automatically.
	envHeader := fmt.Sprintf(`# Generated by `+"`"+`wifi-portal init`+"`"+`. Actual deployment paths are aligned in this .env:
#
#   Config file       %s/wifi-portal.env       (systemd EnvironmentFile=)
#   Data directory    %s     (DATA_DIR + systemd ReadWritePaths=)
#   Binary            %s   (systemd ExecStart=)
#
# To change paths, rerun init with flags:
#   wifi-portal init --conf-dir <path> --data-dir <path> --bin-path <path> --out-dir <path>
#
# Key overrides for bare binary / systemd:
#   LISTEN_ADDR=127.0.0.1:28080    # loopback, reverse-proxy access
#   DATA_DIR=%s    # defaulted here, matches systemd ReadWritePaths
#   TZ=UTC
#   TRUST_PROXY=true               # set when a reverse proxy terminates connections
# ----------------------------------------------------------------------

DATA_DIR=%s
`, *confDir, *dataDir, *binPath, *dataDir, *dataDir)
	envContent := append([]byte(envHeader), embeddedEnvExample...)

	// systemd unit: replace three placeholders.
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
		fmt.Fprintf(os.Stderr, "       # wifi-portal.env is already in conf-dir (%s); no cp needed\n", *confDir)
	}
	fmt.Fprintf(os.Stderr, "       sudo cp %s/wifi-portal.service /etc/systemd/system/\n", absOut)
	fmt.Fprintf(os.Stderr, "       sudo cp wifi-portal %s   # portal binary\n", *binPath)
	fmt.Fprintln(os.Stderr, "       sudo systemctl daemon-reload")
	fmt.Fprintln(os.Stderr, "       sudo systemctl enable --now wifi-portal")
	fmt.Fprintln(os.Stderr, "  3. 反代终结 TLS (Nginx / Caddy), 转发到 127.0.0.1:28080")
	return nil
}

// looksUninitialized returns true when none of the key env vars are set, which usually means the
// user is first-running the bare binary before sourcing .env or wiring systemd EnvironmentFile.
// In that case, enter first-run init and generate config templates instead of mustEnv fatal.
//
// Only "all empty" triggers this. Partial configuration still goes through mustEnv so users get the
// precise missing key instead of being misdetected as first-run.
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
	// Explicit init subcommand with selectable directory, useful for ops init into /etc/wifi-portal.
	if len(os.Args) > 1 && os.Args[1] == "init" {
		if err := runInit(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "init error:", err)
			os.Exit(1)
		}
		return
	}

	// First-run auto init: all key env vars empty means bare run before config, so generate templates
	// in the current directory. Containers and systemd EnvironmentFile paths already have env set.
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

	// Inject into ratelimit.go package var before any clientIP call.
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

	// Graceful shutdown: catch SIGINT/SIGTERM, stop the server, flush banHistory, and close EventLog.
	// Without this, SIGTERM can exit before the async banHistory flusher reaches its next tick.
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

// --- Middleware ---

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

// --- Common ---

func (a *App) healthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

// robotsTxt deters well-behaved crawlers. Malicious crawlers are handled by rate limits.
// Templates also include <meta name="robots" content="noindex, nofollow">; this is the second layer.
func (a *App) robotsTxt(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write([]byte("User-agent: *\nDisallow: /\n"))
}

// --- WiFi login ---

func (a *App) handlePortal(w http.ResponseWriter, r *http.Request) {
	lang := pickLang(r)
	dev, ok := extractDeviceInfo(r, a.cfg)
	if !ok {
		// Language switching or refresh may revisit without iKuai query fields; fall back to the
		// existing cookie. If it is valid and contains IP/MAC, do not treat the session as lost.
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

// handleAuthStart is the routing entry after email submission.
//
// Key security design:
//  1. Check IP cooldown (rule 6) and email failure count (rule 1) before real routing.
//  2. Do not expose the routing decision (Duo vs Entra vs deny) in the response. Store it in
//     proceedStore and return an opaque token; /auth/proceed?token=X performs the real 302.
//     All valid emails therefore look identical at /auth/start.
//  3. Record an email "pending attempt" here and reset it on successful callback. Legitimate users
//     clear it with one success; attackers who never complete callback eventually hit the limit.
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
	// Enforce the domain allowlist only when Duo is enabled; without Duo, Entra handles domain/tenant filtering.
	if a.cfg.IsDuoEnabled() && !isAllowedDomain(email, a.cfg.AllowedEmailDomains) {
		log.Printf("deny domain not in allowlist: %q", email)
		a.recordRequestFailure(r, &sess, "invalid_domain")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_domain"})
		return
	}

	// Rule 1: check this email's failure count in both windows.
	shortN := a.authEmailFails.countIn(email, a.cfg.AuthEmailWindowShort)
	longN := a.authEmailFails.countIn(email, a.cfg.AuthEmailWindowLong)
	if shortN >= a.cfg.AuthEmailFailsShort || longN >= a.cfg.AuthEmailFailsLong {
		log.Printf("/auth/start email ratelimit: %q short=%d long=%d ip=%s",
			email, shortN, longN, ip)
		a.recordRequestFailure(r, &sess, "rate_limited_email")
		// Use the retry_after from whichever window fills first.
		rule := "email_long"
		if shortN >= a.cfg.AuthEmailFailsShort {
			rule = "email_short"
		}
		// If this recordIPFailure call just triggered an IP cooldown, report that cooldown first.
		if bannedIP, ok := a.bannedIPForRequest(r, &sess); ok {
			rule = "ip_ban"
			ip = bannedIP
		}
		a.logLogin(email, ResultRateLimited, MethodSSO, sess.MAC, ip, rule)
		a.writeRateLimited(w, rule, ip)
		return
	}

	// Store email in the session for later handlers.
	sess.Email = email
	if err := writeSessionCookie(w, a.cfg.SessionSecret, sess, true); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cookie_write"})
		return
	}

	// Compute the real destination URL and kind, then store them in the opaque token.
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
				// Do not tell attackers "denied" in the response; send them to Entra and let Entra reject.
				log.Printf("Duo denied account: %s (%s), routing to Entra anyway to hide deny signal",
					email, pre.StatusMsg)
				realURL, kind = ssoURL, proceedDeny
			default:
				log.Printf("unknown Duo preauth result: %s, falling back to SSO", pre.Result)
				realURL, kind = ssoURL, proceedEntra
			}
		}
	}

	// Put the proceed token before recording pending failure. M8 fix: a put failure must not pollute
	// counters. rand.Reader failure is rare, but this keeps counters aligned with token creation.
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

// writeRateLimited sends a 429 with enough information for the frontend to render "try later" or
// "contact admin". The specific internal rule is not returned to avoid exposing ban type:
//   - retry_after_seconds: suggested wait time.
//   - permanent: when true, show contact-admin instead of a countdown.
//   - unban_at_unix: Unix unban time, only for ip_ban.
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
		// Do not reset banHistory. One legitimate login must not erase long-term suspicious IP
		// history; otherwise attackers could authenticate once and avoid permanent escalation.
		// Admin-triggered /admin/ratelimit/reset with type=ip_ban still clears banHistory.
	}
}

// recordIPFailure accumulates IP failures and applies a short cooldown at threshold.
// The escalation model remains as a configurable backstop: attempts 1..IPBanEscalateAt-1 use
// IPBanDuration; attempt IPBanEscalateAt and later become permanent until admin unban.
// IPBanEscalateAt <= 0 explicitly disables permanent escalation and bypasses banHistory (L6).
// reason is only logged for troubleshooting.
func (a *App) recordIPFailure(ip, reason string) {
	a.ipFails.record(ip)
	n := a.ipFails.countIn(ip, a.cfg.IPFailsWindow)
	if n < a.cfg.IPFailsLimit {
		return
	}
	// If already banned, do not re-ban; that would extend cooldown and scramble escalation counts.
	if a.ipBans.isBanned(ip) {
		return
	}
	// L6: when escalation is disabled, skip banHistory because the history is meaningless.
	if a.cfg.IPBanEscalateAt <= 0 {
		a.ipBans.ban(ip, a.cfg.IPBanDuration)
		log.Printf("IP fail-limit reached, cooldown %s: %s (count=%d window=%s reason=%s, escalation disabled)",
			a.cfg.IPBanDuration, ip, n, a.cfg.IPFailsWindow, reason)
		return
	}
	banCount := a.banHistory.increment(ip)
	var duration time.Duration
	if banCount >= a.cfg.IPBanEscalateAt {
		duration = time.Until(PermanentBanUntil) // Duration until the "permanent" marker.
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

// handleLogin redirects to Entra, using ?hint=email as login_hint when present.
// If no hint exists but the session has email, use that.
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

// handleCallback handles Entra callback and routes by session.Purpose.
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
	// Consume state once to prevent replay after cookie theft. A second arrival is rejected.
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
	// After successful auth, clear temporary failure state for the same email/device/IP.
	a.clearSuccessfulAuthState(r, sess, user.UPN)
	ikuaiURL := buildWebAuthURL(a.cfg, DeviceInfo{IP: sess.UserIP, MAC: sess.MAC}, user.UPN,
		IKuaiProfileSSO, a.ikuaiPolicies.Get(IKuaiProfileSSO))
	clearSessionCookie(w, true)
	http.Redirect(w, r, ikuaiURL, http.StatusFound)
}

// handleDuoCallback handles Duo Universal Prompt callback: verify state, exchange code, get username, allow-list.
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
	// Duo Universal Prompt callback parameter names vary by version/tenant:
	// older versions return duo_code, newer OIDC-compliant versions return code. Accept both.
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
	// After successful auth, clear temporary failure state for the same email/device/IP.
	a.clearSuccessfulAuthState(r, sess, username)
	ikuaiURL := buildWebAuthURL(a.cfg, DeviceInfo{IP: sess.UserIP, MAC: sess.MAC}, username,
		IKuaiProfileDuo, a.ikuaiPolicies.Get(IKuaiProfileDuo))
	clearSessionCookie(w, true)
	http.Redirect(w, r, ikuaiURL, http.StatusFound)
}

// --- Guest codes ---

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
	// Rule 5: count failures by session MAC. The MAC is signed into the cookie by /portal, so
	// attackers cannot change it; this is more stable than IP.
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
	// Event logs store only the last 4 code chars, matching terminal logs. /data/events.jsonl may be
	// backed up or aggregated, so it must not contain full codes.
	a.logLogin(upn, ResultSuccess, MethodGuestCode, sess.MAC, sess.UserIP,
		"code-suffix="+tailN(c.Code, 4))
	// Success: clear temporary failure state for the same device/IP.
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
	// POST only: writing cookies from GET violates idempotence and can be passively triggered.
	// admin_login.html already uses <form method="post">.
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
	// Do not prefill email for admin login.
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

// adminGrantReason is only for logs and explains whether admin access came from UPN allowlist or group membership.
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
	// CSRF defense: state-changing requests must come from same origin. Admin cookie is already
	// SameSite=Strict; Origin/Referer checks add another layer. GETs are exempt because many browser
	// GET scenarios omit Origin.
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
	// A signed cookie means this user passed IsAdmin at login via UPN allowlist or Entra group.
	// Do not re-check ADMIN_EMAILS on every request, or group-based admins would be rejected.
	// Group changes cannot be checked during requests because id_token was signed once at login.
	// Admin revocation takes effect within cookie TTL; immediate revocation requires clearing the
	// user's cookie or rotating SessionSecret.
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
		// User-provided codes are length-limited to avoid 1MB codes in events.jsonl.
		// Enforce a 6-char minimum because tailN(code, 4) is used as the audit suffix; shorter codes
		// would effectively expose the whole code. This matches batch generation limits.
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
		// Audit logs never store full codes. The UI returns the code to the admin once at creation;
		// long-term audit only needs a creation trace and last 4 chars for troubleshooting.
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
		// baseProbe only reuses parseExpiry. Each code gets its own CreatedAt so List ordering does
		// not flicker because of identical timestamps.
	baseProbe := &GuestCode{CreatedAt: time.Now()}
	if err := parseExpiry(r, baseProbe, false); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
		// Collision cap: avoid infinite loops if admin chooses a tiny nearly-full code space.
	maxAttempts := count * 50
	if maxAttempts < 200 {
		maxAttempts = 200
	}
		// Generate candidate codes first, then AddMany once. crypto/rand makes same-batch collisions
		// rare, and AddMany avoids N saveLocked rewrites of guest-codes.json (H3).
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
// form: codes=<comma-separated code list>
// Delete multiple guest codes at once. Write one audit event with count and sample suffixes instead
// of one event per code to avoid log noise.
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
// Edit ExpiresAt / DurationMin / MaxUses / Note for an existing code. Code itself cannot change;
// delete and recreate for that. Used codes can still be edited, but already-online iKuai sessions
// keep their existing timeout; changes only affect future allow-list entries.
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
	// Reuse parseExpiry by letting it read expires_at into a temporary GuestCode.
	probe := &GuestCode{CreatedAt: time.Now()}
	// Edit allows past expiry so admins can force a code to expire immediately (H7).
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
// Return the current rate-limit snapshot for admin UI rendering: banned IPs and email/MAC failures.
func (a *App) handleRateLimitStatus(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdmin(w, r, true); !ok {
		return
	}
	// Merge ban-history counts into the ip_bans snapshot so the frontend can show attempt count in
	// one row. Also mark currently banned IPs that are permanent.
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
		"ban_history":     banCounts, // Includes every IP ever banned, even if not currently banned.
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
// Clear or unban the rate-limit state for key. With defaults, ip_ban means short IP cooldown.
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
		a.ipFails.reset(key)    // Also clear accumulated IP failures to avoid immediate re-ban.
		a.banHistory.reset(key) // Clear historical ban count to avoid jumping straight to permanent.
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
// Clear all rate-limit state: IP cooldowns, email/MAC/IP failure counts, and cooldown history.
// Used for broad false positives or to reset after an attack has ended. The action is logged.
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

// handleDenyMACDeleteAll clears the whole MAC denylist. It only touches denylist state, not rate limits.
// This is independent from /admin/ratelimit/reset-all.
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

// ikuaiPolicyDiff creates a readable diff like "policy <profile>: upload 100->200, timeout 60->120".
// It lists only changed fields; if nothing changed, it returns a full snapshot so detail is non-empty.
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

// --- Event log / denylist CSV ---

// parseEventFilter reads filters from URL query. It does not validate enum values; unknown values
// simply filter to empty results rather than returning 500.
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
	// Shape rows for frontend rendering and include both Unix seconds and readable ISO-like time.
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
		f.Limit = 100000 // Do not truncate exports; a large limit is enough here.
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
	// L10 fix: explicitly Flush and check Error instead of defer cw.Flush(). Flush errors are IO
	// write failures; this handler has no return-error path, so log only.
	if err := cw.Write([]string{"mac", "reason", "banned_by", "banned_at"}); err != nil {
		log.Printf("denylist CSV header write: %v", err)
		return
	}
	for _, item := range items {
		// Data rows pass through sanitizeCSVCell to neutralize Excel formula injection.
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
	// Limit to 1MB, enough for about 10k rows.
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
	reader.FieldsPerRecord = -1 // Tolerate inconsistent column counts.
	rows, err := reader.ReadAll()
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "parse_failed"})
		return
	}
	// Convert all valid rows into MACInput, then call AddMACMany once. This avoids one saveLocked
	// per row; a 10k-row CSV used to rewrite denylist.json 10k times (H2), now once.
	inputs := make([]MACInput, 0, len(rows))
	errs := []string{}
	for idx, row := range rows {
		if len(row) == 0 {
			continue
		}
		// Skip header when the first column is "mac", tolerating UTF-8 BOM.
		// "\ufeff" is an escape, not a literal BOM; Go source cannot contain a mid-file BOM.
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
		// Safety: always use current admin.UPN as createdBy. The CSV third column (banned_by) is
		// exported information and must not let importers forge another admin's UPN.
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

// parseExpiry parses the expires_at form field. allowPast=true skips future enforcement for Edit,
// allowing admins to expire an active code immediately. Create still requires future dates.
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

// parseDurationMin caps at 365*24*60 minutes. This prevents huge admin input from overflowing
// h*60+m and sending a negative timeout to iKuai.
//
// duration_min semantics (M9 fix):
//
//	provided and non-negative -> use directly, clamped to [0, maxDurationMin]
//	provided and negative     -> treat as 0 = unlimited, not silent fallback to 18h default
//	empty                     -> use duration_h / duration_m default 18:00
const maxDurationMin = 365 * 24 * 60

func parseDurationMin(r *http.Request) int {
	rawMin := strings.TrimSpace(r.FormValue("duration_min"))
	if rawMin != "" {
		mins, err := strconv.Atoi(rawMin)
		if err != nil {
			// Bad input falls through to the default branch.
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
	if m > 60*24*7 { // One week of minutes, already far beyond reasonable input.
		m = 60 * 24 * 7
	}
	total := h*60 + m
	if total > maxDurationMin {
		total = maxDurationMin
	}
	return total
}

// --- Rendering ---

type pageData struct {
	Lang               Lang
	Brand              brandData
	Message            string
	NowYear            int
	GuestEnabled       bool
	AllowedDomainsHint string // Email input placeholder uses the first allowed domain.
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
	_ = dev // IP/MAC are no longer displayed, but handlePortal still verifies they exist.
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

// DashboardStats backs the top summary cards. All fields are available in memory at render time.
type DashboardStats struct {
	LoginsToday      int
	LoginsWeek       int
	FailedRatePct    int // 0..100 failure percentage in the last 7 days.
	FailedCount7d    int
	ActiveGuestCodes int
	BannedIPs        int
	BannedMACs       int
}

type adminCodeRow struct {
	Code           string
	CreatedAt      string
	ExpiresAt      string // Display format "2006-01-02 15:04".
	ExpiresAtInput string // datetime-local input format "2006-01-02T15:04".
	Duration       string
	DurationMin    int
	Status         string
	UseCount       int
	MaxUses        int // 0 means unlimited.
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

// buildDashboard computes the top summary counters on /admin.
//   - Login stats come from KindLogin events in eventLog.
//   - Guest-code and denylist stats come directly from their stores.
//   - Current online devices should be checked in iKuai; the portal does not duplicate that.
func (a *App) buildDashboard(allCodes []*GuestCode) DashboardStats {
	now := time.Now()
	stats := DashboardStats{
		BannedMACs: len(a.denylist.ListMACs()),
		BannedIPs:  len(a.ipBans.snapshot()),
	}
	// Active guest codes are not expired and not exhausted, matching Validate.
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

	// H6 fix: MultiCount scans multiple filters under one lock. The old implementation did five
	// Count calls, causing five locks and five full scans.
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

// --- Helpers ---

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

// parseMaxUses maps empty / 0 / negative to 0 (unlimited), otherwise returns the value capped at 1e6.
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

// capLen truncates to n bytes to prevent oversized admin input from bloating persistence or logs.
// It does byte truncation; callers only pass mostly-ASCII values such as note/reason/comment/mac.
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
