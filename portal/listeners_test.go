package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kazuhahub/wifi-portal/internal/secret"
	"github.com/kazuhahub/wifi-portal/internal/settings"
)

// newListenerTestApp builds an App with the pieces the listener manager touches:
// a certificate store, a provider, and an ACME manager for the redirect front's
// challenge exemption.
func newListenerTestApp(t *testing.T) *App {
	t.Helper()
	db := testDB(t)
	keys := secret.NewKeyring("0123456789abcdef0123456789abcdef")
	certs := newCertStore(db, keys)
	app := newTestApp(Config{})
	app.certs = certs
	app.certProvider = &certProvider{}
	app.acme = newACMEManager(db, certs, keys)
	app.listenerCommit = &listenerCommit{}
	return app
}

// newSettingsTestApp adds the settings store on top, for the tests that go
// through a real save-and-reload rather than a hand-built Config.
func newSettingsTestApp(t *testing.T) *App {
	t.Helper()
	db := testDB(t)
	keys := secret.NewKeyring("0123456789abcdef0123456789abcdef")
	app := newTestApp(Config{})
	app.db = db
	app.settings = settings.New(db, keys, isSecretSetting)
	app.certs = newCertStore(db, keys)
	app.certProvider = &certProvider{}
	app.acme = newACMEManager(db, app.certs, keys)
	app.listenerCommit = &listenerCommit{}
	app.eventLog = newEventLog(db, 30*24*time.Hour)
	return app
}

// freePort returns a port nothing is listening on, so a test can bind it without
// colliding with whatever else the machine is running.
func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

func okMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "portal")
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	})
	return mux
}

func TestListenerManagerProxyModeBindsNothing(t *testing.T) {
	app := newListenerTestApp(t)
	m := newListenerManager(app, okMux())
	if err := m.apply(&Config{TLSMode: TLSModeProxy}); err != nil {
		t.Fatalf("proxy mode should not fail: %v", err)
	}
	if _, running := m.running(); running {
		t.Fatal("proxy mode must not bring up an HTTPS listener")
	}
}

// The listener has to come and go with the mode, because that is the whole
// promise of configuring TLS from the console: no restart.
func TestListenerManagerStartsAndStopsWithMode(t *testing.T) {
	app := newListenerTestApp(t)
	m := newListenerManager(app, okMux())
	addr := freePort(t)

	if err := m.apply(&Config{TLSMode: TLSModeStandalone, TLSListenAddr: addr}); err != nil {
		t.Fatalf("standalone apply: %v", err)
	}
	got, running := m.running()
	if !running || got != addr {
		t.Fatalf("expected a listener on %s, got %q running=%v", addr, got, running)
	}
	// Reachable, even without a certificate: the handshake will fail, but the
	// port must be open, which is what an operator's connectivity check tests.
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dialling the new listener: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	if err := m.apply(&Config{TLSMode: TLSModeProxy}); err != nil {
		t.Fatalf("switching back to proxy: %v", err)
	}
	if _, running := m.running(); running {
		t.Fatal("switching to proxy mode must release the listener")
	}
}

// A second apply with the same address must not rebuild the listener — doing so
// would drop every connection each time an unrelated field is saved.
func TestListenerManagerApplyIsIdempotent(t *testing.T) {
	app := newListenerTestApp(t)
	m := newListenerManager(app, okMux())
	addr := freePort(t)
	cfg := &Config{TLSMode: TLSModeStandalone, TLSListenAddr: addr}

	if err := m.apply(cfg); err != nil {
		t.Fatal(err)
	}
	first := m.tlsSrv
	if err := m.apply(cfg); err != nil {
		t.Fatal(err)
	}
	if m.tlsSrv != first {
		t.Fatal("re-applying the same address rebuilt the listener")
	}
	if err := m.apply(&Config{TLSMode: TLSModeProxy}); err != nil {
		t.Fatal(err)
	}
}

// A bind that fails must leave the working listener alone. An operator who
// mistypes a port should get an error, not a portal with no HTTPS at all.
func TestListenerManagerFailedBindKeepsPreviousListener(t *testing.T) {
	app := newListenerTestApp(t)
	m := newListenerManager(app, okMux())
	good := freePort(t)
	if err := m.apply(&Config{TLSMode: TLSModeStandalone, TLSListenAddr: good}); err != nil {
		t.Fatal(err)
	}

	// Occupied by something else, so the manager's bind cannot succeed.
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()

	err = m.apply(&Config{TLSMode: TLSModeStandalone, TLSListenAddr: blocker.Addr().String()})
	if err == nil {
		t.Fatal("binding an occupied port should report an error")
	}
	if got, running := m.running(); !running || got != good {
		t.Fatalf("the previous listener was lost: got %q running=%v", got, running)
	}
	if err := m.apply(&Config{TLSMode: TLSModeProxy}); err != nil {
		t.Fatal(err)
	}
}

// The redirect is a pointer swap on a permanently installed handler, never an
// assignment to http.Server.Handler, which races with in-flight requests.
func TestListenerManagerRedirectFront(t *testing.T) {
	app := newListenerTestApp(t)
	m := newListenerManager(app, okMux())
	addr := freePort(t)
	cfg := &Config{
		TLSMode:         TLSModeStandalone,
		TLSListenAddr:   addr,
		TLSDomain:       "portal.example.com",
		TLSRedirectHTTP: true,
	}
	if err := m.apply(cfg); err != nil {
		t.Fatal(err)
	}
	defer m.apply(&Config{TLSMode: TLSModeProxy})

	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://10.0.0.1/login?x=1", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("expected a 302 redirect, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "https://portal.example.com/login?x=1" {
		t.Fatalf("redirect target: %q", loc)
	}

	// The two exemptions: a challenge that must stay on plain HTTP, and a health
	// probe that may not resolve the hostname.
	rec = httptest.NewRecorder()
	m.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://10.0.0.1/healthz", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Fatalf("/healthz was redirected: %d %q", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	m.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"http://10.0.0.1/.well-known/acme-challenge/tok", nil))
	if rec.Code != http.StatusNotFound {
		// 404 is the challenge handler answering for an unknown token; a 302 here
		// would deadlock issuance.
		t.Fatalf("the ACME challenge path was redirected: %d", rec.Code)
	}

	// Turning it off restores the portal on the same handler instance.
	cfg2 := *cfg
	cfg2.TLSRedirectHTTP = false
	if err := m.apply(&cfg2); err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	m.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://10.0.0.1/login", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "portal" {
		t.Fatalf("the portal did not come back: %d %q", rec.Code, rec.Body.String())
	}
}

// Without a listener to redirect to, the redirect must not be installed —
// otherwise a mistyped port takes every plain-HTTP client to a dead address.
func TestListenerManagerRedirectNotInstalledWithoutListener(t *testing.T) {
	app := newListenerTestApp(t)
	m := newListenerManager(app, okMux())
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()

	err = m.apply(&Config{
		TLSMode:         TLSModeStandalone,
		TLSListenAddr:   blocker.Addr().String(),
		TLSDomain:       "portal.example.com",
		TLSRedirectHTTP: true,
	})
	if err == nil {
		t.Fatal("expected the bind to fail")
	}
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://10.0.0.1/login", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("plain HTTP was redirected to a listener that does not exist: %d", rec.Code)
	}
}

// End to end over a real socket: a stored certificate is served by the listener
// the manager brought up.
func TestListenerManagerServesStoredCertificate(t *testing.T) {
	app := newListenerTestApp(t)
	certPEM, keyPEM := mkTestCert(t, "portal.example.com",
		time.Now().Add(-time.Hour), time.Now().Add(48*time.Hour))
	if err := app.certs.Save("portal.example.com", CertSourceManual, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}

	m := newListenerManager(app, okMux())
	addr := freePort(t)
	if err := m.apply(&Config{
		TLSMode: TLSModeStandalone, TLSListenAddr: addr, TLSDomain: "portal.example.com",
	}); err != nil {
		t.Fatal(err)
	}
	defer m.apply(&Config{TLSMode: TLSModeProxy})

	client := &http.Client{Transport: &http.Transport{
		// The certificate is self-signed by construction; what is under test is
		// that the listener serves the stored pair, not that a test CA is trusted.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "portal.example.com"},
	}}
	resp, err := client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("HTTPS request: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "portal" {
		t.Fatalf("body: %q", body)
	}
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		t.Fatal("no peer certificate")
	}
	if cn := resp.TLS.PeerCertificates[0].Subject.CommonName; cn != "portal.example.com" {
		t.Fatalf("served the wrong certificate: %s", cn)
	}
}

func TestListenerRisky(t *testing.T) {
	std := func(mut func(*Config)) *Config {
		c := &Config{TLSMode: TLSModeStandalone, TLSListenAddr: "0.0.0.0:443", TLSDomain: "a.example.com"}
		if mut != nil {
			mut(c)
		}
		return c
	}
	proxy := &Config{TLSMode: TLSModeProxy, TLSDomain: "a.example.com"}

	cases := []struct {
		name       string
		prev, next *Config
		want       bool
	}{
		{"turning off standalone drops the listener the admin may be on",
			std(nil), proxy, true},
		{"moving the HTTPS port",
			std(nil), std(func(c *Config) { c.TLSListenAddr = "0.0.0.0:8443" }), true},
		{"turning the redirect on",
			std(nil), std(func(c *Config) { c.TLSRedirectHTTP = true }), true},
		{"changing the domain the redirect points at",
			std(func(c *Config) { c.TLSRedirectHTTP = true }),
			std(func(c *Config) { c.TLSRedirectHTTP = true; c.TLSDomain = "b.example.com" }), true},
		{"turning standalone on adds a listener and strands nobody",
			proxy, std(nil), false},
		{"turning the redirect off is strictly safer",
			std(func(c *Config) { c.TLSRedirectHTTP = true }), std(nil), false},
		{"an unrelated field",
			std(nil), std(func(c *Config) { c.ACMEEmail = "ops@example.com" }), false},
		{"the domain alone, with no redirect in play",
			std(nil), std(func(c *Config) { c.TLSDomain = "b.example.com" }), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := listenerRisky(tc.prev, tc.next); got != tc.want {
				t.Fatalf("listenerRisky = %v, want %v", got, tc.want)
			}
		})
	}
}

// The rollback has to restore settings that were never written as rows, not just
// the ones that were — otherwise a first-ever save of the TLS section rolls back
// to a half-default state.
func TestApplyListenerChangeRollbackRestoresDefaults(t *testing.T) {
	app := newSettingsTestApp(t)
	addr := freePort(t)

	// The state before the change: standalone on a working port, no redirect.
	if err := app.settings.Save(secTLS, map[string]string{
		"mode": TLSModeStandalone, "listen_addr": addr, "domain": "portal.example.com",
	}, "test"); err != nil {
		t.Fatal(err)
	}
	// The error is expected and ignored throughout this test: reloadRuntime
	// reports "Entra SSO is not configured" for a fixture that has no identity
	// provider, and still installs the state — which is the behaviour that makes
	// a broken configuration repairable from the console.
	_ = app.reloadRuntime(t.Context())
	app.listeners = newListenerManager(app, okMux())
	if err := app.listeners.apply(app.conf()); err != nil {
		t.Fatal(err)
	}
	defer app.listeners.apply(&Config{TLSMode: TLSModeProxy})

	prevCfg := app.conf()
	prevSection, err := app.settings.LoadSection(secTLS)
	if err != nil {
		t.Fatal(err)
	}

	// The risky change: turn the redirect on.
	if err := app.settings.SetOne(secTLS, "redirect_http", "true", "test"); err != nil {
		t.Fatal(err)
	}
	_ = app.reloadRuntime(t.Context())
	armed, deadline, err := app.applyListenerChange(prevCfg, prevSection, "admin@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !armed {
		t.Fatal("turning the redirect on should arm a rollback")
	}
	if time.Until(deadline) <= 0 || time.Until(deadline) > listenerConfirmWindow {
		t.Fatalf("deadline out of range: %s", deadline)
	}

	rec := httptest.NewRecorder()
	app.listeners.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://10.0.0.1/login", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("the redirect was not applied: %d", rec.Code)
	}

	// Fire the rollback by hand rather than waiting out the window.
	app.listenerCommit.mu.Lock()
	rollback := app.listenerCommit.rollback
	app.listenerCommit.pending = false
	app.listenerCommit.mu.Unlock()
	if rollback == nil {
		t.Fatal("no rollback was recorded")
	}
	if err := rollback(); err != nil {
		t.Fatalf("rollback: %v", err)
	}

	if app.conf().TLSRedirectHTTP {
		t.Fatal("the rollback did not restore redirect_http")
	}
	rec = httptest.NewRecorder()
	app.listeners.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://10.0.0.1/login", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("the redirect survived the rollback: %d", rec.Code)
	}
	// And the listener the operator had is still the one they have.
	if got, running := app.listeners.running(); !running || got != addr {
		t.Fatalf("listener after rollback: %q running=%v", got, running)
	}
}

// A change that could not be applied has nothing to roll back from, and arming a
// countdown for it would only take a working configuration away two minutes
// later.
func TestApplyListenerChangeDoesNotArmOnFailure(t *testing.T) {
	app := newSettingsTestApp(t)
	app.listeners = newListenerManager(app, okMux())

	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()

	if err := app.settings.Save(secTLS, map[string]string{
		"mode": TLSModeStandalone, "listen_addr": blocker.Addr().String(), "redirect_http": "true",
	}, "test"); err != nil {
		t.Fatal(err)
	}
	// See the note above: an unconfigured identity provider is reported, not fatal.
	_ = app.reloadRuntime(t.Context())

	armed, _, err := app.applyListenerChange(&Config{TLSMode: TLSModeProxy}, map[string]string{}, "admin")
	if err == nil || !strings.Contains(err.Error(), "cannot listen") {
		t.Fatalf("expected a bind error, got %v", err)
	}
	if armed {
		t.Fatal("a change that failed to apply must not arm a rollback")
	}
	if pending, _ := app.listenerCommit.status(); pending {
		t.Fatal("commit-confirm was armed after a failed apply")
	}
}
