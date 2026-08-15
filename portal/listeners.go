package main

// listeners.go
// The listeners the portal owns, and how they change while it is running.
//
// Before TLS moved into the console this file would not have existed: the
// process bound one address at startup and that was the end of it. Making the
// mode, the HTTPS address and the plain-HTTP redirect editable from a web page
// means those decisions now change under live traffic, which brings two problems
// worth naming.
//
// The first is that http.Server.Handler cannot be reassigned while the server is
// serving — it is read without synchronisation on every request. So the plain
// listener is given one permanent handler that consults an atomic pointer, and
// turning the redirect on or off swaps the pointer instead of the field.
//
// The second is that these are exactly the settings that can take the console
// away from the operator editing them. A redirect to an HTTPS listener whose
// certificate does not load leaves a browser with nowhere to go, and the page
// that would let them undo it is behind that same redirect. applyListenerChange
// therefore commits like a router does — see listenerCommit in tls.go.

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// listenerManager reconciles the running listeners with a configuration.
//
// It is deliberately a reconciler rather than a set of start/stop calls: the
// caller hands it the configuration it wants and it works out what has to
// happen. That keeps startup and a settings save on the same code path, so the
// state a portal reaches by being restarted and the state it reaches by being
// reconfigured cannot diverge.
type listenerManager struct {
	app *App
	// mux is the bare portal mux, served when no front is installed.
	mux http.Handler
	// tlsHandler is the fully wrapped portal handler for the HTTPS server. The
	// redirect never applies there — a request that already arrived over TLS has
	// nowhere better to be sent.
	tlsHandler http.Handler
	// front, when set, replaces the portal on the plain-HTTP listener. Today the
	// only front is the HTTPS redirect.
	front atomic.Pointer[http.Handler]

	mu     sync.Mutex
	tlsSrv *http.Server
	// tlsAddr is the address the running listener is actually bound to, which is
	// not always the configured one: a bind that failed leaves the previous
	// listener in place, and the TLS page shows both so the difference is visible.
	tlsAddr string
}

func newListenerManager(app *App, mux http.Handler) *listenerManager {
	return &listenerManager{
		app:        app,
		mux:        mux,
		tlsHandler: securityHeaders(app.logRequests(mux)),
	}
}

// ServeHTTP is the plain listener's permanent handler.
func (m *listenerManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h := m.front.Load(); h != nil {
		(*h).ServeHTTP(w, r)
		return
	}
	m.mux.ServeHTTP(w, r)
}

// apply brings the listeners into line with cfg.
//
// Errors describe a listener that could not be brought up; they do not undo
// anything, because the previous listener is only released once the new one has
// bound successfully. A caller can therefore report the failure and leave the
// portal serving exactly what it was serving before.
func (m *listenerManager) apply(cfg *Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if cfg.TLSMode != TLSModeStandalone {
		m.stopTLSLocked()
		m.setFront(nil)
		return nil
	}

	var err error
	if m.tlsSrv == nil || m.tlsAddr != cfg.TLSListenAddr {
		err = m.startTLSLocked(cfg)
	}

	// The redirect is installed even when the HTTPS listener failed to bind, but
	// only if one is already running on some address — otherwise an operator who
	// mistyped the port would be redirected to a port nothing is listening on.
	if cfg.TLSRedirectHTTP && m.tlsSrv != nil {
		h := redirectToHTTPS(cfg.TLSDomain, m.mux, m.app.acme)
		m.setFront(&h)
	} else {
		m.setFront(nil)
	}
	return err
}

func (m *listenerManager) setFront(h *http.Handler) {
	m.front.Store(h)
}

// startTLSLocked binds the HTTPS listener.
//
// Bind first, release the old listener second. A new address that cannot be
// bound — port in use, no permission for 443, an interface that does not exist —
// then costs nothing: the portal keeps serving HTTPS where it already was.
func (m *listenerManager) startTLSLocked(cfg *Config) error {
	// Load whatever certificate is stored before the listener accepts anything,
	// so a portal that is restarted, or switched into standalone mode, serves the
	// certificate it already has rather than refusing the first handshakes.
	if pair, _, err := m.app.certs.Load(cfg.TLSDomain); err != nil {
		log.Printf("tls: the stored certificate for %s could not be loaded, "+
			"HTTPS will refuse handshakes until it is fixed: %v", cfg.TLSDomain, err)
	} else if pair != nil {
		m.app.certProvider.set(pair)
	} else {
		log.Printf("tls: standalone mode is on but no certificate is stored for %s; "+
			"issue one from Admin -> TLS, or upload a PEM pair", cfg.TLSDomain)
	}

	ln, err := net.Listen("tcp", cfg.TLSListenAddr)
	if err != nil {
		return fmt.Errorf("HTTPS cannot listen on %s: %w", cfg.TLSListenAddr, err)
	}
	m.stopTLSLocked()

	srv := &http.Server{
		Handler:           m.tlsHandler,
		TLSConfig:         tlsConfig(m.app.certProvider),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	m.tlsSrv, m.tlsAddr = srv, cfg.TLSListenAddr

	go func() {
		// Empty file arguments are correct rather than an omission: certificates
		// come from the GetCertificate callback, which is what lets a renewal take
		// effect without rebuilding this listener.
		if err := srv.ServeTLS(ln, "", ""); err != nil && err != http.ErrServerClosed {
			log.Printf("tls: the HTTPS listener on %s stopped: %v", cfg.TLSListenAddr, err)
		}
	}()
	log.Printf("tls: HTTPS listening on %s for %s", cfg.TLSListenAddr, cfg.TLSDomain)
	return nil
}

func (m *listenerManager) stopTLSLocked() {
	if m.tlsSrv == nil {
		return
	}
	srv, addr := m.tlsSrv, m.tlsAddr
	m.tlsSrv, m.tlsAddr = nil, ""
	// Closed in the background with a grace period: a settings save must not
	// block for as long as the slowest in-flight download on the old listener.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("tls: shutting down the HTTPS listener on %s: %v", addr, err)
		}
	}()
}

// running reports the address the HTTPS listener is bound to, if any.
func (m *listenerManager) running() (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.tlsAddr, m.tlsSrv != nil
}

func (m *listenerManager) shutdown(ctx context.Context) {
	m.mu.Lock()
	srv := m.tlsSrv
	m.tlsSrv, m.tlsAddr = nil, ""
	m.mu.Unlock()
	if srv == nil {
		return
	}
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("tls: shutting down the HTTPS listener: %v", err)
	}
}

// --- change safety ---

// listenerRisky reports whether moving from prev to next could take the console
// away from the operator making the change.
//
// Only in that direction. Adding a listener or removing a redirect cannot strand
// anyone, and arming a two-minute rollback for a change that is strictly safer
// would mean an operator who walks away loses a setting they wanted.
func listenerRisky(prev, next *Config) bool {
	switch {
	case prev.TLSMode == TLSModeStandalone && next.TLSMode != TLSModeStandalone:
		// The HTTPS listener goes away, and the operator may be on it.
		return true
	case next.TLSRedirectHTTP && !prev.TLSRedirectHTTP:
		// Plain HTTP starts bouncing to a listener that may not work.
		return true
	case next.TLSMode == TLSModeStandalone && prev.TLSMode == TLSModeStandalone &&
		prev.TLSListenAddr != next.TLSListenAddr:
		// The console moves to a different port.
		return true
	case next.TLSRedirectHTTP && prev.TLSDomain != next.TLSDomain:
		// The redirect now points at a different hostname.
		return true
	default:
		return false
	}
}

// applyListenerChange reconciles the listeners after a TLS settings save and, for
// a change that could lock the operator out, arms the rollback.
//
// The rollback restores the section exactly as it was, reloads the runtime from
// it and reconciles the listeners again — the same path a save takes, so a
// rolled-back portal is in a state the code already knows how to be in.
func (a *App) applyListenerChange(prev *Config, prevSection map[string]string, updatedBy string) (armed bool, deadline time.Time, err error) {
	next := a.conf()
	applyErr := a.listeners.apply(next)

	if !listenerRisky(prev, next) {
		return false, time.Time{}, applyErr
	}
	// A change that could not even be applied has nothing to roll back from: the
	// portal is still serving what it was, and the operator needs the error, not
	// a countdown.
	if applyErr != nil {
		return false, time.Time{}, applyErr
	}

	// Defaults are filled in for keys the section never had a row for, so a
	// rollback restores the values the portal was actually running with rather
	// than leaving a key at whatever the risky save wrote.
	restore := make(map[string]string, len(prevSection)+4)
	for _, k := range sectionKeys(secTLS) {
		restore[k.Key] = k.Default
	}
	for k, v := range prevSection {
		restore[k] = v
	}

	deadline = a.listenerCommit.begin(func() error {
		if err := a.settings.Save(secTLS, restore, "rollback"); err != nil {
			return fmt.Errorf("restoring the previous TLS settings: %w", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		// Logged, not returned. reloadRuntime reports every configuration problem
		// it finds — an unreachable identity provider, a half-configured Duo — and
		// installs the state regardless. Treating that as a failed rollback would
		// abandon the listener change on exactly the portals most likely to have
		// been locked out: the ones with something else already misconfigured.
		if err := a.reloadRuntime(ctx); err != nil {
			log.Printf("tls: the rollback reloaded with warnings: %v", err)
		}
		a.logAdminAction(updatedBy, "", ResultError, "listener change rolled back unconfirmed")
		return a.listeners.apply(a.conf())
	})
	log.Printf("tls: listener change applied by %s, unconfirmed changes roll back at %s",
		updatedBy, deadline.Format(time.TimeOnly))
	return true, deadline, nil
}
