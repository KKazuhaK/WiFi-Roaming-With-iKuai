package main

// admin_tls.go
// The admin API behind the TLS page.
//
// Everything here is deliberately explicit rather than automatic. Issuing a
// certificate, uploading one, and switching the portal onto its own listener are
// all operations that can take the console away from the operator performing
// them, so each is a button they press with the consequences written next to it
// — not something that happens because a form was saved.

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// tlsStatusResponse is what the TLS page renders.
type tlsStatusResponse struct {
	Mode         string            `json:"mode"`
	Domain       string            `json:"domain"`
	ListenAddr   string            `json:"listenAddr"`
	HTTPListen   string            `json:"httpListen"`
	RedirectHTTP bool              `json:"redirectHttp"`
	ACMEEnabled  bool              `json:"acmeEnabled"`
	ACMEEmail    string            `json:"acmeEmail"`
	ACMEStaging  bool              `json:"acmeStaging"`
	PublicURL    string            `json:"publicUrl"`
	Certificate  certificateStatus `json:"certificate"`
	// Listening is what the process is actually doing, which is not always what
	// the configuration says: a bind that failed leaves the previous listener in
	// place, and an operator staring at "0.0.0.0:443" needs to know whether
	// anything is on it.
	Listening     bool   `json:"listening"`
	ListeningAddr string `json:"listeningAddr,omitempty"`
	// Snippets are ready-to-paste reverse-proxy configuration, generated but
	// never written — see the note on proxySnippet for why the portal does not
	// write into another service's files.
	Snippets map[string]string `json:"snippets"`
	// PendingCommit reports an unconfirmed listener change and when it rolls
	// back, so the page can show a countdown and a confirm button.
	PendingCommit  bool      `json:"pendingCommit"`
	CommitDeadline time.Time `json:"commitDeadline,omitempty"`
	// Reachable reports whether the portal could open a TCP connection to its
	// own public address.
	Reachable      *bool  `json:"reachable,omitempty"`
	ReachableError string `json:"reachableError,omitempty"`
	// HTTP01Viable says whether an HTTP-01 challenge can work here at all. A
	// portal on a LAN box is not publicly routable and never will be, so the UI
	// needs to steer those operators to a manual certificate rather than let
	// them retry a challenge that cannot succeed.
	HTTP01Viable bool   `json:"http01Viable"`
	HTTP01Note   string `json:"http01Note,omitempty"`
}

func (a *App) handleAdminTLS(w http.ResponseWriter, r *http.Request) {
	admin, ok := a.requireAdmin(w, r, true)
	if !ok {
		return
	}
	action := strings.Trim(strings.TrimPrefix(r.URL.Path, "/admin/api/tls"), "/")

	switch {
	case r.Method == http.MethodGet && action == "":
		a.writeTLSStatus(w, r)
	case r.Method == http.MethodPost && action == "issue":
		a.tlsIssue(w, r, admin.UPN)
	case r.Method == http.MethodPost && action == "upload":
		a.tlsUpload(w, r, admin.UPN)
	case r.Method == http.MethodPost && action == "confirm":
		a.tlsConfirm(w, r, admin.UPN)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown_action"})
	}
}

// http01Viability decides whether to offer ACME at all.
//
// The check is deliberately shallow — a private address in the public URL, or a
// hostname that resolves to one — because that is the case that is certain, and
// a certain answer is worth more here than a probabilistic one. A public address
// that happens to be firewalled will still fail at issuance, and the error is
// then recorded against the certificate for the page to show.
func http01Viability(publicURL string) (bool, string) {
	host := hostFromURL(publicURL)
	if host == "" {
		return false, "no public URL is configured"
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return false, fmt.Sprintf("%s does not resolve: %v", host, err)
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
			return false, fmt.Sprintf(
				"%s resolves to %s, which Let's Encrypt cannot reach. "+
					"Upload a certificate obtained elsewhere, or use a DNS-01 capable tool "+
					"and paste the result here.", host, ip)
		}
	}
	return true, ""
}

func (a *App) writeTLSStatus(w http.ResponseWriter, r *http.Request) {
	cfg := a.conf()
	pending, deadline := a.listenerCommit.status()
	boundAddr, listening := "", false
	if a.listeners != nil {
		boundAddr, listening = a.listeners.running()
	}

	resp := tlsStatusResponse{
		Mode:          cfg.TLSMode,
		Domain:        cfg.TLSDomain,
		ListenAddr:    cfg.TLSListenAddr,
		HTTPListen:    cfg.ListenAddr,
		RedirectHTTP:  cfg.TLSRedirectHTTP,
		ACMEEnabled:   cfg.ACMEEnabled,
		ACMEEmail:     cfg.ACMEEmail,
		ACMEStaging:   cfg.ACMEStaging,
		PublicURL:     cfg.PublicURL,
		Certificate:   a.certs.Status(cfg.TLSDomain),
		Listening:     listening,
		ListeningAddr: boundAddr,
		PendingCommit: pending,
		Snippets: map[string]string{
			"nginx": proxySnippet("nginx", cfg.TLSDomain, cfg.ListenAddr),
			"caddy": proxySnippet("caddy", cfg.TLSDomain, cfg.ListenAddr),
		},
	}
	if pending {
		resp.CommitDeadline = deadline
	}
	resp.HTTP01Viable, resp.HTTP01Note = http01Viability(cfg.PublicURL)

	// The self-check runs only when asked, because it costs a DNS lookup and a
	// dial and the page is polled.
	if r.URL.Query().Get("check") == "1" {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		addr := cfg.TLSListenAddr
		if cfg.TLSMode == TLSModeProxy {
			addr = cfg.ListenAddr
		}
		if err := checkReachable(ctx, addr, 4*time.Second); err != nil {
			f := false
			resp.Reachable, resp.ReachableError = &f, err.Error()
		} else {
			t := true
			resp.Reachable = &t
		}
	}

	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, resp)
}

// tlsIssue obtains a certificate now.
//
// Synchronous, with a five-minute ceiling, because an operator pressing "issue"
// is watching for the outcome. A background job would mean polling for a result
// that usually arrives in ten seconds.
func (a *App) tlsIssue(w http.ResponseWriter, r *http.Request, upn string) {
	cfg := a.conf()
	if cfg.TLSDomain == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no_domain"})
		return
	}
	if cfg.ACMEEmail == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no_acme_email"})
		return
	}

	a.logAdminAction(upn, clientIP(r), ResultStarted, "acme issue domain="+cfg.TLSDomain)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if err := a.acme.Issue(ctx, acmeRequest{
		Domain: cfg.TLSDomain, Email: cfg.ACMEEmail, Staging: cfg.ACMEStaging,
	}); err != nil {
		a.certs.RecordFailure(cfg.TLSDomain, err.Error())
		a.logAdminAction(upn, clientIP(r), ResultError, "acme issue failed: "+err.Error())
		// 200 with an error field rather than a 5xx: the request was handled
		// correctly and the failure is Let's’ Encrypt's answer, which the page
		// needs to display in full rather than as a status code.
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}

	if pair, _, err := a.certs.Load(cfg.TLSDomain); err == nil && pair != nil {
		a.certProvider.set(pair)
	}
	a.logAdminAction(upn, clientIP(r), ResultSuccess, "acme issue succeeded domain="+cfg.TLSDomain)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "certificate": a.certs.Status(cfg.TLSDomain)})
}

// tlsUpload stores an operator-supplied PEM pair.
//
// This is the path for every deployment ACME cannot serve: a LAN box that Let's
// Encrypt cannot reach, an internal CA, or a wildcard certificate the
// organisation already owns.
func (a *App) tlsUpload(w http.ResponseWriter, r *http.Request, upn string) {
	var body struct {
		CertPEM string `json:"certPem"`
		KeyPEM  string `json:"keyPem"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_body"})
		return
	}
	cfg := a.conf()
	if cfg.TLSDomain == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no_domain"})
		return
	}

	certPEM := strings.TrimSpace(body.CertPEM)
	keyPEM := strings.TrimSpace(body.KeyPEM)
	if certPEM == "" || keyPEM == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "empty_pem"})
		return
	}

	// Validated before it is stored. An unusable pair saved and only discovered
	// at the next handshake would leave the operator with a listener that
	// refuses every connection and no page telling them why.
	if err := a.certs.Save(cfg.TLSDomain, CertSourceManual, certPEM, keyPEM); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}

	// A certificate for the wrong hostname is the second most common upload
	// mistake and produces a name-mismatch error in every browser. Warn rather
	// than refuse: an operator may be staging a certificate ahead of a rename.
	var warning string
	if leaf, err := parseLeaf(certPEM); err == nil {
		if err := leaf.VerifyHostname(cfg.TLSDomain); err != nil {
			warning = fmt.Sprintf("the certificate does not cover %s (it lists %s)",
				cfg.TLSDomain, strings.Join(leaf.DNSNames, ", "))
		}
	}

	if pair, _, err := a.certs.Load(cfg.TLSDomain); err == nil && pair != nil {
		a.certProvider.set(pair)
	}
	a.logAdminAction(upn, clientIP(r), ResultSuccess, "certificate uploaded domain="+cfg.TLSDomain)
	log.Printf("tls: certificate for %s uploaded by %s", cfg.TLSDomain, upn)

	resp := map[string]any{"ok": true, "certificate": a.certs.Status(cfg.TLSDomain)}
	if warning != "" {
		resp["warning"] = warning
	}
	writeJSON(w, http.StatusOK, resp)
}

// tlsConfirm cancels a pending rollback.
//
// The operator's browser reaching this endpoint is the proof the commit-confirm
// mechanism waits for: it means the console is reachable on the new listener,
// which is the only thing that actually needed verifying.
func (a *App) tlsConfirm(w http.ResponseWriter, r *http.Request, upn string) {
	if a.listenerCommit.confirm() {
		a.logAdminAction(upn, clientIP(r), ResultSuccess, "listener change confirmed")
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": "no_pending_change"})
}
