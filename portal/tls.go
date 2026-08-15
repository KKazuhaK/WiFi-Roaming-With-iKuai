package main

// tls.go
// The portal's own TLS listener and the certificate it serves.
//
// Until now TLS was somebody else's problem: Caddy or Nginx terminated it and
// forwarded plain HTTP, which is still a supported and sometimes necessary
// arrangement — a host that already serves other sites on 443 cannot give the
// port to this process. What changed is that it is no longer the only
// arrangement, because "configure everything in one place" does not survive a
// deployment guide that starts with "now edit your reverse proxy".
//
// Two modes, chosen from the admin console:
//
//	proxy       The portal listens on plain HTTP and something in front of it
//	            terminates TLS. What the console offers here is a generated
//	            config snippet to paste and a connectivity self-check — not a
//	            write into another service's files. Giving a process that faces
//	            unauthenticated client devices write access to /etc/nginx and
//	            the ability to reload it trades a large amount of blast radius
//	            for a copy-paste.
//	standalone  The portal binds 443 itself and serves a certificate from the
//	            database, obtained by ACME or uploaded by the operator.
//
// The dangerous part is not the TLS; it is that the settings which decide where
// the portal listens are edited through the portal. Getting them wrong takes the
// console away. applyListenerChange therefore commits like a router does — the
// old listener is kept until the new one has proven it accepts a request, and
// an unconfirmed change rolls back on a timer.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"

	"github.com/kazuhahub/wifi-portal/internal/dbstore"
	"github.com/kazuhahub/wifi-portal/internal/secret"
)

// TLS modes.
const (
	TLSModeProxy      = "proxy"
	TLSModeStandalone = "standalone"
)

// Certificate sources.
const (
	CertSourceACME   = "acme"
	CertSourceManual = "manual"
)

// certStore reads and writes certificates, decrypting the private key.
type certStore struct {
	db   *dbstore.DB
	keys *secret.Keyring
}

func newCertStore(db *dbstore.DB, keys *secret.Keyring) *certStore {
	return &certStore{db: db, keys: keys}
}

// Load returns the stored certificate for a domain as a usable tls.Certificate.
func (s *certStore) Load(domain string) (*tls.Certificate, *dbstore.Certificate, error) {
	var row dbstore.Certificate
	if err := s.db.Where("domain = ?", domain).First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	if row.CertPEM == "" || row.KeyPEM == "" {
		// A row can exist recording a failed issuance attempt, with LastError
		// set and no material. That is not an error to the caller — it is the
		// state the TLS page renders.
		return nil, &row, nil
	}
	keyPEM, err := s.keys.Decrypt(row.KeyPEM)
	if err != nil {
		return nil, &row, fmt.Errorf("decrypting the private key for %s: %w", domain, err)
	}
	pair, err := tls.X509KeyPair([]byte(row.CertPEM), []byte(keyPEM))
	if err != nil {
		return nil, &row, fmt.Errorf("certificate for %s does not load: %w", domain, err)
	}
	return &pair, &row, nil
}

// Save stores a certificate, encrypting the private key and recording the
// validity window so the renewal loop and the admin page can read it without
// parsing PEM again.
func (s *certStore) Save(domain, source, certPEM, keyPEM string) error {
	leaf, err := parseLeaf(certPEM)
	if err != nil {
		return err
	}
	if err := verifyKeyMatchesCert(certPEM, keyPEM); err != nil {
		return err
	}
	encKey, err := s.keys.Encrypt(keyPEM)
	if err != nil {
		return fmt.Errorf("encrypting the private key: %w", err)
	}
	row := dbstore.Certificate{
		Domain:    domain,
		Source:    source,
		CertPEM:   certPEM,
		KeyPEM:    encKey,
		NotBefore: leaf.NotBefore.UTC(),
		NotAfter:  leaf.NotAfter.UTC(),
		UpdatedAt: time.Now().UTC(),
		LastError: "",
	}
	return s.db.Save(&row).Error
}

// RecordFailure stores why an issuance attempt failed without disturbing any
// certificate already in place. A renewal that fails must not take down a
// listener that is currently serving a perfectly valid, if ageing, certificate.
func (s *certStore) RecordFailure(domain, reason string) {
	now := time.Now().UTC()
	err := s.db.Where("domain = ?", domain).
		Assign(map[string]any{"last_error": reason, "last_attempt": now}).
		FirstOrCreate(&dbstore.Certificate{Domain: domain, Source: CertSourceACME}).Error
	if err != nil {
		log.Printf("tls: recording the failure for %s failed too: %v", domain, err)
	}
}

func parseLeaf(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, errors.New("certificate is not valid PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("certificate does not parse: %w", err)
	}
	return leaf, nil
}

// verifyKeyMatchesCert catches the single most common upload mistake: a
// certificate and a private key from different pairs. Left unchecked it produces
// a listener that fails every handshake, and the operator has already navigated
// away from the page that would tell them why.
func verifyKeyMatchesCert(certPEM, keyPEM string) error {
	if _, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM)); err != nil {
		return fmt.Errorf("the certificate and private key do not match: %w", err)
	}
	return nil
}

// certificateStatus is what the TLS page renders.
type certificateStatus struct {
	Domain      string     `json:"domain"`
	Source      string     `json:"source,omitempty"`
	Present     bool       `json:"present"`
	NotBefore   *time.Time `json:"notBefore,omitempty"`
	NotAfter    *time.Time `json:"notAfter,omitempty"`
	DaysLeft    int        `json:"daysLeft"`
	LastError   string     `json:"lastError,omitempty"`
	LastAttempt *time.Time `json:"lastAttempt,omitempty"`
	// Issuer and DNSNames let an operator confirm at a glance that the
	// certificate the portal is serving is the one they think it is.
	Issuer   string   `json:"issuer,omitempty"`
	DNSNames []string `json:"dnsNames,omitempty"`
}

func (s *certStore) Status(domain string) certificateStatus {
	st := certificateStatus{Domain: domain}
	_, row, err := s.Load(domain)
	if row == nil {
		if err != nil {
			st.LastError = err.Error()
		}
		return st
	}
	st.Source = row.Source
	st.LastError = row.LastError
	st.LastAttempt = row.LastAttempt
	if err != nil && st.LastError == "" {
		st.LastError = err.Error()
	}
	if row.CertPEM == "" {
		return st
	}
	st.Present = true
	nb, na := row.NotBefore, row.NotAfter
	st.NotBefore, st.NotAfter = &nb, &na
	st.DaysLeft = int(time.Until(na).Hours() / 24)
	if leaf, perr := parseLeaf(row.CertPEM); perr == nil {
		st.Issuer = leaf.Issuer.CommonName
		st.DNSNames = leaf.DNSNames
	}
	return st
}

// --- certificate provider for the listener ---

// certProvider hands the current certificate to crypto/tls on each handshake.
//
// A GetCertificate callback rather than a fixed Certificates slice, so a renewal
// takes effect without rebuilding the listener. Rebuilding it would drop
// in-flight connections every sixty days for no reason.
type certProvider struct {
	mu   sync.RWMutex
	cert *tls.Certificate
}

func (p *certProvider) set(c *tls.Certificate) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cert = c
}

func (p *certProvider) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.cert == nil {
		// Answering with an error aborts the handshake, which is the honest
		// outcome: there is no certificate to serve, and a self-signed
		// placeholder would train operators to click through warnings.
		return nil, errors.New("no certificate is configured for this portal")
	}
	return p.cert, nil
}

// tlsConfig builds the server configuration.
//
// TLS 1.2 is the floor rather than 1.3: captive-portal mini browsers on older
// Android builds still negotiate 1.2, and refusing them would leave exactly the
// devices this portal exists to admit unable to reach it.
func tlsConfig(p *certProvider) *tls.Config {
	return &tls.Config{
		GetCertificate: p.get,
		MinVersion:     tls.VersionTLS12,
		NextProtos:     []string{"h2", "http/1.1"},
	}
}

// --- listener change safety ---

// listenerCommit is the pending half of a commit-confirm change.
//
// Changing the listen address or switching on TLS through the console can take
// the console away — a wrong port, a certificate that does not load, a firewall
// that was never opened. Network equipment solves this with commit-confirm, and
// the same shape applies: the change is applied, the operator's browser has a
// bounded window to reach the new listener and confirm, and an unconfirmed
// change is rolled back automatically.
type listenerCommit struct {
	mu       sync.Mutex
	pending  bool
	deadline time.Time
	rollback func() error
	timer    *time.Timer
}

// listenerConfirmWindow is how long an operator has to confirm. Long enough to
// re-resolve DNS and load a page over a fresh TLS handshake, short enough that
// an operator who has locked themselves out is not staring at a dead console.
const listenerConfirmWindow = 2 * time.Minute

// begin arms a rollback. Any previously pending commit is superseded.
func (l *listenerCommit) begin(rollback func() error) time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.timer != nil {
		l.timer.Stop()
	}
	l.pending = true
	l.deadline = time.Now().Add(listenerConfirmWindow)
	l.rollback = rollback
	l.timer = time.AfterFunc(listenerConfirmWindow, func() {
		l.mu.Lock()
		if !l.pending {
			l.mu.Unlock()
			return
		}
		l.pending = false
		fn := l.rollback
		l.mu.Unlock()
		if fn == nil {
			return
		}
		log.Printf("tls: listener change was not confirmed within %s, rolling back", listenerConfirmWindow)
		if err := fn(); err != nil {
			log.Printf("tls: rollback failed: %v — recover with `wifi-portal config set`", err)
		}
	})
	return l.deadline
}

// confirm cancels a pending rollback. Called by the admin UI once it has
// successfully reached the portal on the new listener, which is the only proof
// that matters.
func (l *listenerCommit) confirm() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.pending {
		return false
	}
	l.pending = false
	if l.timer != nil {
		l.timer.Stop()
	}
	l.rollback = nil
	return true
}

func (l *listenerCommit) status() (pending bool, deadline time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.pending, l.deadline
}

// --- reverse-proxy snippets ---

// proxySnippet renders a ready-to-paste configuration for the operator's own
// reverse proxy.
//
// Generated and shown, never written. The portal would need write access to
// /etc/nginx and the ability to reload another service to do it for them, and
// this process is reachable by every unauthenticated device on the guest
// network. That is a large amount of blast radius to trade for a copy-paste.
func proxySnippet(kind, domain, listenAddr string) string {
	upstream := listenAddr
	if strings.HasPrefix(upstream, "0.0.0.0:") {
		// 0.0.0.0 is a bind address, not a destination; a proxy on the same host
		// should be pointed at loopback.
		upstream = "127.0.0.1:" + strings.TrimPrefix(upstream, "0.0.0.0:")
	}
	switch kind {
	case "caddy":
		return fmt.Sprintf(`%s {
	reverse_proxy %s {
		header_up X-Real-IP {remote_host}
	}
}
`, domain, upstream)
	default: // nginx
		return fmt.Sprintf(`server {
    listen 443 ssl;
    http2 on;
    server_name %s;

    # ssl_certificate / ssl_certificate_key are managed by your proxy.

    location / {
        proxy_pass http://%s;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
`, domain, upstream)
	}
}

// checkReachable performs the connectivity self-check the TLS page offers.
//
// It dials the configured public URL from the portal's own process and reports
// what came back. That is a weaker test than a real client's — the portal may
// reach itself over a path a guest device cannot — but it catches the failures
// operators actually hit: a proxy pointed at the wrong port, a listener bound to
// loopback while the proxy is on another host, DNS that does not resolve yet.
func checkReachable(ctx context.Context, addr string, timeout time.Duration) error {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	return conn.Close()
}
