package main

// acme.go
// Automatic certificate issuance and renewal via Let's Encrypt.
//
// The captive-portal complication, stated plainly because it decides which
// challenge an operator can use:
//
// HTTP-01 requires Let's Encrypt to reach port 80 on the portal's public
// address. A portal on a VPS with a public A record (deployment mode A) has
// that. A portal on a LAN box behind a router (mode B) does not, and no amount
// of configuration will give it that — the whole point of that deployment is
// that it is not publicly routable. Those installations need DNS-01, which
// proves control of the domain through a TXT record instead and therefore needs
// an API token for the DNS provider.
//
// So the mode is not a preference, it is a property of where the portal sits,
// and the admin UI says so rather than offering two equal-looking radio buttons.
//
// One further constraint specific to this application: while an HTTP-01
// challenge is in flight, the portal must answer /.well-known/acme-challenge/
// on port 80 — the same port iKuai redirects captive clients to. The challenge
// handler is therefore mounted into the normal mux rather than run on a private
// listener, so both can share the port.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"

	"github.com/kazuhahub/wifi-portal/internal/dbstore"
	"github.com/kazuhahub/wifi-portal/internal/secret"
)

// renewBefore is how long before expiry a renewal is attempted.
//
// Thirty days on a ninety-day Let's Encrypt certificate leaves two full renewal
// windows before anything breaks, which matters here more than usual: this
// portal is the thing standing between guests and the network, and its
// certificate failing is not a degraded experience but a closed door.
const renewBefore = 30 * 24 * time.Hour

// acmeUser satisfies lego's registration.User.
type acmeUser struct {
	email        string
	registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *acmeUser) GetEmail() string                        { return u.email }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.registration }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

// acmeManager owns issuance and the renewal loop.
type acmeManager struct {
	db    *dbstore.DB
	certs *certStore
	keys  *secret.Keyring

	// challenges holds in-flight HTTP-01 tokens. lego's own provider wants to
	// own a listener; this portal already has one on the port the challenge
	// needs, so the tokens are served from the existing mux instead.
	mu         sync.RWMutex
	challenges map[string]string

	// inFlight stops a manual "renew now" from racing the scheduled loop. Two
	// concurrent orders for the same domain burn Let's Encrypt's duplicate-
	// certificate rate limit, which is five per week and unforgiving.
	inFlight sync.Mutex
}

func newACMEManager(db *dbstore.DB, certs *certStore, keys *secret.Keyring) *acmeManager {
	return &acmeManager{db: db, certs: certs, keys: keys, challenges: map[string]string{}}
}

// Present is lego's http01.ChallengeProvider hook.
func (m *acmeManager) Present(domain, token, keyAuth string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.challenges[token] = keyAuth
	log.Printf("acme: serving an HTTP-01 challenge for %s", domain)
	return nil
}

func (m *acmeManager) CleanUp(domain, token, keyAuth string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.challenges, token)
	return nil
}

// handleChallenge answers /.well-known/acme-challenge/<token>.
//
// Mounted in the main mux because the port it needs is the one the portal
// already holds. It is unauthenticated by necessity — Let's Encrypt arrives
// anonymous — and safe: it returns only a token this process just generated, and
// an unknown token 404s.
func (m *acmeManager) handleChallenge(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, http01.ChallengePath(""))
	m.mu.RLock()
	keyAuth, ok := m.challenges[token]
	m.mu.RUnlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	if _, err := w.Write([]byte(keyAuth)); err != nil {
		log.Printf("acme: writing the challenge response failed: %v", err)
	}
}

// loadOrCreateAccountKey returns the ACME account key, generating and storing one
// on first use.
//
// Reusing the account across renewals is what keeps the portal inside Let's
// Encrypt's registration rate limits; generating a fresh account per issuance is
// a well-known way to get an installation blocked.
func (m *acmeManager) loadOrCreateAccountKey(domain string) (crypto.PrivateKey, string, error) {
	var row dbstore.Certificate
	err := m.db.Where("domain = ?", domain).First(&row).Error
	if err == nil && row.ACMEAccount != "" {
		pemKey, derr := m.keys.Decrypt(row.ACMEAccount)
		if derr != nil {
			return nil, "", fmt.Errorf("decrypting the ACME account key: %w", derr)
		}
		block, _ := pem.Decode([]byte(pemKey))
		if block != nil {
			if key, perr := x509.ParseECPrivateKey(block.Bytes); perr == nil {
				return key, row.ACMEAccountU, nil
			}
		}
		log.Printf("acme: the stored account key for %s is unreadable, registering a new account", domain)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	return key, "", nil
}

func (m *acmeManager) saveAccount(domain string, key crypto.PrivateKey, accountURL string) error {
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return errors.New("acme: unexpected account key type")
	}
	der, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		return err
	}
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
	enc, err := m.keys.Encrypt(pemKey)
	if err != nil {
		return err
	}
	return m.db.Where("domain = ?", domain).
		Assign(map[string]any{"acme_account": enc, "acme_account_u": accountURL}).
		FirstOrCreate(&dbstore.Certificate{Domain: domain, Source: CertSourceACME}).Error
}

// acmeRequest is one issuance job.
type acmeRequest struct {
	Domain string
	Email  string
	// Staging points at Let's Encrypt's staging directory, whose certificates
	// are untrusted but whose rate limits are generous. An operator debugging a
	// challenge failure should not burn five real orders a week doing it.
	Staging bool
}

// Issue obtains a certificate and stores it.
func (m *acmeManager) Issue(ctx context.Context, req acmeRequest) error {
	m.inFlight.Lock()
	defer m.inFlight.Unlock()

	if req.Domain == "" {
		return errors.New("no domain configured")
	}
	if req.Email == "" {
		// Let's Encrypt uses this to warn about expiry. Not strictly required,
		// but an installation whose renewal loop silently dies deserves the
		// email that tells them.
		return errors.New("an account email is required for ACME")
	}

	key, accountURL, err := m.loadOrCreateAccountKey(req.Domain)
	if err != nil {
		return err
	}
	user := &acmeUser{email: req.Email, key: key}

	cfg := lego.NewConfig(user)
	cfg.Certificate.KeyType = certcrypto.EC256
	if req.Staging {
		cfg.CADirURL = lego.LEDirectoryStaging
	}
	client, err := lego.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("acme client: %w", err)
	}
	if err := client.Challenge.SetHTTP01Provider(m); err != nil {
		return fmt.Errorf("acme challenge provider: %w", err)
	}

	if accountURL == "" {
		reg, rerr := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if rerr != nil {
			return fmt.Errorf("acme registration: %w", rerr)
		}
		user.registration = reg
		if serr := m.saveAccount(req.Domain, key, reg.URI); serr != nil {
			// Not fatal to this issuance, but it means the next one registers
			// again, which is how installations hit the registration limit.
			log.Printf("acme: could not persist the account, the next renewal will re-register: %v", serr)
		}
	} else {
		reg, rerr := client.Registration.ResolveAccountByKey()
		if rerr != nil {
			return fmt.Errorf("acme account resolve: %w", rerr)
		}
		user.registration = reg
	}

	res, err := client.Certificate.Obtain(certificate.ObtainRequest{
		Domains: []string{req.Domain},
		Bundle:  true, // Full chain: a leaf alone fails validation in many clients.
	})
	if err != nil {
		return fmt.Errorf("acme obtain: %w", err)
	}
	return m.certs.Save(req.Domain, CertSourceACME, string(res.Certificate), string(res.PrivateKey))
}

// needsRenewal reports whether a certificate should be renewed now.
func needsRenewal(row *dbstore.Certificate) bool {
	if row == nil || row.CertPEM == "" {
		return true
	}
	return time.Until(row.NotAfter) < renewBefore
}

// renewalLoop checks daily.
//
// Daily rather than hourly because the renewal window is thirty days wide; a
// missed check costs nothing and a tight loop against a failing challenge is how
// an installation gets rate-limited.
func (a *App) renewalLoop(ctx context.Context) {
	const interval = 12 * time.Hour
	// One check shortly after startup, so a portal that was down through its
	// renewal window catches up rather than waiting half a day.
	timer := time.NewTimer(time.Minute)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			a.renewIfNeeded(ctx)
			timer.Reset(interval)
		}
	}
}

// renewIfNeeded issues or renews when the configuration calls for it.
func (a *App) renewIfNeeded(ctx context.Context) {
	cfg := a.conf()
	if cfg.TLSMode != TLSModeStandalone || !cfg.ACMEEnabled {
		return
	}
	domain := cfg.TLSDomain
	if domain == "" {
		return
	}

	_, row, err := a.certs.Load(domain)
	if err != nil {
		log.Printf("acme: reading the stored certificate for %s failed: %v", domain, err)
	}
	// A manually uploaded certificate is the operator's to manage; renewing over
	// it would silently replace something they installed on purpose.
	if row != nil && row.Source == CertSourceManual {
		return
	}
	if !needsRenewal(row) {
		return
	}

	log.Printf("acme: obtaining a certificate for %s", domain)
	issueCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if err := a.acme.Issue(issueCtx, acmeRequest{
		Domain: domain, Email: cfg.ACMEEmail, Staging: cfg.ACMEStaging,
	}); err != nil {
		log.Printf("acme: issuance for %s failed: %v", domain, err)
		a.certs.RecordFailure(domain, err.Error())
		return
	}
	log.Printf("acme: certificate for %s obtained", domain)
	if pair, _, lerr := a.certs.Load(domain); lerr == nil && pair != nil {
		// Installed without rebuilding the listener, so a renewal does not drop
		// in-flight connections.
		a.certProvider.set(pair)
	}
}
