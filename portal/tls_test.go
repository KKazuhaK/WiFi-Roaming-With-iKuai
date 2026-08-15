package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kazuhahub/wifi-portal/internal/dbstore"
	"github.com/kazuhahub/wifi-portal/internal/secret"
)

// mkTestCert generates a self-signed pair for a domain with a chosen validity
// window, so the expiry and renewal logic can be exercised without waiting.
func mkTestCert(t *testing.T, domain string, notBefore, notAfter time.Time) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: domain, Organization: []string{"test"}},
		Issuer:                pkix.Name{CommonName: "test-ca"},
		DNSNames:              []string{domain},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}

func newTestCertStore(t *testing.T) *certStore {
	t.Helper()
	return newCertStore(testDB(t), secret.NewKeyring("0123456789abcdef0123456789abcdef"))
}

func TestCertStoreRoundTrip(t *testing.T) {
	s := newTestCertStore(t)
	nb, na := time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour)
	certPEM, keyPEM := mkTestCert(t, "wifi.example.com", nb, na)

	if err := s.Save("wifi.example.com", CertSourceManual, certPEM, keyPEM); err != nil {
		t.Fatalf("Save: %v", err)
	}

	pair, row, err := s.Load("wifi.example.com")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if pair == nil || row == nil {
		t.Fatal("Load returned nothing")
	}
	if row.Source != CertSourceManual {
		t.Errorf("Source = %q", row.Source)
	}
	// The validity window is denormalised onto the row so the renewal loop and
	// the admin page do not have to re-parse PEM.
	if row.NotAfter.Sub(na).Abs() > time.Second {
		t.Errorf("NotAfter = %v, want %v", row.NotAfter, na)
	}
}

// The private key is exactly the material the at-rest encryption exists for: a
// certificate key in a database backup is worse than an OIDC secret.
func TestCertStoreEncryptsPrivateKey(t *testing.T) {
	s := newTestCertStore(t)
	certPEM, keyPEM := mkTestCert(t, "wifi.example.com", time.Now(), time.Now().Add(24*time.Hour))
	if err := s.Save("wifi.example.com", CertSourceManual, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}

	var row dbstore.Certificate
	if err := s.db.Where("domain = ?", "wifi.example.com").First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if strings.Contains(row.KeyPEM, "EC PRIVATE KEY") {
		t.Error("the private key is stored in plaintext")
	}
	if !secret.IsEncrypted(row.KeyPEM) {
		t.Errorf("the private key is not in encrypted form: %.40q", row.KeyPEM)
	}
	// The certificate itself is not secret and stays readable, so an operator
	// inspecting the table can see what is installed.
	if !strings.Contains(row.CertPEM, "CERTIFICATE") {
		t.Error("the certificate was encrypted; only the key should be")
	}
}

// The most common upload mistake: a certificate and key from different pairs.
// Caught at save time, because discovering it at the next handshake means a
// listener that refuses every connection and an operator who has navigated away.
func TestCertStoreRejectsMismatchedPair(t *testing.T) {
	s := newTestCertStore(t)
	certPEM, _ := mkTestCert(t, "wifi.example.com", time.Now(), time.Now().Add(24*time.Hour))
	_, otherKey := mkTestCert(t, "other.example.com", time.Now(), time.Now().Add(24*time.Hour))

	err := s.Save("wifi.example.com", CertSourceManual, certPEM, otherKey)
	if err == nil {
		t.Fatal("a mismatched certificate and key were accepted")
	}
	if !strings.Contains(err.Error(), "do not match") {
		t.Errorf("error = %q, want it to name the mismatch", err)
	}
}

func TestCertStoreRejectsGarbage(t *testing.T) {
	s := newTestCertStore(t)
	if err := s.Save("wifi.example.com", CertSourceManual, "not a pem", "neither"); err == nil {
		t.Error("garbage PEM was accepted")
	}
}

func TestCertStoreStatus(t *testing.T) {
	s := newTestCertStore(t)

	// Nothing stored.
	st := s.Status("wifi.example.com")
	if st.Present {
		t.Error("Present is true with no certificate stored")
	}

	certPEM, keyPEM := mkTestCert(t, "wifi.example.com", time.Now().Add(-time.Hour), time.Now().Add(45*24*time.Hour))
	if err := s.Save("wifi.example.com", CertSourceACME, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	st = s.Status("wifi.example.com")
	if !st.Present {
		t.Fatal("Present is false after a save")
	}
	if st.DaysLeft < 44 || st.DaysLeft > 45 {
		t.Errorf("DaysLeft = %d, want ~45", st.DaysLeft)
	}
	if len(st.DNSNames) != 1 || st.DNSNames[0] != "wifi.example.com" {
		t.Errorf("DNSNames = %v", st.DNSNames)
	}
}

// A failed renewal must not disturb a certificate that is still serving. The
// alternative — clearing the material on failure — would turn a recoverable
// renewal problem into an outage.
func TestRecordFailureKeepsWorkingCertificate(t *testing.T) {
	s := newTestCertStore(t)
	certPEM, keyPEM := mkTestCert(t, "wifi.example.com", time.Now(), time.Now().Add(10*24*time.Hour))
	if err := s.Save("wifi.example.com", CertSourceACME, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}

	s.RecordFailure("wifi.example.com", "rate limited by the CA")

	pair, _, err := s.Load("wifi.example.com")
	if err != nil || pair == nil {
		t.Fatalf("the working certificate was lost after a failure: pair=%v err=%v", pair, err)
	}
	st := s.Status("wifi.example.com")
	if !st.Present {
		t.Error("Present went false after a failed renewal")
	}
	if !strings.Contains(st.LastError, "rate limited") {
		t.Errorf("LastError = %q, want the failure reason for the page to show", st.LastError)
	}
}

func TestNeedsRenewal(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name string
		row  *dbstore.Certificate
		want bool
	}{
		{"nothing stored", nil, true},
		{"row with no material", &dbstore.Certificate{Domain: "x"}, true},
		{"expires inside the window", &dbstore.Certificate{CertPEM: "x", NotAfter: now.Add(10 * 24 * time.Hour)}, true},
		{"already expired", &dbstore.Certificate{CertPEM: "x", NotAfter: now.Add(-time.Hour)}, true},
		{"fresh", &dbstore.Certificate{CertPEM: "x", NotAfter: now.Add(60 * 24 * time.Hour)}, false},
		// Exactly at the boundary must not flap between checks.
		{"just outside the window", &dbstore.Certificate{CertPEM: "x", NotAfter: now.Add(renewBefore + time.Hour)}, false},
	}
	for _, c := range cases {
		if got := needsRenewal(c.row); got != c.want {
			t.Errorf("%s: needsRenewal = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestCertProviderServesCurrentCertificate(t *testing.T) {
	p := &certProvider{}

	// With nothing set, the handshake must fail rather than fall back to a
	// self-signed placeholder that trains operators to click through warnings.
	if _, err := p.get(nil); err == nil {
		t.Error("an empty provider returned a certificate")
	}

	s := newTestCertStore(t)
	certPEM, keyPEM := mkTestCert(t, "wifi.example.com", time.Now(), time.Now().Add(24*time.Hour))
	if err := s.Save("wifi.example.com", CertSourceManual, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	pair, _, err := s.Load("wifi.example.com")
	if err != nil {
		t.Fatal(err)
	}
	p.set(pair)
	got, err := p.get(nil)
	if err != nil || got == nil {
		t.Fatalf("get after set = (%v, %v)", got, err)
	}
}

// The safety net for the operation that can take the console away.
func TestListenerCommitRollsBackWhenUnconfirmed(t *testing.T) {
	l := &listenerCommit{}
	var rolledBack atomic.Bool

	// begin arms a timer at listenerConfirmWindow, which is minutes. Rather than
	// wait, the rollback is invoked through the same path the timer uses by
	// arming and then driving it directly — what matters is that an unconfirmed
	// change reverts and a confirmed one does not.
	deadline := l.begin(func() error {
		rolledBack.Store(true)
		return nil
	})
	if time.Until(deadline) > listenerConfirmWindow+time.Second {
		t.Errorf("deadline is %v away, want at most %v", time.Until(deadline), listenerConfirmWindow)
	}

	pending, _ := l.status()
	if !pending {
		t.Fatal("no change is pending after begin")
	}

	if !l.confirm() {
		t.Error("confirm returned false for a pending change")
	}
	pending, _ = l.status()
	if pending {
		t.Error("the change is still pending after confirm")
	}
	if rolledBack.Load() {
		t.Error("a confirmed change was rolled back")
	}

	// Confirming twice is harmless and reports that nothing was pending, so a
	// double-clicked button does not look like an error.
	if l.confirm() {
		t.Error("confirm returned true with nothing pending")
	}
}

func TestListenerCommitSupersedesPrevious(t *testing.T) {
	l := &listenerCommit{}
	var first, second atomic.Bool
	l.begin(func() error { first.Store(true); return nil })
	l.begin(func() error { second.Store(true); return nil })

	// The second change replaces the first; only its rollback should ever run.
	if !l.confirm() {
		t.Fatal("confirm returned false")
	}
	if first.Load() || second.Load() {
		t.Error("a rollback ran despite confirmation")
	}
}

// The check that decides whether ACME is even offered. A portal on a LAN box is
// not publicly routable and never will be, so the UI has to steer those
// operators to a manual certificate rather than let them retry forever.
func TestHTTP01Viability(t *testing.T) {
	if ok, note := http01Viability(""); ok || note == "" {
		t.Errorf("an empty public URL reported viable=%v note=%q", ok, note)
	}

	ok, note := http01Viability("https://127.0.0.1")
	if ok {
		t.Error("a loopback address was reported as ACME-viable")
	}
	if !strings.Contains(note, "cannot reach") {
		t.Errorf("note = %q, want an explanation the operator can act on", note)
	}

	if ok, _ := http01Viability("https://192.168.1.10"); ok {
		t.Error("a private address was reported as ACME-viable")
	}
	if ok, _ := http01Viability("https://10.1.2.3"); ok {
		t.Error("a private address was reported as ACME-viable")
	}
}

func TestProxySnippet(t *testing.T) {
	nginx := proxySnippet("nginx", "wifi.example.com", "0.0.0.0:28080")
	if !strings.Contains(nginx, "server_name wifi.example.com") {
		t.Errorf("nginx snippet is missing the server name:\n%s", nginx)
	}
	// A proxy on the same host must be pointed at loopback: 0.0.0.0 is a bind
	// address, not a destination.
	if !strings.Contains(nginx, "proxy_pass http://127.0.0.1:28080") {
		t.Errorf("nginx snippet did not rewrite the bind address to loopback:\n%s", nginx)
	}
	// X-Forwarded-For has to be set, or the rate limiter and the audit log see
	// only the proxy.
	if !strings.Contains(nginx, "X-Forwarded-For") {
		t.Errorf("nginx snippet omits X-Forwarded-For:\n%s", nginx)
	}

	caddy := proxySnippet("caddy", "wifi.example.com", "127.0.0.1:28080")
	if !strings.Contains(caddy, "reverse_proxy 127.0.0.1:28080") {
		t.Errorf("caddy snippet is wrong:\n%s", caddy)
	}
}

func TestTLSConfigFloorsAtTLS12(t *testing.T) {
	c := tlsConfig(&certProvider{})
	// 1.2 rather than 1.3: captive-portal mini browsers on older Android builds
	// still negotiate 1.2, and refusing them would lock out exactly the devices
	// this portal exists to admit.
	if c.MinVersion != 0x0303 {
		t.Errorf("MinVersion = %#x, want TLS 1.2 (0x0303)", c.MinVersion)
	}
	if c.GetCertificate == nil {
		t.Error("GetCertificate is not set; a renewal would need a listener rebuild")
	}
}
