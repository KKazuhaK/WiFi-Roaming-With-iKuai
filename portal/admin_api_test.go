package main

// admin_api_test.go
// Routing and authorisation for the settings and TLS admin APIs.
//
// These exist because both endpoints dispatch on a path suffix they trim
// themselves, which is the kind of code that looks obviously correct and then
// answers 404 to its own index route — as /admin/api/settings did until a
// browser run found it. Every route the frontend calls is asserted here.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// adminRequest builds a request carrying a valid admin session cookie.
func adminRequest(t *testing.T, app *App, method, path, body string) *http.Request {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	if err := writeAdminCookie(rec, app.conf().SessionSecret,
		AdminSession{UPN: "ops@example.org", Exp: time.Now().Add(time.Hour).Unix()}, false); err != nil {
		t.Fatal(err)
	}
	for _, c := range rec.Result().Cookies() {
		r.AddCookie(c)
	}
	// Same-origin proof for the non-GET verbs; requireAdmin blocks them otherwise.
	r.Header.Set("Origin", "http://portal.example.com")
	r.Host = "portal.example.com"
	return r
}

// newAdminAPITestApp is a settings-backed App with the admin console enabled and
// a session secret, so requireAdmin lets a request through.
func newAdminAPITestApp(t *testing.T) *App {
	t.Helper()
	app := newSettingsTestApp(t)
	if err := app.settings.Save(secAdmin, map[string]string{"emails": "ops@example.org"}, "test"); err != nil {
		t.Fatal(err)
	}
	if err := app.settings.Save(secPortal, map[string]string{
		"public_url": "http://portal.example.com",
	}, "test"); err != nil {
		t.Fatal(err)
	}
	app.boot.SessionSecret = []byte("0123456789abcdef0123456789abcdef")
	// Reported problems (no identity provider in a fixture) are expected; the
	// state is installed regardless.
	_ = app.reloadRuntime(t.Context())
	app.listeners = newListenerManager(app, okMux())
	t.Cleanup(func() { app.listeners.apply(&Config{TLSMode: TLSModeProxy}) })
	return app
}

func TestAdminSettingsIndexRoute(t *testing.T) {
	app := newAdminAPITestApp(t)

	rec := httptest.NewRecorder()
	app.handleAdminSettings(rec, adminRequest(t, app, http.MethodGet, "/admin/api/settings", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("the section index answered %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Sections []struct {
			Section string           `json:"section"`
			Keys    []settingKeyInfo `json:"keys"`
		} `json:"sections"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Sections) < 10 {
		t.Fatalf("only %d sections listed", len(body.Sections))
	}
	seen := map[string]bool{}
	for _, s := range body.Sections {
		seen[s.Section] = true
		if len(s.Keys) == 0 {
			t.Fatalf("section %s listed with no keys", s.Section)
		}
	}
	for _, want := range []string{secOIDC, secBrand, secTLS, secLocalAdmin} {
		if !seen[want] {
			t.Fatalf("section %s missing from the index", want)
		}
	}
}

func TestAdminSettingsSectionRoutes(t *testing.T) {
	app := newAdminAPITestApp(t)

	// A trailing slash is what a link or a proxy rewrite can produce, and it must
	// reach the same section rather than the index.
	for _, path := range []string{"/admin/api/settings/brand", "/admin/api/settings/brand/"} {
		rec := httptest.NewRecorder()
		app.handleAdminSettings(rec, adminRequest(t, app, http.MethodGet, path, ""))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s answered %d", path, rec.Code)
		}
		var body settingsSectionResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body.Section != secBrand {
			t.Fatalf("GET %s returned section %q", path, body.Section)
		}
	}

	rec := httptest.NewRecorder()
	app.handleAdminSettings(rec, adminRequest(t, app, http.MethodGet, "/admin/api/settings/nope", ""))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("an unknown section answered %d", rec.Code)
	}
}

// A save must not become a way to write arbitrary rows into the settings table.
func TestAdminSettingsSaveRejectsUnknownKeys(t *testing.T) {
	app := newAdminAPITestApp(t)

	rec := httptest.NewRecorder()
	app.handleAdminSettings(rec, adminRequest(t, app, http.MethodPost, "/admin/api/settings/brand",
		`{"name":"Renamed","not_a_setting":"x"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("save answered %d: %s", rec.Code, rec.Body.String())
	}
	stored, err := app.settings.LoadSection(secBrand)
	if err != nil {
		t.Fatal(err)
	}
	if stored["name"] != "Renamed" {
		t.Fatalf("the known key was not saved: %q", stored["name"])
	}
	if _, ok := stored["not_a_setting"]; ok {
		t.Fatal("an unknown key was written to the settings table")
	}
	if app.conf().BrandName != "Renamed" {
		t.Fatalf("the runtime did not pick the change up: %q", app.conf().BrandName)
	}
}

func TestAdminTLSRoutes(t *testing.T) {
	app := newAdminAPITestApp(t)

	rec := httptest.NewRecorder()
	app.handleAdminTLS(rec, adminRequest(t, app, http.MethodGet, "/admin/api/tls", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/tls answered %d: %s", rec.Code, rec.Body.String())
	}
	var status tlsStatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.Mode != TLSModeProxy {
		t.Fatalf("mode: %q", status.Mode)
	}
	// The snippets are the whole reverse-proxy answer, so an empty one is a
	// broken page rather than a cosmetic miss.
	if !strings.Contains(status.Snippets["nginx"], "proxy_pass") ||
		!strings.Contains(status.Snippets["caddy"], "reverse_proxy") {
		t.Fatalf("snippets: %#v", status.Snippets)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("TLS status must not be cached")
	}

	// Confirm with nothing pending is a no-op, not an error page.
	rec = httptest.NewRecorder()
	app.handleAdminTLS(rec, adminRequest(t, app, http.MethodPost, "/admin/api/tls/confirm", "{}"))
	if rec.Code != http.StatusOK {
		t.Fatalf("confirm answered %d", rec.Code)
	}
	var confirm struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &confirm); err != nil {
		t.Fatal(err)
	}
	if confirm.OK || confirm.Error != "no_pending_change" {
		t.Fatalf("confirm: %+v", confirm)
	}

	// Issuance without a domain is refused before anything is asked of the CA.
	rec = httptest.NewRecorder()
	app.handleAdminTLS(rec, adminRequest(t, app, http.MethodPost, "/admin/api/tls/issue", "{}"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("issue without a domain answered %d: %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	app.handleAdminTLS(rec, adminRequest(t, app, http.MethodPost, "/admin/api/tls/nonsense", "{}"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("an unknown action answered %d", rec.Code)
	}
}

// The upload path end to end: a valid pair is stored, installed, and then served
// by the provider the listener reads from.
func TestAdminTLSUpload(t *testing.T) {
	app := newAdminAPITestApp(t)
	if err := app.settings.Save(secTLS, map[string]string{"domain": "portal.example.com"}, "test"); err != nil {
		t.Fatal(err)
	}
	_ = app.reloadRuntime(t.Context())

	certPEM, keyPEM := mkTestCert(t, "portal.example.com",
		time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour))
	body, err := json.Marshal(map[string]string{"certPem": certPEM, "keyPem": keyPEM})
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	app.handleAdminTLS(rec, adminRequest(t, app, http.MethodPost, "/admin/api/tls/upload", string(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("upload answered %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		OK          bool              `json:"ok"`
		Warning     string            `json:"warning"`
		Certificate certificateStatus `json:"certificate"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.OK || !resp.Certificate.Present {
		t.Fatalf("upload response: %+v", resp)
	}
	if resp.Warning != "" {
		t.Fatalf("a matching certificate should not warn: %s", resp.Warning)
	}
	if _, err := app.certProvider.get(nil); err != nil {
		t.Fatalf("the uploaded certificate was not installed: %v", err)
	}

	// A certificate for another name is stored with a warning rather than
	// refused: an operator may be staging one ahead of a rename.
	otherCert, otherKey := mkTestCert(t, "other.example.com",
		time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour))
	body, err = json.Marshal(map[string]string{"certPem": otherCert, "keyPem": otherKey})
	if err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	app.handleAdminTLS(rec, adminRequest(t, app, http.MethodPost, "/admin/api/tls/upload", string(body)))
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.OK || !strings.Contains(resp.Warning, "portal.example.com") {
		t.Fatalf("expected a hostname warning, got %+v", resp)
	}

	// A mismatched pair is refused outright — it would break every handshake.
	body, err = json.Marshal(map[string]string{"certPem": certPEM, "keyPem": otherKey})
	if err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	app.handleAdminTLS(rec, adminRequest(t, app, http.MethodPost, "/admin/api/tls/upload", string(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a mismatched pair answered %d", rec.Code)
	}
}

// Both APIs are behind the admin session, and both answer JSON rather than a
// redirect the frontend's fetch would follow and then fail to parse.
func TestAdminAPIsRequireASession(t *testing.T) {
	app := newAdminAPITestApp(t)
	for _, path := range []string{"/admin/api/settings", "/admin/api/settings/brand", "/admin/api/tls"} {
		rec := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, path, nil)
		switch {
		case strings.HasPrefix(path, "/admin/api/tls"):
			app.handleAdminTLS(rec, r)
		default:
			app.handleAdminSettings(rec, r)
		}
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s without a session answered %d", path, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "json") {
			t.Fatalf("%s answered %s, which fetch cannot parse", path, ct)
		}
	}
}
