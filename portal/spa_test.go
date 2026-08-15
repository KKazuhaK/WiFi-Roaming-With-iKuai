package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mkSPAApp builds an App with a hand-made bundle so these tests do not depend on
// a Node toolchain having run. loadSPA caches behind a sync.Once, so the index is
// injected directly rather than through it.
func mkSPAApp(t *testing.T, assets map[string]*spaAsset) *App {
	t.Helper()
	loadTranslations()
	spaLoaded = &spaBundle{assets: assets, built: true}
	spaOnce.Do(func() {}) // Burn the Once so a later loadSPA cannot overwrite the fixture.
	t.Cleanup(func() { spaLoaded = &spaBundle{assets: map[string]*spaAsset{}} })
	return newTestApp(Config{
		BrandName:  "Kazuha Hub",
		BrandColor: "#2563eb",
		PublicURL:  "https://wifi.test",
	})
}

func testDoc(body string) *spaAsset {
	return &spaAsset{
		body:        []byte(body),
		contentType: "text/html; charset=utf-8",
		etag:        `"doc"`,
	}
}

const minimalDoc = `<!DOCTYPE html><html lang="__PORTAL_LANG__"><head><!--PORTAL_HEAD--></head><body></body></html>`

func TestRenderSPAInjectsConfigAndLang(t *testing.T) {
	app := mkSPAApp(t, map[string]*spaAsset{"portal.html": testDoc(minimalDoc)})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	data := app.baseSPAData("login", LangZHCN)
	data.GuestEnabled = true
	data.AllowedDomainsHint = "example.com"
	app.renderSPA(rec, req, "portal.html", data, http.StatusOK)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()

	if strings.Contains(body, langPlaceholder) {
		t.Errorf("__PORTAL_LANG__ placeholder survived into the response")
	}
	if !strings.Contains(body, `<html lang="zh-cn">`) {
		t.Errorf("lang attribute not set to zh-cn:\n%s", body)
	}
	if strings.Contains(body, headMarker) {
		t.Errorf("head marker survived into the response")
	}

	// The config has to be parseable by lib/config.ts, which locates it by id.
	const open = `<script type="application/json" id="` + cfgElementID + `">`
	i := strings.Index(body, open)
	if i < 0 {
		t.Fatalf("config script block missing:\n%s", body)
	}
	rest := body[i+len(open):]
	j := strings.Index(rest, "</script>")
	if j < 0 {
		t.Fatalf("config script block unterminated")
	}
	var got spaPageData
	if err := json.Unmarshal([]byte(rest[:j]), &got); err != nil {
		t.Fatalf("config block is not valid JSON: %v\n%s", err, rest[:j])
	}
	if got.Page != "login" || got.Lang != LangZHCN || !got.GuestEnabled {
		t.Errorf("config = %+v, want page=login lang=zh-cn guestEnabled=true", got)
	}
	if got.Brand.Name != "Kazuha Hub" || got.Brand.Color != "#2563eb" {
		t.Errorf("brand = %+v, want it taken from cfg", got.Brand)
	}

	// The documents carry the signed-in admin's UPN and, on the error page, why a
	// sign-in failed. Neither belongs in a disk cache on a shared device.
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
}

// A hostile Message must not be able to close the JSON data block and start a
// real script. encoding/json escapes < > and & by default; this pins that the
// injection path never opts out of it.
func TestRenderSPAEscapesConfigPayload(t *testing.T) {
	app := mkSPAApp(t, map[string]*spaAsset{"portal.html": testDoc(minimalDoc)})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	data := app.baseSPAData("error", LangEN)
	data.Message = `</script><script>alert(1)</script><!--`
	app.renderSPA(rec, req, "portal.html", data, http.StatusBadRequest)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want the caller's 400 to be preserved", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Fatalf("payload escaped its data block:\n%s", body)
	}
	// Exactly one script element: the JSON block itself.
	if n := strings.Count(body, "<script"); n != 1 {
		t.Fatalf("found %d <script occurrences, want 1:\n%s", n, body)
	}
	// And it must still round-trip — escaping that corrupted the JSON would take
	// the whole page down instead of just neutering the payload.
	start := strings.Index(body, `id="`+cfgElementID+`">`)
	if start < 0 {
		t.Fatal("config block missing")
	}
	start += len(`id="` + cfgElementID + `">`)
	end := strings.Index(body[start:], "</script>")
	var got spaPageData
	if err := json.Unmarshal([]byte(body[start:start+end]), &got); err != nil {
		t.Fatalf("escaped config is not valid JSON: %v", err)
	}
	if got.Message != data.Message {
		t.Errorf("Message round-trip = %q, want %q", got.Message, data.Message)
	}
}

func TestRenderSPAMissingBundle(t *testing.T) {
	app := mkSPAApp(t, map[string]*spaAsset{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	app.renderSPA(rec, req, "portal.html", app.baseSPAData("login", LangEN), http.StatusOK)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	// The message has to name the fix: this is the failure a first-time
	// contributor hits after `go build` without running the frontend build.
	if !strings.Contains(rec.Body.String(), "npm run build") {
		t.Errorf("unhelpful error body: %q", rec.Body.String())
	}
}

func TestAcceptsEncoding(t *testing.T) {
	cases := []struct {
		header string
		enc    string
		want   bool
	}{
		{"gzip, deflate, br", "br", true},
		{"gzip, deflate, br", "gzip", true},
		{"gzip, deflate", "br", false},
		{"", "br", false},
		{"br;q=1.0, gzip;q=0.8", "br", true},
		// An explicit refusal must not read as support.
		{"br;q=0, gzip", "br", false},
		{"br;q=0, gzip", "gzip", true},
		{"*", "br", true},
		{"identity", "gzip", false},
		{"  br  ", "br", true},
		// A malformed q-value is treated as acceptance rather than dropping to
		// identity for everyone behind a broken proxy.
		{"br;q=abc", "br", true},
	}
	for _, c := range cases {
		if got := acceptsEncoding(c.header, c.enc); got != c.want {
			t.Errorf("acceptsEncoding(%q, %q) = %v, want %v", c.header, c.enc, got, c.want)
		}
	}
}

func mkAsset(body, br, gz string) *spaAsset {
	a := &spaAsset{
		body:        []byte(body),
		contentType: "application/javascript",
		etag:        `"abc123"`,
	}
	if br != "" {
		a.brotli = []byte(br)
	}
	if gz != "" {
		a.gzip = []byte(gz)
	}
	return a
}

func TestHandleAssetsEncodingNegotiation(t *testing.T) {
	// Bodies differ in length so the assertion can tell which variant was sent.
	asset := mkAsset("IDENTITY-BODY-LONG", "BR", "GZIPX")
	app := mkSPAApp(t, map[string]*spaAsset{"assets/app.abcd1234.js": asset})

	cases := []struct {
		name         string
		accept       string
		wantEncoding string
		wantBody     string
	}{
		{"prefers brotli", "gzip, deflate, br", "br", "BR"},
		{"falls back to gzip", "gzip, deflate", "gzip", "GZIPX"},
		{"identity when nothing offered", "", "", "IDENTITY-BODY-LONG"},
		{"identity when br refused and gzip absent", "br;q=0", "", "IDENTITY-BODY-LONG"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/assets/app.abcd1234.js", nil)
			if c.accept != "" {
				req.Header.Set("Accept-Encoding", c.accept)
			}
			app.handleAssets(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			if got := rec.Header().Get("Content-Encoding"); got != c.wantEncoding {
				t.Errorf("Content-Encoding = %q, want %q", got, c.wantEncoding)
			}
			if got := rec.Body.String(); got != c.wantBody {
				t.Errorf("body = %q, want %q", got, c.wantBody)
			}
			// Without Vary a shared cache could hand a brotli body to a client
			// that only asked for gzip.
			if got := rec.Header().Get("Vary"); got != "Accept-Encoding" {
				t.Errorf("Vary = %q, want Accept-Encoding", got)
			}
			if got := rec.Header().Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
				t.Errorf("Cache-Control = %q, want a year of immutable caching", got)
			}
		})
	}
}

func TestHandleAssetsConditionalRequest(t *testing.T) {
	asset := mkAsset("BODY", "BR", "")
	app := mkSPAApp(t, map[string]*spaAsset{"assets/app.abcd1234.js": asset})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/assets/app.abcd1234.js", nil)
	req.Header.Set("If-None-Match", `"abc123"`)
	req.Header.Set("Accept-Encoding", "br")
	app.handleAssets(rec, req)

	if rec.Code != http.StatusNotModified {
		t.Fatalf("status = %d, want 304", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("304 carried a body of %d bytes", rec.Body.Len())
	}

	// A weak validator and a wildcard both have to match: Go's own reverse proxy
	// rewrites strong ETags to weak ones when it re-encodes.
	for _, inm := range []string{`W/"abc123"`, `*`, `"other", "abc123"`} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/assets/app.abcd1234.js", nil)
		req.Header.Set("If-None-Match", inm)
		app.handleAssets(rec, req)
		if rec.Code != http.StatusNotModified {
			t.Errorf("If-None-Match %q: status = %d, want 304", inm, rec.Code)
		}
	}

	// A non-matching validator must serve the body.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/assets/app.abcd1234.js", nil)
	req.Header.Set("If-None-Match", `"stale"`)
	app.handleAssets(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("stale validator: status = %d, want 200", rec.Code)
	}
}

func TestHandleAssetsRejectsNonAssetPaths(t *testing.T) {
	app := mkSPAApp(t, map[string]*spaAsset{
		"assets/app.abcd1234.js": mkAsset("BODY", "", ""),
		"portal.html":            testDoc(minimalDoc),
	})

	// /assets/ must not become a second route to the documents — those carry the
	// per-session config block and are served with no-store, not a year of
	// immutable caching.
	for _, p := range []string{
		"/assets/../portal.html",
		"/assets/missing.js",
		"/assets/",
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, p, nil)
		app.handleAssets(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s: status = %d, want 404", p, rec.Code)
		}
	}
}

func TestHandleAssetsMethodNotAllowed(t *testing.T) {
	app := mkSPAApp(t, map[string]*spaAsset{"assets/app.abcd1234.js": mkAsset("BODY", "", "")})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/assets/app.abcd1234.js", nil)
	app.handleAssets(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rec.Code)
	}
	if got := rec.Header().Get("Allow"); got != "GET, HEAD" {
		t.Errorf("Allow = %q, want %q", got, "GET, HEAD")
	}
}

func TestHandleAssetsHeadSendsNoBody(t *testing.T) {
	app := mkSPAApp(t, map[string]*spaAsset{"assets/app.abcd1234.js": mkAsset("BODY-LONGER", "BR", "")})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodHead, "/assets/app.abcd1234.js", nil)
	req.Header.Set("Accept-Encoding", "br")
	app.handleAssets(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("HEAD returned %d bytes of body", rec.Body.Len())
	}
	// Content-Length must still describe the encoded body a GET would return.
	if got := rec.Header().Get("Content-Length"); got != "2" {
		t.Errorf("Content-Length = %q, want 2 (the brotli variant)", got)
	}
}

// The favicon is generated rather than a file on disk, so the escaping is worth
// asserting: the brand name reaches an SVG that reaches a data URI in an
// attribute, which is three nested contexts.
func TestFaviconLink(t *testing.T) {
	generated := faviconLink(&Config{BrandName: "Kazuha Hub", BrandColor: "#2563eb"})
	if !strings.HasPrefix(generated, `<link rel="icon" href="data:image/svg+xml,`) {
		t.Fatalf("generated mark: %s", generated)
	}
	// Percent-encoded, so no raw angle bracket or quote can escape the attribute.
	uri := strings.TrimSuffix(strings.TrimPrefix(generated, `<link rel="icon" href="`), `">`)
	if strings.ContainsAny(uri, `<>"`) {
		t.Fatalf("unescaped characters in the data URI: %s", uri)
	}
	if !strings.Contains(generated, "%232563eb") {
		t.Fatalf("brand colour missing from the mark: %s", generated)
	}

	// A configured logo wins: an operator who uploaded one expects to see it.
	withLogo := faviconLink(&Config{BrandLogoURL: "/static/logo.png", BrandName: "Kazuha Hub"})
	if withLogo != `<link rel="icon" href="/static/logo.png">` {
		t.Fatalf("logo link: %s", withLogo)
	}

	// A hostile brand name cannot break out of the attribute.
	hostile := faviconLink(&Config{BrandName: `"><script>alert(1)</script>`, BrandColor: "#000"})
	if strings.Contains(hostile, "<script") || strings.Contains(hostile, `"><`) {
		t.Fatalf("escaping failed: %s", hostile)
	}
}

func TestRenderSPAIncludesFavicon(t *testing.T) {
	app := mkSPAApp(t, map[string]*spaAsset{"portal.html": testDoc(minimalDoc)})
	rec := httptest.NewRecorder()
	app.renderSPA(rec, httptest.NewRequest(http.MethodGet, "/login", nil),
		"portal.html", app.baseSPAData("login", LangEN), http.StatusOK)
	if !strings.Contains(rec.Body.String(), `rel="icon"`) {
		t.Fatalf("no favicon link in the served document:\n%s", rec.Body.String())
	}
}
