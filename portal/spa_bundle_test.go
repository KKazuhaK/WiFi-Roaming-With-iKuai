package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// These exercise the real embedded bundle rather than a fixture, which is what
// makes them worth having: they catch the seam where the Vite output and the Go
// handler have to agree — the head marker, the asset URLs the documents point
// at, the pre-compressed siblings. A unit test with a hand-written document
// cannot see any of that go wrong.
//
// On a checkout where the frontend has not been built, portal/internal/web/dist
// holds only .gitkeep and these skip. That is the same condition under which
// `go build` still works by design, so failing here would punish exactly the
// contributor the placeholder exists to help.
func requireBuiltBundle(t *testing.T) *spaBundle {
	t.Helper()
	b := loadSPA()
	if !b.built {
		t.Skip("frontend bundle not built; run `cd portal/web-react && npm ci && npm run build`")
	}
	return b
}

// mkBundleServer wraps the real SPA routes in the production middleware so the
// assertions see the headers a browser would.
func mkBundleServer(t *testing.T) (*httptest.Server, *App) {
	t.Helper()
	loadTranslations()
	app := newTestApp(Config{
		BrandName:  "Kazuha Hub",
		BrandColor: "#2563eb",
		PublicURL:  "https://wifi.test",
	})
	mux := http.NewServeMux()
	mux.HandleFunc("/assets/", app.handleAssets)
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		data := app.baseSPAData("login", pickLang(r))
		data.GuestEnabled = true
		data.AllowedDomainsHint = "example.com"
		app.renderSPA(w, r, "portal.html", data, http.StatusOK)
	})
	srv := httptest.NewServer(securityHeaders(mux))
	t.Cleanup(srv.Close)
	return srv, app
}

var assetRefRe = regexp.MustCompile(`(?:src|href)="(/assets/[^"]+)"`)

// TestBundleDocumentReferencesResolve is the integration check that matters: a
// build that renames or drops a chunk leaves the document pointing at a URL the
// handler will 404, and nothing else in the test suite would notice until a
// browser hit a blank page.
func TestBundleDocumentReferencesResolve(t *testing.T) {
	requireBuiltBundle(t)
	srv, _ := mkBundleServer(t)

	resp, err := http.Get(srv.URL + "/login")
	if err != nil {
		t.Fatalf("GET /login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /login: status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	body := string(raw)

	if strings.Contains(body, headMarker) || strings.Contains(body, langPlaceholder) {
		t.Errorf("placeholders survived into the served document")
	}
	if !strings.Contains(body, `id="`+cfgElementID+`"`) {
		t.Errorf("config block missing from the served document")
	}
	// The pre-mount skeleton is what a captive-portal user looks at while the
	// bundle downloads. Losing it is silent and only visible on a slow link.
	if !strings.Contains(body, `id="boot"`) {
		t.Errorf("first-paint skeleton missing from portal.html")
	}

	refs := assetRefRe.FindAllStringSubmatch(body, -1)
	if len(refs) == 0 {
		t.Fatal("document references no /assets/ URLs at all")
	}
	seen := map[string]bool{}
	for _, m := range refs {
		url := m[1]
		if seen[url] {
			continue
		}
		seen[url] = true

		ar, err := http.Get(srv.URL + url)
		if err != nil {
			t.Errorf("GET %s: %v", url, err)
			continue
		}
		ar.Body.Close()
		if ar.StatusCode != http.StatusOK {
			t.Errorf("GET %s: status %d, want 200 — the document points at an asset the handler does not serve", url, ar.StatusCode)
			continue
		}
		if cc := ar.Header.Get("Cache-Control"); cc != "public, max-age=31536000, immutable" {
			t.Errorf("GET %s: Cache-Control = %q, want immutable", url, cc)
		}
		if ar.Header.Get("ETag") == "" {
			t.Errorf("GET %s: no ETag", url)
		}
	}
	t.Logf("verified %d distinct asset references", len(seen))
}

// TestBundleAssetsArePreCompressed guards the build-time compression: if the
// Vite plugin stops running, every client silently drops to identity bytes and
// the only symptom is a slower captive portal.
func TestBundleAssetsArePreCompressed(t *testing.T) {
	requireBuiltBundle(t)
	srv, _ := mkBundleServer(t)

	resp, err := http.Get(srv.URL + "/login")
	if err != nil {
		t.Fatalf("GET /login: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	checked := 0
	for _, m := range assetRefRe.FindAllStringSubmatch(string(raw), -1) {
		url := m[1]
		if !strings.HasSuffix(url, ".js") && !strings.HasSuffix(url, ".css") {
			continue
		}
		req, _ := http.NewRequest(http.MethodGet, srv.URL+url, nil)
		req.Header.Set("Accept-Encoding", "gzip, deflate, br")
		// The default client transparently adds gzip and strips the header, so
		// the request has to go through a transport that leaves it alone.
		ar, err := (&http.Transport{DisableCompression: true}).RoundTrip(req)
		if err != nil {
			t.Errorf("GET %s: %v", url, err)
			continue
		}
		body, _ := io.ReadAll(ar.Body)
		ar.Body.Close()

		// Under ~1KB the compression plugin skips the file by design.
		asset := loadSPA().assets[strings.TrimPrefix(url, "/")]
		if asset == nil || len(asset.body) < 1024 {
			continue
		}
		checked++
		if enc := ar.Header.Get("Content-Encoding"); enc != "br" {
			t.Errorf("GET %s: Content-Encoding = %q, want br", url, enc)
		}
		if len(body) >= len(asset.body) {
			t.Errorf("GET %s: encoded body (%d B) is not smaller than identity (%d B)", url, len(body), len(asset.body))
		}
	}
	if checked == 0 {
		t.Error("no compressible assets were checked; the reference scan or the build layout changed")
	}
}

// TestSecurityHeadersOnBundledPages pins the CSP tightening that moving off
// html/template bought. The bundle has no inline scripts, so a future edit that
// re-adds 'unsafe-inline' to script-src should have to justify itself against a
// failing test.
func TestSecurityHeadersOnBundledPages(t *testing.T) {
	requireBuiltBundle(t)
	srv, _ := mkBundleServer(t)

	resp, err := http.Get(srv.URL + "/login")
	if err != nil {
		t.Fatalf("GET /login: %v", err)
	}
	defer resp.Body.Close()

	csp := resp.Header.Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("no Content-Security-Policy header")
	}
	if strings.Contains(csp, "script-src 'self' 'unsafe-inline'") {
		t.Errorf("script-src still allows 'unsafe-inline':\n%s", csp)
	}
	for _, want := range []string{
		"script-src 'self'",
		"frame-ancestors 'none'",
		"base-uri 'none'",
		"object-src 'none'",
		"form-action 'self'",
	} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP missing %q:\n%s", want, csp)
		}
	}

	// The served document must not contain an executable inline script — that is
	// the property the tightened script-src depends on. The config block is
	// type="application/json", which browsers treat as data.
	raw, _ := io.ReadAll(resp.Body)
	for _, chunk := range strings.Split(string(raw), "<script")[1:] {
		attrs, _, _ := strings.Cut(chunk, ">")
		if strings.Contains(attrs, `type="application/json"`) {
			continue
		}
		if strings.Contains(attrs, "src=") {
			continue // External module script, allowed by script-src 'self'.
		}
		t.Errorf("document contains an inline executable script: <script%s>", attrs)
	}
}
