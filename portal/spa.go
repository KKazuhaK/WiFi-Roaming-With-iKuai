package main

// spa.go
// Serves the embedded React bundle (portal/internal/web/dist, built by
// portal/web-react) and injects the per-deployment configuration the templates
// used to interpolate.
//
// Design notes:
//
//   - Assets are loaded into memory once at startup, not read per request.
//     go:embed reads are already memory-backed, but Content-Type lookup, the
//     encoding pick and the ETag would otherwise be recomputed on every hit.
//   - Compression happens at build time. Vite emits a .br and .gz sibling for
//     every compressible asset, so this only has to choose between variants that
//     already exist — no compress/gzip writer in the request path, and the
//     brotli quality is 11, which nothing would attempt on the fly. It also means
//     the binary contains no brotli encoder: Go's standard library has none, and
//     pulling one in for a handful of static files was not worth a dependency in
//     a project that has two.
//   - Hashed assets get a year of immutable caching, HTML documents get
//     no-store. The documents carry a per-session config block (admin UPN, error
//     text) and their asset URLs change on every build, so caching them buys
//     nothing and risks serving a stale bundle reference.

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io/fs"
	"log"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kazuhahub/wifi-portal/internal/web"
)

// headMarker is replaced in the served HTML by the <title>, the brand colour
// custom property and the JSON configuration block. web-react/*.html carry it
// verbatim and web-react/scripts/smoke-dist.mjs fails the build if it is lost.
const headMarker = "<!--PORTAL_HEAD-->"

// langPlaceholder sits in <html lang="..."> in the built documents.
const langPlaceholder = "__PORTAL_LANG__"

// cfgElementID must match the id lib/config.ts looks for.
const cfgElementID = "__portal_cfg__"

// spaAsset is one pre-loaded file plus whatever the request path would otherwise
// have to compute.
type spaAsset struct {
	body        []byte
	contentType string
	// Pre-compressed siblings, nil when the build produced none (images, or
	// files under the 1KB threshold).
	brotli []byte
	gzip   []byte
	// ETag over the identity bytes. Variants share it because they are
	// representations of the same resource; Vary: Accept-Encoding tells caches
	// the encoding is part of the key.
	etag string
}

type spaBundle struct {
	assets map[string]*spaAsset
	// built is false when only the .gitkeep placeholder is embedded, i.e. the
	// binary was compiled without running the frontend build.
	built bool
}

var (
	spaOnce   sync.Once
	spaLoaded *spaBundle
)

// loadSPA walks the embedded dist tree once and indexes it.
func loadSPA() *spaBundle {
	spaOnce.Do(func() {
		b := &spaBundle{assets: map[string]*spaAsset{}}
		sub, err := fs.Sub(web.DistFS, "dist")
		if err != nil {
			log.Printf("spa: fs.Sub on embedded dist failed: %v", err)
			spaLoaded = b
			return
		}

		// First pass collects raw bytes. The .br/.gz siblings are attached
		// afterwards because WalkDir has no ordering guarantee and a sibling may
		// well be visited before the file it belongs to.
		raw := map[string][]byte{}
		err = fs.WalkDir(sub, ".", func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				// spaOnce makes this index permanent for the process lifetime, so
				// a silently dropped file becomes a permanent 404 with no trail.
				log.Printf("spa: walk error at %q: %v", p, err)
				return nil
			}
			if d.IsDir() || d.Name() == ".gitkeep" {
				return nil
			}
			data, rerr := fs.ReadFile(sub, p)
			if rerr != nil {
				log.Printf("spa: read %q failed: %v", p, rerr)
				return nil
			}
			raw[p] = data
			return nil
		})
		if err != nil {
			log.Printf("spa: walk failed: %v", err)
		}

		for p, data := range raw {
			if strings.HasSuffix(p, ".br") || strings.HasSuffix(p, ".gz") {
				continue
			}
			ct := mime.TypeByExtension(path.Ext(p))
			if ct == "" {
				ct = "application/octet-stream"
			}
			sum := sha256.Sum256(data)
			a := &spaAsset{
				body:        data,
				contentType: ct,
				etag:        `"` + base64.RawURLEncoding.EncodeToString(sum[:16]) + `"`,
			}
			// Only adopt a variant that is actually smaller. skipIfLargerOrEqual
			// in the Vite config should prevent the opposite, but serving a
			// larger encoded body because a file happened to be incompressible
			// would be a silent pessimisation.
			if v, ok := raw[p+".br"]; ok && len(v) < len(data) {
				a.brotli = v
			}
			if v, ok := raw[p+".gz"]; ok && len(v) < len(data) {
				a.gzip = v
			}
			b.assets[p] = a
		}

		b.built = b.assets["portal.html"] != nil && b.assets["admin.html"] != nil
		if !b.built {
			log.Printf("spa: embedded bundle is missing portal.html/admin.html — " +
				"build the frontend (cd portal/web-react && npm ci && npm run build) and rebuild the binary")
		} else {
			log.Printf("spa: loaded %d embedded assets", len(b.assets))
		}
		spaLoaded = b
	})
	return spaLoaded
}

// acceptsEncoding reports whether the client accepts enc with a non-zero
// q-value. Deliberately a substring-plus-q check rather than a full RFC 7231
// parse: the header comes from a browser on the other side of a captive portal,
// the only two tokens that matter are "br" and "gzip", and the failure mode of
// guessing wrong is serving identity bytes.
func acceptsEncoding(header, enc string) bool {
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, params, _ := strings.Cut(part, ";")
		name = strings.TrimSpace(name)
		if name != enc && name != "*" {
			continue
		}
		// "br;q=0" is an explicit refusal and must not be treated as support.
		if q, ok := strings.CutPrefix(strings.TrimSpace(params), "q="); ok {
			if v, err := strconv.ParseFloat(strings.TrimSpace(q), 64); err == nil && v == 0 {
				continue
			}
		}
		return true
	}
	return false
}

// writeAsset sends the best available representation of a, honouring
// If-None-Match. cache is the Cache-Control value to apply.
func writeAsset(w http.ResponseWriter, r *http.Request, a *spaAsset, cache string) {
	h := w.Header()
	h.Set("Content-Type", a.contentType)
	h.Set("Cache-Control", cache)
	h.Set("ETag", a.etag)
	// Without this a shared cache could hand a brotli body to a client that
	// asked for gzip.
	h.Set("Vary", "Accept-Encoding")

	// A conditional request has to be answered before the body is chosen —
	// the ETag is over the identity bytes and does not depend on the encoding.
	if match := r.Header.Get("If-None-Match"); match != "" {
		for _, tag := range strings.Split(match, ",") {
			tag = strings.TrimSpace(tag)
			tag = strings.TrimPrefix(tag, "W/")
			if tag == a.etag || tag == "*" {
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}
	}

	body := a.body
	ae := r.Header.Get("Accept-Encoding")
	switch {
	case a.brotli != nil && acceptsEncoding(ae, "br"):
		h.Set("Content-Encoding", "br")
		body = a.brotli
	case a.gzip != nil && acceptsEncoding(ae, "gzip"):
		h.Set("Content-Encoding", "gzip")
		body = a.gzip
	}
	h.Set("Content-Length", strconv.Itoa(len(body)))
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(body); err != nil {
		// Normal when a captive-portal client walks away mid-download; logged at
		// the same level as the existing request log so it stays greppable.
		log.Printf("spa: write %s failed: %v", r.URL.Path, err)
	}
}

// handleAssets serves /assets/*, the content-hashed output of the Vite build.
func (a *App) handleAssets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	bundle := loadSPA()
	// path.Clean collapses any ../ before the lookup. The map has no such keys,
	// so a traversal attempt can only miss, but normalising keeps the 404 honest
	// rather than depending on that.
	name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
	asset, ok := bundle.assets[name]
	if !ok || !strings.HasPrefix(name, "assets/") {
		http.NotFound(w, r)
		return
	}
	writeAsset(w, r, asset, "public, max-age=31536000, immutable")
}

// spaPageData is the runtime configuration handed to the bundle. Field names
// match the AppConfig interface in web-react/src/lib/config.ts.
type spaPageData struct {
	Page               string   `json:"page"`
	Lang               Lang     `json:"lang"`
	Brand              spaBrand `json:"brand"`
	NowYear            int      `json:"nowYear"`
	GuestEnabled       bool     `json:"guestEnabled"`
	AllowedDomainsHint string   `json:"allowedDomainsHint"`
	Message            string   `json:"message,omitempty"`
	AdminUPN           string   `json:"adminUPN,omitempty"`
}

type spaBrand struct {
	Name    string `json:"name"`
	Color   string `json:"color"`
	LogoURL string `json:"logoUrl"`
	Initial string `json:"initial"`
}

// renderSPA serves one of the two built documents with the configuration block
// spliced in.
//
// doc is "portal.html" or "admin.html"; status lets the error page keep its
// non-200 code, which matters because renderError is what answers a rejected
// #EXT# account or an expired OIDC state.
func (a *App) renderSPA(w http.ResponseWriter, r *http.Request, doc string, data spaPageData, status int) {
	bundle := loadSPA()
	asset := bundle.assets[doc]
	if asset == nil {
		// Reachable only for a binary built without running the frontend build.
		// Say exactly that instead of a bare 500 — this is the failure a
		// first-time contributor is most likely to hit.
		log.Printf("spa: %s missing from the embedded bundle", doc)
		http.Error(w,
			"frontend bundle not built: run `cd portal/web-react && npm ci && npm run build`, then rebuild the binary",
			http.StatusInternalServerError)
		return
	}

	cfg, err := json.Marshal(data)
	if err != nil {
		log.Printf("spa: marshal page config failed: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	title := a.spaTitle(data)
	// The JSON goes into a <script type="application/json"> data block, which the
	// browser parses as text rather than executing — the reason the CSP no longer
	// needs script-src 'unsafe-inline'. The two sequences that could break out of
	// such a block are "</script" and "<!--", and neither can appear here:
	// encoding/json escapes '<', '>' and '&' to <, > and & unless
	// an Encoder is explicitly configured with SetEscapeHTML(false). json.Marshal
	// is used above precisely so that stays the default. The only fields carrying
	// attacker-influenced text are Message (server-produced) and AdminUPN (from a
	// signed id_token), and both are covered by that escaping regardless.

	var head strings.Builder
	head.WriteString("<title>")
	head.WriteString(html.EscapeString(title))
	head.WriteString("</title>")
	// The brand colour has to be a custom property before first paint so the
	// static skeleton and the mounted app agree. BrandColor is validated at
	// config load; escaping it here as well keeps this function safe on its own
	// terms rather than depending on that.
	head.WriteString(`<style>:root{--brand-color:`)
	head.WriteString(html.EscapeString(a.cfg.BrandColor))
	head.WriteString(`}</style>`)
	head.WriteString(`<script type="application/json" id="` + cfgElementID + `">`)
	head.Write(cfg)
	head.WriteString(`</script>`)

	body := bytes.Replace(asset.body, []byte(headMarker), []byte(head.String()), 1)
	body = bytes.Replace(body, []byte(langPlaceholder), []byte(string(data.Lang)), 1)

	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	// no-store, not no-cache: the document embeds the admin's UPN and, on the
	// error page, the reason a sign-in failed. Neither belongs in a disk cache
	// on a shared device, and the pages are ~3KB so re-fetching costs nothing.
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	if r.Method == http.MethodHead {
		return
	}
	if _, err := w.Write(body); err != nil {
		log.Printf("spa: write %s failed: %v", r.URL.Path, err)
	}
}

// spaTitle picks the <title> for a page. Kept server-side so the tab is labelled
// correctly before any JavaScript runs — in a captive-portal mini browser that
// title is often the only chrome the user sees.
func (a *App) spaTitle(data spaPageData) string {
	switch data.Page {
	case "error":
		return fmt.Sprintf("%s · %s", T(data.Lang, "errors.title"), a.cfg.BrandName)
	case "adminLogin":
		return T(data.Lang, "admin.login.title", a.cfg.BrandName)
	case "admin":
		return T(data.Lang, "admin.pageTitle", a.cfg.BrandName)
	default:
		return T(data.Lang, "login.title", a.cfg.BrandName)
	}
}

// baseSPAData fills in the fields every page needs.
func (a *App) baseSPAData(page string, lang Lang) spaPageData {
	return spaPageData{
		Page:    page,
		Lang:    lang,
		NowYear: time.Now().Year(),
		Brand: spaBrand{
			Name:    a.cfg.BrandName,
			Color:   a.cfg.BrandColor,
			LogoURL: a.cfg.BrandLogoURL,
			Initial: brandInitial(a.cfg.BrandName),
		},
	}
}

func brandInitial(name string) string {
	for _, r := range name {
		return string(r)
	}
	return "?"
}
