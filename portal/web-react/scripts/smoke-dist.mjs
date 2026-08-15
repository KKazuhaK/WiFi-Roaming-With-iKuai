// Post-build sanity check on portal/internal/web/dist/.
//
// A `vite build` can exit 0 and still produce a bundle the Go binary cannot serve:
// a renamed entry, a missing head marker, an asset that never got pre-compressed.
// Every one of those only shows up when a real device hits the captive portal,
// which is the worst place to find out. This runs in CI right after the build.
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs'
import { join } from 'node:path'

const dist = '../internal/web/dist'
const failures = []

function fail(msg) {
  failures.push(msg)
}

// 1. Both entry documents exist and still carry the marker the Go handler
//    rewrites. Vite renames assets freely but leaves HTML comments alone, so a
//    missing marker means someone edited the template by hand.
for (const page of ['portal.html', 'admin.html']) {
  const path = join(dist, page)
  if (!existsSync(path)) {
    fail(`${page}: missing from dist`)
    continue
  }
  const html = readFileSync(path, 'utf8')
  if (!html.includes('<!--PORTAL_HEAD-->')) {
    fail(`${page}: lost the <!--PORTAL_HEAD--> marker; the Go handler cannot inject config`)
  }
  if (!html.includes('__PORTAL_LANG__')) {
    fail(`${page}: lost the __PORTAL_LANG__ placeholder on <html lang>`)
  }
  if (!/<script type="module"[^>]+src="\/assets\//.test(html)) {
    fail(`${page}: no hashed module script found; check build.rollupOptions.input`)
  }
  if (!html.includes('id="root"')) {
    fail(`${page}: no #root mount point`)
  }
}

// 2. Assets are content-hashed. Without the hash the year-long immutable
//    Cache-Control the Go handler sets would pin stale code in browsers.
const assetsDir = join(dist, 'assets')
if (!existsSync(assetsDir)) {
  fail('assets/: missing from dist')
} else {
  const assets = readdirSync(assetsDir).filter((f) => !f.endsWith('.gz') && !f.endsWith('.br'))
  if (assets.length === 0) fail('assets/: empty')
  for (const name of assets) {
    if (!/\.[A-Za-z0-9_-]{8,}\.(js|css|png|jpe?g|svg|woff2?)$/.test(name)) {
      fail(`assets/${name}: filename carries no content hash, unsafe to cache immutably`)
    }
  }

  // 3. Every compressible asset over the plugin threshold has both siblings.
  //    A missing .br silently downgrades every client to gzip.
  for (const name of assets) {
    if (!/\.(js|css|svg|json)$/.test(name)) continue
    const full = join(assetsDir, name)
    if (statSync(full).size < 1024) continue
    for (const ext of ['.gz', '.br']) {
      if (!existsSync(full + ext)) {
        fail(`assets/${name}: no ${ext} sibling; pre-compression did not run`)
      }
    }
  }

  // 4. Budget guard for the captive-portal entry. This page loads inside a
  //    mini browser on a link that has not been unlocked yet, so a regression
  //    here is a support call, not a slow page. Compare brotli sizes.
  // Measured at 129KB after moving antd's <App> and the locale tables into the
  // admin entry. The headroom is for the odd component addition, not for an
  // admin-only import leaking across — that shows up as tens of KB at once.
  const PORTAL_BUDGET_KB = 160
  const portalHtml = existsSync(join(dist, 'portal.html'))
    ? readFileSync(join(dist, 'portal.html'), 'utf8')
    : ''
  const referenced = new Set(
    [...portalHtml.matchAll(/(?:src|href)="\/assets\/([^"]+)"/g)].map((m) => m[1]),
  )
  let portalBytes = 0
  for (const name of referenced) {
    const br = join(assetsDir, name + '.br')
    const raw = join(assetsDir, name)
    if (existsSync(br)) portalBytes += statSync(br).size
    else if (existsSync(raw)) portalBytes += statSync(raw).size
  }
  const portalKB = Math.round(portalBytes / 1024)
  if (portalBytes > PORTAL_BUDGET_KB * 1024) {
    fail(
      `portal entry is ${portalKB}KB brotli, over the ${PORTAL_BUDGET_KB}KB captive-portal budget. ` +
        `Check what got pulled into the portal graph — an antd import that only /admin needs will land here too.`,
    )
  } else {
    console.log(`portal entry: ${portalKB}KB brotli (budget ${PORTAL_BUDGET_KB}KB)`)
  }
}

if (failures.length > 0) {
  console.error('dist smoke check failed:')
  for (const f of failures) console.error('  - ' + f)
  process.exit(1)
}
console.log('dist smoke check passed')
