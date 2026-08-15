import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { compression, defineAlgorithm } from 'vite-plugin-compression2'
import path from 'node:path'
import zlib from 'node:zlib'

// Vite 8 loads this config natively, where __dirname is not defined.
const here = import.meta.dirname

// Two entries, not one SPA with lazy routes.
//
// /login runs inside the captive-portal mini browser (iOS CNA, Android
// CaptivePortalLogin) before the device has internet access, so its bundle has
// to stay small. A single-entry SPA with React.lazy would still ship one shared
// vendor chunk holding the union of everything both pages import — the portal
// page would pay for the admin panel's Table/DatePicker/Upload. With separate
// Rollup entries the import graphs are analysed independently: modules used by
// both land in an automatic shared chunk, admin-only components never reach the
// portal entry.
const entries = {
  portal: path.join(here, 'portal.html'),
  admin: path.join(here, 'admin.html'),
}

export default defineConfig({
  // Assets are referenced as /assets/... from pages served at /login, /admin and
  // /admin/login. Absolute base keeps one URL per asset across all three paths,
  // so the immutable cache entry is shared instead of duplicated per depth.
  base: '/',
  plugins: [
    react(),
    // Pre-compress at build time instead of gzipping per request. The assets are
    // baked into the Go binary via //go:embed, so compressing once here costs
    // nothing at runtime and lets brotli run at quality 11 — a level no
    // sane on-the-fly middleware would use. The Go static handler picks the
    // .br/.gz sibling based on Accept-Encoding.
    compression({
      algorithms: [
        defineAlgorithm('gzip', { level: 9 }),
        defineAlgorithm('brotliCompress', {
          params: { [zlib.constants.BROTLI_PARAM_QUALITY]: 11 },
        }),
      ],
      // PNG/JPEG/WOFF2 carry their own compression; a second pass costs build
      // time and usually produces a *larger* file, which the Go handler would
      // then have to reject at runtime.
      exclude: [/\.(png|jpe?g|gif|webp|avif|ico|woff2?)$/],
      // Below ~1KB the encoding header and the framing cost more than the
      // handful of bytes saved.
      threshold: 1024,
      // Keep the originals: clients that send no Accept-Encoding (some captive
      // portal mini browsers, and curl in a support session) still need them.
      deleteOriginalAssets: false,
      // An incompressible asset that slipped past `exclude` should not get a
      // useless sibling for the handler to prefer.
      skipIfLargerOrEqual: true,
    }),
  ],
  resolve: {
    alias: {
      '@': path.join(here, 'src'),
      // The Go binary embeds portal/i18n/*.json and validates key parity at
      // startup (i18n.go loadTranslations). The frontend imports those exact
      // files rather than keeping a second copy, so a key can never drift
      // between the server-rendered strings and the SPA.
      '@i18n': path.join(here, '../i18n'),
    },
  },
  server: {
    port: 5174,
    host: true,
    proxy: {
      '/auth': 'http://localhost:28080',
      '/admin': 'http://localhost:28080',
      '/static': 'http://localhost:28080',
      '/healthz': 'http://localhost:28080',
    },
    fs: {
      // portal/i18n lives outside web-react/, so the dev server has to be
      // allowed to read one level up.
      allow: ['..'],
    },
  },
  build: {
    // Write straight into the //go:embed location so `go build` picks up the
    // latest bundle with no copy step.
    outDir: '../internal/web/dist',
    emptyOutDir: true,
    // The captive-portal page must not block on a stylesheet request in a mini
    // browser; antd injects its own styles at runtime anyway, so the only CSS
    // left is our small base sheet. Inlining it below 8KB removes a round trip.
    assetsInlineLimit: 8192,
    cssCodeSplit: true,
    sourcemap: false,
    rollupOptions: {
      input: entries,
      output: {
        // No manualChunks for antd, deliberately.
        //
        // Forcing every antd module into one named vendor chunk looks like good
        // cache hygiene and is the opposite: the chunk becomes the union of what
        // both entries import, so the captive-portal page — which uses Input,
        // Button and ConfigProvider — ends up downloading Table, DatePicker and
        // Upload as well. Measured, that was a 517KB chunk where the portal page
        // needs a fraction of it. Left alone, the bundler treats each entry's
        // import graph separately and emits a shared chunk holding only what
        // both actually reach.
        //
        // React is small enough that pinning it buys nothing the automatic
        // shared chunk does not already give us.
        entryFileNames: 'assets/[name].[hash].js',
        chunkFileNames: 'assets/[name].[hash].js',
        assetFileNames: 'assets/[name].[hash][extname]',
      },
    },
  },
})
