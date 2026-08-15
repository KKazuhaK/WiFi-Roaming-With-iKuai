// Package web embeds the built React bundle so the portal still ships as a
// single self-contained binary.
//
// During development the assets are served by Vite's dev server (npm run dev,
// which proxies /auth, /admin and /static back to a locally running portal).
// In production `npm run build` writes the bundle into this package's dist/
// subdirectory — vite.config.ts points build.outDir straight here — and the
// directive below packs it into the binary.
//
// dist/ is git-ignored except for .gitkeep. That placeholder is load-bearing:
// `//go:embed all:dist` fails to compile against an empty or missing directory,
// so without it a fresh clone could not run `go build ./...` or `go test`
// without installing Node first.
//
// The `all:` prefix matters too. Plain `//go:embed dist` skips files whose names
// begin with "." or "_", and Vite is free to emit such names; `all:` takes the
// directory verbatim.
package web

import "embed"

//go:embed all:dist
var DistFS embed.FS
