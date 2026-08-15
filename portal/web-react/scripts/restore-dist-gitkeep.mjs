// `vite build` runs with emptyOutDir:true, so it wipes portal/internal/web/dist/ —
// including the tracked .gitkeep placeholder. That placeholder is the only reason
// `//go:embed all:dist` (portal/internal/web/web.go) finds a non-empty directory on
// a fresh clone, which is what lets `go build ./...` and the `go vet` / `go test` CI
// jobs compile without running the frontend build first. If a build leaves the
// directory without it, `git add -A` stages the deletion and the next clean checkout
// fails with "pattern all:dist: no matching files found".
//
// Runs automatically as the npm `postbuild` hook. cwd is web-react/.
import { mkdirSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'

const target = '../internal/web/dist/.gitkeep'

const content = `# Keeps portal/internal/web/dist/ present on a fresh clone so \`go:embed all:dist\`
# (portal/internal/web/web.go) has a non-empty directory and \`go build ./...\`
# compiles before the frontend is built. The real bundle (npm run build) lands
# here and is git-ignored; only this placeholder is tracked (see .gitignore).
`

mkdirSync(dirname(target), { recursive: true })
writeFileSync(target, content)
