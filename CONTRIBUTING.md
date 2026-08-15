# Contributing

Thanks for your interest in contributing. This project is an iKuai captive-portal authentication gateway written in Go: users authenticate via Microsoft Entra SSO, Duo 2FA, or admin-issued one-time guest codes, and on success the device MAC/IP is allow-listed on an iKuai router through iKuai custom authentication (`type=20`).

Contributions of all kinds are welcome: bug fixes, new auth paths, hardening, translations, and documentation. The sections below describe how to build, run, test, and submit changes.

## Prerequisites

- **Go 1.25+** (the module targets `go 1.25.0`; see `portal/go.mod`). CI pins to `>=1.25.10`, so use a recent 1.25 toolchain to match it.
- **Node 22+** — needed only if you touch the frontend (`portal/web-react/`) or want to produce a binary that actually serves pages. See below.
- **Docker** (optional) — only needed if you want to build or run the container image, or reproduce the Docker steps from the README.
- **MySQL / PostgreSQL** (optional) — the test suite runs against the embedded SQLite by default. See "Testing against MySQL and PostgreSQL" below if you touch the storage layer.

Go work happens inside the `portal/` directory, which is where `go.mod` lives. The frontend lives in `portal/web-react/`.

## Building

The frontend is a Vite bundle that `//go:embed` packs into the binary, so a full build is two steps:

```bash
cd portal/web-react && npm ci && npm run build   # writes portal/internal/web/dist/
cd .. && go build ./...
```

**You can skip the first step when you are only changing Go code.** `portal/internal/web/dist/` ships with a tracked `.gitkeep` and nothing else, which is what lets `//go:embed all:dist` compile on a fresh clone — so `go build ./...`, `go vet ./...` and `go test ./...` all work without Node installed. The binary you get that way starts normally but answers every page with `frontend bundle not built`, and logs the same hint at startup. That is expected; only a binary you intend to ship or to click through needs the bundle.

The build output is git-ignored. If `git status` ever shows files under `internal/web/dist/`, something is wrong with `.gitignore` — CI fails the build in that case (see the `go-build-clean` job).

### Frontend development

`npm run dev` starts Vite on port 5174 and proxies `/auth`, `/admin` and `/static` to a portal running on `localhost:28080`, so you get hot reload against a real backend:

```bash
cd portal/web-react && npm run dev
```

Useful scripts:

| Command | What it does |
| --- | --- |
| `npm run build` | Typechecks (`tsc -b`), builds, pre-compresses to `.br`/`.gz`, restores the dist `.gitkeep` |
| `npm run typecheck` | Typecheck only |
| `npm run smoke:dist` | Verifies the built output: entry markers the Go handler rewrites, content hashes, compression siblings, and the brotli budget on the captive-portal entry |

The captive-portal page (`/login`) has a **160KB brotli budget** enforced by `smoke:dist`. It loads inside a mini browser before the device has internet access, so an admin-only import leaking into that entry's chunk is a real regression — that is what the budget catches.

Translations live in `portal/i18n/*.json` and are read by **both** sides: Go through `T()` in `i18n.go`, and the frontend through the `@i18n` alias in `web-react/src/lib/i18n.ts`. Add a key to all three language files or the Go startup validation will refuse to boot.

### Release build flags

CI also produces stripped, reproducible cross-compiled binaries (`.github/workflows/release.yml`) with the same flags; locally you can do the equivalent:

```bash
# linux/amd64
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /tmp/wifi-portal-amd64 .

# linux/arm64
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o /tmp/wifi-portal-arm64 .
```

`CGO_ENABLED=0` keeps the binary static (no libc dependency, works in `scratch`/distroless and alpine images), `-trimpath` strips build-machine paths, and `-ldflags="-s -w"` strips symbols to reduce size. The Docker build (`portal/Dockerfile`) uses the same flags.

## Running locally

The binary embeds `portal/.env.example` and the systemd unit template (`portal/embed/wifi-portal.service`). On first run with the key configuration env vars unset, it writes the config templates instead of starting, so a bare-binary deployment never needs the source tree:

```bash
cd portal
go run .          # or run a built binary
```

If the key env vars look unset, this generates in the current directory:

- `wifi-portal.env`
- `wifi-portal.service`

You can also drive the init flow explicitly with custom output and install paths:

```bash
go run . init \
  --out-dir ./tmpconfig \
  --conf-dir /etc/wifi-portal \
  --data-dir /var/lib/wifi-portal \
  --bin-path /usr/local/bin/wifi-portal
```

Alternatively, for the Docker/compose flow: the compose file lives at [`deploy/docker-compose.yml`](./deploy/docker-compose.yml), and its build context expects `./portal` next to it, so you do **not** run compose from the repo's `deploy/` directory. Instead, assemble a deployment directory (the README uses `/opt/wifi-portal/`) containing `docker-compose.yml`, `.env`, and a copy of `portal/`, then start it there. The env file is copied from the example and locked down:

```bash
cp portal/.env.example .env
chmod 600 .env
# edit .env: TENANT_ID, CLIENT_ID, CLIENT_SECRET, IKUAI_APPKEY, PUBLIC_URL,
# SESSION_SECRET (openssl rand -hex 32), etc.
```

A minimal local run needs `SESSION_SECRET` and `ENCRYPTION_KEY`, plus the Entra/iKuai values if you want to exercise the real auth paths. Those last ones are only seeds: they are imported into the database on first start, and after that configuration is edited in `/admin` → Settings or with `wifi-portal config set`. If a local instance is ignoring your `.env` edits, that is why.

To reach `/admin` without a working Entra tenant, use the break-glass account — which is also the fastest way to click through admin changes locally:

```bash
cd portal
go run . admin add ops        # prompts for a password
go run . admin enable         # exposes /admin/login/local
``` For full deployment instructions (Modes A–D, reverse proxy/TLS, iKuai integration, Duo setup, admin console, and the exact compose directory layout), see [`README.en.md`](./README.en.md) (or [`README.md`](./README.md) for 简体中文). Never commit a real `.env`; use placeholder values such as `00000000-0000-0000-0000-000000000000`, `you@example.com`, and `portal.example.com`.

## Testing

Run the full suite from `./portal`:

```bash
cd portal
go vet ./...
go test ./...
```

To mirror CI exactly, also run the race detector and coverage:

```bash
go test -race -count=1 ./...
go test -count=1 -cover ./...
```

### Testing against MySQL and PostgreSQL

Every test runs against an embedded SQLite file by default, which is what you get with no setup. That is not enough when you touch `store_*.go`, `internal/dbstore/` or `internal/settings/`: the three engines disagree about upsert syntax, about whether `SELECT ... FOR UPDATE` exists, about whether `LIKE` is case-sensitive, and about timestamp precision — and all four of those differences are load-bearing here.

Point the suite at a real server with `TEST_DB_DSN`:

```bash
# PostgreSQL
docker run --rm -d -p 5432:5432 -e POSTGRES_USER=portal -e POSTGRES_PASSWORD=portal \
  -e POSTGRES_DB=wifi_portal_test --name pg-test postgres:16-alpine
TEST_DB_DSN='postgres://portal:portal@127.0.0.1:5432/wifi_portal_test?sslmode=disable' \
  go test -count=1 -p 1 ./...

# MySQL
docker run --rm -d -p 3306:3306 -e MYSQL_ROOT_PASSWORD=portal -e MYSQL_USER=portal \
  -e MYSQL_PASSWORD=portal -e MYSQL_DATABASE=wifi_portal_test --name my-test mysql:8
TEST_DB_DSN='portal:portal@tcp(127.0.0.1:3306)/wifi_portal_test?parseTime=true&loc=UTC' \
  go test -count=1 -p 1 ./...
```

`-p 1` matters: with an external server the tests share one database and empty it at the start of each test, so two packages running concurrently would clear each other's rows. CI runs both engines on every push (the `go-test-databases` job).

Before committing, keep the code gofmt-clean:

```bash
gofmt -l .        # lists files needing formatting; should print nothing
go fmt ./...      # rewrites in place
```

The repository has extensive `*_test.go` coverage (config, oidc, duo, ikuai, ratelimit, admin, denylist, eventlog, session, handlers, TLS and listeners, admin APIs, multi-instance and paging behaviour in `scale_test.go`, and a dedicated `regressions_test.go`). Tests are **table-driven**: a slice of input/expected-output cases iterated in a loop, with `t.Errorf`/`t.Fatalf` reporting the offending case. New behavior must come with tests in the same style, and bug fixes should add a regression test (write it to fail first, then make it pass). Security-sensitive logic, in particular, is expected to include attack-payload cases (see `config_test.go`'s `TestSanitizeBrandColor`).

`go vet ./...` and `go test ./...` must pass. CI also runs `govulncheck ./...`, `npm audit --audit-level=high` over the frontend tree, a Docker image build, and `go test` a second time against a freshly built bundle — `spa_bundle_test.go` skips itself when only the dist placeholder is present, so those checks only actually run in the job that builds the frontend first.

## Internationalization

User-facing strings live in three locale files under `portal/i18n/`:

- `en.json`
- `zh-cn.json`
- `zh-tw.json`

**English is the source of truth.** At startup the binary validates that every other language contains every key present in `en.json`; a missing key is fatal (the process refuses to start). Therefore:

- Any change to user-facing text must update **all three** files and keep the key set identical across them.
- When adding a string, add the key to `en.json` first, then provide `zh-cn` and `zh-tw` translations.
- Do not remove a key from one file without removing it from the others.

There is no pluralization layer; formatting uses `fmt.Sprintf` with `%s`/`%d`. The READMEs (`README.md` / `README.en.md`) are bilingual and kept in sync — if your change affects documented behavior, update both.

## Commit & PR conventions

- Use **Conventional Commits** prefixes: `feat:`, `fix:`, `docs:`, `i18n:` (these match the existing history). Use the prefix that fits the change.
- Keep PRs **small and focused** — one logical change per PR is much easier to review.
- `go test ./...` and `go vet ./...` must pass before you open or update a PR; code must be gofmt-clean.
- Frontend changes must also pass `npm run build` (which typechecks) and `npm run smoke:dist` from `portal/web-react/`.
- Write **code comments in English**.
- Update tests and, where relevant, the READMEs and `portal/i18n/*` in the same PR as the behavior change.

## License of contributions

This project is licensed under the **GNU AGPL-3.0** (see [`LICENSE`](./LICENSE)). By submitting a contribution, you agree that it is licensed under AGPL-3.0 on the same terms as the project (inbound = outbound). There is no separate Contributor License Agreement (CLA) to sign.

## Reporting bugs and security issues

- **Security vulnerabilities:** do not open a public issue. Follow the disclosure process described in [`SECURITY.md`](./SECURITY.md).
- **Normal bugs and feature requests:** open a GitHub issue at <https://github.com/KKazuhaK/WiFi-Roaming-With-iKuai/issues>. Include reproduction steps, expected vs. actual behavior, and your Go version / deployment mode where relevant. Never paste real tenant/client/group GUIDs, secrets, email addresses, or internal domain names — redact them with placeholders.
