# Contributing

Thanks for your interest in contributing. This project is an iKuai captive-portal authentication gateway written in Go: users authenticate via Microsoft Entra SSO, Duo 2FA, or admin-issued one-time guest codes, and on success the device MAC/IP is allow-listed on an iKuai router through iKuai custom authentication (`type=20`).

Contributions of all kinds are welcome: bug fixes, new auth paths, hardening, translations, and documentation. The sections below describe how to build, run, test, and submit changes.

## Prerequisites

- **Go 1.25+** (the module targets `go 1.25.0`; see `portal/go.mod`). CI pins to `>=1.25.10`, so use a recent 1.25 toolchain to match it.
- **Docker** (optional) — only needed if you want to build or run the container image, or reproduce the Docker steps from the README.

All Go work happens inside the `portal/` directory, which is where `go.mod` lives.

## Building

From `./portal`:

```bash
cd portal
go build ./...
```

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

A minimal local run needs at least `SESSION_SECRET` and the Entra/iKuai values to exercise the real auth paths. For full deployment instructions (Modes A–D, reverse proxy/TLS, iKuai integration, Duo setup, admin console, and the exact compose directory layout), see [`README.en.md`](./README.en.md) (or [`README.md`](./README.md) for 简体中文). Never commit a real `.env`; use placeholder values such as `00000000-0000-0000-0000-000000000000`, `you@example.com`, and `portal.example.com`.

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

Before committing, keep the code gofmt-clean:

```bash
gofmt -l .        # lists files needing formatting; should print nothing
go fmt ./...      # rewrites in place
```

The repository has extensive `*_test.go` coverage (config, oidc, duo, ikuai, ratelimit, admin, denylist, eventlog, session, handlers, and a dedicated `regressions_test.go`). Tests are **table-driven**: a slice of input/expected-output cases iterated in a loop, with `t.Errorf`/`t.Fatalf` reporting the offending case. New behavior must come with tests in the same style, and bug fixes should add a regression test (write it to fail first, then make it pass). Security-sensitive logic, in particular, is expected to include attack-payload cases (see `config_test.go`'s `TestSanitizeBrandColor`).

`go vet ./...` and `go test ./...` must pass; CI also runs `govulncheck ./...` and a Docker image build, so avoid introducing vulnerable dependencies.

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
- Write **code comments in English**.
- Update tests and, where relevant, the READMEs and `portal/i18n/*` in the same PR as the behavior change.

## License of contributions

This project is licensed under the **GNU AGPL-3.0** (see [`LICENSE`](./LICENSE)). By submitting a contribution, you agree that it is licensed under AGPL-3.0 on the same terms as the project (inbound = outbound). There is no separate Contributor License Agreement (CLA) to sign.

## Reporting bugs and security issues

- **Security vulnerabilities:** do not open a public issue. Follow the disclosure process described in [`SECURITY.md`](./SECURITY.md).
- **Normal bugs and feature requests:** open a GitHub issue at <https://github.com/KKazuhaK/WiFi-Roaming-With-iKuai/issues>. Include reproduction steps, expected vs. actual behavior, and your Go version / deployment mode where relevant. Never paste real tenant/client/group GUIDs, secrets, email addresses, or internal domain names — redact them with placeholders.
