# Kazuha Hub Roaming

Languages: [中文](./README.md) | [English](./README.en.md)

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](./LICENSE)
[![Go](https://img.shields.io/github/go-mod/go-version/KKazuhaK/WiFi-Roaming-With-iKuai?filename=portal%2Fgo.mod)](portal/go.mod)
[![Build](https://github.com/KKazuhaK/WiFi-Roaming-With-iKuai/actions/workflows/build.yml/badge.svg)](https://github.com/KKazuhaK/WiFi-Roaming-With-iKuai/actions/workflows/build.yml)
[![Release](https://img.shields.io/github/v/release/KKazuhaK/WiFi-Roaming-With-iKuai)](https://github.com/KKazuhaK/WiFi-Roaming-With-iKuai/releases)

A unified WiFi access portal for the SSID **`Kazuha Hub Roaming`**.

Users land on a captive portal and choose one of these paths:

- **Duo users** who are enrolled in Duo Mobile go directly to Duo Universal Prompt, complete 2FA, and are allow-listed.
- **Non-Duo users** fall back to Microsoft Entra SSO and are allow-listed after login.
- **External guest accounts** whose UPN contains `#EXT#` are rejected.
- **Visitors without organization accounts** use one-time guest codes issued by admins.

Every successful path ultimately calls iKuai custom authentication (`type=20`) and allow-lists the device MAC / IP.

## Quick Start

Fastest path to a running instance using **Mode A** (Portal only, TLS handled by an external reverse proxy). See [Docker Deployment](#docker-deployment) and [Required Configuration](#required-configuration) for the full guide.

```bash
# 1. Clone.
git clone https://github.com/KKazuhaK/WiFi-Roaming-With-iKuai.git
cd WiFi-Roaming-With-iKuai

# 2. Arrange a working dir with portal/, the compose file, and .env together.
#    The build context expects ./portal next to docker-compose.yml.
sudo mkdir -p /opt/wifi-portal
sudo chown $USER:$USER /opt/wifi-portal
cp -r portal /opt/wifi-portal/
cp deploy/docker-compose.yml /opt/wifi-portal/
cd /opt/wifi-portal

# 3. Create and lock down .env.
cp portal/.env.example .env
chmod 600 .env

# 4. Fill the required variables in .env (leave COMPOSE_PROFILES empty for Mode A):
#      TENANT_ID, CLIENT_ID, CLIENT_SECRET   - Entra App Registration
#      IKUAI_APPKEY                          - iKuai custom authentication appkey
#      PUBLIC_URL                            - externally reachable Portal URL, e.g. https://portal.example.com
#      SESSION_SECRET                        - openssl rand -hex 32
#      ENCRYPTION_KEY                        - openssl rand -hex 32, encrypts stored credentials
#
#    These are first-run seeds: they are imported into the database on startup,
#    and from then on configuration is edited in /admin -> Settings. See
#    "Where Configuration Lives" below.
vim .env

# 5. Build and start.
docker compose up -d --build
docker compose logs -f portal
```

Portal listens on host `127.0.0.1:28080` for your external Nginx / aaPanel proxy to forward to. For built-in Caddy TLS (Mode B), prebuilt images (Mode C), or bare binary + systemd (Mode D), see [Deployment Modes](#deployment-modes).

## Where Configuration Lives

**Everything except a handful of bootstrap variables is edited in the admin console and stored in the database.**

Configuration used to be entirely environment variables, so changing a brand colour meant editing `.env` and restarting the container. What is left in the environment is what has to be known before the settings table can be read, or what must not be changeable from a web page:

| Bootstrap variable | Why it cannot move |
|---|---|
| `SESSION_SECRET` | Signs the admin cookie. Storing it in the database is circular: you would have to sign in to configure the thing that lets you sign in |
| `ENCRYPTION_KEY` | Encrypts credentials at rest. Keeping it inside the database it protects defeats the purpose |
| `DATA_DIR` | Where the embedded SQLite file lives |
| `DB_DSN` | The database address, needed before any setting can be read |
| `DB_MAX_OPEN_CONNS` | Pool size; the pool is built before the settings table is readable |
| `LISTEN_ADDR` | The plain-HTTP listener iKuai redirects captive clients to, so it cannot move at runtime |
| `TRUST_PROXY` | Decides whether `X-Forwarded-For` is believed. Getting it wrong silently disables rate limiting, which is not a mistake a web form should be able to make |

Everything else lives in **/admin → Settings**, grouped by section: Entra SSO, Duo, sign-in policy, administrator access, emergency sign-in, iKuai integration, iKuai policy defaults, Portal, branding, rate limiting, event log. Saving applies immediately — the OIDC client is rebuilt and swapped atomically with the configuration it came from, so no request ever sees a new tenant with an old client.

Credentials (`CLIENT_SECRET`, `IKUAI_APPKEY`, both Duo secrets) are encrypted with AES-256-GCM using a key derived from `ENCRYPTION_KEY`, and are **never** sent back to the browser: the settings page shows only whether one is set, and saving a blank field leaves it unchanged.

### Upgrading an existing installation

**Nothing to do.** On first start the new version imports the values from `.env` and the five JSON state files under `DATA_DIR` (guest codes, MAC denylist, iKuai policy, ban history, event log), then renames them to `*.migrated` and reads only the database from then on.

The import happens once, when the database is empty. After that the runtime environment variables are ignored — the startup log lists the ones still set, so the change is announced rather than silent.

## What the Console Configures

`/admin` is a Passwall-style sidebar with four groups:

- **Overview** — dashboard (logins today/this week, failure rate, active guest codes, bans)
- **Access** — guest codes, allow-list policy (iKuai rate limits and durations)
- **Security** — MAC denylist, rate-limit state, event log
- **System** — TLS, settings

Branding (name, colour, logo) is under Settings → Branding and applies to both the captive portal and the console without rebuilding the frontend.

### TLS, domain and port

**System → TLS** offers two modes:

- **A reverse proxy terminates TLS** (the default; existing deployments are unaffected) — the portal listens on plain HTTP. The page generates ready-to-paste nginx and Caddy snippets and offers a connectivity self-check. It does **not** write into your proxy's configuration: that would mean giving a process reachable by every unauthenticated device write access to `/etc/nginx`, which is a large amount of blast radius to trade for a copy-paste.
- **The portal terminates TLS** — it binds 443 itself and serves a certificate from the database. Two sources:
  - **Let's Encrypt over HTTP-01** — set the domain and an account email, then press issue. Renewal runs automatically at 30 days remaining. The challenge is answered from the portal's own mux, sharing the port iKuai already redirects clients to.
  - **Upload a PEM pair** — for an internal CA, a wildcard the organisation already owns, or a certificate obtained elsewhere with DNS-01. The private key is encrypted before storage.

  **DNS-01 is not implemented.** A portal on a LAN box (Mode B) cannot pass HTTP-01 and never will — not being publicly routable is the point of that deployment — so the page detects that case and steers those installations to the upload path rather than offering a challenge that cannot succeed.

Listener changes commit like a router's: after the new listener comes up you have two minutes to confirm from the new address, and an unconfirmed change rolls back. Turning on the HTTP→HTTPS redirect takes the console away from the plain address, so the page hands you the new URL when you save.

Binding 443 needs root or `CAP_NET_BIND_SERVICE`.

## Database

The default is an embedded SQLite file under `DATA_DIR` — zero configuration, right for a single instance. For multiple instances or larger deployments, set `DB_DSN`:

```bash
DB_DSN=user:pass@tcp(127.0.0.1:3306)/wifi_portal?parseTime=true         # MySQL 8
DB_DSN=postgres://user:pass@127.0.0.1:5432/wifi_portal?sslmode=disable  # PostgreSQL
DB_DSN=sqlite:/var/lib/wifi-portal/portal.db                            # explicit SQLite path
```

Create the database first; the schema migrates itself at startup. The SQLite driver is pure Go, so `CGO_ENABLED=0` static binaries still work.

**Multi-instance semantics** — what actually matters when running more than one portal:

| State | Shared across instances |
|---|---|
| Guest-code redemption | Yes. One transaction with a row lock; 16 concurrent requests for a single-use code produce exactly one success |
| MAC denylist / iKuai policy / settings / certificates | Yes |
| Event log | Yes. Every instance writes the same table, and the console shows all of it |
| IP cooldowns | Yes. Stored in the database with a two-second write-through cache |
| Permanent-ban escalation counts | Yes |
| Failure counters (email / MAC / IP) | **No, per-process** |

The last row is deliberate. Those counters are read and written on every failed attempt, which is the volume an attacker controls, so moving them into the database would put a write on the path an attacker can drive. The cost is that with N instances an attacker spreading attempts evenly gets up to N times the threshold before a ban — but the ban that follows is global, and the escalation to a permanent ban has been shared from the start. The weakening is bounded; the enforcement is not.

The event table is swept in batches of 5,000 rather than one DELETE across months of history, which on MySQL holds locks for the duration and on PostgreSQL leaves a very large vacuum behind.

## Locked Out

The SSO configuration now lives in the database and is edited through a console that SSO guards, so one wrong tenant ID could lock out every administrator. Two ways back in:

**A local emergency account** (through the browser):

```bash
wifi-portal admin add ops          # prompts for a password, stored with argon2id
wifi-portal admin enable           # turns on /admin/login/local
wifi-portal admin enable 10.0.0.0/8,192.168.0.0/16   # optionally restrict by network
wifi-portal admin disable          # turn it off when done
```

While disabled, `/admin/login/local` returns 404 rather than advertising that it exists. Ten failures in fifteen minutes locks the account.

**The CLI, straight against the database** (no browser needed):

```bash
wifi-portal config list                    # every setting, credentials masked
wifi-portal config get oidc.tenant_id
wifi-portal config set oidc.tenant_id 00000000-1111-2222-3333-444444444444
wifi-portal config unset tls.mode          # back to the default
```

These read the same bootstrap environment the portal does (`SESSION_SECRET`, `ENCRYPTION_KEY`, `DATA_DIR`, `DB_DSN`), so run them with the same env file. Under Docker: `docker compose exec portal wifi-portal config list`.

There is one more layer: **a bad configuration no longer stops the portal from starting**. It used to exit on a broken OIDC setup, which was right when the only fix was editing `.env` and restarting. The fix now lives in a console this same process serves, so exiting would take away the only tool for repairing it. Instead the portal starts, sign-in returns a clear error, and the console shows the problem on the settings section that causes it.

## Deployment Modes

| | **A - External reverse proxy** | **B - LAN box** | **C - Prebuilt image UI** | **D - Bare binary + systemd** |
|---|---|---|---|---|
| Best for | Public VPS with aaPanel/Nginx TLS | On-site Pi / mini-PC | Synology NAS / iKuai UI without CLI | Linux host without Docker |
| Runtime | docker compose | docker compose | Docker UI | systemd |
| Source on target | yes | yes | no, upload image tarball | no, download binary |
| Main UI | CLI | CLI | Web UI | CLI |
| TLS | external proxy **or portal-terminated** | Caddy DNS-01, or upload a PEM | Caddy DNS-01 | external proxy **or portal-terminated** |
| Public attack surface | yes, mitigated by app rate limits | no, iKuai DNS hijack | no | depends on proxy |
| Remote admin access | yes | usually no | usually no | yes |

Modes A and B share [`deploy/docker-compose.yml`](./deploy/docker-compose.yml) and switch through `.env`:

- empty `COMPOSE_PROFILES` -> Mode A, Portal only, TLS handled externally
- `COMPOSE_PROFILES=caddy` -> Mode B, Portal plus Caddy with DNS-01 TLS

Mode C uses [`deploy/prebuilt-image/`](./deploy/prebuilt-image/) and skips builds on the target machine. See [`deploy/prebuilt-image/README.md`](./deploy/prebuilt-image/README.md).

Mode D uses release binaries and systemd. See "Bare Binary + systemd" below.

All modes can be mixed. Sharing the same `SESSION_SECRET` lets one admin login work across all `/admin` deployments.

Since TLS moved into the console (see [Where Configuration Lives](#where-configuration-lives)), Modes A and D can drop the reverse proxy: switch System → TLS to "the portal terminates TLS" and set the domain, port and certificate on that one page. The "external proxy" column is still correct for a host where 443 already belongs to another site.

Several instances can share one MySQL or PostgreSQL database; see [Database](#database).

## Repository Layout

```text
WiFi-Roaming-With-iKuai/
├── README.md
├── README.en.md
├── portal/
│   ├── main.go                # HTTP routes and startup
│   ├── config.go              # env config loader
│   ├── session.go             # HMAC signed cookies
│   ├── oidc.go                # Entra OIDC flow
│   ├── duo.go                 # Duo Auth API preauth client
│   ├── duo_universal.go       # Duo Universal Prompt client
│   ├── admin.go               # guest-code storage and generation
│   ├── auth_proceed.go        # opaque /auth/proceed bridge
│   ├── ratelimit.go           # failure counters, cooldowns, client IP parsing
│   ├── ikuai.go               # iKuai allow-list token generation
│   ├── eventlog.go            # structured login/admin audit log
│   ├── i18n.go                # zh-cn / zh-tw / en strings
│   ├── templates/
│   ├── static/
│   ├── Dockerfile
│   ├── .env.example
│   └── go.mod
└── deploy/
    ├── docker-compose.yml
    ├── Caddyfile
    ├── Dockerfile.caddy
    ├── aapanel-nginx-snippet.conf
    └── prebuilt-image/
```

## Docker Deployment

Prerequisites:

- Entra App Registration
- DNS and reverse proxy / TLS infrastructure
- iKuai custom authentication appkey

Recommended directory on the target:

```bash
sudo mkdir -p /opt/wifi-portal
sudo chown $USER:$USER /opt/wifi-portal
cd /opt/wifi-portal
```

Copy these files into the target directory:

- `portal/`
- `deploy/docker-compose.yml`
- for Mode B only: `deploy/Caddyfile` and `deploy/Dockerfile.caddy`
- copy `portal/.env.example` to `.env`

The final layout should place `docker-compose.yml`, `.env`, and `portal/` in the same directory. Do not run compose from the repository `deploy/` directory, because the build context expects `./portal` next to the compose file.

```bash
cp portal/.env.example .env
chmod 600 .env
vim .env
```

Key mode switch:

```bash
# Mode A: Portal only, TLS handled by external reverse proxy.
COMPOSE_PROFILES=

# Mode B: Portal + Caddy, automatic DNS-01 TLS.
COMPOSE_PROFILES=caddy
```

Start:

```bash
docker compose up -d --build
docker compose ps
docker compose logs -f portal
```

Mode A should expose Portal only on host `127.0.0.1:28080` for Nginx / aaPanel to reverse proxy.

Mode B starts an additional Caddy container and serves HTTPS on `${PORTAL_HTTPS_PORT:-28081}`. Add the matching Entra Redirect URI, for example:

```text
https://wifi.login.example.com:28081/auth/callback
```

For each site in Mode B, configure iKuai internal DNS:

```text
wifi.login.example.com -> LAN IP of the box running Caddy
```

Then set iKuai custom authentication URL:

```text
https://wifi.login.example.com:28081/portal
```

## Required Configuration

> Everything in this table except `SESSION_SECRET` and `ENCRYPTION_KEY` is a
> **first-run seed**: imported into the database at startup, then edited in
> /admin → Settings. Editing `.env` afterwards has no effect. See
> [Where Configuration Lives](#where-configuration-lives).

Common variables:

| Variable | Meaning |
|---|---|
| `TENANT_ID` | Microsoft Entra tenant ID |
| `CLIENT_ID` | Entra App Registration client ID |
| `CLIENT_SECRET` | Entra client secret |
| `IKUAI_APPKEY` | iKuai custom authentication appkey |
| `PUBLIC_URL` | externally reachable Portal URL, including port if any |
| `SESSION_SECRET` | `openssl rand -hex 32`; share across sites if admin cookie sharing is wanted (**bootstrap, stays in the environment**) |
| `ENCRYPTION_KEY` | `openssl rand -hex 32`; encrypts credentials at rest (**bootstrap, stays in the environment**). Empty still starts, with a warning, and stores them in plaintext |
| `DB_DSN` | Optional. Empty uses the embedded SQLite file; see [Database](#database) |
| `BRAND_NAME` | display name |
| `BRAND_COLOR` | CSS hex color, defaults to `#2563eb` |
| `BRAND_LOGO_URL` | optional external logo; empty uses bundled static logos |
| `ADMIN_EMAILS` | comma-separated admin UPN allowlist |
| `ADMIN_GROUP_IDS` | comma-separated Entra Security Group Object IDs |

Duo variables are optional. All five must be set or all five empty:

| Variable | Duo Application |
|---|---|
| `DUO_IKEY` / `DUO_SKEY` | Duo "Auth API", used only for preauth lookup |
| `DUO_CLIENT_ID` / `DUO_CLIENT_SECRET` | Duo "Web SDK", used for Universal Prompt |
| `DUO_API_HOST` | shared Duo API hostname, such as `api-XXXXXXXX.duosecurity.com` |
| `ALLOWED_EMAIL_DOMAINS` | required when Duo is enabled |

Mode B Caddy variables:

| Variable | Meaning |
|---|---|
| `CLOUDFLARE_API_TOKEN` | Cloudflare token scoped to `Zone:DNS:Edit` and `Zone:Zone:Read` |
| `ACME_EMAIL` | Let's Encrypt / ZeroSSL account email |
| `PORTAL_HOSTNAME` | public hostname, usually `wifi.login.example.com` |
| `PORTAL_HTTPS_PORT` | HTTPS port, default `28081` |

## Duo Setup

Create two Applications in Duo Admin Panel:

1. **Auth API**
   - Used only for `preauth`, to ask whether a user exists in Duo.
   - Maps to `DUO_IKEY` and `DUO_SKEY`.

2. **Web SDK**
   - Used for Duo Universal Prompt.
   - Redirect URI: `https://wifi.login.example.com/auth/duo-callback`
   - Maps to `DUO_CLIENT_ID` and `DUO_CLIENT_SECRET`.

Both applications share `DUO_API_HOST`.

## Admin Console

`/admin` is enabled when either `ADMIN_EMAILS` or `ADMIN_GROUP_IDS` is configured.

Recommended Entra group setup:

1. Add a `groups` claim to the Entra App Registration token configuration.
2. Create or choose a Security Group.
3. Copy the group's Object ID into `ADMIN_GROUP_IDS`.

The admin console provides:

- dashboard counters for login volume, failure rate, active guest codes, banned IPs/MACs
- guest-code creation, batch generation, expiry, per-use duration, max-use limits, search, filters, bulk cleanup
- iKuai allow-list policy editing by auth source
- MAC denylist with CSV export/import
- rate-limit state inspection and manual reset
- event log filtering and CSV export

The console also configures the portal itself — settings, TLS and certificates — see [Where Configuration Lives](#where-configuration-lives).

State lives in the database, by default an SQLite file under `/data` in containers:

| Table | Content |
|---|---|
| `setting` | every runtime setting; credential fields encrypted |
| `guest_code` / `guest_code_use` | guest codes and each redemption |
| `denied_mac` | MAC denylist |
| `ikuai_policy` | admin-edited iKuai policies |
| `event` | login and admin audit events |
| `ip_ban` / `ban_history` | IP cooldowns and escalation counts |
| `local_admin` | emergency accounts (argon2id) |
| `certificate` | TLS certificates and the ACME account, private keys encrypted |

`docker-compose.yml` bind-mounts `/data` to host `./data`. Change the volume line to move storage, or set `DB_DSN` to use an external server.

The five JSON files older versions wrote are imported once on first start and left in place renamed to `*.migrated`.

## Bare Binary + systemd

Download a release binary:

- `wifi-portal-vX.Y.Z-linux-amd64`
- `wifi-portal-vX.Y.Z-linux-arm64`

Or build from source with Go 1.25+ and Node 22+:

```bash
cd portal

# 1. Build the frontend. The output lands in internal/web/dist/, which the next
#    step packs into the binary via //go:embed.
cd web-react && npm ci && npm run build && cd ..

# 2. Build the Go binary.
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /tmp/wifi-portal .
```

> **Skipping step 1**: `go build` still succeeds — a `.gitkeep` placeholder in
> `internal/web/dist/` exists precisely so contributors touching only Go code do
> not need Node, and so the `go vet` / `go test` CI jobs do not have to build the
> frontend first. The resulting binary starts, but answers every page with
> `frontend bundle not built` and logs the same hint. A binary you intend to ship
> must have the frontend built first.

Run once without env to generate config templates:

```bash
./wifi-portal
```

The binary embeds `.env.example` and `wifi-portal.service`; first-run init writes:

- `wifi-portal.env`
- `wifi-portal.service`

Custom paths:

```bash
./wifi-portal init \
  --out-dir ./tmpconfig \
  --conf-dir /etc/wifi-portal \
  --data-dir /var/lib/wifi-portal \
  --bin-path /usr/local/bin/wifi-portal
```

Install:

```bash
sudo useradd -r -s /usr/sbin/nologin -d /var/lib/wifi-portal wifi-portal
sudo mkdir -p /var/lib/wifi-portal /etc/wifi-portal
sudo chown wifi-portal:wifi-portal /var/lib/wifi-portal
sudo cp ./tmpconfig/wifi-portal.env /etc/wifi-portal/
sudo chmod 600 /etc/wifi-portal/wifi-portal.env
sudo cp ./tmpconfig/wifi-portal.service /etc/systemd/system/
sudo cp ./wifi-portal /usr/local/bin/
sudo systemctl daemon-reload
sudo systemctl enable --now wifi-portal
sudo journalctl -u wifi-portal -f
```

For TLS, either keep the portal on `127.0.0.1:28080` and terminate with nginx / Caddy / aaPanel — the console generates the snippet under System → TLS — or let the portal terminate TLS itself. Binding 443 from systemd needs the capability:

```ini
# [Service] section of /etc/systemd/system/wifi-portal.service
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
```

Without it, choose a listen address above port 1024 on the TLS page.

## iKuai Integration

Configure iKuai:

1. Generate custom authentication appkey and set `IKUAI_APPKEY`.
2. Configure Web Authentication -> Custom Authentication.
3. Portal URL:
   - Mode A/D: `https://wifi.login.example.com/portal`
   - Mode B/C: `https://wifi.login.example.com:28081/portal`
4. Bind the SSID `Kazuha Hub Roaming` to this authentication.
5. Add unauthenticated allowlist domains for Entra, Duo, Portal, and iKuai cloud auth.

Required domain allowlist examples:

```text
microsoftonline.com
microsoft.com
windows.net
live.com
msftauth.net
msauth.net
duosecurity.com
example.com
ikuai8-wifi.com
```

iKuai domain rules usually cover subdomains when the bare domain is listed. If you prefer stricter matching, list exact FQDNs such as `login.microsoftonline.com`, `aadcdn.msauth.net`, your Duo API host, `wifi.login.example.com`, and `portal.ikuai8-wifi.com`.

Do not allowlist captive-portal detection domains such as `connectivitycheck.gstatic.com`, `captive.apple.com`, or `www.msftconnecttest.com`; operating systems must be intercepted so the login page opens.

## Operations

Common commands:

```bash
docker compose logs -f portal
docker compose restart portal          # only needed for bootstrap variables
docker compose up -d --build
docker compose down
docker stats wifi-portal
docker compose exec portal sh

# Read and repair settings without a browser; see "Locked Out".
docker compose exec portal wifi-portal config list
docker compose exec portal wifi-portal config set oidc.tenant_id <tenant>
docker compose exec -it portal wifi-portal admin add ops
docker compose exec portal wifi-portal admin enable
```

Health check:

```bash
curl https://wifi.login.example.com/healthz
```

Basic portal check with fake iKuai query:

```bash
curl -I "https://wifi.login.example.com/portal?user_ip=192.168.1.100&mac=aa:bb:cc:dd:ee:ff"
```

Expected: HTTP 200 and `Set-Cookie: kz_wifi_sess=...`.

## Troubleshooting

### A change to `.env` had no effect

By design. After the first start, runtime configuration is read from the database
and the `.env` values are only seeds. Change it in /admin → Settings, or with
`wifi-portal config set`. The startup log lists any stale variables still set.

Only the bootstrap variables (`SESSION_SECRET`, `ENCRYPTION_KEY`, `DATA_DIR`,
`DB_DSN`, `DB_MAX_OPEN_CONNS`, `LISTEN_ADDR`, `TRUST_PROXY`) still come from the
environment, and those need a restart.

### The console is unreachable after a TLS change

Listener changes are commit-confirm: without a confirmation from the new address
within two minutes, the previous configuration is restored. Wait it out. If the
rollback also failed — the log says so — use the CLI:

```bash
wifi-portal config set tls.mode proxy
wifi-portal config set tls.redirect_http false
# then restart the process
```

### 502 from external reverse proxy

Check:

```bash
docker compose ps
ss -tlnp | grep 28080
docker compose exec portal wget -O- http://127.0.0.1:28080/healthz
```

### 502 from Caddy with `connect: connection refused`

Portal must listen on `0.0.0.0:28080` inside the container. If it listens only on `127.0.0.1:28080`, healthcheck can pass while Caddy cannot connect over the compose network.

Use:

```yaml
environment:
  - LISTEN_ADDR=0.0.0.0:28080
```

Then recreate the container:

```bash
docker compose up -d --force-recreate portal
```

### `session lost`

iKuai may be sending different query field names. Check request logs and update:

```text
IKUAI_IP_KEYS=user_ip,ip,ipaddr
IKUAI_MAC_KEYS=user_mac,mac,usrmac,devmac
```

### Entra login hangs

The client device probably cannot reach Entra before authentication. Add the required Microsoft domains to the iKuai unauthenticated allowlist.

## Security Model

Default application-level defenses:

- OIDC `state` and `nonce` verification.
- Entra `tid`, `iss`, and `aud` verification.
- B2B guests containing `#EXT#` rejected.
- Signed short-lived cookies.
- Secure response headers.
- Account-enumeration defense through opaque `/auth/proceed` token.
- Three rate-limit layers:
  - email failures at `/auth/start`
  - MAC failures at `/auth/guest-code`
  - IP failures across endpoints
- Short IP cooldowns; no permanent IP bans by default.
- MAC denylist for device-level operational blocks.
- Structured event log and admin audit log.
- `robots.txt` and noindex templates.
- Credentials encrypted at rest with AES-256-GCM, and never returned to the browser.

Rate-limit defaults, edited under Settings → Rate limiting (or with
`wifi-portal config set`):

```text
ratelimit.email_fails_short=5     ratelimit.email_window_short=3m
ratelimit.email_fails_long=20     ratelimit.email_window_long=1h
ratelimit.mac_fails=6             ratelimit.mac_window=30m
ratelimit.ip_fails=20             ratelimit.ip_window=5m
ratelimit.ip_ban_duration=2m
ratelimit.ip_ban_escalate_at=999999
auth.proceed_ttl=5m
eventlog.retention_days=7
```

Across several instances, IP cooldowns and escalation counts are shared through
the database while the failure counters are per-process; see [Database](#database)
for what that means.

`TRUST_PROXY=true` is correct behind a reverse proxy. If Portal is directly exposed to the public internet, set `TRUST_PROXY=false`; otherwise attackers can spoof `X-Real-IP` and bypass IP limits. It stays an environment variable on purpose: setting it wrong silently disables every IP limit, which should not be one mis-click away in a web form.

For stronger perimeter protection, allowlist `/portal` and `/auth/*` at nginx by the known iKuai router WAN IPs. Valid captive-portal traffic should come from those router WAN IPs.

## Release

Pushing a tag matching `v*.*.*` triggers `.github/workflows/release.yml`, which:

- builds linux/amd64 and linux/arm64 binaries
- builds and pushes a multi-arch GHCR image
- saves single-arch Docker tarballs for Mode C
- computes SHA-256 checksums
- creates a GitHub Release with assets

```bash
git tag v0.4.1
git push origin v0.4.1
```

## License

Licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**. Full text: [`LICENSE`](./LICENSE).

You are free to use, modify, and redistribute this software. Because it is AGPL-3.0, if you run a version of it as a network service, you must offer its users the corresponding complete source code of that version.

Bundled dependencies are licensed under Apache-2.0 (`github.com/coreos/go-oidc/v3`, `github.com/go-jose/go-jose/v4`) and BSD-3-Clause (`golang.org/x/oauth2`), both compatible with AGPL-3.0.
