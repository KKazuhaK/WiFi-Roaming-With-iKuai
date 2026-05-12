# Kazuha Hub Roaming

Languages: [中文](./README.md) | [English](./README.en.md)

A unified WiFi access portal for the SSID **`Kazuha Hub Roaming`**.

Users land on a captive portal and choose one of these paths:

- **Duo users** who are enrolled in Duo Mobile go directly to Duo Universal Prompt, complete 2FA, and are allow-listed.
- **Non-Duo users** fall back to Microsoft Entra SSO and are allow-listed after login.
- **External guest accounts** whose UPN contains `#EXT#` are rejected.
- **Visitors without organization accounts** use one-time guest codes issued by admins.

Every successful path ultimately calls iKuai custom authentication (`type=20`) and allow-lists the device MAC / IP.

## Deployment Modes

| | **A - External reverse proxy** | **B - LAN box** | **C - Prebuilt image UI** | **D - Bare binary + systemd** |
|---|---|---|---|---|
| Best for | Public VPS with aaPanel/Nginx TLS | On-site Pi / mini-PC | Synology NAS / iKuai UI without CLI | Linux host without Docker |
| Runtime | docker compose | docker compose | Docker UI | systemd |
| Source on target | yes | yes | no, upload image tarball | no, download binary |
| Main UI | CLI | CLI | Web UI | CLI |
| TLS | external proxy | Caddy DNS-01 | Caddy DNS-01 | external proxy |
| Public attack surface | yes, mitigated by app rate limits | no, iKuai DNS hijack | no | depends on proxy |
| Remote admin access | yes | usually no | usually no | yes |

Modes A and B share [`deploy/docker-compose.yml`](./deploy/docker-compose.yml) and switch through `.env`:

- empty `COMPOSE_PROFILES` -> Mode A, Portal only, TLS handled externally
- `COMPOSE_PROFILES=caddy` -> Mode B, Portal plus Caddy with DNS-01 TLS

Mode C uses [`deploy/prebuilt-image/`](./deploy/prebuilt-image/) and skips builds on the target machine. See [`deploy/prebuilt-image/README.md`](./deploy/prebuilt-image/README.md).

Mode D uses release binaries and systemd. See "Bare Binary + systemd" below.

All modes can be mixed. Sharing the same `SESSION_SECRET` lets one admin login work across all `/admin` deployments.

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
https://wifi.login.kazuhahub.com:28081/auth/callback
```

For each site in Mode B, configure iKuai internal DNS:

```text
wifi.login.kazuhahub.com -> LAN IP of the box running Caddy
```

Then set iKuai custom authentication URL:

```text
https://wifi.login.kazuhahub.com:28081/portal
```

## Required Configuration

Common variables:

| Variable | Meaning |
|---|---|
| `TENANT_ID` | Microsoft Entra tenant ID |
| `CLIENT_ID` | Entra App Registration client ID |
| `CLIENT_SECRET` | Entra client secret |
| `IKUAI_APPKEY` | iKuai custom authentication appkey |
| `PUBLIC_URL` | externally reachable Portal URL, including port if any |
| `SESSION_SECRET` | `openssl rand -hex 32`; share across sites if admin cookie sharing is wanted |
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
| `PORTAL_HOSTNAME` | public hostname, usually `wifi.login.kazuhahub.com` |
| `PORTAL_HTTPS_PORT` | HTTPS port, default `28081` |

## Duo Setup

Create two Applications in Duo Admin Panel:

1. **Auth API**
   - Used only for `preauth`, to ask whether a user exists in Duo.
   - Maps to `DUO_IKEY` and `DUO_SKEY`.

2. **Web SDK**
   - Used for Duo Universal Prompt.
   - Redirect URI: `https://wifi.login.kazuhahub.com/auth/duo-callback`
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

Persistent files live under `/data` in containers:

| File | Content |
|---|---|
| `/data/guest-codes.json` | guest codes |
| `/data/denylist.json` | MAC denylist |
| `/data/ikuai-policy.json` | admin-edited iKuai policies |
| `/data/ratelimit-state.json` | IP cooldown history |
| `/data/events.jsonl` | login and admin audit events |

`docker-compose.yml` bind-mounts `/data` to host `./data`. Change the volume line to move storage.

## Bare Binary + systemd

Download a release binary:

- `wifi-portal-vX.Y.Z-linux-amd64`
- `wifi-portal-vX.Y.Z-linux-arm64`

Or build from source with Go 1.25+:

```bash
cd portal
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /tmp/wifi-portal .
```

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

Portal should listen on `127.0.0.1:28080`; terminate TLS with nginx / Caddy / aaPanel and reverse proxy to it.

## iKuai Integration

Configure iKuai:

1. Generate custom authentication appkey and set `IKUAI_APPKEY`.
2. Configure Web Authentication -> Custom Authentication.
3. Portal URL:
   - Mode A/D: `https://wifi.login.kazuhahub.com/portal`
   - Mode B/C: `https://wifi.login.kazuhahub.com:28081/portal`
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
kazuhahub.com
ikuai8-wifi.com
```

iKuai domain rules usually cover subdomains when the bare domain is listed. If you prefer stricter matching, list exact FQDNs such as `login.microsoftonline.com`, `aadcdn.msauth.net`, your Duo API host, `wifi.login.kazuhahub.com`, and `portal.ikuai8-wifi.com`.

Do not allowlist captive-portal detection domains such as `connectivitycheck.gstatic.com`, `captive.apple.com`, or `www.msftconnecttest.com`; operating systems must be intercepted so the login page opens.

## Operations

Common commands:

```bash
docker compose logs -f portal
docker compose restart portal
docker compose up -d --build
docker compose down
docker stats wifi-portal
docker compose exec portal sh
```

Health check:

```bash
curl https://wifi.login.kazuhahub.com/healthz
```

Basic portal check with fake iKuai query:

```bash
curl -I "https://wifi.login.kazuhahub.com/portal?user_ip=192.168.1.100&mac=aa:bb:cc:dd:ee:ff"
```

Expected: HTTP 200 and `Set-Cookie: kz_wifi_sess=...`.

## Troubleshooting

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

Rate-limit defaults:

```text
AUTH_EMAIL_FAILS_SHORT=5
AUTH_EMAIL_WINDOW_SHORT=3m
AUTH_EMAIL_FAILS_LONG=20
AUTH_EMAIL_WINDOW_LONG=1h
GUEST_CODE_MAC_FAILS=6
GUEST_CODE_MAC_WINDOW=30m
IP_FAILS_LIMIT=20
IP_FAILS_WINDOW=5m
IP_BAN_DURATION=2m
IP_BAN_ESCALATE_AT=999999
AUTH_PROCEED_TTL=5m
EVENT_LOG_RETENTION_DAYS=7
```

`TRUST_PROXY=true` is correct behind a reverse proxy. If Portal is directly exposed to the public internet, set `TRUST_PROXY=false`; otherwise attackers can spoof `X-Real-IP` and bypass IP limits.

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
