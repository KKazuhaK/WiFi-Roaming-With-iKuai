# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities **privately**. Do **not** open a public
GitHub issue, pull request, or discussion for a security problem — public
disclosure before a fix is available puts deployments at risk.

Use GitHub private vulnerability reporting:

1. Go to the repository **Security** tab.
2. Click **Report a vulnerability**.
3. Describe the issue, affected version/commit, and reproduction steps.

<!-- Optional: maintainers may add a dedicated security contact email here, e.g. security@example.com -->

This is a small, best-effort project. We will acknowledge reports as soon as we
can, but cannot commit to a fixed response time. Please include enough detail to
reproduce the issue. We appreciate coordinated disclosure and will credit
reporters who want it.

## Supported Versions

Only the latest tagged release and the `main` branch receive security fixes.
Older tags are not patched — upgrade to the latest release.

| Version            | Supported          |
|--------------------|--------------------|
| Latest release tag | :white_check_mark: |
| `main` branch      | :white_check_mark: |
| Older tags         | :x:                |

## Security Model

This is a self-hosted iKuai captive-portal authentication gateway. Users
authenticate via Microsoft Entra SSO, Duo 2FA, or admin-issued one-time guest
codes; on success the device MAC/IP is allow-listed on the iKuai router. The
portal is designed to face the public internet and ships the following
application-level defenses on by default:

- **OIDC `state` and `nonce`** verification on the Entra flow (CSRF / replay).
- **Entra token validation**: `tid` (tenant), `iss` (issuer), and `aud`
  (audience) claims are checked.
- **B2B guest rejection**: UPNs containing `#EXT#` are denied.
- **Signed, short-lived cookies**: HMAC-signed session cookies (15 min for Wi-Fi
  login, 1 h for the `/admin` console).
- **Three rate-limit layers**: email failures at `/auth/start`, MAC failures at
  `/auth/guest-code`, and a per-IP failure backstop across all endpoints, with
  short IP cooldowns (no permanent IP bans by default).
- **MAC denylist**: device-level operational blocking, checked at `/portal` and
  on every auth callback.
- **Account-enumeration defense**: `/auth/start` returns an opaque token and the
  browser is redirected through `/auth/proceed`, so responses are uniform across
  emails and Duo-vs-Entra routing is not leaked.
- **Secure response headers** (CSP, X-Frame-Options, X-Content-Type-Options,
  Referrer-Policy) plus `robots.txt` `Disallow: /` and `noindex` templates.
- **Structured audit log**: login events and admin actions are recorded to
  `/data/events.jsonl`; passwords and tokens are never logged, and guest login
  events record only the last 4 characters of the code.

For full detail (thresholds, env vars, the IP cooldown model, and what is
intentionally *not* handled at the app layer), see the Security Model section in
the README:

- English: [Security Model](./README.en.md#security-model)
- 中文: [安全 / 防滥用](./README.md#%E5%AE%89%E5%85%A8--%E9%98%B2%E6%BB%A5%E7%94%A8)

## Operator Responsibilities

The portal handles application-level authentication, but it relies on the
operator for the deployment perimeter. When you run this gateway you are
responsible for:

- **Terminating TLS** in front of the portal (external nginx / aaPanel, or the
  built-in Caddy in Mode B). The portal speaks plain HTTP to the proxy.
- **Not exposing the portal port publicly**. Bind the host listener to
  `127.0.0.1:28080` (Mode A / D) or keep it on the internal compose network only
  (Mode B / C). If the portal port *is* directly reachable from the internet,
  you **must** set `TRUST_PROXY=false`, otherwise attackers can spoof
  `X-Real-IP` and bypass every IP rate limit.
- **Keeping `TRUST_PROXY` correct** for your topology: `true` only when a trusted
  reverse proxy terminates the connection and appends the real client IP.
- **Rotating secrets**: regenerate `SESSION_SECRET` (`openssl rand -hex 32`) and
  rotate the Entra `CLIENT_SECRET` before it expires. Keep `.env` /
  `wifi-portal.env` at mode `600` and out of version control.
- **Protecting the data directory**: guest codes, the MAC denylist, rate-limit
  state, and the audit log live under `DATA_DIR` (`/data` in containers,
  `/var/lib/wifi-portal` for systemd). Restrict access to it.

For the full operator checklist, see:

- English: [Security Model](./README.en.md#security-model)
- 中文: [安全清单](./README.md#%E5%AE%89%E5%85%A8%E6%B8%85%E5%8D%95)
