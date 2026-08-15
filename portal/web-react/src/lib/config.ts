// Runtime configuration handed over by the Go server.
//
// The old templates interpolated brand name, colour and feature flags straight
// into the HTML. The bundle is a static, content-hashed asset now, so anything
// that varies per deployment has to arrive at runtime. The server rewrites the
// <!--PORTAL_HEAD--> marker into a <script type="application/json"> block, which
// this module parses once at import time.
//
// A JSON script is a *data block*, not executable code — the browser never runs
// it, so it stays legal under a CSP without script-src 'unsafe-inline'. That is
// the whole reason for not using `window.__CFG = {...}` here: dropping
// 'unsafe-inline' from script-src was one of the wins of moving off templates.

export type Lang = 'zh-cn' | 'zh-tw' | 'en'

export const SUPPORTED_LANGS: readonly Lang[] = ['zh-cn', 'zh-tw', 'en']

export interface BrandConfig {
  name: string
  color: string
  /** Optional override; empty means fall back to the bundled /static logos. */
  logoUrl: string
  initial: string
}

export type PageKind = 'login' | 'error' | 'adminLogin' | 'localLogin' | 'admin'

export interface AppConfig {
  page: PageKind
  lang: Lang
  brand: BrandConfig
  nowYear: number
  /** login: whether the guest-code button is shown at all. */
  guestEnabled: boolean
  /** login: first allowed email domain, used for the input placeholder. */
  allowedDomainsHint: string
  /** error: the human-readable message the server produced. */
  message: string
  /** admin: UPN of the signed-in administrator, shown in the header. */
  adminUPN: string
}

const FALLBACK: AppConfig = {
  page: 'login',
  lang: 'en',
  brand: { name: 'Wi-Fi Portal', color: '#2563eb', logoUrl: '', initial: 'W' },
  nowYear: new Date().getFullYear(),
  guestEnabled: false,
  allowedDomainsHint: 'example.com',
  message: '',
  adminUPN: '',
}

function isLang(v: unknown): v is Lang {
  return typeof v === 'string' && (SUPPORTED_LANGS as readonly string[]).includes(v)
}

function readConfig(): AppConfig {
  const el = document.getElementById('__portal_cfg__')
  if (!el || !el.textContent) {
    // Only reachable when the bundle is opened outside the Go server — the Vite
    // dev server serves the raw template with the marker still in place. Keep
    // the app booting so `npm run dev` is usable without a backend running.
    return FALLBACK
  }
  let raw: unknown
  try {
    raw = JSON.parse(el.textContent)
  } catch {
    return FALLBACK
  }
  if (typeof raw !== 'object' || raw === null) return FALLBACK
  const o = raw as Record<string, unknown>
  const brand = (typeof o.brand === 'object' && o.brand !== null ? o.brand : {}) as Record<
    string,
    unknown
  >
  return {
    page: (o.page as PageKind) ?? FALLBACK.page,
    lang: isLang(o.lang) ? o.lang : FALLBACK.lang,
    brand: {
      name: typeof brand.name === 'string' && brand.name ? brand.name : FALLBACK.brand.name,
      color: typeof brand.color === 'string' && brand.color ? brand.color : FALLBACK.brand.color,
      logoUrl: typeof brand.logoUrl === 'string' ? brand.logoUrl : '',
      initial: typeof brand.initial === 'string' ? brand.initial : FALLBACK.brand.initial,
    },
    nowYear: typeof o.nowYear === 'number' ? o.nowYear : FALLBACK.nowYear,
    guestEnabled: o.guestEnabled === true,
    allowedDomainsHint:
      typeof o.allowedDomainsHint === 'string' && o.allowedDomainsHint
        ? o.allowedDomainsHint
        : FALLBACK.allowedDomainsHint,
    message: typeof o.message === 'string' ? o.message : '',
    adminUPN: typeof o.adminUPN === 'string' ? o.adminUPN : '',
  }
}

export const config: AppConfig = readConfig()
