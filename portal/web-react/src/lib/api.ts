// Thin fetch wrapper over the portal's JSON endpoints.
//
// Contract notes that the handlers impose and this module has to respect:
//
//   - Mutations are POST and read their inputs with r.FormValue, so bodies go
//     out url-encoded rather than as JSON. Switching the handlers to JSON would
//     have meant touching every one of them plus their tests for no user-visible
//     gain, so the wire format stays as it was.
//   - CSRF is an Origin/Referer same-origin check (isSameOriginRequest in
//     main.go), not a token. credentials:'same-origin' on a same-origin fetch
//     satisfies it with nothing to thread through the UI.
//   - Admin sessions expire server-side after an hour and every /admin/* JSON
//     endpoint answers 401 {"error":"not_logged_in"} afterwards. The old page
//     patched window.fetch globally to catch that; here it is handled once, in
//     the one place every admin request already passes through.

export class ApiError extends Error {
  readonly status: number
  /** Machine-readable code from the handler's {"error": "..."} body. */
  readonly code: string
  /** Full decoded body, for handlers that add fields such as retry_after_seconds. */
  readonly body: Record<string, unknown>

  constructor(status: number, code: string, body: Record<string, unknown>) {
    super(code)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.body = body
  }
}

let redirectingToLogin = false

function handleAdminExpiry(url: string, status: number): void {
  if (status !== 401) return
  if (!url.startsWith('/admin/')) return
  if (redirectingToLogin) return
  redirectingToLogin = true
  window.location.assign('/admin/login')
}

async function decode(resp: Response): Promise<Record<string, unknown>> {
  const text = await resp.text()
  if (!text) return {}
  try {
    const parsed: unknown = JSON.parse(text)
    return typeof parsed === 'object' && parsed !== null ? (parsed as Record<string, unknown>) : {}
  } catch {
    // A proxy error page or an HTML redirect landed here instead of JSON.
    return {}
  }
}

async function request(
  url: string,
  init: RequestInit & { rawBody?: BodyInit },
): Promise<Record<string, unknown>> {
  let resp: Response
  try {
    resp = await fetch(url, { credentials: 'same-origin', ...init })
  } catch {
    // Network-level failure: DNS, TLS, or the captive-portal walled garden
    // dropping the request. Give it a code so callers can show one message.
    throw new ApiError(0, 'network_error', {})
  }
  handleAdminExpiry(url, resp.status)
  const body = await decode(resp)
  if (!resp.ok) {
    const code = typeof body.error === 'string' ? body.error : `http_${resp.status}`
    throw new ApiError(resp.status, code, body)
  }
  return body
}

/** GET a JSON endpoint. `params` entries with undefined/empty values are dropped. */
export async function get<T = Record<string, unknown>>(
  path: string,
  params?: Record<string, string | number | undefined>,
): Promise<T> {
  let url = path
  if (params) {
    const qs = new URLSearchParams()
    for (const [k, v] of Object.entries(params)) {
      if (v === undefined || v === '') continue
      qs.set(k, String(v))
    }
    const q = qs.toString()
    if (q) url += (url.includes('?') ? '&' : '?') + q
  }
  return (await request(url, { method: 'GET' })) as T
}

/** POST url-encoded form fields, matching what r.FormValue expects. */
export async function postForm<T = Record<string, unknown>>(
  path: string,
  fields: Record<string, string | number | boolean | undefined>,
): Promise<T> {
  const body = new URLSearchParams()
  for (const [k, v] of Object.entries(fields)) {
    if (v === undefined) continue
    body.set(k, String(v))
  }
  return (await request(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8' },
    body,
  })) as T
}

/**
 * POST a JSON body.
 *
 * The older admin endpoints take url-encoded forms and stay that way; the
 * settings endpoints take JSON because a settings form submits a variable set of
 * keys and a flat form body cannot distinguish an omitted key from an empty one
 * — which is exactly the distinction the blank-means-unchanged rule for secrets
 * depends on.
 */
export async function postJSON<T = Record<string, unknown>>(
  path: string,
  body: unknown,
): Promise<T> {
  return (await request(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })) as T
}

/**
 * POST a multipart body. Only the denylist CSV import needs this; the Content-Type
 * header is deliberately not set so the browser appends the multipart boundary.
 */
export async function postMultipart<T = Record<string, unknown>>(
  path: string,
  form: FormData,
): Promise<T> {
  return (await request(path, { method: 'POST', body: form })) as T
}
