// Wire types for the admin endpoints.
//
// These mirror Go structs whose JSON tags are the actual contract:
// adminPageData / adminCodeRow / adminDeniedMACRow / DashboardStats in main.go,
// IKuaiPolicyRow in ikuai_policy.go, and the anonymous response structs in
// handleRateLimitStatus and handleEventsQuery. A field renamed on one side and
// not the other fails silently — it decodes as undefined rather than throwing —
// so the two sides carry cross-references in their comments.

export interface CodeRow {
  code: string
  createdAt: string
  /** Pre-formatted for display, or the "never expires" string. */
  expiresAt: string
  /** "2006-01-02T15:04" for the DatePicker, empty when the code never expires. */
  expiresAtInput: string
  duration: string
  durationMin: number
  status: 'unused' | 'used' | 'expired'
  useCount: number
  /** 0 means unlimited. */
  maxUses: number
  lastUsedAt: string
  lastUsedMac: string
  lastUsedIp: string
  note: string
}

export interface DeniedMacRow {
  mac: string
  reason: string
  createdAt: string
  createdBy: string
}

export interface IKuaiPolicyRow {
  Profile: string
  Label: string
  Upload: number
  Download: number
  Timeout: number
  Comment: string
}

export interface DashboardStats {
  loginsToday: number
  loginsWeek: number
  failedRatePct: number
  failedCount7d: number
  activeGuestCodes: number
  bannedIps: number
  bannedMacs: number
}

/** Counts behind the status tabs, computed server-side over the whole table. */
export interface CodeStats {
  total: number
  used: number
  unused: number
  expired: number
}

/**
 * The shared admin state.
 *
 * Deliberately no longer carries the guest-code or denylist rows: those arrive
 * a page at a time from /admin/api/codes and /admin/api/macs, so an installation
 * with fifty thousand codes no longer serialises all of them — plus every
 * redemption ever recorded — on each page load.
 */
export interface AdminState {
  lang: string
  ikuaiPolicies: IKuaiPolicyRow[]
  total: number
  used: number
  unused: number
  expired: number
  dashboard: DashboardStats
}

// --- Rate limiting ---

export interface FailSnapshot {
  key: string
  count: number
  latest_unix: number
}

export interface IpBan {
  ip: string
  expires_unix: number
  ban_count: number
  permanent: boolean
}

export interface RateLimitThresholds {
  email_short: number
  email_short_s: number
  email_long: number
  email_long_s: number
  mac: number
  mac_s: number
  ip: number
  ip_s: number
  ip_ban_s: number
  ip_ban_escalate: number
}

export interface RateLimitStatus {
  ok: boolean
  ip_bans: IpBan[]
  /** Every IP ever cooled down, including ones no longer banned. */
  ban_history: Record<string, number>
  email_fails: FailSnapshot[]
  guest_mac_fails: FailSnapshot[]
  ip_fails: FailSnapshot[]
  now_unix: number
  thresholds: RateLimitThresholds
}

/** The four counters /admin/ratelimit/reset accepts as its `type` field. */
export type ResetType = 'ip_ban' | 'email' | 'mac' | 'ip_fails'

// --- Event log ---

export interface EventRow {
  time_unix: number
  /** Pre-formatted in the server's timezone; see buildAdminData's note. */
  time_iso: string
  kind: string
  subject: string
  result: string
  method: string
  mac?: string
  ip?: string
  detail?: string
}

export interface EventsResponse {
  ok: boolean
  events: EventRow[]
  count: number
}

export interface EventFilters {
  kind: string
  method: string
  result: string
  subject: string
  /** Seconds of history; 0 means no lower bound. */
  rangeSeconds: number
}
