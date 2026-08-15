import { t } from '@/lib/i18n'

/**
 * Format a duration in seconds the way the old panel did: seconds under a
 * minute, minutes under an hour, then hours with a minutes remainder when there
 * is one. Used for the rate-limit thresholds line and cooldown countdowns.
 */
export function formatDurationSecs(s: number): string {
  if (s <= 0) return `0 ${t('units.seconds')}`
  if (s < 60) return `${s} ${t('units.seconds')}`
  if (s < 3600) return `${Math.round(s / 60)} ${t('units.minutes')}`
  const h = Math.floor(s / 3600)
  const m = Math.round((s % 3600) / 60)
  return m > 0 ? `${h} ${t('units.hours')} ${m} ${t('units.minutes')}` : `${h} ${t('units.hours')}`
}

/**
 * Clock time for a Unix timestamp.
 *
 * The old code hardcoded the 'zh-CN' locale here, which rendered a 24-hour clock
 * for every operator regardless of the language they had selected. Passing
 * undefined uses the browser's locale, and hour12:false keeps the 24-hour clock
 * that made the original readable — an admin scanning a cooldown list should not
 * have to parse AM/PM.
 */
export function formatClock(unix: number): string {
  return new Date(unix * 1000).toLocaleTimeString(undefined, { hour12: false })
}

/** Split minutes into the hours/minutes pair the duration inputs use. */
export function splitDuration(totalMin: number): { h: number; m: number } {
  const safe = totalMin < 0 ? 0 : totalMin
  return { h: Math.floor(safe / 60), m: safe % 60 }
}

/**
 * Ten random digits, from crypto.getRandomValues rather than Math.random.
 *
 * Modulo 10 over a uint32 is very slightly biased — 2^32 is not a multiple of
 * 10 — but this only pre-fills a suggestion in the "add code" form that an
 * admin can overwrite, and the server generates the real codes (generateCode in
 * Go) when the field is left empty. The bias is 2^-30 per digit and irrelevant
 * at this job.
 */
export function suggestNumericCode(): string {
  const arr = new Uint32Array(10)
  crypto.getRandomValues(arr)
  return Array.from(arr, (n) => String(n % 10)).join('')
}
