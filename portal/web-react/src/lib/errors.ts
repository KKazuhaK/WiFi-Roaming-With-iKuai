import { ApiError } from './api'
import { t } from './i18n'

/**
 * Render a retry delay using the same three buckets the old inline script used:
 * seconds under a minute, minutes under an hour, hours beyond that. Rounding is
 * up on purpose — telling someone to wait "1 minute" when 119 seconds remain
 * just produces a second failed attempt.
 */
export function formatRetryAfter(seconds: number): string {
  if (!seconds || seconds <= 0) return ''
  if (seconds < 60) return `${seconds} ${t('units.seconds')}`
  if (seconds < 3600) return `${Math.ceil(seconds / 60)} ${t('units.minutes')}`
  return `${Math.ceil(seconds / 3600)} ${t('units.hours')}`
}

/**
 * Turn a 429 body into a sentence. The rate limiter answers with either
 * permanent:true (the IP or MAC is on the denylist and no amount of waiting
 * helps) or retry_after_seconds, and the two need visibly different wording so
 * the user does not sit refreshing a page that will never let them in.
 */
export function rateLimitMessage(body: Record<string, unknown>): string {
  if (body.permanent === true) return t('errors.rateLimitedPermanent')
  const retry = body.retry_after_seconds
  if (typeof retry === 'number' && retry > 0) {
    return t('errors.rateLimitedRetry', formatRetryAfter(retry))
  }
  return t('errors.rateLimited')
}

/**
 * Map an ApiError from the sign-in endpoints onto a user-facing string.
 *
 * `fallback` is the message for codes this page has no specific wording for —
 * the guest-code form wants "that code is not valid" where the email form wants
 * the generic network message.
 */
export function authErrorMessage(err: unknown, fallback: string): string {
  if (!(err instanceof ApiError)) return fallback
  switch (err.code) {
    case 'invalid_email':
      return t('errors.invalidEmail')
    case 'invalid_domain':
      return t('errors.invalidDomain')
    case 'account_denied':
      return t('errors.accountDenied')
    case 'rate_limited':
      return rateLimitMessage(err.body)
    case 'network_error':
      return t('errors.generic')
    default:
      return fallback
  }
}
