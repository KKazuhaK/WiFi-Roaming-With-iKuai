// Translation lookup, deliberately not i18next.
//
// portal/i18n/*.json is a flat key -> string map with printf-style %s / %d
// placeholders, and the Go side (i18n.go) validates at startup that every
// language carries every EN key. Adopting i18next would mean either rewriting
// 229 strings into {{named}} interpolation — breaking the Go templates that
// still read the same files during auth redirects — or maintaining a converter.
// Reimplementing Go's T() is about thirty lines and keeps one source of truth.
//
// The three locales are imported statically rather than fetched per language.
// They are roughly 10KB brotli in total, and the alternative — a dynamic import
// keyed on config.lang — inserts a network round trip before first paint, which
// is exactly the wrong trade on a captive-portal page whose whole job is to run
// before the device has working internet.

import zhCN from '@i18n/zh-cn.json'
import zhTW from '@i18n/zh-tw.json'
import en from '@i18n/en.json'
import { config, SUPPORTED_LANGS, type Lang } from './config'

// Re-exported so components import the language type from the module they
// already import t() from, instead of reaching into config for it.
export type { Lang }

type Dict = Record<string, string>

const DICTS: Record<Lang, Dict> = {
  'zh-cn': zhCN as Dict,
  'zh-tw': zhTW as Dict,
  en: en as Dict,
}

let current: Lang = config.lang

export function getLang(): Lang {
  return current
}

/**
 * Switch the active language in place.
 *
 * The old pages navigated to ?lang=xx for this. Re-requesting the document on a
 * captive-portal link that has not been unlocked yet is the slowest possible way
 * to relabel some buttons, so the swap happens client-side. The query parameter
 * is still rewritten via replaceState because the server reads it: pickLang()
 * consults ?lang first, so any later form post, OIDC redirect or full reload
 * lands on the language the user actually picked.
 */
export function setLang(lang: Lang): void {
  if (!SUPPORTED_LANGS.includes(lang)) return
  current = lang
  const url = new URL(window.location.href)
  url.searchParams.set('lang', lang)
  window.history.replaceState(null, '', url.pathname + url.search + url.hash)
  document.documentElement.setAttribute('lang', lang)
}

/**
 * Look up `key` and substitute positional %s / %d placeholders, mirroring
 * fmt.Sprintf as used by Go's T(). Missing keys fall back to EN and then to the
 * literal key, so an untranslated string shows up as `admin.foo.bar` in the UI
 * instead of silently rendering as empty text.
 */
export function t(key: string, ...args: (string | number)[]): string {
  const s = DICTS[current]?.[key] ?? DICTS.en[key]
  if (s === undefined) return key
  if (args.length === 0) return s
  let i = 0
  return s.replace(/%[sd]/g, () => {
    const v = args[i++]
    return v === undefined || v === null ? '' : String(v)
  })
}
