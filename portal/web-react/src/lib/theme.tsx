// antd theming, shared by both entries.
//
// Two things the old CSS did that have to survive the port:
//
//   1. Every page followed prefers-color-scheme with no toggle and no stored
//      preference. useDarkMode keeps that behaviour and, unlike the CSS media
//      query it replaces, reacts to the OS flipping mid-session.
//   2. --brand-color came from BRAND_COLOR in .env and coloured the primary
//      buttons, focus rings and active language link. It is fed to antd as
//      colorPrimary so a deployment's brand colour still drives the whole UI.
//
// What this file deliberately does NOT provide is antd's <App> wrapper or a
// locale. Both are real weight — <App> drags in the message, notification and
// modal machinery, and each locale is a separate string table — and the pages in
// the portal entry use none of it: their errors render as inline text under the
// field, and Input/Button carry no localised strings of their own. Only the
// admin entry pulls them in (see AdminShell), which keeps them out of the
// captive-portal page's chunk entirely.

import { useEffect, useState, type ReactNode } from 'react'
import { ConfigProvider, theme } from 'antd'
import type { Locale } from 'antd/es/locale'
import { config } from './config'
import type { Lang } from './config'

const DARK_QUERY = '(prefers-color-scheme: dark)'

export function useDarkMode(): boolean {
  const [dark, setDark] = useState(
    () => typeof window !== 'undefined' && window.matchMedia(DARK_QUERY).matches,
  )
  useEffect(() => {
    const mq = window.matchMedia(DARK_QUERY)
    const onChange = (e: MediaQueryListEvent) => setDark(e.matches)
    mq.addEventListener('change', onChange)
    return () => mq.removeEventListener('change', onChange)
  }, [])
  return dark
}

/**
 * Mirror the resolved scheme onto <html data-theme> and the CSS custom
 * properties the static shell in portal.html/admin.html already defines. Plain
 * CSS in our own stylesheets can then follow the same switch antd does, instead
 * of re-deriving it from a second media query that could disagree.
 */
function useSyncDocumentTheme(dark: boolean): void {
  useEffect(() => {
    const root = document.documentElement
    root.setAttribute('data-theme', dark ? 'dark' : 'light')
    root.style.setProperty('--brand-color', config.brand.color)
  }, [dark])
}

export function ThemeProvider({
  locale,
  children,
}: {
  /** Only the admin entry passes one; see the note at the top of this file. */
  locale?: Locale
  children: ReactNode
}) {
  const dark = useDarkMode()
  useSyncDocumentTheme(dark)
  return (
    <ConfigProvider
      locale={locale}
      theme={{
        algorithm: dark ? theme.darkAlgorithm : theme.defaultAlgorithm,
        token: {
          colorPrimary: config.brand.color,
          borderRadius: 10,
          // Match the stack the old templates set on body, so the port does not
          // silently change how Chinese text renders on Windows and Android.
          fontFamily:
            '-apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", ' +
            '"Hiragino Sans GB", "Microsoft YaHei", Roboto, sans-serif',
        },
      }}
    >
      {children}
    </ConfigProvider>
  )
}

export type { Lang }
