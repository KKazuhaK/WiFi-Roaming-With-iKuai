import type { ReactNode } from 'react'
import { BrandLogo } from './BrandLogo'
import { LangSwitch } from './LangSwitch'
import { config } from '@/lib/config'
import { t, type Lang } from '@/lib/i18n'

/**
 * Common frame for the three card pages — sign-in, admin SSO hand-off, error.
 * All three had byte-identical logo/footer/language-switch markup across three
 * templates; centralising it here means the next brand tweak is one edit.
 */
export function CardShell({
  lang,
  onLang,
  title,
  titleDanger,
  subtitle,
  children,
}: {
  lang: Lang
  onLang: (l: Lang) => void
  title: string
  titleDanger?: boolean
  subtitle?: string
  children: ReactNode
}) {
  return (
    <main className="card">
      <BrandLogo />
      <h1 className={titleDanger ? 'card-title danger' : 'card-title'}>{title}</h1>
      {subtitle ? <p className="card-subtitle">{subtitle}</p> : null}
      {children}
      <LangSwitch current={lang} onChange={onLang} />
      <div className="card-footer">
        {t('common.footer', config.brand.name)} · {config.nowYear}
      </div>
    </main>
  )
}
