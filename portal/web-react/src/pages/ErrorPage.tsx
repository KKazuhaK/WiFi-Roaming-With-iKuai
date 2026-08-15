import { Button } from 'antd'
import { CardShell } from '@/components/CardShell'
import { config } from '@/lib/config'
import { t, type Lang } from '@/lib/i18n'

/**
 * Terminal state for a failed auth attempt. The message is produced server-side
 * (renderError) and arrives through the injected config, because the reasons are
 * decided in Go — a rejected #EXT# guest account, a Duo denial, an expired state
 * parameter — and only the server knows which one happened.
 *
 * The action is a plain link, not a fetch: the user needs a fresh document with
 * a fresh session, and this page is often reached after the previous one's state
 * was invalidated.
 */
export function ErrorPage({ lang, onLang }: { lang: Lang; onLang: (l: Lang) => void }) {
  return (
    <CardShell lang={lang} onLang={onLang} title={t('errors.title')} titleDanger>
      <p className="card-subtitle">{config.message}</p>
      <Button type="primary" size="large" block href="/login">
        {t('login.btn.sso', config.brand.name)}
      </Button>
    </CardShell>
  )
}
