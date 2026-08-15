import { Button } from 'antd'
import { LoginOutlined } from '@ant-design/icons'
import { CardShell } from '@/components/CardShell'
import { t, type Lang } from '@/lib/i18n'
import { config } from '@/lib/config'

/**
 * Admin SSO hand-off.
 *
 * Submitted as a real form POST rather than a fetch. /admin/login/start answers
 * with a 302 to Entra, and a redirect chain that ends at an identity provider
 * has to happen as a top-level navigation — following it with fetch would drop
 * the browser into a CORS wall and lose the OIDC state cookie the handler just
 * set. The POST method matters too: the handler enforces it so a prefetch or a
 * link preview cannot burn a state parameter.
 *
 * ?lang is carried on the action URL because this leaves the SPA entirely; the
 * language the user picked has to survive the trip through Entra and back.
 */
export function AdminLoginPage({ lang, onLang }: { lang: Lang; onLang: (l: Lang) => void }) {
  return (
    <CardShell
      lang={lang}
      onLang={onLang}
      title={t('admin.login.title', config.brand.name)}
      subtitle={t('admin.login.subtitle')}
    >
      <p className="card-hint">{t('admin.login.hint')}</p>
      <form method="post" action={`/admin/login/start?lang=${encodeURIComponent(lang)}`}>
        <Button type="primary" size="large" block htmlType="submit" icon={<LoginOutlined />}>
          {t('admin.login.btn.sso')}
        </Button>
      </form>
    </CardShell>
  )
}
