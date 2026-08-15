import { useState } from 'react'
import { Alert, Button, Input } from 'antd'
import { LoginOutlined } from '@ant-design/icons'
import { CardShell } from '@/components/CardShell'
import { config } from '@/lib/config'
import { t, type Lang } from '@/lib/i18n'
import { postForm, ApiError } from '@/lib/api'

/**
 * Break-glass password login.
 *
 * Reached only when an operator has explicitly enabled it; the endpoint 404s
 * otherwise, so this page is not a permanent part of the admin surface. It
 * exists because the Entra configuration now lives in the database and is edited
 * from the admin console — a wrong tenant ID would otherwise lock everyone out
 * of the only tool that can fix it.
 *
 * Unlike the SSO hand-off next door, this posts through fetch rather than as a
 * native form: there is no identity provider to navigate to, and staying on the
 * page lets a failed attempt render inline instead of reloading into a blank
 * error.
 */
export function LocalAdminLoginPage({ lang, onLang }: { lang: Lang; onLang: (l: Lang) => void }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit() {
    if (!username.trim() || !password) {
      setError(t('admin.local.error.required'))
      return
    }
    setError('')
    setBusy(true)
    try {
      const body = await postForm<{ redirect?: string }>('/admin/login/local', {
        username: username.trim(),
        password,
      })
      window.location.assign(body.redirect ?? '/admin')
    } catch (err) {
      // The server answers the same way for an unknown account and a wrong
      // password, so this endpoint cannot be used to discover usernames. The
      // message stays equally vague.
      const code = err instanceof ApiError ? err.code : 'error'
      setError(code === 'rate_limited' ? t('errors.rateLimited') : t('admin.local.error.invalid'))
      setBusy(false)
    }
  }

  return (
    <CardShell
      lang={lang}
      onLang={onLang}
      title={t('admin.local.title', config.brand.name)}
      subtitle={t('admin.local.subtitle')}
    >
      <Alert
        type="warning"
        showIcon
        style={{ marginBottom: 16 }}
        message={t('admin.local.warning')}
      />
      <Input
        size="large"
        autoComplete="username"
        placeholder={t('admin.local.username')}
        value={username}
        disabled={busy}
        onChange={(e) => setUsername(e.target.value)}
        style={{ marginBottom: 10 }}
      />
      <Input.Password
        size="large"
        autoComplete="current-password"
        placeholder={t('admin.local.password')}
        value={password}
        disabled={busy}
        onChange={(e) => setPassword(e.target.value)}
        onPressEnter={() => void submit()}
        style={{ marginBottom: 10 }}
      />
      <div className="field-error" role="alert">
        {error}
      </div>
      <Button type="primary" size="large" block loading={busy} icon={<LoginOutlined />} onClick={() => void submit()}>
        {t('admin.local.submit')}
      </Button>
      <a className="card-back" href="/admin/login">
        ← {t('admin.local.backToSso')}
      </a>
    </CardShell>
  )
}
