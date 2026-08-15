import { useRef, useState } from 'react'
import { Button, Input, type InputRef } from 'antd'
import { KeyOutlined, LoginOutlined } from '@ant-design/icons'
import { CardShell } from '@/components/CardShell'
import { config } from '@/lib/config'
import { t, type Lang } from '@/lib/i18n'
import { postForm } from '@/lib/api'
import { authErrorMessage } from '@/lib/errors'

type Step = 'choice' | 'email' | 'guest'

/**
 * Basic shape check before spending a request: exactly one @, and something on
 * either side of it. The server re-validates and owns the domain allowlist —
 * this only exists to turn an obvious typo into instant feedback instead of a
 * round trip over a link that has not been unlocked yet.
 */
function looksLikeEmail(v: string): boolean {
  const at = v.indexOf('@')
  return at > 0 && at === v.lastIndexOf('@') && at < v.length - 1
}

export function LoginPage({ lang, onLang }: { lang: Lang; onLang: (l: Lang) => void }) {
  const [step, setStep] = useState<Step>('choice')
  const [email, setEmail] = useState('')
  const [code, setCode] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const emailRef = useRef<InputRef>(null)
  const codeRef = useRef<InputRef>(null)

  function goto(next: Step) {
    setStep(next)
    setError('')
    // The mini browser needs the field focused for its keyboard to open without
    // a second tap. The delay lets the step actually render first.
    setTimeout(() => {
      if (next === 'email') emailRef.current?.focus()
      if (next === 'guest') codeRef.current?.focus()
    }, 60)
  }

  async function submitEmail() {
    const value = email.trim().toLowerCase()
    if (!looksLikeEmail(value)) {
      setError(t('errors.invalidEmail'))
      return
    }
    setError('')
    setBusy(true)
    try {
      const body = await postForm<{ redirect?: string }>('/auth/start', { email: value })
      if (body.redirect) {
        // Entra or Duo takes over from here; this is a full navigation, so the
        // busy flag is deliberately left set — re-enabling the button would only
        // invite a double submit while the browser is already leaving.
        window.location.assign(body.redirect)
        return
      }
      setError(t('errors.generic'))
      setBusy(false)
    } catch (err) {
      setError(authErrorMessage(err, t('errors.generic')))
      setBusy(false)
    }
  }

  async function submitGuestCode() {
    const value = code.trim()
    if (!value) {
      setError(t('login.guest.invalid'))
      return
    }
    setError('')
    setBusy(true)
    try {
      const body = await postForm<{ redirect?: string }>('/auth/guest-code', { code: value })
      if (body.redirect) {
        window.location.assign(body.redirect)
        return
      }
      setError(t('login.guest.invalid'))
      setBusy(false)
    } catch (err) {
      // Anything the shared mapper has no wording for is an invalid code: the
      // handler answers 401 invalid_code for wrong, expired and used-up codes
      // alike, and it must stay that way so the response cannot be used to probe
      // which codes exist.
      setError(authErrorMessage(err, t('login.guest.invalid')))
      setBusy(false)
    }
  }

  return (
    <CardShell
      lang={lang}
      onLang={onLang}
      title={t('login.title', config.brand.name)}
      subtitle={t('login.subtitle', config.brand.name)}
    >
      {step === 'choice' ? (
        <div className="card-actions">
          <Button type="primary" size="large" block icon={<LoginOutlined />} onClick={() => goto('email')}>
            {t('login.btn.sso', config.brand.name)}
          </Button>
          {config.guestEnabled ? (
            <Button size="large" block icon={<KeyOutlined />} onClick={() => goto('guest')}>
              {t('login.btn.guest')}
            </Button>
          ) : null}
        </div>
      ) : null}

      {step === 'email' ? (
        <>
          <p className="card-hint">{t('login.email.hint')}</p>
          <Input
            ref={emailRef}
            type="email"
            size="large"
            autoComplete="email"
            inputMode="email"
            aria-label={t('login.email.label')}
            placeholder={`you@${config.allowedDomainsHint}`}
            value={email}
            disabled={busy}
            onChange={(e) => setEmail(e.target.value)}
            onPressEnter={() => void submitEmail()}
            style={{ marginBottom: 10 }}
          />
          <div className="field-error" role="alert">
            {error}
          </div>
          <Button type="primary" size="large" block loading={busy} onClick={() => void submitEmail()}>
            {t('login.email.continue')}
          </Button>
          <button type="button" className="card-back" disabled={busy} onClick={() => goto('choice')}>
            ← {t('common.back')}
          </button>
        </>
      ) : null}

      {step === 'guest' ? (
        <>
          <p className="card-hint">{t('login.guest.hint')}</p>
          <Input
            ref={codeRef}
            size="large"
            autoComplete="off"
            autoCapitalize="off"
            autoCorrect="off"
            spellCheck={false}
            aria-label={t('login.guest.label')}
            placeholder={t('login.guest.label')}
            value={code}
            disabled={busy}
            onChange={(e) => setCode(e.target.value)}
            onPressEnter={() => void submitGuestCode()}
            style={{ marginBottom: 10 }}
          />
          <div className="field-error" role="alert">
            {error}
          </div>
          <Button type="primary" size="large" block loading={busy} onClick={() => void submitGuestCode()}>
            {t('login.guest.verify')}
          </Button>
          <button type="button" className="card-back" disabled={busy} onClick={() => goto('choice')}>
            ← {t('common.back')}
          </button>
        </>
      ) : null}
    </CardShell>
  )
}
