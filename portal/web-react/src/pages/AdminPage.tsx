import { useCallback, useEffect, useState } from 'react'
import { Alert, Button, Skeleton } from 'antd'
import { get, ApiError } from '@/lib/api'
import { t, type Lang } from '@/lib/i18n'
import { AdminLayout, ADMIN_VIEWS, type AdminView } from './admin/AdminLayout'
import { DashboardSection } from './admin/DashboardSection'
import { CodesSection } from './admin/CodesSection'
import { PolicySection } from './admin/PolicySection'
import { MacsSection } from './admin/MacsSection'
import { RateLimitSection } from './admin/RateLimitSection'
import { EventsSection } from './admin/EventsSection'
import { SettingsSection } from './admin/SettingsSection'
import { TLSSection } from './admin/TLSSection'
import type { AdminState } from './admin/types'

/**
 * The selected view lives in the URL fragment.
 *
 * It costs nothing — no router, no dependency — and makes the panel's views
 * linkable and reload-proof, which the original could not do: it reset to the
 * guest-code tab after every mutation, because every mutation ended in
 * location.reload().
 */
function viewFromHash(): AdminView {
  const raw = window.location.hash.replace(/^#/, '')
  return (ADMIN_VIEWS as string[]).includes(raw) ? (raw as AdminView) : 'dashboard'
}

export function AdminPage({ lang, onLang }: { lang: Lang; onLang: (l: Lang) => void }) {
  const [state, setState] = useState<AdminState | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [view, setView] = useState<AdminView>(viewFromHash)

  const refresh = useCallback(async () => {
    try {
      setState(await get<AdminState>('/admin/api/state'))
      setError(null)
    } catch (err) {
      // A 401 has already sent the browser to /admin/login from lib/api.ts, so
      // anything landing here is a real failure worth showing.
      setError(err instanceof ApiError ? err.code : 'error')
    }
  }, [])

  useEffect(() => {
    void refresh()
    // The language is a server-side concern too — buildAdminData formats
    // durations and the "never expires" label with it — so a switch has to
    // re-fetch rather than merely re-render.
  }, [refresh, lang])

  useEffect(() => {
    const onHashChange = () => setView(viewFromHash())
    window.addEventListener('hashchange', onHashChange)
    return () => window.removeEventListener('hashchange', onHashChange)
  }, [])

  function selectView(v: AdminView) {
    setView(v)
    window.location.hash = v
  }

  const reload = () => void refresh()

  // Views that render server state wait for it; the settings page has its own
  // fetch and does not.
  function body() {
    if (view === 'settings') return <SettingsSection refresh={reload} />
    if (view === 'tls') return <TLSSection />
    if (view === 'ratelimit') return <RateLimitSection active refresh={reload} />
    if (view === 'events') return <EventsSection active />
    if (!state) return <Skeleton active paragraph={{ rows: 8 }} />
    switch (view) {
      case 'dashboard':
        return <DashboardSection state={state} onView={selectView} />
      case 'codes':
        return <CodesSection refresh={reload} />
      case 'policy':
        return <PolicySection state={state} refresh={reload} />
      case 'macs':
        return <MacsSection refresh={reload} />
      default:
        return null
    }
  }

  return (
    <AdminLayout view={view} onView={selectView} lang={lang} onLang={onLang}>
      {error ? (
        <Alert
          type="error"
          showIcon
          style={{ marginBottom: 16 }}
          message={error}
          action={
            <Button size="small" onClick={reload}>
              {t('common.retry')}
            </Button>
          }
        />
      ) : null}
      {body()}
    </AdminLayout>
  )
}
