import { useCallback, useEffect, useState } from 'react'
import { Alert, Button, Card, Skeleton, Statistic, Tabs, Typography } from 'antd'
import { LogoutOutlined } from '@ant-design/icons'
import { get, ApiError } from '@/lib/api'
import { config } from '@/lib/config'
import { t, type Lang } from '@/lib/i18n'
import { LangSwitch } from '@/components/LangSwitch'
import { CodesSection } from './admin/CodesSection'
import { PolicySection } from './admin/PolicySection'
import { MacsSection } from './admin/MacsSection'
import { RateLimitSection } from './admin/RateLimitSection'
import { EventsSection } from './admin/EventsSection'
import type { AdminState } from './admin/types'

type TabKey = 'codes' | 'policy' | 'macs' | 'ratelimit' | 'events'

const TAB_KEYS: TabKey[] = ['codes', 'policy', 'macs', 'ratelimit', 'events']

/**
 * Tab selection lives in the URL fragment rather than component state.
 *
 * It costs nothing — no router, no dependency — and it makes the panel's five
 * views linkable and survivable across a reload, which the old page could not
 * do: it reset to the guest-code tab after every mutation, because every
 * mutation ended in location.reload().
 */
function tabFromHash(): TabKey {
  const raw = window.location.hash.replace(/^#/, '')
  return (TAB_KEYS as string[]).includes(raw) ? (raw as TabKey) : 'codes'
}

export function AdminPage({ lang, onLang }: { lang: Lang; onLang: (l: Lang) => void }) {
  const [state, setState] = useState<AdminState | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [tab, setTab] = useState<TabKey>(tabFromHash)

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
  }, [refresh])

  // The language is a server-side concern too: buildAdminData formats durations
  // and the "never expires" label with it, so a switch has to re-fetch rather
  // than just re-render.
  useEffect(() => {
    void refresh()
  }, [lang, refresh])

  useEffect(() => {
    const onHashChange = () => setTab(tabFromHash())
    window.addEventListener('hashchange', onHashChange)
    return () => window.removeEventListener('hashchange', onHashChange)
  }, [])

  function selectTab(key: string) {
    setTab(key as TabKey)
    window.location.hash = key
  }

  const dash = state?.dashboard

  return (
    <div className="admin-root">
      <header className="admin-header">
        <Typography.Text strong className="admin-title">
          {t('admin.pageTitle', config.brand.name)}
        </Typography.Text>
        <div className="admin-toolbar-spacer" />
        <LangSwitch current={lang} onChange={onLang} />
        <Typography.Text type="secondary" className="admin-upn">
          {config.adminUPN}
        </Typography.Text>
        {/* A form POST, not a fetch: the handler clears the cookie and redirects,
            and the browser needs to follow that as a navigation to land on the
            login page with the cleared session. */}
        <form method="post" action="/admin/logout" style={{ margin: 0 }}>
          <Button htmlType="submit" icon={<LogoutOutlined />}>
            {t('admin.header.logout')}
          </Button>
        </form>
      </header>

      <main className="admin-main">
        {error ? (
          <Alert
            type="error"
            showIcon
            style={{ marginBottom: 16 }}
            message={error}
            action={
              <Button size="small" onClick={() => void refresh()}>
                {t('common.retry')}
              </Button>
            }
          />
        ) : null}

        <div className="admin-dashboard">
          {dash ? (
            <>
              <Card size="small">
                <Statistic title={t('admin.dash.loginsToday')} value={dash.loginsToday} />
              </Card>
              <Card size="small">
                <Statistic title={t('admin.dash.loginsWeek')} value={dash.loginsWeek} />
              </Card>
              <Card size="small">
                <Statistic
                  title={t('admin.dash.failRate')}
                  // The percent sign belongs to the number, not to the suffix:
                  // antd puts a 4px gap before a suffix, which renders "25 % (9)".
                  value={`${dash.failedRatePct}%`}
                  suffix={`(${dash.failedCount7d})`}
                  // Above one in five terminal attempts failing is worth an
                  // operator's attention; the old page flagged the same ratio.
                  valueStyle={dash.failedRatePct > 20 ? { color: '#dc2626' } : undefined}
                />
              </Card>
              <Card size="small">
                <Statistic title={t('admin.dash.activeCodes')} value={dash.activeGuestCodes} />
              </Card>
              <Card size="small">
                <Statistic
                  title={t('admin.dash.bannedIp')}
                  value={dash.bannedIps}
                  valueStyle={dash.bannedIps > 0 ? { color: '#dc2626' } : undefined}
                />
              </Card>
              <Card size="small">
                <Statistic
                  title={t('admin.dash.bannedMac')}
                  value={dash.bannedMacs}
                  valueStyle={dash.bannedMacs > 0 ? { color: '#dc2626' } : undefined}
                />
              </Card>
              <Card size="small">
                <Statistic title={t('admin.dash.totalCodes')} value={state.total} />
              </Card>
            </>
          ) : (
            // Seven placeholders so the grid does not reflow when the data lands.
            Array.from({ length: 7 }, (_, i) => (
              <Card size="small" key={i}>
                <Skeleton active paragraph={false} title={{ width: '80%' }} />
              </Card>
            ))
          )}
        </div>

        <Tabs
          activeKey={tab}
          onChange={selectTab}
          // Sections mounted lazily and kept alive afterwards: the rate-limit and
          // event tables poll only while visible (they take an `active` prop),
          // and destroying them would throw away an operator's filter selections
          // every time they glanced at another tab.
          destroyOnHidden={false}
          items={[
            {
              key: 'codes',
              label: t('admin.tab.codes'),
              children: state ? (
                <CodesSection state={state} refresh={() => void refresh()} />
              ) : (
                <Skeleton active />
              ),
            },
            {
              key: 'policy',
              label: t('admin.tab.policy'),
              children: state ? (
                <PolicySection state={state} refresh={() => void refresh()} />
              ) : (
                <Skeleton active />
              ),
            },
            {
              key: 'macs',
              label: t('admin.tab.macs'),
              children: state ? (
                <MacsSection state={state} refresh={() => void refresh()} />
              ) : (
                <Skeleton active />
              ),
            },
            {
              key: 'ratelimit',
              label: t('admin.tab.ratelimit'),
              children: <RateLimitSection active={tab === 'ratelimit'} refresh={() => void refresh()} />,
            },
            {
              key: 'events',
              label: t('admin.tab.events'),
              children: <EventsSection active={tab === 'events'} />,
            },
          ]}
        />
      </main>

      <footer className="admin-footer">
        {t('common.footer', config.brand.name)} · {config.nowYear}
      </footer>
    </div>
  )
}
