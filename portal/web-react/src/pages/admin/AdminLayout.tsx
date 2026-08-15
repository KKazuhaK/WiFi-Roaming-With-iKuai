import { useState, type ReactNode } from 'react'
import { Button, Layout, Menu, Tooltip, Typography } from 'antd'
import {
  AuditOutlined,
  DashboardOutlined,
  KeyOutlined,
  LogoutOutlined,
  MenuFoldOutlined,
  MenuUnfoldOutlined,
  SafetyOutlined,
  SettingOutlined,
  StopOutlined,
  ThunderboltOutlined,
} from '@ant-design/icons'
import { LangSwitch } from '@/components/LangSwitch'
import { config } from '@/lib/config'
import { t, type Lang } from '@/lib/i18n'

const { Sider, Header, Content } = Layout

export type AdminView =
  | 'dashboard'
  | 'codes'
  | 'policy'
  | 'macs'
  | 'ratelimit'
  | 'events'
  | 'settings'

export const ADMIN_VIEWS: AdminView[] = [
  'dashboard',
  'codes',
  'policy',
  'macs',
  'ratelimit',
  'events',
  'settings',
]

/**
 * Sidebar grouping.
 *
 * Five tabs became seven views, which is where a horizontal tab strip stops
 * working — on a laptop the labels start wrapping, and there is no room left for
 * the section headings that tell an operator whether they are looking at access
 * management or at security. Grouped sections make the growth affordable: the
 * TLS and certificate pages still to come slot into System without another
 * layout decision.
 */
const GROUPS: { labelKey: string; items: AdminView[] }[] = [
  { labelKey: 'nav.section.overview', items: ['dashboard'] },
  { labelKey: 'nav.section.access', items: ['codes', 'policy'] },
  { labelKey: 'nav.section.security', items: ['macs', 'ratelimit', 'events'] },
  { labelKey: 'nav.section.system', items: ['settings'] },
]

const ICONS: Record<AdminView, ReactNode> = {
  dashboard: <DashboardOutlined />,
  codes: <KeyOutlined />,
  policy: <ThunderboltOutlined />,
  macs: <StopOutlined />,
  ratelimit: <SafetyOutlined />,
  events: <AuditOutlined />,
  settings: <SettingOutlined />,
}

const COLLAPSED_KEY = 'wifi-portal.sidebar-collapsed'

export function AdminLayout({
  view,
  onView,
  lang,
  onLang,
  children,
}: {
  view: AdminView
  onView: (v: AdminView) => void
  lang: Lang
  onLang: (l: Lang) => void
  children: ReactNode
}) {
  // Remembered per browser. The collapse is a workspace preference, not
  // application state, so it belongs in localStorage rather than in the URL or
  // on the server — an operator on a narrow laptop should not have to re-collapse
  // it on every visit, and it should not follow them to a different machine.
  const [collapsed, setCollapsed] = useState(() => {
    try {
      return localStorage.getItem(COLLAPSED_KEY) === '1'
    } catch {
      // Private browsing modes throw on localStorage access.
      return false
    }
  })

  function toggle() {
    setCollapsed((c) => {
      const next = !c
      try {
        localStorage.setItem(COLLAPSED_KEY, next ? '1' : '0')
      } catch {
        /* Preference is simply not remembered. */
      }
      return next
    })
  }

  return (
    <Layout className="admin-shell">
      <Sider
        collapsible
        collapsed={collapsed}
        trigger={null}
        width={216}
        collapsedWidth={64}
        theme="light"
        className="admin-sider"
      >
        <div className="admin-brand">
          {config.brand.logoUrl ? (
            <img src={config.brand.logoUrl} alt="" className="admin-brand-logo" />
          ) : (
            <span className="admin-brand-initial" style={{ background: config.brand.color }}>
              {config.brand.initial}
            </span>
          )}
          {!collapsed ? (
            <Typography.Text strong ellipsis className="admin-brand-name">
              {config.brand.name}
            </Typography.Text>
          ) : null}
        </div>

        <Menu
          mode="inline"
          theme="light"
          selectedKeys={[view]}
          onClick={({ key }) => onView(key as AdminView)}
          items={GROUPS.map((g) => ({
            key: g.labelKey,
            // A collapsed rail has no room for a group heading, and antd renders
            // it as a tooltip-less stub; dropping the label leaves the icons
            // grouped by their separators alone.
            label: collapsed ? '' : t(g.labelKey),
            type: 'group',
            children: g.items.map((v) => ({
              key: v,
              icon: ICONS[v],
              label: t(`nav.${v}`),
            })),
          }))}
        />
      </Sider>

      <Layout>
        <Header className="admin-header">
          <Tooltip title={collapsed ? t('nav.expand') : t('nav.collapse')}>
            <Button
              type="text"
              aria-label={collapsed ? t('nav.expand') : t('nav.collapse')}
              icon={collapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />}
              onClick={toggle}
            />
          </Tooltip>
          <Typography.Text strong className="admin-title">
            {t(`nav.${view}`)}
          </Typography.Text>
          <div className="admin-toolbar-spacer" />
          <LangSwitch current={lang} onChange={onLang} />
          <Typography.Text type="secondary" className="admin-upn">
            {config.adminUPN}
          </Typography.Text>
          {/* A form POST, not a fetch: the handler clears the cookie and
              redirects, and the browser has to follow that as a navigation. */}
          <form method="post" action="/admin/logout" style={{ margin: 0 }}>
            <Button htmlType="submit" icon={<LogoutOutlined />}>
              {t('admin.header.logout')}
            </Button>
          </form>
        </Header>

        <Content className="admin-content">{children}</Content>

        <footer className="admin-footer">
          {t('common.footer', config.brand.name)} · {config.nowYear}
        </footer>
      </Layout>
    </Layout>
  )
}
