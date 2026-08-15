import { useCallback, useEffect, useMemo, useState } from 'react'
import { Alert, App, Button, Card, Form, Input, Skeleton, Space, Tabs, Tag, Typography } from 'antd'
import { SaveOutlined, UndoOutlined } from '@ant-design/icons'
import { get, postJSON, ApiError } from '@/lib/api'
import { t } from '@/lib/i18n'

interface SettingKeyInfo {
  key: string
  secret: boolean
  default: string
  legacyEnv?: string
}

interface SettingProblem {
  section: string
  key?: string
  message: string
  fatal: boolean
}

interface SectionResponse {
  section: string
  fields: Record<string, string>
  secretsPresent: Record<string, boolean>
  keys: SettingKeyInfo[]
  problems: SettingProblem[]
}

interface SectionsIndex {
  sections: { section: string; keys: SettingKeyInfo[] }[]
}

/**
 * Section order and grouping.
 *
 * Fixed rather than taken from the server's alphabetical list: an operator
 * setting this up works outward from identity to network to cosmetics, and
 * "Branding" landing above "Entra SSO" because b sorts before o would be a
 * worse first-run experience than a hardcoded order is a maintenance cost.
 * Sections the server reports but this list does not know still render, at the
 * end — so adding one server-side does not require a frontend change to be
 * reachable.
 */
const SECTION_ORDER = [
  'oidc',
  'duo',
  'auth',
  'admin',
  'local_admin',
  'ikuai',
  'ikuai_policy',
  'portal',
  'brand',
  'ratelimit',
  'eventlog',
]

/**
 * Sections with a page of their own.
 *
 * TLS has one because its settings are not values that take effect on save —
 * they rebind sockets, and getting them wrong takes the console away. That page
 * pairs them with the certificate, the connectivity check and the confirm
 * button, none of which a generic key/value form can offer. Listing them twice
 * would let an operator change the listen address from a form with none of that.
 */
const OWN_PAGE = new Set(['tls'])

function sectionLabel(section: string): string {
  const key = `settings.section.${section}`
  const label = t(key)
  // t() returns the key itself when a translation is missing, which for a
  // section added server-side without an i18n entry would render as
  // "settings.section.foo". Falling back to the raw name is less alarming and
  // still identifies the section.
  return label === key ? section : label
}

/** A multi-line value is more usable as a textarea; these are the long ones. */
const MULTILINE_KEYS = new Set(['allowed_email_domains', 'emails', 'group_ids', 'allowed_from', 'ip_keys', 'mac_keys'])

function SectionForm({ section, onSaved }: { section: string; onSaved: () => void }) {
  const { message } = App.useApp()
  const [form] = Form.useForm<Record<string, string>>()
  const [data, setData] = useState<SectionResponse | null>(null)
  const [saving, setSaving] = useState(false)

  const load = useCallback(async () => {
    try {
      const body = await get<SectionResponse>(`/admin/api/settings/${section}`)
      setData(body)
      // Secrets are never sent back, so their inputs start blank; blank means
      // "unchanged" on save, which is the same convention the server applies.
      form.setFieldsValue(body.fields)
    } catch (err) {
      message.error(err instanceof ApiError ? err.code : 'error')
    }
  }, [section, form, message])

  useEffect(() => {
    void load()
  }, [load])

  async function submit(values: Record<string, string>) {
    setSaving(true)
    try {
      const body = await postJSON<{ warning?: string }>(`/admin/api/settings/${section}`, values)
      if (body.warning) {
        // The values were saved; the runtime could not fully apply them. Saying
        // "failed" here would have the operator retype an edit that landed.
        message.warning(t('settings.savedWithWarning', body.warning))
      } else {
        message.success(t('settings.saved'))
      }
      await load()
      onSaved()
    } catch (err) {
      message.error(t('settings.saveFailed', err instanceof ApiError ? err.code : 'error'))
    } finally {
      setSaving(false)
    }
  }

  if (!data) return <Skeleton active />

  return (
    <Form form={form} layout="vertical" onFinish={(v) => void submit(v)} disabled={saving}>
      {data.problems.map((p, i) => (
        <Alert
          key={i}
          type={p.fatal ? 'error' : 'warning'}
          showIcon
          style={{ marginBottom: 12 }}
          message={p.message}
        />
      ))}

      {data.keys.map((k) => {
        const isSecret = k.secret
        const present = data.secretsPresent[k.key]
        return (
          <Form.Item
            key={k.key}
            name={k.key}
            label={
              <Space size={6}>
                <span>{k.key}</span>
                {k.legacyEnv ? (
                  <Typography.Text type="secondary" style={{ fontSize: 11 }}>
                    {t('settings.legacyEnv', k.legacyEnv)}
                  </Typography.Text>
                ) : null}
                {isSecret ? (
                  <Tag color={present ? 'green' : 'default'}>
                    {present ? t('settings.secretSet') : t('settings.secretUnset')}
                  </Tag>
                ) : null}
              </Space>
            }
          >
            {isSecret ? (
              <Input.Password autoComplete="new-password" placeholder={present ? '••••••••' : ''} />
            ) : MULTILINE_KEYS.has(k.key) ? (
              <Input.TextArea rows={2} placeholder={k.default} />
            ) : (
              <Input placeholder={k.default} />
            )}
          </Form.Item>
        )
      })}

      <Space>
        <Button type="primary" htmlType="submit" icon={<SaveOutlined />} loading={saving}>
          {t('settings.save')}
        </Button>
        <Button icon={<UndoOutlined />} onClick={() => void load()}>
          {t('settings.reset')}
        </Button>
      </Space>
    </Form>
  )
}

/**
 * Settings page.
 *
 * The section list comes from the server's schema rather than a hardcoded copy,
 * so a setting added to the registry in Go appears here without a frontend
 * change — which is the whole reason the GET response carries `keys`.
 */
export function SettingsSection({ refresh }: { refresh: () => void }) {
  const [sections, setSections] = useState<string[] | null>(null)

  useEffect(() => {
    void (async () => {
      try {
        const body = await get<SectionsIndex>('/admin/api/settings')
        setSections(body.sections.map((s) => s.section))
      } catch {
        setSections([])
      }
    })()
  }, [])

  const ordered = useMemo(() => {
    if (!sections) return []
    const known = SECTION_ORDER.filter((s) => sections.includes(s))
    const extra = sections
      .filter((s) => !SECTION_ORDER.includes(s) && !OWN_PAGE.has(s))
      .sort()
    return [...known, ...extra]
  }, [sections])

  if (!sections) return <Skeleton active />

  return (
    <>
      <Alert type="info" showIcon style={{ marginBottom: 16 }} message={t('settings.envNotice')} />
      <Card size="small" styles={{ body: { paddingTop: 0 } }}>
        <Tabs
          tabPosition="left"
          // Mounted lazily and kept alive: a half-filled OIDC form must survive
          // a glance at another tab.
          destroyOnHidden={false}
          items={ordered.map((s) => ({
            key: s,
            label: sectionLabel(s),
            children: <SectionForm section={s} onSaved={refresh} />,
          }))}
        />
      </Card>
    </>
  )
}
