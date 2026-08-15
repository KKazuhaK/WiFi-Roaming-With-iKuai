import { useCallback, useEffect, useState } from 'react'
import {
  Alert,
  App,
  Button,
  Card,
  Descriptions,
  Divider,
  Form,
  Input,
  Modal,
  Radio,
  Skeleton,
  Space,
  Switch,
  Tag,
  Typography,
} from 'antd'
import {
  CheckCircleOutlined,
  CopyOutlined,
  SafetyCertificateOutlined,
  SaveOutlined,
  ThunderboltOutlined,
  UploadOutlined,
} from '@ant-design/icons'
import { get, postJSON, ApiError } from '@/lib/api'
import { t } from '@/lib/i18n'
import { formatDurationSecs } from './format'

interface CertificateStatus {
  domain: string
  source?: string
  present: boolean
  notBefore?: string
  notAfter?: string
  daysLeft: number
  lastError?: string
  lastAttempt?: string
  issuer?: string
  dnsNames?: string[]
}

interface TLSStatus {
  mode: string
  domain: string
  listenAddr: string
  httpListen: string
  redirectHttp: boolean
  acmeEnabled: boolean
  acmeEmail: string
  acmeStaging: boolean
  publicUrl: string
  certificate: CertificateStatus
  listening: boolean
  listeningAddr?: string
  snippets: Record<string, string>
  pendingCommit: boolean
  commitDeadline?: string
  reachable?: boolean
  reachableError?: string
  http01Viable: boolean
  http01Note?: string
}

/** The settings-section shape, which is what a save actually writes. */
interface TLSForm {
  mode: string
  domain: string
  listen_addr: string
  redirect_http: boolean
  acme_enabled: boolean
  acme_email: string
  acme_staging: boolean
}

/**
 * Where the console will answer after a listener change.
 *
 * Built from the values being saved rather than from the current location,
 * because the point of the message is that the current location is about to stop
 * working. The port is omitted when it is 443, which is what an operator typed
 * into their browser in the first place.
 */
function consoleURL(v: TLSForm): string {
  const host = v.domain?.trim() || window.location.hostname
  if (v.mode !== 'standalone') return `${window.location.origin}/admin#tls`
  const port = (v.listen_addr ?? '').split(':').pop() ?? '443'
  const authority = port === '443' ? host : `${host}:${port}`
  return `https://${authority}/admin#tls`
}

/** Amber below this, red below a week — the same thresholds the renewal loop uses. */
const EXPIRY_WARN_DAYS = 30

function certTag(cert: CertificateStatus) {
  if (!cert.present) return <Tag>{t('tls.cert.none')}</Tag>
  if (cert.daysLeft <= 0) return <Tag color="red">{t('tls.cert.expired')}</Tag>
  if (cert.daysLeft < EXPIRY_WARN_DAYS)
    return <Tag color="orange">{t('tls.cert.expiringSoon')}</Tag>
  return (
    <Tag color="green" icon={<CheckCircleOutlined />}>
      {t('tls.cert.valid')}
    </Tag>
  )
}

function formatDate(iso?: string): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleString(undefined, { hour12: false })
}

/**
 * The pending-commit banner.
 *
 * A countdown rather than a static warning, because the number is the whole
 * point: the operator has to decide whether this page still works before it
 * reaches zero, and "a change is pending" tells them nothing about how long they
 * have to decide.
 */
function CommitBanner({ deadline, onConfirm }: { deadline: string; onConfirm: () => void }) {
  const [left, setLeft] = useState(() => Math.max(0, (new Date(deadline).getTime() - Date.now()) / 1000))

  useEffect(() => {
    const id = setInterval(() => {
      setLeft(Math.max(0, (new Date(deadline).getTime() - Date.now()) / 1000))
    }, 1000)
    return () => clearInterval(id)
  }, [deadline])

  return (
    <Alert
      type="warning"
      showIcon
      style={{ marginBottom: 16 }}
      message={t('tls.commit.pending', formatDurationSecs(Math.round(left)))}
      description={t('tls.commit.hint')}
      action={
        <Button type="primary" size="small" onClick={onConfirm}>
          {t('tls.commit.confirm')}
        </Button>
      }
    />
  )
}

function SnippetBlock({ label, text }: { label: string; text: string }) {
  const { message } = App.useApp()

  async function copy() {
    try {
      await navigator.clipboard.writeText(text)
      message.success(t('tls.proxy.copied'))
    } catch {
      // clipboard is unavailable over plain HTTP in every current browser, which
      // is exactly the situation an operator configuring a reverse proxy is in.
      // Selecting the text is then the fallback, so say nothing and leave it.
    }
  }

  return (
    <div style={{ marginBottom: 12 }}>
      <Space style={{ marginBottom: 4 }}>
        <Typography.Text strong>{label}</Typography.Text>
        <Button size="small" icon={<CopyOutlined />} onClick={() => void copy()}>
          {t('tls.proxy.copy')}
        </Button>
      </Space>
      <pre className="tls-snippet">{text}</pre>
    </div>
  )
}

export function TLSSection() {
  const { message, modal } = App.useApp()
  const [form] = Form.useForm<TLSForm>()
  const [status, setStatus] = useState<TLSStatus | null>(null)
  const [saving, setSaving] = useState(false)
  const [issuing, setIssuing] = useState(false)
  const [checking, setChecking] = useState(false)
  const [uploadOpen, setUploadOpen] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [mode, setMode] = useState('proxy')

  const load = useCallback(
    async (check = false) => {
      try {
        const body = await get<TLSStatus>('/admin/api/tls', check ? { check: '1' } : undefined)
        setStatus(body)
        setMode(body.mode)
        form.setFieldsValue({
          mode: body.mode,
          domain: body.domain,
          listen_addr: body.listenAddr,
          redirect_http: body.redirectHttp,
          acme_enabled: body.acmeEnabled,
          acme_email: body.acmeEmail,
          acme_staging: body.acmeStaging,
        })
      } catch (err) {
        message.error(err instanceof ApiError ? err.code : 'error')
      }
    },
    [form, message],
  )

  useEffect(() => {
    void load()
  }, [load])

  async function save(values: TLSForm) {
    setSaving(true)
    try {
      // The settings store holds strings; booleans are the form's convenience,
      // not the wire format.
      const body = await postJSON<{ warning?: string; pendingCommit?: boolean }>(
        '/admin/api/settings/tls',
        {
          mode: values.mode,
          domain: values.domain ?? '',
          listen_addr: values.listen_addr ?? '',
          redirect_http: String(!!values.redirect_http),
          acme_enabled: String(!!values.acme_enabled),
          acme_email: values.acme_email ?? '',
          acme_staging: String(!!values.acme_staging),
        },
      )
      if (body.warning) message.warning(t('settings.savedWithWarning', body.warning))
      else message.success(t('settings.saved'))

      // A change that armed a rollback usually moves the console: enabling the
      // redirect means this origin now bounces to HTTPS, so the page cannot even
      // poll its own status from here. Hand the operator the new address rather
      // than leaving them on a page whose requests have started failing.
      if (body.pendingCommit) {
        const url = consoleURL(values)
        modal.confirm({
          title: t('tls.moved.title'),
          width: 620,
          okText: t('tls.moved.open'),
          cancelText: t('tls.moved.stay'),
          content: (
            <div>
              <p>{t('tls.moved.body', url)}</p>
              <p>{t('tls.commit.hint')}</p>
            </div>
          ),
          onOk: () => window.location.assign(url),
        })
        // Not reloaded from here: this origin may already be redirecting, and a
        // failed refresh would put an error toast on top of the message telling
        // the operator where to go.
        return
      }
      await load()
    } catch (err) {
      message.error(t('settings.saveFailed', err instanceof ApiError ? err.code : 'error'))
    } finally {
      setSaving(false)
    }
  }

  async function confirmCommit() {
    try {
      await postJSON('/admin/api/tls/confirm', {})
      message.success(t('tls.commit.confirmed'))
      await load()
    } catch (err) {
      message.error(err instanceof ApiError ? err.code : 'error')
    }
  }

  async function issue() {
    setIssuing(true)
    try {
      const body = await postJSON<{ ok: boolean; error?: string }>('/admin/api/tls/issue', {})
      if (body.ok) message.success(t('tls.acme.issued'))
      // A failure comes back 200 with the CA's own words in it. Shown in a modal
      // rather than a toast: an ACME error is three lines long and names the
      // exact check that failed, which is the only thing that will fix it.
      else
        modal.error({
          title: t('tls.acme.failed', ''),
          width: 640,
          content: <div style={{ whiteSpace: 'pre-wrap' }}>{body.error}</div>,
        })
      await load()
    } catch (err) {
      const code = err instanceof ApiError ? err.code : 'error'
      if (code === 'no_domain') message.error(t('tls.acme.noDomain'))
      else if (code === 'no_acme_email') message.error(t('tls.acme.noEmail'))
      else message.error(t('tls.acme.failed', code))
    } finally {
      setIssuing(false)
    }
  }

  async function upload(values: { certPem: string; keyPem: string }) {
    setUploading(true)
    try {
      const body = await postJSON<{ ok: boolean; warning?: string }>(
        '/admin/api/tls/upload',
        values,
      )
      if (body.warning) message.warning(body.warning)
      else message.success(t('tls.upload.done'))
      setUploadOpen(false)
      await load()
    } catch (err) {
      message.error(
        err instanceof ApiError && typeof err.body.error === 'string' ? err.body.error : 'error',
      )
    } finally {
      setUploading(false)
    }
  }

  if (!status) return <Skeleton active paragraph={{ rows: 8 }} />

  const cert = status.certificate
  const standalone = mode === 'standalone'

  return (
    <>
      {status.pendingCommit && status.commitDeadline ? (
        <CommitBanner deadline={status.commitDeadline} onConfirm={() => void confirmCommit()} />
      ) : null}

      <Card
        size="small"
        title={t('tls.section.listener')}
        style={{ marginBottom: 16 }}
        extra={
          standalone ? (
            status.listening ? (
              <Tag color="green">{t('tls.listening', status.listeningAddr ?? '')}</Tag>
            ) : (
              <Tag color="red">{t('tls.notListening')}</Tag>
            )
          ) : null
        }
      >
        <Form form={form} layout="vertical" onFinish={(v) => void save(v)} disabled={saving}>
          <Form.Item name="mode" label={t('tls.mode')}>
            <Radio.Group onChange={(e) => setMode(e.target.value as string)}>
              <Space direction="vertical">
                <Radio value="proxy">
                  {t('tls.mode.proxy')}
                  <div className="tls-hint">{t('tls.mode.proxyHint')}</div>
                </Radio>
                <Radio value="standalone">
                  {t('tls.mode.standalone')}
                  <div className="tls-hint">{t('tls.mode.standaloneHint')}</div>
                </Radio>
              </Space>
            </Radio.Group>
          </Form.Item>

          <Form.Item name="domain" label={t('tls.domain')} extra={t('tls.domainHint')}>
            <Input placeholder="portal.example.com" autoComplete="off" />
          </Form.Item>

          <Form.Item label={t('tls.httpListen')} extra={t('tls.httpListenHint')}>
            <Input value={status.httpListen} disabled />
          </Form.Item>

          {standalone ? (
            <>
              <Form.Item
                name="listen_addr"
                label={t('tls.listenAddr')}
                extra={t('tls.listenAddrHint')}
              >
                <Input placeholder="0.0.0.0:443" autoComplete="off" />
              </Form.Item>
              <Form.Item
                name="redirect_http"
                label={t('tls.redirectHttp')}
                valuePropName="checked"
                extra={t('tls.redirectHttpHint')}
              >
                <Switch />
              </Form.Item>

              <Divider titlePlacement="start" plain>
                ACME
              </Divider>

              {status.http01Viable ? null : (
                <Alert
                  type="info"
                  showIcon
                  style={{ marginBottom: 12 }}
                  message={t('tls.acme.unavailable')}
                  description={status.http01Note}
                />
              )}
              <Form.Item name="acme_enabled" label={t('tls.acme.enabled')} valuePropName="checked">
                <Switch disabled={saving || !status.http01Viable} />
              </Form.Item>
              <Form.Item name="acme_email" label={t('tls.acme.email')}>
                <Input placeholder="ops@example.com" autoComplete="off" />
              </Form.Item>
              <Form.Item
                name="acme_staging"
                label={t('tls.acme.staging')}
                valuePropName="checked"
                extra={t('tls.acme.stagingHint')}
              >
                <Switch />
              </Form.Item>
            </>
          ) : null}

          <Space>
            <Button type="primary" htmlType="submit" icon={<SaveOutlined />} loading={saving}>
              {t('tls.save')}
            </Button>
            <Button icon={<ThunderboltOutlined />} loading={checking} onClick={() => {
              setChecking(true)
              void load(true).finally(() => setChecking(false))
            }}>
              {t('tls.check.run')}
            </Button>
          </Space>

          {status.reachable === undefined ? null : status.reachable ? (
            <Alert type="success" showIcon style={{ marginTop: 12 }} message={t('tls.check.ok')} />
          ) : (
            <Alert
              type="error"
              showIcon
              style={{ marginTop: 12 }}
              message={t('tls.check.fail', status.reachableError ?? '')}
            />
          )}
        </Form>
      </Card>

      <Card
        size="small"
        title={t('tls.cert.title')}
        style={{ marginBottom: 16 }}
        extra={certTag(cert)}
        actions={undefined}
      >
        <Descriptions size="small" column={1}>
          <Descriptions.Item label={t('tls.domain')}>{cert.domain || '—'}</Descriptions.Item>
          {cert.present ? (
            <Descriptions.Item label={t('tls.cert.issuer')}>
              {cert.issuer || '—'}
              {cert.source ? (
                <Tag style={{ marginLeft: 8 }}>
                  {cert.source === 'acme' ? t('tls.cert.source.acme') : t('tls.cert.source.manual')}
                </Tag>
              ) : null}
            </Descriptions.Item>
          ) : null}
          {cert.present ? (
            <Descriptions.Item label={t('tls.cert.expires')}>
              {formatDate(cert.notAfter)}
              <Typography.Text
                type={cert.daysLeft < EXPIRY_WARN_DAYS ? 'danger' : 'secondary'}
                style={{ marginLeft: 8 }}
              >
                ({t('tls.cert.daysLeft', cert.daysLeft)})
              </Typography.Text>
            </Descriptions.Item>
          ) : null}
          {cert.dnsNames?.length ? (
            <Descriptions.Item label={t('tls.cert.dnsNames')}>
              {cert.dnsNames.join(', ')}
            </Descriptions.Item>
          ) : null}
          {cert.lastError ? (
            <Descriptions.Item label={t('tls.cert.lastError', '')}>
              <Typography.Text type="danger">{cert.lastError}</Typography.Text>
            </Descriptions.Item>
          ) : null}
        </Descriptions>

        <Space style={{ marginTop: 12 }}>
          <Button
            type="primary"
            icon={<SafetyCertificateOutlined />}
            loading={issuing}
            disabled={!status.http01Viable || !status.domain}
            onClick={() => void issue()}
          >
            {issuing ? t('tls.acme.issuing') : t('tls.acme.issue')}
          </Button>
          <Button icon={<UploadOutlined />} onClick={() => setUploadOpen(true)}>
            {t('tls.upload.title')}
          </Button>
        </Space>
      </Card>

      {standalone ? null : (
        <Card size="small" title={t('tls.proxy.snippet')}>
          <Alert type="info" showIcon style={{ marginBottom: 12 }} message={t('tls.proxy.hint')} />
          <SnippetBlock label="nginx" text={status.snippets.nginx ?? ''} />
          <SnippetBlock label="Caddy" text={status.snippets.caddy ?? ''} />
        </Card>
      )}

      <UploadModal
        open={uploadOpen}
        busy={uploading}
        onCancel={() => setUploadOpen(false)}
        onSubmit={(v) => void upload(v)}
      />
    </>
  )
}

function UploadModal({
  open,
  busy,
  onCancel,
  onSubmit,
}: {
  open: boolean
  busy: boolean
  onCancel: () => void
  onSubmit: (v: { certPem: string; keyPem: string }) => void
}) {
  const [form] = Form.useForm<{ certPem: string; keyPem: string }>()

  return (
    <Modal
      open={open}
      title={t('tls.upload.title')}
      width={720}
      confirmLoading={busy}
      okText={t('tls.upload.submit')}
      cancelText={t('admin.common.cancel')}
      onCancel={onCancel}
      afterClose={() => form.resetFields()}
      onOk={() => form.submit()}
    >
      <Alert type="info" showIcon style={{ marginBottom: 12 }} message={t('tls.uploadHint')} />
      <Form form={form} layout="vertical" onFinish={onSubmit} disabled={busy}>
        <Form.Item name="certPem" label={t('tls.upload.cert')} rules={[{ required: true }]}>
          <Input.TextArea rows={7} spellCheck={false} placeholder="-----BEGIN CERTIFICATE-----" />
        </Form.Item>
        <Form.Item name="keyPem" label={t('tls.upload.key')} rules={[{ required: true }]}>
          <Input.TextArea rows={5} spellCheck={false} placeholder="-----BEGIN PRIVATE KEY-----" />
        </Form.Item>
      </Form>
    </Modal>
  )
}
