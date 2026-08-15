import { useCallback, useEffect, useState } from 'react'
import { Button, Descriptions, Input, Modal, Select, Space, Table, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { DownloadOutlined, InfoCircleOutlined, ReloadOutlined } from '@ant-design/icons'
import { get } from '@/lib/api'
import { t } from '@/lib/i18n'
import type { EventFilters, EventRow, EventsResponse } from './types'

const REFRESH_MS = 30_000
const QUERY_LIMIT = 500
const SUBJECT_DEBOUNCE_MS = 300

const KIND_LABEL: Record<string, string> = {}
const METHOD_LABEL: Record<string, string> = {}
const RESULT_LABEL: Record<string, string> = {}

// Populated per render rather than at module scope so a language switch
// re-labels the table. Cheap: three small objects.
function refreshLabels() {
  KIND_LABEL.login = t('admin.events.kind.login')
  KIND_LABEL.admin_action = t('admin.events.kind.adminAction')
  METHOD_LABEL.sso = t('admin.events.method.sso')
  METHOD_LABEL.duo = t('admin.events.method.duo')
  METHOD_LABEL.guest_code = t('admin.events.method.guestCode')
  METHOD_LABEL.admin = t('admin.events.method.admin')
  RESULT_LABEL.started = t('admin.events.result.started')
  RESULT_LABEL.success = t('admin.events.result.success')
  RESULT_LABEL.denied = t('admin.events.result.denied')
  RESULT_LABEL.rate_limited = t('admin.events.result.rateLimited')
  RESULT_LABEL.error = t('admin.events.result.error')
}

const RESULT_COLOR: Record<string, string> = {
  success: 'green',
  started: 'blue',
  denied: 'red',
  rate_limited: 'orange',
  error: 'red',
}

const DEFAULT_FILTERS: EventFilters = {
  kind: '',
  method: '',
  result: '',
  subject: '',
  rangeSeconds: 7 * 24 * 3600,
}

/**
 * Build the query string shared by the table request and the CSV export, so the
 * file an operator downloads always matches what they are looking at.
 *
 * `since` is computed from the browser clock against a server that stamps events
 * with its own. A few seconds of skew shifts the window edge harmlessly; a badly
 * wrong client clock would not, but that is equally true of the old page and the
 * alternative is a round trip to ask the server what time it is.
 */
function buildQuery(f: EventFilters): Record<string, string | number | undefined> {
  return {
    kind: f.kind || undefined,
    method: f.method || undefined,
    result: f.result || undefined,
    subject: f.subject.trim() || undefined,
    since: f.rangeSeconds > 0 ? Math.floor(Date.now() / 1000) - f.rangeSeconds : undefined,
  }
}

export function EventsSection({ active }: { active: boolean }) {
  const [filters, setFilters] = useState<EventFilters>(DEFAULT_FILTERS)
  // Separate from filters.subject so typing does not fire a request per keypress.
  const [subjectInput, setSubjectInput] = useState('')
  const [events, setEvents] = useState<EventRow[]>([])
  const [loading, setLoading] = useState(false)
  const [detail, setDetail] = useState<EventRow | null>(null)

  refreshLabels()

  useEffect(() => {
    const id = setTimeout(
      () => setFilters((f) => ({ ...f, subject: subjectInput })),
      SUBJECT_DEBOUNCE_MS,
    )
    return () => clearTimeout(id)
  }, [subjectInput])

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const body = await get<EventsResponse>('/admin/events/query', {
        ...buildQuery(filters),
        limit: QUERY_LIMIT,
      })
      setEvents(body.events ?? [])
    } catch {
      // Same reasoning as the rate-limit poll: a periodic refresh must not
      // produce a toast per failure.
    } finally {
      setLoading(false)
    }
  }, [filters])

  useEffect(() => {
    if (!active) return
    void load()
    const id = setInterval(() => void load(), REFRESH_MS)
    return () => clearInterval(id)
  }, [active, load])

  function exportCSV() {
    const qs = new URLSearchParams()
    for (const [k, v] of Object.entries(buildQuery(filters))) {
      if (v === undefined) continue
      qs.set(k, String(v))
    }
    // No limit parameter: the export covers the whole filtered range, while the
    // table caps at QUERY_LIMIT rows for responsiveness.
    window.location.assign(`/admin/events/export.csv?${qs.toString()}`)
  }

  const columns: ColumnsType<EventRow> = [
    { title: t('admin.events.col.time'), dataIndex: 'time_iso', width: 160 },
    {
      title: t('admin.events.col.kind'),
      dataIndex: 'kind',
      width: 100,
      render: (v: string) => <Tag>{KIND_LABEL[v] ?? v}</Tag>,
    },
    { title: t('admin.events.col.subject'), dataIndex: 'subject', ellipsis: true },
    {
      title: t('admin.events.col.method'),
      dataIndex: 'method',
      width: 110,
      render: (v: string) => METHOD_LABEL[v] ?? v ?? '-',
    },
    {
      title: t('admin.events.col.result'),
      dataIndex: 'result',
      width: 120,
      render: (v: string) => <Tag color={RESULT_COLOR[v]}>{RESULT_LABEL[v] ?? v}</Tag>,
    },
    { title: t('admin.events.col.mac'), dataIndex: 'mac', width: 160, render: (v?: string) => v || '-' },
    { title: t('admin.events.col.ip'), dataIndex: 'ip', width: 130, render: (v?: string) => v || '-' },
    {
      title: t('admin.events.col.detail'),
      dataIndex: 'detail',
      render: (v: string | undefined, row) =>
        v ? (
          <Space size={4}>
            {/* Truncated to keep the row height stable; the full text is one
                click away rather than wrapping the table into unreadability. */}
            <span>{v.length > 60 ? v.slice(0, 60) + '…' : v}</span>
            <Button
              type="text"
              size="small"
              icon={<InfoCircleOutlined />}
              title={t('admin.events.btn.detail')}
              onClick={() => setDetail(row)}
            />
          </Space>
        ) : (
          <Typography.Text type="secondary">-</Typography.Text>
        ),
    },
  ]

  return (
    <>
      <div className="admin-toolbar">
        <Typography.Title level={5} style={{ margin: 0 }}>
          {t('admin.events.title')}
        </Typography.Title>
        <div className="admin-toolbar-spacer" />
        <Select
          value={filters.kind}
          onChange={(kind) => setFilters((f) => ({ ...f, kind }))}
          style={{ width: 130 }}
          options={[
            { value: '', label: t('admin.events.kind.all') },
            { value: 'login', label: t('admin.events.kind.login') },
            { value: 'admin_action', label: t('admin.events.kind.adminAction') },
          ]}
        />
        <Select
          value={filters.method}
          onChange={(method) => setFilters((f) => ({ ...f, method }))}
          style={{ width: 140 }}
          options={[
            { value: '', label: t('admin.events.method.all') },
            { value: 'sso', label: t('admin.events.method.sso') },
            { value: 'duo', label: t('admin.events.method.duo') },
            { value: 'guest_code', label: t('admin.events.method.guestCode') },
            { value: 'admin', label: t('admin.events.method.admin') },
          ]}
        />
        <Select
          value={filters.result}
          onChange={(result) => setFilters((f) => ({ ...f, result }))}
          style={{ width: 140 }}
          options={[
            { value: '', label: t('admin.events.result.all') },
            { value: 'started', label: t('admin.events.result.started') },
            { value: 'success', label: t('admin.events.result.success') },
            { value: 'denied', label: t('admin.events.result.denied') },
            { value: 'rate_limited', label: t('admin.events.result.rateLimited') },
            { value: 'error', label: t('admin.events.result.error') },
          ]}
        />
        <Select
          value={filters.rangeSeconds}
          onChange={(rangeSeconds) => setFilters((f) => ({ ...f, rangeSeconds }))}
          style={{ width: 110 }}
          options={[
            { value: 86400, label: t('admin.events.range.24h') },
            { value: 604800, label: t('admin.events.range.7d') },
            { value: 0, label: t('admin.events.range.all') },
          ]}
        />
        <Input
          allowClear
          placeholder={t('admin.events.placeholder.subject')}
          value={subjectInput}
          onChange={(e) => setSubjectInput(e.target.value)}
          style={{ width: 170 }}
        />
        <Button icon={<ReloadOutlined />} loading={loading} onClick={() => void load()}>
          {t('admin.events.btn.refresh')}
        </Button>
        <Button icon={<DownloadOutlined />} onClick={exportCSV}>
          {t('admin.events.btn.exportCsv')}
        </Button>
      </div>

      <Table<EventRow>
        rowKey={(e) => `${e.time_unix}:${e.kind}:${e.subject}:${e.detail ?? ''}`}
        size="small"
        columns={columns}
        dataSource={events}
        loading={loading && events.length === 0}
        locale={{ emptyText: t('admin.events.empty') }}
        pagination={{ pageSize: 50, showSizeChanger: true, hideOnSinglePage: true }}
        scroll={{ x: 'max-content' }}
      />

      <Modal
        open={detail !== null}
        title={t('admin.events.detail.title')}
        onCancel={() => setDetail(null)}
        onOk={() => setDetail(null)}
        okText={t('admin.modal.result.btn.done')}
        cancelButtonProps={{ style: { display: 'none' } }}
        width={620}
      >
        {detail ? (
          <Descriptions column={1} size="small" bordered styles={{ content: { wordBreak: 'break-all' } }}>
            <Descriptions.Item label={t('admin.events.col.time')}>{detail.time_iso}</Descriptions.Item>
            <Descriptions.Item label={t('admin.events.col.kind')}>
              {KIND_LABEL[detail.kind] ?? detail.kind}
            </Descriptions.Item>
            <Descriptions.Item label={t('admin.events.col.subject')}>
              {detail.subject || '-'}
            </Descriptions.Item>
            <Descriptions.Item label={t('admin.events.col.method')}>
              {METHOD_LABEL[detail.method] ?? detail.method ?? '-'}
            </Descriptions.Item>
            <Descriptions.Item label={t('admin.events.col.result')}>
              {RESULT_LABEL[detail.result] ?? detail.result}
            </Descriptions.Item>
            <Descriptions.Item label={t('admin.events.col.mac')}>{detail.mac || '-'}</Descriptions.Item>
            <Descriptions.Item label={t('admin.events.col.ip')}>{detail.ip || '-'}</Descriptions.Item>
            <Descriptions.Item label={t('admin.events.col.detail')}>
              {detail.detail || '-'}
            </Descriptions.Item>
          </Descriptions>
        ) : null}
      </Modal>
    </>
  )
}
