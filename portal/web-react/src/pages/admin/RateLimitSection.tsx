import { useCallback, useEffect, useMemo, useState } from 'react'
import { App, Button, Space, Table, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { DeleteOutlined, ReloadOutlined, StopOutlined } from '@ant-design/icons'
import { get, postForm, ApiError } from '@/lib/api'
import { t } from '@/lib/i18n'
import { formatClock, formatDurationSecs } from './format'
import type { RateLimitStatus, ResetType } from './types'

/** One flattened line in the table: bans, historical bans, and the three counters. */
interface Row {
  id: string
  type: string
  color: string
  key: string
  status: string
  resetType: ResetType
  resetKey: string
  /** Guest-code MAC rows offer a direct escalation to a permanent ban. */
  canBanMac?: boolean
}

const REFRESH_MS = 15_000

/**
 * Flatten the status payload into table rows, ordered by how much attention each
 * deserves: live IP cooldowns, then IPs with a ban history, then the email, MAC
 * and IP failure counters.
 */
function buildRows(s: RateLimitStatus): Row[] {
  const rows: Row[] = []
  const th = s.thresholds
  const active = new Set((s.ip_bans ?? []).map((b) => b.ip))

  for (const b of s.ip_bans ?? []) {
    const remain = Math.max(0, b.expires_unix - s.now_unix)
    rows.push({
      id: `ban:${b.ip}`,
      type: b.permanent
        ? t('admin.rl.row.ipPermBan', b.ban_count || '?')
        : t('admin.rl.row.ipCooldown', b.ban_count || '?'),
      color: 'red',
      key: b.ip,
      status: b.permanent
        ? t('admin.rl.status.permanent')
        : t('admin.rl.status.expire', formatClock(b.expires_unix), formatDurationSecs(remain)),
      resetType: 'ip_ban',
      resetKey: b.ip,
    })
  }

  // Repeat offenders that are not currently held. Kept visible so an admin
  // reviewing a pattern can see the history rather than only the live bans.
  for (const [ip, count] of Object.entries(s.ban_history ?? {})) {
    if (active.has(ip)) continue
    rows.push({
      id: `hist:${ip}`,
      type: t('admin.rl.row.historicalBan'),
      color: 'blue',
      key: ip,
      status: t('admin.rl.status.bannedTimes', count),
      resetType: 'ip_ban',
      resetKey: ip,
    })
  }

  for (const e of s.email_fails ?? []) {
    rows.push({
      id: `email:${e.key}`,
      type: t('admin.rl.row.email'),
      color: e.count >= th.email_short || e.count >= th.email_long ? 'red' : 'blue',
      key: e.key,
      status: t('admin.rl.status.failedLast', e.count, formatClock(e.latest_unix)),
      resetType: 'email',
      resetKey: e.key,
    })
  }

  for (const m of s.guest_mac_fails ?? []) {
    rows.push({
      id: `mac:${m.key}`,
      type: t('admin.rl.row.guestMac'),
      color: m.count >= th.mac ? 'red' : 'blue',
      key: m.key,
      status: t('admin.rl.status.failedLast', m.count, formatClock(m.latest_unix)),
      resetType: 'mac',
      resetKey: m.key,
      canBanMac: true,
    })
  }

  for (const i of s.ip_fails ?? []) {
    // An IP already shown as banned above would otherwise appear twice.
    if (active.has(i.key)) continue
    rows.push({
      id: `ipfail:${i.key}`,
      type: t('admin.rl.row.ipAccum'),
      // Amber once halfway to the limit, so an IP on its way to a cooldown is
      // visible before it gets there.
      color: i.count >= Math.ceil(th.ip * 0.5) ? 'blue' : 'default',
      key: i.key,
      status: t('admin.rl.status.failedLast', i.count, formatClock(i.latest_unix)),
      resetType: 'ip_fails',
      resetKey: i.key,
    })
  }

  return rows
}

function thresholdSummary(th: RateLimitStatus['thresholds']): string {
  return t(
    'admin.rl.thresholds.fmt',
    th.email_short,
    formatDurationSecs(th.email_short_s),
    th.email_long,
    formatDurationSecs(th.email_long_s),
    th.mac,
    formatDurationSecs(th.mac_s),
    th.ip,
    formatDurationSecs(th.ip_s),
    formatDurationSecs(th.ip_ban_s),
    th.ip_ban_escalate >= 999999
      ? t('admin.rl.thresholds.noEscalation')
      : t('admin.rl.thresholds.escalateAt', th.ip_ban_escalate),
  )
}

export function RateLimitSection({ active, refresh }: { active: boolean; refresh: () => void }) {
  const { message, modal } = App.useApp()
  const [status, setStatus] = useState<RateLimitStatus | null>(null)
  const [loading, setLoading] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      setStatus(await get<RateLimitStatus>('/admin/ratelimit/status'))
    } catch {
      // Silent: this polls every 15s and a transient failure that pops a toast
      // would bury the operator in noise. The stale table stays on screen.
    } finally {
      setLoading(false)
    }
  }, [])

  // Poll only while this tab is showing. The old page polled unconditionally
  // from load, which kept hitting the endpoint while an admin sat on the event
  // log for an hour.
  useEffect(() => {
    if (!active) return
    void load()
    const id = setInterval(() => void load(), REFRESH_MS)
    return () => clearInterval(id)
  }, [active, load])

  const rows = useMemo(() => (status ? buildRows(status) : []), [status])

  function confirmReset(row: Row) {
    modal.confirm({
      title: t('admin.confirm.resetRl', row.resetType, row.resetKey),
      okType: 'danger',
      okText: t('admin.rl.btn.reset'),
      cancelText: t('admin.common.cancel'),
      onOk: async () => {
        try {
          await postForm('/admin/ratelimit/reset', { type: row.resetType, key: row.resetKey })
          message.success(t('admin.toast.rlReset'))
          await load()
          // The dashboard's banned-IP counter is derived from this state.
          refresh()
        } catch (err) {
          message.error(t('admin.toast.rlResetFailed', err instanceof ApiError ? err.code : 'unknown'))
        }
      },
    })
  }

  function confirmResetAll() {
    modal.confirm({
      title: t('admin.rl.btn.resetAll'),
      content: <div style={{ whiteSpace: 'pre-line' }}>{t('admin.confirm.resetAllRl')}</div>,
      okType: 'danger',
      width: 560,
      okText: t('admin.rl.btn.resetAll'),
      cancelText: t('admin.common.cancel'),
      onOk: async () => {
        try {
          const body = await postForm<{ cleared?: Record<string, number> }>(
            '/admin/ratelimit/reset-all',
            {},
          )
          const c = body.cleared ?? {}
          message.success(
            t(
              'admin.toast.rlResetAllFmt',
              c.ip_bans ?? 0,
              c.ban_history ?? 0,
              c.email_fails ?? 0,
              c.guest_mac_fails ?? 0,
              c.ip_fails ?? 0,
            ),
          )
          await load()
          refresh()
        } catch (err) {
          message.error(t('admin.toast.clearFailed', err instanceof ApiError ? err.code : 'unknown'))
        }
      },
    })
  }

  function confirmBanMac(row: Row) {
    modal.confirm({
      title: t('admin.confirm.banMacFromRow', row.resetKey),
      okType: 'danger',
      okText: t('admin.rl.btn.banMac'),
      cancelText: t('admin.common.cancel'),
      onOk: async () => {
        try {
          await postForm('/admin/denylist/macs/create', {
            mac: row.resetKey,
            reason: t('admin.rl.row.guestMac'),
          })
          message.success(t('admin.toast.macBanned', row.resetKey))
          await load()
          refresh()
        } catch (err) {
          message.error(t('admin.toast.macBanFailed', err instanceof ApiError ? err.code : 'error'))
        }
      },
    })
  }

  const columns: ColumnsType<Row> = [
    {
      title: t('admin.rl.col.type'),
      dataIndex: 'type',
      width: 190,
      render: (v: string, row) => <Tag color={row.color}>{v}</Tag>,
    },
    {
      title: t('admin.rl.col.key'),
      dataIndex: 'key',
      render: (v: string) => <Typography.Text code>{v}</Typography.Text>,
    },
    { title: t('admin.rl.col.status'), dataIndex: 'status', width: 280 },
    {
      title: t('admin.rl.col.actions'),
      key: 'actions',
      width: 180,
      render: (_, row) => (
        <Space>
          <Button size="small" danger icon={<DeleteOutlined />} onClick={() => confirmReset(row)}>
            {t('admin.rl.btn.reset')}
          </Button>
          {row.canBanMac ? (
            <Button size="small" danger icon={<StopOutlined />} onClick={() => confirmBanMac(row)}>
              {t('admin.rl.btn.banMac')}
            </Button>
          ) : null}
        </Space>
      ),
    },
  ]

  return (
    <>
      <div className="admin-toolbar">
        <Typography.Title level={5} style={{ margin: 0 }}>
          {t('admin.rl.title')}
        </Typography.Title>
        <div className="admin-toolbar-spacer" />
        {status ? (
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {thresholdSummary(status.thresholds)}
          </Typography.Text>
        ) : null}
        <Button icon={<ReloadOutlined />} loading={loading} onClick={() => void load()}>
          {t('admin.rl.btn.refresh')}
        </Button>
        <Button danger icon={<DeleteOutlined />} onClick={confirmResetAll}>
          {t('admin.rl.btn.resetAll')}
        </Button>
      </div>

      <Table<Row>
        rowKey="id"
        size="small"
        columns={columns}
        dataSource={rows}
        loading={loading && status === null}
        locale={{ emptyText: t('admin.rl.empty') }}
        pagination={{ pageSize: 50, hideOnSinglePage: true }}
        scroll={{ x: 'max-content' }}
      />
    </>
  )
}
