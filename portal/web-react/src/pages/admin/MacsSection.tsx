import { useRef, useState } from 'react'
import { App, Button, Input, Space, Table, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { DeleteOutlined, DownloadOutlined, StopOutlined, UploadOutlined } from '@ant-design/icons'
import { postForm, postMultipart, ApiError } from '@/lib/api'
import { t } from '@/lib/i18n'
import { useDebounced, useServerTable, PAGE_SIZES } from './useServerTable'
import type { DeniedMacRow } from './types'

export function MacsSection({ refresh }: { refresh: () => void }) {
  const { message, modal } = App.useApp()
  const [mac, setMac] = useState('')
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const [query, setQuery] = useState('')
  const fileRef = useRef<HTMLInputElement>(null)

  const search = useDebounced(query)
  const table = useServerTable<DeniedMacRow>('/admin/api/macs', { q: search.trim() })

  // Every mutation refreshes both: the table for the rows, the shared state for
  // the dashboard's banned-device counter.
  function reload() {
    void table.reload()
    refresh()
  }

  async function ban() {
    const value = mac.trim()
    if (!value) {
      message.warning(t('admin.toast.macInputRequired'))
      return
    }
    setBusy(true)
    try {
      const body = await postForm<{ created?: boolean; mac?: string }>('/admin/denylist/macs/create', {
        mac: value,
        reason: reason.trim(),
      })
      // The handler is idempotent and reports which case happened, so a repeat
      // ban does not masquerade as a new one.
      message.success(
        body.created ? t('admin.toast.macBanned', body.mac ?? value) : t('admin.toast.macAlreadyBanned'),
      )
      setMac('')
      setReason('')
      reload()
    } catch (err) {
      message.error(t('admin.toast.macBanFailed', err instanceof ApiError ? err.code : 'error'))
    } finally {
      setBusy(false)
    }
  }

  function confirmUnban(target: string) {
    modal.confirm({
      title: t('admin.confirm.unbanMac', target),
      okType: 'danger',
      okText: t('admin.macs.btn.unban'),
      cancelText: t('admin.common.cancel'),
      onOk: async () => {
        try {
          await postForm('/admin/denylist/macs/delete', { mac: target })
          message.success(t('admin.toast.unbanned'))
          reload()
        } catch (err) {
          message.error(t('admin.toast.unbanFailed', err instanceof ApiError ? err.code : 'unknown'))
        }
      },
    })
  }

  function confirmUnbanAll() {
    modal.confirm({
      title: t('admin.macs.btn.unbanAll'),
      // The warning text is multi-line and spells out that rate-limit state is
      // untouched — this is the most destructive button on the page, so it keeps
      // the full body rather than being shortened to a title.
      content: <div style={{ whiteSpace: 'pre-line' }}>{t('admin.confirm.unbanAllMac')}</div>,
      okType: 'danger',
      okText: t('admin.macs.btn.unbanAll'),
      cancelText: t('admin.common.cancel'),
      onOk: async () => {
        try {
          const body = await postForm<{ cleared?: number }>('/admin/denylist/macs/delete-all', {})
          message.success(t('admin.toast.unbanAllCleared', body.cleared ?? 0))
          reload()
        } catch (err) {
          message.error(t('admin.toast.clearFailed', err instanceof ApiError ? err.code : 'unknown'))
        }
      },
    })
  }

  async function importCSV(file: File) {
    const form = new FormData()
    form.append('file', file)
    try {
      const body = await postMultipart<{ imported?: number; skipped?: number; errors?: string[] }>(
        '/admin/denylist/import',
        form,
      )
      const errors = body.errors ?? []
      const summary = t('admin.toast.imported', body.imported ?? 0, body.skipped ?? 0)
      if (errors.length > 0) {
        // Row-level problems need to stay on screen long enough to act on, so
        // they go in a modal rather than a toast that vanishes in two seconds.
        modal.info({
          title: summary,
          content: <div style={{ whiteSpace: 'pre-line' }}>{t('admin.toast.importErrors', errors.slice(0, 3).join('; '))}</div>,
        })
      } else {
        message.success(summary)
      }
      reload()
    } catch (err) {
      message.error(t('admin.toast.importFailed', err instanceof ApiError ? err.code : 'error'))
    }
  }

  const columns: ColumnsType<DeniedMacRow> = [
    {
      title: t('admin.macs.col.mac'),
      dataIndex: 'mac',
      width: 200,
      render: (v: string) => <Typography.Text code>{v}</Typography.Text>,
    },
    { title: t('admin.macs.col.reason'), dataIndex: 'reason', ellipsis: true },
    { title: t('admin.macs.col.createdAt'), dataIndex: 'createdAt', width: 170 },
    { title: t('admin.macs.col.createdBy'), dataIndex: 'createdBy', width: 220, ellipsis: true },
    {
      title: t('admin.macs.col.actions'),
      key: 'actions',
      width: 120,
      render: (_, row) => (
        <Button size="small" danger icon={<DeleteOutlined />} onClick={() => confirmUnban(row.mac)}>
          {t('admin.macs.btn.unban')}
        </Button>
      ),
    },
  ]

  return (
    <>
      <div className="admin-toolbar">
        <Typography.Title level={5} style={{ margin: 0 }}>
          {t('admin.macs.title')}
        </Typography.Title>
        <Space.Compact>
          <Input
            placeholder={t('admin.macs.placeholder.mac')}
            value={mac}
            onChange={(e) => setMac(e.target.value)}
            onPressEnter={() => void ban()}
            style={{ width: 190 }}
          />
          <Input
            placeholder={t('admin.macs.placeholder.reason')}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            onPressEnter={() => void ban()}
            style={{ width: 190 }}
          />
          <Button danger icon={<StopOutlined />} loading={busy} onClick={() => void ban()}>
            {t('admin.macs.btn.ban')}
          </Button>
        </Space.Compact>
        <Input.Search
          allowClear
          placeholder={t('admin.macs.searchPlaceholder')}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          style={{ width: 220 }}
        />
        <div className="admin-toolbar-spacer" />
        {/* A plain link, not a fetch: the handler answers with a
            Content-Disposition attachment and letting the browser handle the
            navigation avoids buffering the whole CSV into a blob. */}
        <Button icon={<DownloadOutlined />} href="/admin/denylist/export.csv">
          {t('admin.macs.btn.exportCsv')}
        </Button>
        <Button icon={<UploadOutlined />} onClick={() => fileRef.current?.click()}>
          {t('admin.macs.btn.importCsv')}
        </Button>
        <input
          ref={fileRef}
          type="file"
          accept=".csv,text/csv"
          hidden
          onChange={(e) => {
            const file = e.target.files?.[0]
            // Cleared unconditionally so picking the same file twice in a row
            // still fires a change event.
            e.target.value = ''
            if (file) void importCSV(file)
          }}
        />
        <Button danger icon={<DeleteOutlined />} onClick={confirmUnbanAll}>
          {t('admin.macs.btn.unbanAll')}
        </Button>
      </div>

      <Table<DeniedMacRow>
        rowKey="mac"
        size="small"
        columns={columns}
        dataSource={table.rows}
        loading={table.loading}
        locale={{ emptyText: table.error ?? t('admin.macs.empty') }}
        pagination={{
          current: table.page,
          pageSize: table.pageSize,
          total: table.total,
          showSizeChanger: true,
          pageSizeOptions: PAGE_SIZES,
          hideOnSinglePage: table.total <= table.pageSize,
          onChange: (page, size) => {
            table.setPage(page)
            table.setPageSize(size)
          },
        }}
        scroll={{ x: 'max-content' }}
      />
    </>
  )
}
