import { useMemo, useState } from 'react'
import { App, Button, Input, Segmented, Space, Table, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { DeleteOutlined, EditOutlined, PlusOutlined } from '@ant-design/icons'
import { postForm, ApiError } from '@/lib/api'
import { t } from '@/lib/i18n'
import { AddCodeModal, BatchCodeModal, BatchResultModal, EditCodeModal } from './CodeModals'
import { useDebounced, useServerTable, PAGE_SIZES } from './useServerTable'
import type { CodeRow, CodeStats } from './types'

type StatusFilter = 'all' | 'used' | 'unused' | 'expired'

const STATUS_COLOR: Record<CodeRow['status'], string> = {
  unused: 'green',
  used: 'blue',
  expired: 'default',
}

export function CodesSection({ refresh }: { refresh: () => void }) {
  const { message, modal } = App.useApp()
  const [status, setStatus] = useState<StatusFilter>('all')
  const [query, setQuery] = useState('')
  const [selected, setSelected] = useState<string[]>([])
  const [addOpen, setAddOpen] = useState(false)
  const [batchOpen, setBatchOpen] = useState(false)
  const [editing, setEditing] = useState<CodeRow | null>(null)
  const [generated, setGenerated] = useState<string[] | null>(null)

  // Debounced so a typed search is one request per pause rather than per key.
  const search = useDebounced(query)
  const table = useServerTable<CodeRow, { stats: CodeStats }>('/admin/api/codes', {
    q: search.trim(),
    status: status === 'all' ? '' : status,
  })
  const rows = table.rows
  const stats = table.extra?.stats

  // Only *visible* checked rows count. Filtering hides rows without unchecking
  // them, and a stale selection would delete codes the admin can no longer see —
  // which matters more now that the rows they cannot see are on another page
  // rather than merely filtered out.
  const visibleSelected = useMemo(() => {
    const visible = new Set(rows.map((r) => r.code))
    return selected.filter((c) => visible.has(c))
  }, [rows, selected])

  async function afterMutation(msg: string) {
    message.success(msg)
    setSelected([])
    await table.reload()
    // The dashboard counters live in /admin/api/state and are derived from
    // these rows, so they need the refresh too.
    refresh()
  }

  function confirmDelete(code: string) {
    modal.confirm({
      title: t('admin.confirm.delete', code),
      okType: 'danger',
      okText: t('admin.codes.btn.delete'),
      cancelText: t('admin.common.cancel'),
      onOk: async () => {
        try {
          await postForm('/admin/codes/delete', { code })
          await afterMutation(t('admin.toast.deleted'))
        } catch {
          message.error(t('admin.toast.deleteFailed'))
        }
      },
    })
  }

  function confirmBulkDelete() {
    if (visibleSelected.length === 0) return
    modal.confirm({
      title: t('admin.confirm.bulkDelete', visibleSelected.length),
      okType: 'danger',
      okText: t('admin.codes.btn.deleteSelected'),
      cancelText: t('admin.common.cancel'),
      onOk: async () => {
        try {
          const body = await postForm<{ deleted?: number }>('/admin/codes/delete-bulk', {
            codes: visibleSelected.join(','),
          })
          await afterMutation(t('admin.toast.bulkDeleted', body.deleted ?? 0))
        } catch (err) {
          message.error(t('admin.toast.bulkFailed', err instanceof ApiError ? err.code : 'unknown'))
        }
      },
    })
  }

  function confirmDeleteInactive() {
    modal.confirm({
      title: t('admin.confirm.deleteExpired'),
      okType: 'danger',
      okText: t('admin.codes.btn.deleteExpired'),
      cancelText: t('admin.common.cancel'),
      onOk: async () => {
        try {
          const body = await postForm<{ deleted?: number }>('/admin/codes/delete-inactive', {})
          await afterMutation(t('admin.toast.expiredDeleted', body.deleted ?? 0))
        } catch (err) {
          message.error(t('admin.toast.clearFailed', err instanceof ApiError ? err.code : 'unknown'))
        }
      },
    })
  }

  function reload() {
    void table.reload()
    refresh()
  }

  const columns: ColumnsType<CodeRow> = [
    {
      title: t('admin.codes.col.code'),
      dataIndex: 'code',
      render: (code: string) => <Typography.Text copyable code>{code}</Typography.Text>,
    },
    {
      title: t('admin.codes.col.status'),
      dataIndex: 'status',
      width: 110,
      render: (s: CodeRow['status']) => (
        <Tag color={STATUS_COLOR[s]}>{t(`admin.codes.status.${s}`)}</Tag>
      ),
    },
    { title: t('admin.codes.col.duration'), dataIndex: 'duration', width: 140 },
    {
      title: t('admin.codes.col.expires'),
      dataIndex: 'expiresAt',
      width: 170,
      // No sorter any more: it would sort the fifty rows currently loaded and
      // present the result as if it were the whole table, which is worse than
      // not offering it. The server order — newest first — is the useful one.
    },
    {
      title: t('admin.codes.col.usage'),
      key: 'usage',
      width: 200,
      render: (_, row) => {
        if (row.useCount > 0) {
          const count = row.maxUses > 0 ? `${row.useCount}/${row.maxUses}` : String(row.useCount)
          return (
            <span>
              {count} {t('admin.codes.col.usage')} · {row.lastUsedAt}
              {row.lastUsedMac ? (
                <>
                  <br />
                  <Typography.Text type="secondary" style={{ fontSize: 11 }}>
                    {row.lastUsedMac}
                  </Typography.Text>
                </>
              ) : null}
            </span>
          )
        }
        if (row.maxUses > 0) return `0/${row.maxUses} ${t('admin.codes.col.usage')}`
        return t('admin.codes.usage.dash')
      },
    },
    { title: t('admin.codes.col.note'), dataIndex: 'note', ellipsis: true },
    {
      title: t('admin.codes.col.actions'),
      key: 'actions',
      width: 170,
      render: (_, row) => (
        <Space>
          <Button size="small" icon={<EditOutlined />} onClick={() => setEditing(row)}>
            {t('admin.codes.btn.edit')}
          </Button>
          <Button size="small" danger icon={<DeleteOutlined />} onClick={() => confirmDelete(row.code)}>
            {t('admin.codes.btn.delete')}
          </Button>
        </Space>
      ),
    },
  ]

  return (
    <>
      <div className="admin-toolbar">
        <Segmented<StatusFilter>
          value={status}
          onChange={setStatus}
          options={[
            { label: `${t('admin.codes.filter.all')} (${stats?.total ?? 0})`, value: 'all' },
            { label: `${t('admin.codes.filter.used')} (${stats?.used ?? 0})`, value: 'used' },
            { label: `${t('admin.codes.filter.unused')} (${stats?.unused ?? 0})`, value: 'unused' },
            { label: `${t('admin.codes.filter.expired')} (${stats?.expired ?? 0})`, value: 'expired' },
          ]}
        />
        <Input.Search
          allowClear
          placeholder={t('admin.codes.searchPlaceholder')}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          style={{ width: 240 }}
        />
        <div className="admin-toolbar-spacer" />
        <Button type="primary" icon={<PlusOutlined />} onClick={() => setAddOpen(true)}>
          {t('admin.codes.btn.add')}
        </Button>
        <Button icon={<PlusOutlined />} onClick={() => setBatchOpen(true)}>
          {t('admin.codes.btn.batch')}
        </Button>
        <Button danger icon={<DeleteOutlined />} disabled={visibleSelected.length === 0} onClick={confirmBulkDelete}>
          {t('admin.codes.btn.deleteSelected')} ({visibleSelected.length})
        </Button>
        <Button danger icon={<DeleteOutlined />} onClick={confirmDeleteInactive}>
          {t('admin.codes.btn.deleteExpired')}
        </Button>
      </div>

      <Table<CodeRow>
        rowKey="code"
        size="small"
        columns={columns}
        dataSource={rows}
        loading={table.loading}
        locale={{ emptyText: table.error ?? t('admin.codes.empty') }}
        rowSelection={{
          selectedRowKeys: visibleSelected,
          onChange: (keys) => setSelected(keys as string[]),
        }}
        // Controlled by the server: `total` is the count of matching rows, not
        // of loaded ones, so the pager knows about pages the browser has never
        // seen.
        pagination={{
          current: table.page,
          pageSize: table.pageSize,
          total: table.total,
          showSizeChanger: true,
          pageSizeOptions: PAGE_SIZES,
          showTotal: (n) => t('admin.codes.filter.all') + `: ${n}`,
          onChange: (page, size) => {
            table.setPage(page)
            table.setPageSize(size)
          },
        }}
        scroll={{ x: 'max-content' }}
      />

      <AddCodeModal open={addOpen} onClose={() => setAddOpen(false)} onDone={reload} />
      <BatchCodeModal
        open={batchOpen}
        onClose={() => setBatchOpen(false)}
        onGenerated={(codes) => {
          setGenerated(codes)
          reload()
        }}
      />
      <EditCodeModal row={editing} onClose={() => setEditing(null)} onDone={reload} />
      <BatchResultModal codes={generated} onClose={() => setGenerated(null)} />
    </>
  )
}
