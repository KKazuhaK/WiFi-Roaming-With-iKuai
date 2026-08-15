import { useMemo, useState } from 'react'
import { App, Button, Input, Segmented, Space, Table, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { DeleteOutlined, EditOutlined, PlusOutlined } from '@ant-design/icons'
import { postForm, ApiError } from '@/lib/api'
import { t } from '@/lib/i18n'
import { AddCodeModal, BatchCodeModal, BatchResultModal, EditCodeModal } from './CodeModals'
import type { AdminState, CodeRow } from './types'

type StatusFilter = 'all' | 'used' | 'unused' | 'expired'

const STATUS_COLOR: Record<CodeRow['status'], string> = {
  unused: 'green',
  used: 'blue',
  expired: 'default',
}

export function CodesSection({ state, refresh }: { state: AdminState; refresh: () => void }) {
  const { message, modal } = App.useApp()
  const [status, setStatus] = useState<StatusFilter>('all')
  const [query, setQuery] = useState('')
  const [selected, setSelected] = useState<string[]>([])
  const [addOpen, setAddOpen] = useState(false)
  const [batchOpen, setBatchOpen] = useState(false)
  const [editing, setEditing] = useState<CodeRow | null>(null)
  const [generated, setGenerated] = useState<string[] | null>(null)

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase()
    return state.codes.filter((c) => {
      if (status !== 'all' && c.status !== status) return false
      if (!q) return true
      return c.code.toLowerCase().includes(q) || c.note.toLowerCase().includes(q)
    })
  }, [state.codes, status, query])

  // The old page counted only *visible* checked rows, because filtering hid rows
  // without unchecking them and a stale selection would delete codes the admin
  // could no longer see. Intersecting the selection with the filtered rows keeps
  // that guarantee without the DOM inspection it used to need.
  const visibleSelected = useMemo(() => {
    const visible = new Set(rows.map((r) => r.code))
    return selected.filter((c) => visible.has(c))
  }, [rows, selected])

  async function afterMutation(msg: string) {
    message.success(msg)
    setSelected([])
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
      // Sorted on the raw string because it is either "YYYY-MM-DD HH:mm" — which
      // sorts correctly as text — or the localised "never" label, which sorts to
      // one end and stays grouped.
      sorter: (a, b) => a.expiresAt.localeCompare(b.expiresAt),
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
            { label: `${t('admin.codes.filter.all')} (${state.total})`, value: 'all' },
            { label: `${t('admin.codes.filter.used')} (${state.used})`, value: 'used' },
            { label: `${t('admin.codes.filter.unused')} (${state.unused})`, value: 'unused' },
            { label: `${t('admin.codes.filter.expired')} (${state.expired})`, value: 'expired' },
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
        locale={{ emptyText: t('admin.codes.empty') }}
        rowSelection={{
          selectedRowKeys: visibleSelected,
          onChange: (keys) => setSelected(keys as string[]),
        }}
        pagination={{ pageSize: 50, showSizeChanger: true, hideOnSinglePage: true }}
        scroll={{ x: 'max-content' }}
      />

      <AddCodeModal open={addOpen} onClose={() => setAddOpen(false)} onDone={refresh} />
      <BatchCodeModal
        open={batchOpen}
        onClose={() => setBatchOpen(false)}
        onGenerated={(codes) => {
          setGenerated(codes)
          refresh()
        }}
      />
      <EditCodeModal row={editing} onClose={() => setEditing(null)} onDone={refresh} />
      <BatchResultModal codes={generated} onClose={() => setGenerated(null)} />
    </>
  )
}
