import { useEffect, useState } from 'react'
import { App, Button, Input, InputNumber, Table, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { SaveOutlined } from '@ant-design/icons'
import { postForm, ApiError } from '@/lib/api'
import { t } from '@/lib/i18n'
import type { AdminState, IKuaiPolicyRow } from './types'

type Draft = Pick<IKuaiPolicyRow, 'Upload' | 'Download' | 'Timeout' | 'Comment'>

/**
 * iKuai bandwidth and timeout policy, one row per authentication method.
 *
 * Each row saves independently, as it did before. The template achieved that
 * with HTML's `form=` attribute pointing scattered inputs at a per-row <form>;
 * here it is a per-row draft in state, which also makes the save button able to
 * stay disabled until something actually changed.
 */
export function PolicySection({ state, refresh }: { state: AdminState; refresh: () => void }) {
  const { message } = App.useApp()
  const [drafts, setDrafts] = useState<Record<string, Draft>>({})
  const [saving, setSaving] = useState<string | null>(null)

  // Re-seed whenever the server state changes, so a refresh triggered by another
  // section does not leave this table showing stale numbers.
  useEffect(() => {
    const next: Record<string, Draft> = {}
    for (const p of state.ikuaiPolicies) {
      next[p.Profile] = {
        Upload: p.Upload,
        Download: p.Download,
        Timeout: p.Timeout,
        Comment: p.Comment,
      }
    }
    setDrafts(next)
  }, [state.ikuaiPolicies])

  function edit(profile: string, patch: Partial<Draft>) {
    setDrafts((d) => ({ ...d, [profile]: { ...d[profile], ...patch } }))
  }

  function isDirty(row: IKuaiPolicyRow): boolean {
    const d = drafts[row.Profile]
    if (!d) return false
    return (
      d.Upload !== row.Upload ||
      d.Download !== row.Download ||
      d.Timeout !== row.Timeout ||
      d.Comment !== row.Comment
    )
  }

  async function save(row: IKuaiPolicyRow) {
    const d = drafts[row.Profile]
    if (!d) return
    setSaving(row.Profile)
    try {
      await postForm('/admin/ikuai-policy/update', {
        profile: row.Profile,
        upload: d.Upload,
        download: d.Download,
        // The guest profile's timeout comes from each code's own session
        // duration, so the field is not editable and always posts 0 — the same
        // hidden input the template sent.
        timeout: row.Profile === 'guest' ? 0 : d.Timeout,
        comment: d.Comment,
      })
      message.success(t('admin.toast.policySaved'))
      refresh()
    } catch (err) {
      message.error(t('admin.toast.policySaveFailed', err instanceof ApiError ? err.code : 'error'))
    } finally {
      setSaving(null)
    }
  }

  const columns: ColumnsType<IKuaiPolicyRow> = [
    {
      title: t('admin.policy.col.method'),
      dataIndex: 'Label',
      width: 140,
      render: (label: string) => <Tag>{label}</Tag>,
    },
    {
      title: t('admin.policy.col.upload'),
      key: 'upload',
      width: 150,
      render: (_, row) => (
        <InputNumber
          min={0}
          value={drafts[row.Profile]?.Upload}
          onChange={(v) => edit(row.Profile, { Upload: v ?? 0 })}
          placeholder="KB/s"
          style={{ width: '100%' }}
        />
      ),
    },
    {
      title: t('admin.policy.col.download'),
      key: 'download',
      width: 150,
      render: (_, row) => (
        <InputNumber
          min={0}
          value={drafts[row.Profile]?.Download}
          onChange={(v) => edit(row.Profile, { Download: v ?? 0 })}
          placeholder="KB/s"
          style={{ width: '100%' }}
        />
      ),
    },
    {
      title: t('admin.policy.col.timeout'),
      key: 'timeout',
      width: 160,
      render: (_, row) =>
        row.Profile === 'guest' ? (
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {t('admin.policy.guestNote')}
          </Typography.Text>
        ) : (
          <InputNumber
            min={0}
            value={drafts[row.Profile]?.Timeout}
            onChange={(v) => edit(row.Profile, { Timeout: v ?? 0 })}
            placeholder={t('admin.modal.add.unitM')}
            style={{ width: '100%' }}
          />
        ),
    },
    {
      title: t('admin.policy.col.comment'),
      key: 'comment',
      render: (_, row) => (
        <Input
          maxLength={128}
          value={drafts[row.Profile]?.Comment}
          onChange={(e) => edit(row.Profile, { Comment: e.target.value })}
        />
      ),
    },
    {
      title: t('admin.policy.col.actions'),
      key: 'actions',
      width: 120,
      render: (_, row) => (
        <Button
          type="primary"
          size="small"
          icon={<SaveOutlined />}
          loading={saving === row.Profile}
          disabled={!isDirty(row)}
          onClick={() => void save(row)}
        >
          {t('admin.policy.btn.save')}
        </Button>
      ),
    },
  ]

  return (
    <>
      <div className="admin-toolbar">
        <Typography.Title level={5} style={{ margin: 0 }}>
          {t('admin.policy.title')}
        </Typography.Title>
        <div className="admin-toolbar-spacer" />
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          {t('admin.policy.hint')}
        </Typography.Text>
      </div>
      <Table<IKuaiPolicyRow>
        rowKey="Profile"
        size="small"
        columns={columns}
        dataSource={state.ikuaiPolicies}
        pagination={false}
        scroll={{ x: 'max-content' }}
      />
    </>
  )
}
