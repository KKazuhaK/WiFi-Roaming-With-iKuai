import { useEffect } from 'react'
import { App, Button, Form, Input, InputNumber, Modal, Radio, Space, Typography } from 'antd'
import { postForm } from '@/lib/api'
import { ApiError } from '@/lib/api'
import { t } from '@/lib/i18n'
import { splitDuration, suggestNumericCode } from './format'
import type { CodeRow } from './types'

const { TextArea } = Input

// The duration inputs are hours+minutes but the handler takes a single
// duration_min, so every form flattens them the same way. Kept here so the add,
// batch and edit forms cannot drift apart on the arithmetic.
function durationMin(values: { durationH?: number; durationM?: number }): number {
  return (values.durationH ?? 0) * 60 + (values.durationM ?? 0)
}

/**
 * The expiry field is a plain text input in "YYYY-MM-DDTHH:mm" form rather than
 * an antd DatePicker.
 *
 * parseExpiry on the server parses exactly that layout in the server's local
 * zone. A DatePicker would hand back a dayjs object that has to be formatted
 * back into the same string, which pulls dayjs and its locale files into the
 * bundle to produce a value the native control already produces — and the native
 * picker is the one mobile browsers render properly. type="datetime-local" is
 * what the old form used and it is still the right control here.
 */
function ExpiryField() {
  return (
    <Form.Item name="expiresAt" label={t('admin.modal.add.expires.label')}>
      <Input type="datetime-local" />
    </Form.Item>
  )
}

function DurationFields() {
  return (
    <Form.Item label={t('admin.modal.add.duration.label')}>
      <Space>
        <Form.Item name="durationH" noStyle>
          <InputNumber min={0} style={{ width: 90 }} addonAfter={t('admin.modal.add.unitH')} />
        </Form.Item>
        <Form.Item name="durationM" noStyle>
          <InputNumber min={0} max={59} style={{ width: 100 }} addonAfter={t('admin.modal.add.unitM')} />
        </Form.Item>
      </Space>
    </Form.Item>
  )
}

interface AddValues {
  code?: string
  expiresAt?: string
  durationH?: number
  durationM?: number
  maxUses?: number
  note?: string
}

export function AddCodeModal({
  open,
  onClose,
  onDone,
}: {
  open: boolean
  onClose: () => void
  onDone: () => void
}) {
  const { message } = App.useApp()
  const [form] = Form.useForm<AddValues>()

  async function submit(values: AddValues) {
    try {
      const body = await postForm<{ code?: string }>('/admin/codes/create', {
        // Omitted entirely when blank: the handler treats an absent code as
        // "generate one" and a present-but-empty one the same way, but sending
        // the field would also trip its 6-character minimum on a stray space.
        code: values.code?.trim() || undefined,
        expires_at: values.expiresAt || undefined,
        duration_min: durationMin(values),
        max_uses: values.maxUses ?? 0,
        note: values.note ?? '',
      })
      message.success(t('admin.toast.added', body.code ?? ''))
      onClose()
      onDone()
    } catch (err) {
      if (err instanceof ApiError && err.code === 'duplicate_code') {
        message.error(t('admin.toast.dupCode'))
        return
      }
      // expires_at parse failures come back as their own message from
      // parseExpiry and are more useful raw than wrapped.
      const code = err instanceof ApiError ? err.code : 'error'
      message.error(code.includes('expires_at') ? code : t('admin.toast.addFailed', code))
    }
  }

  return (
    <Modal
      open={open}
      title={t('admin.modal.add.title')}
      onCancel={onClose}
      okText={t('admin.modal.add.btn.save')}
      cancelText={t('admin.common.cancel')}
      onOk={() => form.submit()}
      destroyOnHidden
    >
      <Form
        form={form}
        layout="vertical"
        onFinish={(v) => void submit(v)}
        initialValues={{ durationH: 18, durationM: 0, maxUses: 1 }}
      >
        <Form.Item label={t('admin.modal.add.code.label')}>
          <Space.Compact style={{ width: '100%' }}>
            <Form.Item name="code" noStyle>
              <Input placeholder={t('admin.modal.add.code.placeholder')} />
            </Form.Item>
            <Button onClick={() => form.setFieldValue('code', suggestNumericCode())}>
              {t('admin.modal.add.btn.autoGen')}
            </Button>
          </Space.Compact>
        </Form.Item>
        <ExpiryField />
        <DurationFields />
        <Form.Item name="maxUses" label={t('admin.modal.add.maxUses.label')}>
          <InputNumber min={0} style={{ width: '100%' }} />
        </Form.Item>
        <Form.Item name="note" label={t('admin.modal.add.note.label')}>
          <TextArea rows={2} />
        </Form.Item>
      </Form>
    </Modal>
  )
}

interface BatchValues extends AddValues {
  codeType: 'numeric' | 'alpha' | 'alphanumeric'
  count: number
  length: number
}

export function BatchCodeModal({
  open,
  onClose,
  onGenerated,
}: {
  open: boolean
  onClose: () => void
  /** Hands the generated codes up so the result modal can show them once. */
  onGenerated: (codes: string[]) => void
}) {
  const { message } = App.useApp()
  const [form] = Form.useForm<BatchValues>()

  async function submit(values: BatchValues) {
    try {
      const body = await postForm<{ codes?: string[] }>('/admin/codes/batch', {
        code_type: values.codeType,
        count: values.count,
        length: values.length,
        expires_at: values.expiresAt || undefined,
        duration_min: durationMin(values),
        max_uses: values.maxUses ?? 0,
        note: values.note ?? '',
      })
      onClose()
      onGenerated(body.codes ?? [])
    } catch (err) {
      message.error(t('admin.toast.batchFailed', err instanceof ApiError ? err.code : 'error'))
    }
  }

  return (
    <Modal
      open={open}
      title={t('admin.modal.batch.title')}
      onCancel={onClose}
      okText={t('admin.modal.batch.btn.generate')}
      cancelText={t('admin.common.cancel')}
      onOk={() => form.submit()}
      destroyOnHidden
    >
      <Form
        form={form}
        layout="vertical"
        onFinish={(v) => void submit(v)}
        initialValues={{
          codeType: 'numeric',
          count: 10,
          length: 15,
          durationH: 18,
          durationM: 0,
          maxUses: 1,
        }}
      >
        <Form.Item name="codeType" label={t('admin.modal.batch.codeType.label')}>
          <Radio.Group>
            <Radio value="numeric">{t('admin.modal.batch.codeType.numeric')}</Radio>
            <Radio value="alpha">{t('admin.modal.batch.codeType.alpha')}</Radio>
            <Radio value="alphanumeric">{t('admin.modal.batch.codeType.alphanumeric')}</Radio>
          </Radio.Group>
        </Form.Item>
        <Space size="large">
          {/* Bounds mirror handleCodeBatch, which silently clamps out-of-range
              values. Enforcing them here means the admin sees the limit instead
              of wondering why they asked for 500 codes and got 200. */}
          <Form.Item name="count" label={t('admin.modal.batch.count.label')}>
            <InputNumber min={1} max={200} />
          </Form.Item>
          <Form.Item name="length" label={t('admin.modal.batch.length.label')}>
            <InputNumber min={6} max={32} />
          </Form.Item>
        </Space>
        <ExpiryField />
        <DurationFields />
        <Form.Item name="maxUses" label={t('admin.modal.batch.eachMaxUses.label')}>
          <InputNumber min={0} style={{ width: '100%' }} />
        </Form.Item>
        <Form.Item name="note" label={t('admin.modal.add.note.label')}>
          <TextArea rows={2} />
        </Form.Item>
      </Form>
    </Modal>
  )
}

export function EditCodeModal({
  row,
  onClose,
  onDone,
}: {
  /** null closes the modal; a row opens it pre-filled with that code. */
  row: CodeRow | null
  onClose: () => void
  onDone: () => void
}) {
  const { message } = App.useApp()
  const [form] = Form.useForm<AddValues>()

  useEffect(() => {
    if (!row) return
    // Defaults to 18h when the stored duration is missing, matching the old
    // panel's fallback so an edit never silently zeroes a code's session length.
    const { h, m } = splitDuration(row.durationMin || 1080)
    form.setFieldsValue({
      expiresAt: row.expiresAtInput,
      durationH: h,
      durationM: m,
      maxUses: row.maxUses,
      note: row.note,
    })
  }, [row, form])

  async function submit(values: AddValues) {
    if (!row) return
    try {
      await postForm('/admin/codes/edit', {
        code: row.code,
        // Sent even when empty: an empty expires_at is how the handler is told
        // to clear an expiry, so undefined-ing it would make "never expires"
        // unreachable from the edit form.
        expires_at: values.expiresAt ?? '',
        duration_min: durationMin(values),
        max_uses: values.maxUses ?? 0,
        note: values.note ?? '',
      })
      message.success(t('admin.toast.saved'))
      onClose()
      onDone()
    } catch (err) {
      message.error(t('admin.toast.editFailed', err instanceof ApiError ? err.code : 'error'))
    }
  }

  return (
    <Modal
      open={row !== null}
      title={
        <Space>
          {t('admin.modal.edit.titleFmt')}
          <Typography.Text code>{row?.code}</Typography.Text>
        </Space>
      }
      onCancel={onClose}
      okText={t('admin.modal.add.btn.save')}
      cancelText={t('admin.common.cancel')}
      onOk={() => form.submit()}
      destroyOnHidden
    >
      <Form form={form} layout="vertical" onFinish={(v) => void submit(v)}>
        <ExpiryField />
        <DurationFields />
        <Form.Item name="maxUses" label={t('admin.modal.add.maxUses.label')}>
          <InputNumber min={0} style={{ width: '100%' }} />
        </Form.Item>
        <Form.Item name="note" label={t('admin.modal.add.note.label')}>
          <TextArea rows={2} />
        </Form.Item>
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          {t('admin.modal.edit.subtext')}
        </Typography.Text>
      </Form>
    </Modal>
  )
}

/**
 * Shows a freshly generated batch. This is the only moment the full codes are
 * ever displayed — the audit log stores just the last four characters — so the
 * modal is deliberately blocking and offers a copy-all button.
 */
export function BatchResultModal({ codes, onClose }: { codes: string[] | null; onClose: () => void }) {
  const { message } = App.useApp()
  const text = (codes ?? []).join('\n')

  async function copy() {
    try {
      await navigator.clipboard.writeText(text)
      message.success(t('admin.toast.copied'))
    } catch {
      // clipboard.writeText needs a secure context. A portal reached over plain
      // HTTP on a lab network has none, and the codes would otherwise be
      // unrecoverable once this modal closes — so say so rather than failing
      // silently.
      message.error(t('admin.toast.copyFailed'))
    }
  }

  return (
    <Modal
      open={codes !== null}
      title={t('admin.modal.result.titleFmt', codes?.length ?? 0)}
      onCancel={onClose}
      footer={[
        <Button key="copy" onClick={() => void copy()}>
          {t('admin.modal.result.btn.copy')}
        </Button>,
        <Button key="done" type="primary" onClick={onClose}>
          {t('admin.modal.result.btn.done')}
        </Button>,
      ]}
    >
      <TextArea value={text} readOnly rows={12} style={{ fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace' }} />
    </Modal>
  )
}
