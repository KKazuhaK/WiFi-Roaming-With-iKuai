import { Card, Statistic } from 'antd'
import { t } from '@/lib/i18n'
import type { AdminState } from './types'
import type { AdminView } from './AdminLayout'

/** Above one in five terminal attempts failing is worth an operator's attention. */
const FAILURE_RATE_ALERT = 20

const DANGER = { color: '#dc2626' }

/**
 * The counters that used to sit above every tab.
 *
 * They are their own view now rather than a permanent header. Seven statistics
 * pinned above a table are useful on the first visit and noise on the hundredth,
 * and they were pushing the guest-code table below the fold on a laptop. Cards
 * that lead somewhere are more useful than cards that only inform, so the ones
 * with a natural destination are clickable.
 */
export function DashboardSection({
  state,
  onView,
}: {
  state: AdminState
  onView: (v: AdminView) => void
}) {
  const d = state.dashboard
  const link = (v: AdminView) => ({
    hoverable: true,
    onClick: () => onView(v),
    style: { cursor: 'pointer' },
  })

  return (
    <div className="admin-dashboard">
      <Card size="small" {...link('events')}>
        <Statistic title={t('admin.dash.loginsToday')} value={d.loginsToday} />
      </Card>
      <Card size="small" {...link('events')}>
        <Statistic title={t('admin.dash.loginsWeek')} value={d.loginsWeek} />
      </Card>
      <Card size="small" {...link('events')}>
        <Statistic
          title={t('admin.dash.failRate')}
          // The percent sign belongs to the number: antd puts a 4px gap before
          // a suffix, which renders "25 % (9)".
          value={`${d.failedRatePct}%`}
          suffix={`(${d.failedCount7d})`}
          valueStyle={d.failedRatePct > FAILURE_RATE_ALERT ? DANGER : undefined}
        />
      </Card>
      <Card size="small" {...link('codes')}>
        <Statistic title={t('admin.dash.activeCodes')} value={d.activeGuestCodes} />
      </Card>
      <Card size="small" {...link('ratelimit')}>
        <Statistic
          title={t('admin.dash.bannedIp')}
          value={d.bannedIps}
          valueStyle={d.bannedIps > 0 ? DANGER : undefined}
        />
      </Card>
      <Card size="small" {...link('macs')}>
        <Statistic
          title={t('admin.dash.bannedMac')}
          value={d.bannedMacs}
          valueStyle={d.bannedMacs > 0 ? DANGER : undefined}
        />
      </Card>
      <Card size="small" {...link('codes')}>
        <Statistic title={t('admin.dash.totalCodes')} value={state.total} />
      </Card>
    </div>
  )
}
