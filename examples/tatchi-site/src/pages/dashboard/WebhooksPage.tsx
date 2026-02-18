import React from 'react'
import DashboardChecklistGrid from '../../components/dashboard/DashboardChecklistGrid'
import { getDashboardChecklistCards } from '../../components/dashboard/dashboardContent'

export function WebhooksPage(): React.JSX.Element {
  const cards = getDashboardChecklistCards('/dashboard/webhooks')

  return (
    <div className="dashboard-view" aria-label="Webhooks page">
      <DashboardChecklistGrid cards={cards} />
    </div>
  )
}

export default WebhooksPage
