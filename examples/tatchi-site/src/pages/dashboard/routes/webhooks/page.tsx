import React from 'react';
import DashboardChecklistGrid from '../../components/DashboardChecklistGrid';
import { getDashboardChecklistCards } from '../../components/dashboardContent';

export function WebhooksPage(): React.JSX.Element {
  const cards = getDashboardChecklistCards('/dashboard/webhooks');

  return (
    <div className="dashboard-view" aria-label="Webhooks page">
      <DashboardChecklistGrid cards={cards} />
    </div>
  );
}

export default WebhooksPage;
