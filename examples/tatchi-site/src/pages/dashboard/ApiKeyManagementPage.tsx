import React from 'react';
import DashboardChecklistGrid from '../../components/dashboard/DashboardChecklistGrid';
import { getDashboardChecklistCards } from '../../components/dashboard/dashboardContent';

export function ApiKeyManagementPage(): React.JSX.Element {
  const cards = getDashboardChecklistCards('/dashboard/api-keys');

  return (
    <div className="dashboard-view" aria-label="API key management page">
      <DashboardChecklistGrid cards={cards} />
    </div>
  );
}

export default ApiKeyManagementPage;
