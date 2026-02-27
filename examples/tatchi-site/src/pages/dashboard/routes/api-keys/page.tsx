import React from 'react';
import DashboardChecklistGrid from '../../components/DashboardChecklistGrid';
import { getDashboardChecklistCards } from '../../components/dashboardContent';

export function ApiKeyManagementPage(): React.JSX.Element {
  const cards = getDashboardChecklistCards('/dashboard/api-keys');

  return (
    <div className="dashboard-view" aria-label="API key management page">
      <DashboardChecklistGrid cards={cards} />
    </div>
  );
}

export default ApiKeyManagementPage;
