import React from 'react';
import DashboardChecklistGrid from '../../components/dashboard/DashboardChecklistGrid';
import { getDashboardChecklistCards } from '../../components/dashboard/dashboardContent';

export function AppSettingsPage(): React.JSX.Element {
  const cards = getDashboardChecklistCards('/dashboard/app-settings');

  return (
    <div className="dashboard-view" aria-label="App settings page">
      <DashboardChecklistGrid cards={cards} />
    </div>
  );
}

export default AppSettingsPage;
