import React from 'react';
import DashboardChecklistGrid from '../../components/DashboardChecklistGrid';
import { getDashboardChecklistCards } from '../../components/dashboardContent';

export function AppSettingsPage(): React.JSX.Element {
  const cards = getDashboardChecklistCards('/dashboard/app-settings');

  return (
    <div className="dashboard-view" aria-label="App settings page">
      <DashboardChecklistGrid cards={cards} />
    </div>
  );
}

export default AppSettingsPage;
