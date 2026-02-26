import React from 'react';
import DashboardChecklistGrid from '../../components/dashboard/DashboardChecklistGrid';
import { getDashboardChecklistCards } from '../../components/dashboard/dashboardContent';

export function ExportKeysSettingsPage(): React.JSX.Element {
  const cards = getDashboardChecklistCards('/dashboard/export-keys');

  return (
    <div className="dashboard-view" aria-label="Export keys settings page">
      <DashboardChecklistGrid cards={cards} />
    </div>
  );
}

export default ExportKeysSettingsPage;
