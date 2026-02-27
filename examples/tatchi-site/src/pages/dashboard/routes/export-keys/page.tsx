import React from 'react';
import DashboardChecklistGrid from '../../components/DashboardChecklistGrid';
import { getDashboardChecklistCards } from '../../components/dashboardContent';

export function ExportKeysSettingsPage(): React.JSX.Element {
  const cards = getDashboardChecklistCards('/dashboard/export-keys');

  return (
    <div className="dashboard-view" aria-label="Export keys settings page">
      <DashboardChecklistGrid cards={cards} />
    </div>
  );
}

export default ExportKeysSettingsPage;
