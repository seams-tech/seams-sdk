import React from 'react';
import DashboardChecklistGrid from '../../components/dashboard/DashboardChecklistGrid';
import { getDashboardChecklistCards } from '../../components/dashboard/dashboardContent';

export function PolicyEnginePage(): React.JSX.Element {
  const cards = getDashboardChecklistCards('/dashboard/policy-engine');

  return (
    <div className="dashboard-view" aria-label="Policy engine page">
      <DashboardChecklistGrid cards={cards} />
    </div>
  );
}

export default PolicyEnginePage;
