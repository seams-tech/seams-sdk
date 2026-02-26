import React from 'react';
import DashboardChecklistGrid from '../../components/dashboard/DashboardChecklistGrid';
import { getDashboardChecklistCards } from '../../components/dashboard/dashboardContent';

export function GasSponsorshipSmartWalletsPage(): React.JSX.Element {
  const cards = getDashboardChecklistCards('/dashboard/gas-smart-wallets');

  return (
    <div className="dashboard-view" aria-label="Gas sponsorship and smart wallets page">
      <DashboardChecklistGrid cards={cards} />
    </div>
  );
}

export default GasSponsorshipSmartWalletsPage;
