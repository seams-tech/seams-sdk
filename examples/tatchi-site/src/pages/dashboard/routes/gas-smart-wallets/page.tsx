import React from 'react';
import DashboardChecklistGrid from '../../components/DashboardChecklistGrid';
import { getDashboardChecklistCards } from '../../components/dashboardContent';

export function GasSponsorshipSmartWalletsPage(): React.JSX.Element {
  const cards = getDashboardChecklistCards('/dashboard/gas-smart-wallets');

  return (
    <div className="dashboard-view" aria-label="Gas sponsorship and smart wallets page">
      <DashboardChecklistGrid cards={cards} />
    </div>
  );
}

export default GasSponsorshipSmartWalletsPage;
