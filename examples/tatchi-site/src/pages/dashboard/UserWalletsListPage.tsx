import React from 'react';
import {
  USER_WALLETS_LIST_KPIS,
  USER_WALLETS_TABLE_COLUMNS,
  USER_WALLETS_TABLE_NOTE,
} from '../../components/dashboard/dashboardContent';

export function UserWalletsListPage(): React.JSX.Element {
  return (
    <div className="dashboard-view" aria-label="User wallets list page">
      <section
        className="dashboard-kpi-grid dashboard-kpi-grid--content"
        aria-label="Wallet KPI summary"
      >
        {USER_WALLETS_LIST_KPIS.map((metric) => (
          <article className="dashboard-kpi-card" key={metric.label}>
            <p className="dashboard-kpi-card__label">{metric.label}</p>
            <p className="dashboard-kpi-card__value">{metric.value}</p>
            <p className="dashboard-kpi-card__hint">{metric.hint}</p>
          </article>
        ))}
      </section>

      <section className="dashboard-table-wrapper" aria-label="Wallets table">
        <div className="dashboard-table-header" role="row">
          {USER_WALLETS_TABLE_COLUMNS.map((column) => (
            <span key={column}>{column}</span>
          ))}
        </div>
        <p className="dashboard-table-limit">{USER_WALLETS_TABLE_NOTE}</p>
      </section>
    </div>
  );
}

export default UserWalletsListPage;
