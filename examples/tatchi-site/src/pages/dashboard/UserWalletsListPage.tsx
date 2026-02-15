import React from 'react'

export function UserWalletsListPage(): React.JSX.Element {
  return (
    <div className="dashboard-view" aria-label="User wallets list page">
      <section className="dashboard-kpi-grid dashboard-kpi-grid--content" aria-label="Wallet KPI summary">
        <article className="dashboard-kpi-card">
          <p className="dashboard-kpi-card__label">Total assets</p>
          <p className="dashboard-kpi-card__value">$12.4M</p>
          <p className="dashboard-kpi-card__hint">Across all tracked wallets</p>
        </article>
        <article className="dashboard-kpi-card">
          <p className="dashboard-kpi-card__label">Total wallets</p>
          <p className="dashboard-kpi-card__value">24,581</p>
          <p className="dashboard-kpi-card__hint">Includes EOA and smart wallets</p>
        </article>
        <article className="dashboard-kpi-card">
          <p className="dashboard-kpi-card__label">Funded wallets</p>
          <p className="dashboard-kpi-card__value">9,742</p>
          <p className="dashboard-kpi-card__hint">39.6% funded ratio</p>
        </article>
        <article className="dashboard-kpi-card">
          <p className="dashboard-kpi-card__label">Activity (7d)</p>
          <p className="dashboard-kpi-card__value">18,902 tx</p>
          <p className="dashboard-kpi-card__hint">24h and 7d windows available</p>
        </article>
      </section>

      <section className="dashboard-table-wrapper" aria-label="Wallets table">
        <div className="dashboard-table-header" role="row">
          <span>Wallet ID</span>
          <span>Address</span>
          <span>Chain</span>
          <span>Owner/User</span>
          <span>Policy</span>
          <span>Balance</span>
          <span>Status</span>
          <span>Updated</span>
        </div>
        <p className="dashboard-table-limit">
          Row actions: view details, view activity, assign policy, and freeze/unfreeze where supported.
        </p>
      </section>
    </div>
  )
}

export default UserWalletsListPage
