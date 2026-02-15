import React from 'react'

export function GasSponsorshipSmartWalletsPage(): React.JSX.Element {
  return (
    <div className="dashboard-view" aria-label="Gas sponsorship and smart wallets page">
      <section className="dashboard-view-grid dashboard-view-grid--two">
        <article className="dashboard-view-card">
          <h2>Gas sponsorship controls</h2>
          <ul className="dashboard-view-list">
            <li>Enable/disable at org, environment, policy, and wallet segment scope.</li>
            <li>Budget and quota controls by chain and billing period.</li>
            <li>Alert thresholds for overspend and budget exhaustion.</li>
          </ul>
        </article>

        <article className="dashboard-view-card">
          <h2>Smart wallet controls</h2>
          <ul className="dashboard-view-list">
            <li>Account abstraction mode and account type selection.</li>
            <li>Paymaster mode and fallback behavior.</li>
            <li>Telemetry for sponsored tx count, spend, and failures.</li>
          </ul>
        </article>
      </section>
    </div>
  )
}

export default GasSponsorshipSmartWalletsPage
