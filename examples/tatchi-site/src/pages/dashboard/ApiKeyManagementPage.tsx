import React from 'react'

export function ApiKeyManagementPage(): React.JSX.Element {
  return (
    <div className="dashboard-view" aria-label="API key management page">
      <section className="dashboard-view-grid dashboard-view-grid--two">
        <article className="dashboard-view-card">
          <h2>Key lifecycle</h2>
          <ul className="dashboard-view-list">
            <li>Create, revoke, and rotate API keys with scoped permissions.</li>
            <li>Environment scoping and optional IP restrictions.</li>
            <li>Secrets visible once at creation and never retrievable.</li>
          </ul>
        </article>

        <article className="dashboard-view-card">
          <h2>Usage and anomaly monitoring</h2>
          <ul className="dashboard-view-list">
            <li>Last-used timestamp and endpoint distribution.</li>
            <li>Anomaly flags for suspicious usage patterns.</li>
            <li>Audit logging for create/revoke/rotate actions.</li>
          </ul>
        </article>
      </section>
    </div>
  )
}

export default ApiKeyManagementPage
