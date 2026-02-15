import React from 'react'

export function ExportKeysSettingsPage(): React.JSX.Element {
  return (
    <div className="dashboard-view" aria-label="Export keys settings page">
      <section className="dashboard-view-grid dashboard-view-grid--two">
        <article className="dashboard-view-card">
          <h2>Export policy modes</h2>
          <ul className="dashboard-view-list">
            <li>Disabled</li>
            <li>Approval required</li>
            <li>Allowed with scoped constraints</li>
          </ul>
        </article>

        <article className="dashboard-view-card">
          <h2>Approval and audit controls</h2>
          <ul className="dashboard-view-list">
            <li>Constraints by role, chain, wallet type, and environment.</li>
            <li>Step-up requirements with MFA and reason capture.</li>
            <li>Immutable logs for who, what, when, why, and approval chain.</li>
          </ul>
        </article>
      </section>
    </div>
  )
}

export default ExportKeysSettingsPage
