import React from 'react'

export function AppSettingsPage(): React.JSX.Element {
  return (
    <div className="dashboard-view" aria-label="App settings page">
      <section className="dashboard-view-grid dashboard-view-grid--two">
        <article className="dashboard-view-card">
          <h2>Origins and session configuration</h2>
          <ul className="dashboard-view-list">
            <li>Environment-scoped allowed origins/domains with strict validation.</li>
            <li>Cookie mode controls: HttpOnly, Secure, SameSite.</li>
            <li>Guardrails for risky changes with warnings and confirmations.</li>
          </ul>
        </article>

        <article className="dashboard-view-card">
          <h2>JWT and optional controls</h2>
          <ul className="dashboard-view-list">
            <li>Issuer, audience, key IDs, token TTL, and refresh TTL.</li>
            <li>Optional IP allowlist configuration.</li>
            <li>Optional SSO metadata fields by environment.</li>
          </ul>
        </article>
      </section>
    </div>
  )
}

export default AppSettingsPage
