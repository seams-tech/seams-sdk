import React from 'react'

export function WebhooksPage(): React.JSX.Element {
  return (
    <div className="dashboard-view" aria-label="Webhooks page">
      <section className="dashboard-view-grid dashboard-view-grid--two">
        <article className="dashboard-view-card">
          <h2>Endpoint and signing setup</h2>
          <ul className="dashboard-view-list">
            <li>Register endpoints with event subscriptions.</li>
            <li>Signed payloads with rotating secrets.</li>
            <li>Subscription scopes: wallet, policy, auth, tx lifecycle.</li>
          </ul>
        </article>

        <article className="dashboard-view-card">
          <h2>Delivery operations</h2>
          <ul className="dashboard-view-list">
            <li>Backoff retries and dead-letter queue handling.</li>
            <li>Delivery logs with request and response metadata.</li>
            <li>Replay actions for failed webhook deliveries.</li>
          </ul>
        </article>
      </section>
    </div>
  )
}

export default WebhooksPage
