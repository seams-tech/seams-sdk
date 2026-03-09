import React from 'react';

const requirements = [
  'Reserve a customer-owned wallet origin such as `wallet.dev1.com` before the first production launch.',
  'Point that origin at the hosted deployment with a CNAME, custom hostname, or reverse proxy.',
  'Keep WebAuthn `rpId`, headers, and wallet paths stable across hosted and self-hosted environments.',
] as const;

export function SelfHostingPage(): React.JSX.Element {
  return (
    <div className="dashboard-view" aria-label="Self hosting page">
      <section className="dashboard-view__section" aria-label="Self hosting overview">
        <h2>Self Hosting</h2>
        <p>
          Start with a customer-owned wallet origin, run it on hosted infrastructure first, then
          move the same origin to customer infrastructure later. Passkeys stay valid as long as the
          visible hostname and `rpId` do not change.
        </p>
      </section>

      <section className="dashboard-view__section" aria-label="Self hosting requirements">
        <h2>Requirements</h2>
        <ul className="dashboard-view-list">
          {requirements.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      </section>

      <section className="dashboard-view__section" aria-label="Hosted to self-hosted rollout">
        <h2>Recommended rollout</h2>
        <p>
          1. Launch on the customer-owned hostname while traffic is still served by hosted
          infrastructure.
        </p>
        <p>
          2. Keep the same wallet contract, asset paths, and WebAuthn boundary while validating the
          deployment.
        </p>
        <p>
          3. Cut over DNS or proxy routing to the customer deployment when the team is ready to
          self-host.
        </p>
      </section>

      <section className="dashboard-view__section" aria-label="Self hosting tradeoffs">
        <h2>Tradeoffs</h2>
        <p>
          Self-hosting gives the customer direct control over wallet infrastructure and operations,
          but it narrows composability. Shared wallet reuse works best on a common hosted origin,
          while customer-owned infrastructure optimizes for isolation, branding, and long-term
          control.
        </p>
      </section>
    </div>
  );
}
