import React from 'react';

const prerequisites = [
  'Customer already controls a domain and reserves a stable wallet hostname such as wallet.dev1.com.',
  'Customer points that hostname at vendor infrastructure with a browser-transparent CNAME, custom hostname, or reverse proxy.',
  'Customer app config uses the customer-owned wallet origin from day 0 instead of a shared vendor wallet hostname.',
] as const;

const rolloutPlan = [
  'Vendor hosts /wallet-service and wallet assets behind https://wallet.dev1.com while the browser-visible origin remains customer-owned.',
  'Customer keeps rpId stable on the customer boundary, typically dev1.com or wallet.dev1.com.',
  'Customer app delegates WebAuthn to the wallet origin and treats that hostname as the permanent wallet trust boundary.',
] as const;

const migrationPath = [
  'Customer deploys the same wallet-service contract and asset paths on their own infrastructure.',
  'Customer preserves the same hostname, rpId, headers, and path structure during cutover.',
  'Customer repoints DNS or proxy routing from vendor edge to customer infrastructure without forcing passkey re-enrollment.',
] as const;

const composabilityTradeoffs = [
  'Shared network composability across unrelated customers is lost once each customer gets its own wallet domain.',
  'Wallet reuse is preserved only across apps that integrate the same customer-owned wallet origin.',
  'The customer-owned model is the clean path for white-label deployments and later self-hosting.',
] as const;

export function EnterpriseIsolationPage(): React.JSX.Element {
  return (
    <div className="dashboard-view" aria-label="Self hosting page">
      <section className="dashboard-view__section" aria-label="Self hosting overview">
        <h2>Self Hosting</h2>
        <p>
          The clean self-hosting path is to start on a customer-owned wallet hostname such as{' '}
          <code>https://wallet.dev1.com</code>, host it on vendor infrastructure first, and keep that
          hostname stable when the customer later moves the wallet service in-house.
        </p>
      </section>

      <section className="dashboard-view__section" aria-label="Customer-owned wallet prerequisites">
        <h2>Customer prerequisites</h2>
        <ul className="dashboard-view-list">
          {prerequisites.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      </section>

      <section className="dashboard-view__section" aria-label="Vendor-hosted rollout plan">
        <h2>Vendor-hosted first</h2>
        <ul className="dashboard-view-list">
          {rolloutPlan.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      </section>

      <section className="dashboard-view__section" aria-label="Self-host migration path">
        <h2>Migration path to self-hosted</h2>
        <ul className="dashboard-view-list">
          {migrationPath.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      </section>

      <section className="dashboard-view__section" aria-label="Wallet composability tradeoffs">
        <h2>Wallet composability tradeoffs</h2>
        <ul className="dashboard-view-list">
          {composabilityTradeoffs.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      </section>
    </div>
  );
}
