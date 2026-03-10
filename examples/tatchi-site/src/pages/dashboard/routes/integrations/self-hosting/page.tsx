import React from 'react';

const requirements = [
  'Reserve a customer-owned wallet origin such as `wallet.dev1.com` before the first production launch.',
  'Keep DNS control for that hostname so the team can add vendor-provided CNAME and TXT records.',
  'Keep WebAuthn `rpId`, headers, and wallet paths stable across hosted and self-hosted environments.',
] as const;

const rollout = [
  'Add the hosted CNAME and verification TXT records while traffic is still served by hosted infrastructure.',
  'Keep the same wallet contract, asset paths, and WebAuthn boundary while validating the deployment.',
  'When the team is ready to self-host, update the CNAME target or equivalent edge routing without changing the visible hostname.',
] as const;

const dnsExample = [
  'wallet.dev1.com CNAME customer-wallet-edge.tatchi.xyz',
  '_tatchi-verify.wallet.dev1.com TXT <vendor-generated-verification-token>',
  '_acme-challenge.wallet.dev1.com TXT <vendor-generated-acme-token>  # optional when requested for TLS',
].join('\n');

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

      <section className="dashboard-view__section" aria-label="Hosted rollout DNS records">
        <h2>Hosted rollout DNS records</h2>
        <p>
          The default setup is <code>CNAME + TXT</code>. The customer keeps DNS in their own
          provider, copies the records below, and the hosted edge is activated after they resolve.
        </p>
        <pre className="dashboard-code-block">
          <code>{dnsExample}</code>
        </pre>
        <p>
          Do not redirect the browser to a vendor hostname. The wallet must stay visible at
          {' '}
          <code>https://wallet.dev1.com</code> so passkeys and wallet-origin state remain stable.
        </p>
      </section>

      <section className="dashboard-view__section" aria-label="Hosted to self-hosted rollout">
        <h2>Recommended rollout</h2>
        <ul className="dashboard-view-list">
          {rollout.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
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
