import React from 'react';

const requirements = [
  'Use a customer-owned wallet hostname, like `wallet.dev1.com`, from the start.',
  'Keep DNS access so you can add our CNAME and TXT records.',
  'Keep the same WebAuthn `rpId`, headers, and wallet paths in hosted and self-hosted setups.',
] as const;

const dnsExample = [
  'wallet.dev1.com CNAME customer-wallet-edge.seams.xyz',
  '_seams-verify.wallet.dev1.com TXT <vendor-generated-verification-token>',
  '_acme-challenge.wallet.dev1.com TXT <vendor-generated-acme-token>  # optional when requested for TLS',
].join('\n');

export function SelfHostingPage(): React.JSX.Element {
  return (
    <div className="dashboard-view" aria-label="Self hosting page">
      <section className="dashboard-view__section" aria-label="Self hosting overview">
        <h2>Self Hosting (to be implemented later)</h2>
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

      <section className="dashboard-view__section" aria-label="After DNS setup">
        <h2>After DNS setup</h2>
        <ul className="dashboard-view-list">
          <li>Wait for the CNAME and TXT records to propagate and for hostname verification/TLS activation to finish.</li>
          <li>
            Once activation completes, <code>https://wallet.dev1.com</code> automatically routes to
            our hosted wallet-service and SDK asset endpoints through the configured CNAME target.
          </li>
          <li>
            Point the customer app at <code>https://wallet.dev1.com</code>, keep the same
            {' '}
            <code>/wallet-service</code> path and WebAuthn <code>rpId</code>, then validate
            registration, login, and signing.
          </li>
          <li>
            If DNS has not propagated yet, or verification/TLS is still pending, the hostname is
            not ready for production traffic.
          </li>
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
