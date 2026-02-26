import React from 'react';
import { Footer } from '../components/Footer';
import NavbarStatic from '../components/Navbar/NavbarStatic';
import { useSiteRouter } from '../hooks/useSiteRouter';

export function PricingPage(): React.JSX.Element {
  const { linkProps } = useSiteRouter();
  const dashboardProps = linkProps('/dashboard');

  return (
    <>
      <NavbarStatic />
      <main className="pricing-page" aria-labelledby="pricing-page-title">
        <div className="pricing-wrap">
          <section className="pricing-hero">
            <p className="pricing-kicker">Pricing</p>
            <h1 id="pricing-page-title">
              Simple wallet infrastructure pricing that scales with your app
            </h1>
            <p className="pricing-subtitle">
              Start in self-serve mode, then move to enterprise controls when you need stricter
              policy workflows, compliance, and operational guarantees.
            </p>
            <div className="pricing-hero-actions">
              <a
                className="pricing-button pricing-button--solid"
                href={dashboardProps.href}
                onClick={dashboardProps.onClick}
              >
                Open dashboard preview
              </a>
              <a
                className="pricing-button pricing-button--ghost"
                href={dashboardProps.href}
                onClick={dashboardProps.onClick}
              >
                Talk to sales
              </a>
            </div>
          </section>

          <section className="pricing-cards" aria-label="Plans">
            <article className="pricing-card pricing-card--self-serve">
              <div className="pricing-card-header">
                <div>
                  <p className="pricing-card-label">Self-serve</p>
                  <h2>Build and launch fast</h2>
                  <p>Ideal for teams shipping embedded wallets for the first time.</p>
                </div>
                <div className="pricing-price-pill">
                  <strong>$0</strong>
                  <span>base / month</span>
                </div>
              </div>
              <ul className="pricing-feature-list">
                <li>Passkey login and embedded wallet SDK</li>
                <li>Wallet list + wallet search controls</li>
                <li>Base policy presets and chain controls</li>
                <li>Standard API keys and webhook endpoints</li>
              </ul>
              <div className="pricing-tier-list" role="list" aria-label="Usage tiers">
                <div className="pricing-tier" role="listitem">
                  <p>Starter</p>
                  <p>Up to 5K MAW</p>
                  <p>Included</p>
                </div>
                <div className="pricing-tier" role="listitem">
                  <p>Growth</p>
                  <p>5K to 100K MAW</p>
                  <p>Usage-based</p>
                </div>
                <div className="pricing-tier" role="listitem">
                  <p>Scale</p>
                  <p>100K+ MAW</p>
                  <p>Volume discounts</p>
                </div>
              </div>
              <a
                className="pricing-button pricing-button--solid pricing-button--full"
                href={dashboardProps.href}
                onClick={dashboardProps.onClick}
              >
                Start with dashboard mock
              </a>
            </article>

            <article className="pricing-card pricing-card--enterprise">
              <p className="pricing-card-label">Enterprise</p>
              <h2>Advanced controls and support</h2>
              <p className="pricing-enterprise-copy">
                For teams that need approval workflows, dedicated environments, and
                compliance-oriented operations.
              </p>
              <ul className="pricing-feature-list">
                <li>Custom policy engine with staged rollouts</li>
                <li>Gas sponsorship and smart wallet orchestration</li>
                <li>Dedicated SLA, onboarding, and architecture reviews</li>
                <li>Advanced RBAC, audit logs, and export controls</li>
              </ul>
              <a
                className="pricing-button pricing-button--ghost pricing-button--full"
                href={dashboardProps.href}
                onClick={dashboardProps.onClick}
              >
                Contact sales
              </a>
            </article>
          </section>

          <section className="pricing-includes" aria-label="Included with all plans">
            <h3>Included with every plan</h3>
            <div className="pricing-includes-grid">
              <article className="pricing-include-card">
                <strong>Wallets</strong>
                <p>User wallet list, search, and chain visibility.</p>
              </article>
              <article className="pricing-include-card">
                <strong>Policy controls</strong>
                <p>Action-level controls for threshold wallet operations.</p>
              </article>
              <article className="pricing-include-card">
                <strong>Authentication</strong>
                <p>Passkey-first auth and optional MFA enforcement.</p>
              </article>
              <article className="pricing-include-card">
                <strong>App settings</strong>
                <p>Origins, cookie/JWT modes, and environment controls.</p>
              </article>
              <article className="pricing-include-card">
                <strong>API keys</strong>
                <p>Scoped API keys with revocation and rotation support.</p>
              </article>
              <article className="pricing-include-card">
                <strong>Webhooks</strong>
                <p>Event delivery, retries, and delivery logs.</p>
              </article>
            </div>
          </section>

          <section className="pricing-compare" aria-label="Comparison">
            <h3>Compare plans</h3>
            <table>
              <thead>
                <tr>
                  <th scope="col">Capability</th>
                  <th scope="col">Self-serve</th>
                  <th scope="col">Enterprise</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>User wallets list + search</td>
                  <td>Yes</td>
                  <td>Yes + custom indexing</td>
                </tr>
                <tr>
                  <td>Policy engine</td>
                  <td>Preset and configurable rules</td>
                  <td>Custom workflows and approvals</td>
                </tr>
                <tr>
                  <td>Gas sponsorship / smart wallets</td>
                  <td>Supported</td>
                  <td>Advanced orchestration</td>
                </tr>
                <tr>
                  <td>App settings and security controls</td>
                  <td>Core controls</td>
                  <td>SSO and advanced governance</td>
                </tr>
                <tr>
                  <td>Support</td>
                  <td>Standard</td>
                  <td>Dedicated SLA</td>
                </tr>
              </tbody>
            </table>
          </section>

          <section className="pricing-faq" aria-label="FAQ">
            <h3>FAQ</h3>
            <details open>
              <summary>When do I move from self-serve to enterprise?</summary>
              <p>
                Most teams upgrade when they need custom policy approvals, stricter compliance
                workflows, or dedicated support channels.
              </p>
            </details>
            <details>
              <summary>Do both plans support threshold wallets?</summary>
              <p>
                Yes. Both tiers support threshold wallet flows, with enterprise adding deeper policy
                and governance controls.
              </p>
            </details>
            <details>
              <summary>Can I start in self-serve and migrate later?</summary>
              <p>
                Yes. Configuration and wallet infrastructure can be migrated without rebuilding your
                client integration.
              </p>
            </details>
          </section>

          <section className="pricing-cta">
            <div>
              <h3>Want a realistic control-plane walkthrough?</h3>
              <p>
                Use the mocked dashboard to align product, security, and platform requirements
                before implementation.
              </p>
            </div>
            <a
              className="pricing-button pricing-button--solid"
              href={dashboardProps.href}
              onClick={dashboardProps.onClick}
            >
              Go to dashboard mock
            </a>
          </section>
        </div>
      </main>
      <Footer />
    </>
  );
}

export default PricingPage;
