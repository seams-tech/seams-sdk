import React from 'react';
import { H2Footer } from '@/components/h2/sections';
import NavbarCompact from '@/components/Navbar/NavbarCompact';
import { useSiteRouter } from '@/app/router/useSiteRouter';
import '@/styles/h2.css';
import './styles.css';

export function PricingPage(): React.JSX.Element {
  const { linkProps } = useSiteRouter();
  const dashboardProps = linkProps('/dashboard');
  const docsProps = linkProps('/docs/');

  return (
    <div className="h2-page">
      <NavbarCompact />
      <div className="h2-col">
        <main className="pricing-page" aria-labelledby="pricing-page-title">
          <div className="pricing-wrap">
            <section className="pricing-hero h2-rule">
              <p className="pricing-kicker">Pricing</p>
              <h1 id="pricing-page-title">
                Simple key and credential infrastructure pricing that scales with your app
              </h1>
              <p className="pricing-subtitle">
                Start in self-serve mode, then move to enterprise controls when you need stricter
                policy workflows, compliance, and operational guarantees.
              </p>
              <div className="pricing-hero-tools">
                <nav className="pricing-plan-picker" aria-label="Jump to a pricing plan">
                  <a href="#starter">Self-serve</a>
                  <a href="#enterprise">Enterprise</a>
                </nav>
                <p className="pricing-billing-note">Usage-based billing</p>
              </div>
            </section>

            <section className="pricing-cards h2-rule" aria-label="Plans">
              <article id="starter" className="pricing-card pricing-card--self-serve">
                <div className="pricing-card-spotlight">
                  <div>
                    <p className="pricing-card-label">Self-serve</p>
                    <h2>Build and launch fast</h2>
                    <p className="pricing-card-summary">
                      Ideal for teams shipping policy-bound keys for the first time.
                    </p>
                  </div>
                  <div className="pricing-price">
                    <strong>$0</strong>
                    <span>base / month</span>
                  </div>
                </div>
                <a
                  className="pricing-button pricing-button--solid pricing-button--full"
                  {...docsProps}
                >
                  Get started
                </a>
                <p className="pricing-feature-intro">Everything you need to launch</p>
                <ul className="pricing-feature-list">
                  <li>Passkey, Email OTP, and embedded wallet SDK</li>
                  <li>Wallet list + wallet search controls</li>
                  <li>Base policy presets, auth methods, and chain controls</li>
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
              </article>

              <article id="enterprise" className="pricing-card pricing-card--enterprise">
                <div className="pricing-card-spotlight">
                  <div>
                    <p className="pricing-card-label">Enterprise</p>
                    <h2>Advanced controls and support</h2>
                    <p className="pricing-card-summary">
                      For teams that need approval workflows, dedicated environments, and
                      compliance-oriented operations.
                    </p>
                  </div>
                  <div className="pricing-price pricing-price--custom">
                    <strong>Custom</strong>
                    <span>tailored to your usage</span>
                  </div>
                </div>
                <a
                  className="pricing-button pricing-button--solid pricing-button--full"
                  href={dashboardProps.href}
                  onClick={dashboardProps.onClick}
                >
                  Contact sales
                </a>
                <p className="pricing-feature-intro">Everything in self-serve, plus</p>
                <ul className="pricing-feature-list">
                  <li>Custom policy engine with staged rollouts</li>
                  <li>Gas sponsorship controls</li>
                  <li>Dedicated SLA, onboarding, and architecture reviews</li>
                  <li>Advanced RBAC, audit logs, and export controls</li>
                </ul>
              </article>
            </section>

            <section className="pricing-includes h2-rule" aria-label="Included with all plans">
              <div className="pricing-section-heading">
                <p className="pricing-kicker">Core platform</p>
                <h3>Included with every plan</h3>
              </div>
              <div className="pricing-includes-grid">
                <article className="pricing-include-card">
                  <strong>Wallets and keys</strong>
                  <p>User wallet list, key state, search, and chain visibility.</p>
                </article>
                <article className="pricing-include-card">
                  <strong>Policy controls</strong>
                  <p>Action-level controls for signing and delegated execution.</p>
                </article>
                <article className="pricing-include-card">
                  <strong>Authentication</strong>
                  <p>Passkeys, Email OTP, VoiceID, and optional step-up enforcement.</p>
                </article>
                <article className="pricing-include-card">
                  <strong>Browser origin controls</strong>
                  <p>Manage publishable_key origins for browser registration flows.</p>
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

            <section className="pricing-compare h2-rule" aria-label="Comparison">
              <div className="pricing-section-heading">
                <p className="pricing-kicker">Plan details</p>
                <h3>Compare plans</h3>
              </div>
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
                    <td>User wallets and keys list + search</td>
                    <td>Yes</td>
                    <td>Yes + custom indexing</td>
                  </tr>
                  <tr>
                    <td>Policy engine</td>
                    <td>Preset and configurable rules</td>
                    <td>Custom workflows and approvals</td>
                  </tr>
                  <tr>
                    <td>Gas sponsorship</td>
                    <td>Supported</td>
                    <td>Advanced orchestration</td>
                  </tr>
                  <tr>
                    <td>Browser origin controls</td>
                    <td>Per-key origin allowlists</td>
                    <td>Advanced governance</td>
                  </tr>
                  <tr>
                    <td>Support</td>
                    <td>Standard</td>
                    <td>Dedicated SLA</td>
                  </tr>
                </tbody>
              </table>
            </section>

            <section className="pricing-faq h2-rule" aria-label="FAQ">
              <div className="pricing-section-heading">
                <p className="pricing-kicker">Questions</p>
                <h3>FAQ</h3>
              </div>
              <details open>
                <summary>When do I move from self-serve to enterprise?</summary>
                <p>
                  Most teams upgrade when they need custom policy approvals, stricter compliance
                  workflows, or dedicated support channels.
                </p>
              </details>
              <details>
                <summary>Do both plans support threshold signing?</summary>
                <p>
                  Yes. Both tiers support threshold signing flows, with enterprise adding deeper
                  policy and governance controls.
                </p>
              </details>
              <details>
                <summary>Can I start in self-serve and migrate later?</summary>
                <p>
                  Yes. Configuration and key infrastructure can be migrated without rebuilding your
                  client integration.
                </p>
              </details>
            </section>

            <section className="pricing-cta h2-rule">
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
        <H2Footer />
      </div>
    </div>
  );
}

export default PricingPage;
