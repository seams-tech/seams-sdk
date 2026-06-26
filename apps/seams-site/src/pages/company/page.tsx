import React from 'react';
import { useSiteRouter } from '@/app/router/useSiteRouter';
import { SitePageFrame } from '@/pages/shared/SitePageFrame';

export function CompanyPage(): React.JSX.Element {
  const { linkProps } = useSiteRouter();
  const architectureProps = linkProps('/docs/concepts/architecture');
  const overviewProps = linkProps('/docs/concepts/');

  return (
    <SitePageFrame
      title="Company"
      subtitle="Developer-first key, credential, and policy infrastructure with explicit custody boundaries."
    >
      <article className="site-card">
        <h2>Focus Areas</h2>
        <ul className="site-bullets">
          <li>Policy-bound embedded wallet UX</li>
          <li>Threshold signing, Router A/B, and session hardening</li>
          <li>Mandates, credentials, and delegated-agent flows</li>
        </ul>
      </article>
      <article className="site-card">
        <h2>Open Source</h2>
        <p>
          <a href="https://github.com/web3-authn/seams" target="_blank" rel="noopener noreferrer">
            GitHub Repository
          </a>
        </p>
      </article>
      <article className="site-card">
        <h2>Get Started</h2>
        <ul className="site-links-list">
          <li>
            <a href={architectureProps.href} onClick={architectureProps.onClick}>
              Architecture
            </a>
          </li>
          <li>
            <a href={overviewProps.href} onClick={overviewProps.onClick}>
              Overview
            </a>
          </li>
        </ul>
      </article>
    </SitePageFrame>
  );
}

export default CompanyPage;
