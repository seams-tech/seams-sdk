import React from 'react';
import { useSiteRouter } from '../hooks/useSiteRouter';
import { SitePageFrame } from './SitePageFrame';

export function CompanyPage(): React.JSX.Element {
  const { linkProps } = useSiteRouter();
  const installationProps = linkProps('/docs/getting-started/installation');
  const overviewProps = linkProps('/docs/getting-started/overview');

  return (
    <SitePageFrame
      title="Company"
      subtitle="Developer-first embedded wallet infrastructure with security defaults that scale."
    >
      <article className="site-card">
        <h2>Focus Areas</h2>
        <ul className="site-bullets">
          <li>Passkey-native embedded wallet UX</li>
          <li>Threshold signing and session hardening</li>
          <li>Practical integrations for React and web apps</li>
        </ul>
      </article>
      <article className="site-card">
        <h2>Open Source</h2>
        <p>
          <a href="https://github.com/web3-authn/tatchi" target="_blank" rel="noopener noreferrer">
            GitHub Repository
          </a>
        </p>
      </article>
      <article className="site-card">
        <h2>Get Started</h2>
        <ul className="site-links-list">
          <li>
            <a href={installationProps.href} onClick={installationProps.onClick}>
              Installation
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
