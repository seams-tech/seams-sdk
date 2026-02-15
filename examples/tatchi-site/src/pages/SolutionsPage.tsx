import React from 'react'
import { useSiteRouter } from '../hooks/useSiteRouter'
import { SitePageFrame } from './SitePageFrame'

export function SolutionsPage(): React.JSX.Element {
  const { linkProps } = useSiteRouter()
  const architectureProps = linkProps('/docs/concepts/architecture')
  const scopeProps = linkProps('/docs/concepts/passkey-scope')
  const sessionsProps = linkProps('/docs/concepts/secureconfirm-sessions')

  return (
    <SitePageFrame
      title="Solutions"
      subtitle="Embedded wallet and signing patterns for security-sensitive products and teams."
    >
      <article className="site-card">
        <h2>By Use Case</h2>
        <ul className="site-bullets">
          <li><strong>Consumer Apps:</strong> passkey-native wallet flows without extension installs.</li>
          <li><strong>Stablecoin Payments:</strong> embedded confirmation and signing in checkout flows.</li>
          <li><strong>Treasury and Payouts:</strong> policy-based approvals for internal transfers.</li>
          <li><strong>Recovery and Device Linking:</strong> secure continuity across devices.</li>
        </ul>
      </article>
      <article className="site-card">
        <h2>By Team</h2>
        <ul className="site-bullets">
          <li><strong>Product Teams:</strong> composable UX patterns that reduce onboarding friction.</li>
          <li><strong>Security Teams:</strong> SecureConfirm and threshold controls for transaction integrity.</li>
          <li><strong>Platform Teams:</strong> reusable wallet infrastructure across applications.</li>
        </ul>
      </article>
      <article className="site-card">
        <h2>Learn More</h2>
        <ul className="site-links-list">
          <li><a href={architectureProps.href} onClick={architectureProps.onClick}>Architecture</a></li>
          <li><a href={scopeProps.href} onClick={scopeProps.onClick}>Passkey Scope</a></li>
          <li><a href={sessionsProps.href} onClick={sessionsProps.onClick}>SecureConfirm Sessions</a></li>
        </ul>
      </article>
    </SitePageFrame>
  )
}

export default SolutionsPage

