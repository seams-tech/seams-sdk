import React from 'react'
import { useSiteRouter } from '../hooks/useSiteRouter'
import { SitePageFrame } from './SitePageFrame'

export function ContactPage(): React.JSX.Element {
  const { linkProps } = useSiteRouter()
  const installationProps = linkProps('/docs/getting-started/installation')
  const securityProps = linkProps('/docs/concepts/security-model')
  const pricingProps = linkProps('/pricing')

  return (
    <SitePageFrame
      title="Contact Sales"
      subtitle="Talk with the Tatchi team about architecture fit, rollout planning, and support requirements."
    >
      <article className="site-card">
        <h2>Sales Inquiry</h2>
        <p>Open an inquiry with implementation context so our team can respond with concrete guidance.</p>
        <p>
          <a
            href="https://github.com/web3-authn/tatchi/issues/new?title=Sales%20Inquiry%3A%20Tatchi%20Evaluation&body=Company%3A%0AUse%20case%3A%0AExpected%20monthly%20wallet%20volume%3A%0ATarget%20chains%3A%0ATimeline%3A%0ACompliance%20or%20security%20requirements%3A%0A"
            target="_blank"
            rel="noopener noreferrer"
          >
            Open Sales Inquiry
          </a>
        </p>
      </article>
      <article className="site-card">
        <h2>Prefer Self-Serve First?</h2>
        <ul className="site-links-list">
          <li><a href={installationProps.href} onClick={installationProps.onClick}>Getting Started Installation</a></li>
          <li><a href={securityProps.href} onClick={securityProps.onClick}>Security Model</a></li>
          <li><a href={pricingProps.href} onClick={pricingProps.onClick}>Pricing</a></li>
        </ul>
      </article>
    </SitePageFrame>
  )
}

export default ContactPage

