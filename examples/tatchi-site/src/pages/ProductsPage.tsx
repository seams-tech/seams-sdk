import React from 'react'
import { useSiteRouter } from '../hooks/useSiteRouter'
import { SitePageFrame } from './SitePageFrame'

export function ProductsPage(): React.JSX.Element {
  const { linkProps } = useSiteRouter()
  const overviewProps = linkProps('/docs/getting-started/overview')
  const thresholdProps = linkProps('/docs/concepts/threshold-signing')
  const securityProps = linkProps('/docs/concepts/security-model')

  return (
    <SitePageFrame
      title="Products"
      subtitle="Composable wallet and signing building blocks for embedded Web3 user experiences."
    >
      <article className="site-card">
        <h2>Embedded Wallets</h2>
        <p>Passkey-native wallet flows that live directly in your app without popup handoffs.</p>
      </article>
      <article className="site-card">
        <h2>Threshold Signing</h2>
        <p>Distributed signing primitives for strict, policy-based transaction authorization.</p>
      </article>
      <article className="site-card">
        <h2>SecureConfirm WebAuthn</h2>
        <p>Onchain-verifiable confirmation challenges for high-integrity signing workflows.</p>
      </article>
      <article className="site-card">
        <h2>Learn More</h2>
        <ul className="site-links-list">
          <li><a href={overviewProps.href} onClick={overviewProps.onClick}>Overview</a></li>
          <li><a href={thresholdProps.href} onClick={thresholdProps.onClick}>Threshold Signing</a></li>
          <li><a href={securityProps.href} onClick={securityProps.onClick}>Security Model</a></li>
        </ul>
      </article>
    </SitePageFrame>
  )
}

export default ProductsPage

