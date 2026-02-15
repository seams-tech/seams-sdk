type CredibilityLogo = {
  label: string
  tone?: 'ink' | 'slate'
}

const trustedLogos: CredibilityLogo[] = [
  { label: 'stripe', tone: 'ink' },
  { label: 'Klarna', tone: 'ink' },
  { label: 'Farcaster', tone: 'ink' },
  { label: 'Hyperliquid', tone: 'slate' },
  { label: 'BLACKBIRD', tone: 'ink' },
  { label: 'PUMP.FUN', tone: 'ink' },
  { label: 'lightspark', tone: 'ink' },
  { label: 'OpenSea', tone: 'slate' },
  { label: 'Bitso', tone: 'ink' },
]

function renderLogo(logo: CredibilityLogo): React.JSX.Element {
  const tone = logo.tone ?? 'ink'
  return (
    <li key={logo.label} className={`credibility-logo credibility-logo--${tone}`}>
      {logo.label}
    </li>
  )
}

export function CredibilityBands(): React.JSX.Element {
  return (
    <section className="credibility-bands" aria-label="Credibility">
      <p id="credibility-trusted-title" className="credibility-bands__title">
        Powering 75M+ accounts for 1,000+ teams.
      </p>
      <ul className="credibility-bands__logos" aria-label="Trusted by">
        {trustedLogos.map(renderLogo)}
      </ul>
      <p className="credibility-bands__subtitle">
        ...across Ethereum, Stripe Tempo, Circle Arc, NEAR protocol
      </p>
    </section>
  )
}

export default CredibilityBands
