type CredibilityLogo = {
  label: string
  tone?: 'ink' | 'slate'
}

const trustedLogos: CredibilityLogo[] = [
  { label: 'Ethereum', tone: 'ink' },
  { label: 'Base', tone: 'ink' },
  { label: 'Stripe Tempo', tone: 'ink' },
  { label: 'Circle Arc', tone: 'slate' },
  { label: 'NEAR protocol', tone: 'ink' },
  { label: 'Hyperliquid', tone: 'ink' },
  { label: 'Solana', tone: 'ink' },
  { label: 'Polygon', tone: 'slate' },
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
        Powering thousands of accounts for projects built on
      </p>
      <ul className="credibility-bands__logos" aria-label="Trusted by">
        {trustedLogos.map(renderLogo)}
      </ul>
      <p className="credibility-bands__subtitle">
        Ethereum, Base, Polygon, Stripe Tempo, Circle Arc, NEAR protocol
      </p>
    </section>
  )
}

export default CredibilityBands
