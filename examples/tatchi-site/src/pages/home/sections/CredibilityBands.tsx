type CredibilityLogo = {
  label: string;
  tone?: 'ink' | 'slate';
};

const trustedLogos: CredibilityLogo[] = [
  { label: 'Ethereum', tone: 'ink' },
  { label: 'Stripe Tempo', tone: 'slate' },
  { label: 'Circle Arc', tone: 'ink' },
  { label: 'NEAR', tone: 'slate' },
  { label: 'Hyperliquid', tone: 'ink' },
  { label: 'Polygon', tone: 'slate' },
  { label: 'Solana (soon)', tone: 'ink' },
];

function renderLogo(logo: CredibilityLogo): React.JSX.Element {
  const tone = logo.tone ?? 'ink';
  return (
    <li key={logo.label} className={`credibility-logo credibility-logo--${tone}`}>
      {logo.label}
    </li>
  );
}

export function CredibilityBands(): React.JSX.Element {
  return (
    <section className="credibility-bands" aria-label="Credibility">
      <p id="credibility-trusted-title" className="credibility-bands__title">
        Powering frictionless accounts for projects built on
      </p>
      <ul className="credibility-bands__logos" aria-label="Trusted by">
        {trustedLogos.map(renderLogo)}
      </ul>
    </section>
  );
}

export default CredibilityBands;
