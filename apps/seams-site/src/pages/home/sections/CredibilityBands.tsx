const supportedNetworks: string[] = [
  'Ethereum',
  'Stripe Tempo',
  'Circle Arc',
  'NEAR',
  'Hyperliquid',
  'Polygon',
];

export function CredibilityBands(): React.JSX.Element {
  return (
    <section className="credibility-bands" aria-label="Supported networks">
      <p id="credibility-trusted-title" className="credibility-bands__title">
        Works with
      </p>
      <ul className="credibility-bands__logos" aria-label="Supported networks">
        {supportedNetworks.map((network) => (
          <li key={network} className="credibility-logo">
            {network}
          </li>
        ))}
      </ul>
    </section>
  );
}

export default CredibilityBands;
