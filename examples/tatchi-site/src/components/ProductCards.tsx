import { Fingerprint, ShieldCheck, Wallet } from 'lucide-react';
import { useSiteRouter } from '../hooks/useSiteRouter';

type MarketingCard = {
  title: string;
  description: string;
  to: string;
  icon?: React.ComponentType<{ className?: string; size?: number; 'aria-hidden'?: boolean }>;
};

const productModules: MarketingCard[] = [
  {
    title: 'Passkey-native UX',
    description: 'No extension installs or popup handoffs in core wallet flows.',
    to: '/products/',
    icon: Fingerprint,
  },
  {
    title: 'Threshold Signing',
    description: 'Distributed signing primitives with policy-focused authorization.',
    to: '/docs/concepts/threshold-signing',
    icon: ShieldCheck,
  },
  {
    title: 'Embedded Wallet SDK',
    description: 'Developer-first integration path with quickstart docs and examples.',
    to: '/docs/getting-started/quickstart',
    icon: Wallet,
  },
];

const solutionCards: MarketingCard[] = [
  {
    title: 'Consumer Apps',
    description: 'Keep wallet flows in your app to reduce onboarding drop-off.',
    to: '/solutions/#consumer-apps',
  },
  {
    title: 'Stablecoin Payments',
    description: 'Embed confirmation and signing directly in payment journeys.',
    to: '/solutions/#stablecoin-payments',
  },
  {
    title: 'Treasury and Payouts',
    description: 'Use policy-based approvals for internal transfers and disbursements.',
    to: '/solutions/#treasury-and-payouts',
  },
];

export function ProductCards(): React.JSX.Element {
  const { linkProps } = useSiteRouter();

  return (
    <section
      className="product-cards product-cards--combined gradient-lilac-warm gradient-lilac-warm-overlay"
      aria-labelledby="product-cards-title"
    >
      <div>
        <header className="product-cards__header">
          <p className="product-cards__eyebrow">Products</p>
          <h2 id="product-cards-title" className="product-cards__title">
            Composable wallet and signing building blocks
          </h2>
        </header>
        <div className="product-cards__grid">
          {productModules.map((module) => {
            const props = linkProps(module.to);
            const Icon = module.icon;
            return (
              <a
                key={module.title}
                className="product-cards__item"
                href={props.href}
                onClick={props.onClick}
              >
                {Icon ? <Icon className="product-cards__icon" size={18} aria-hidden /> : null}
                <h3>{module.title}</h3>
                <p>{module.description}</p>
              </a>
            );
          })}
        </div>
      </div>

      <div className="product-cards__solutions" aria-labelledby="solution-cards-title">
        <header className="solution-cards__header">
          <p className="solution-cards__eyebrow">Solutions</p>
          <h2 id="solution-cards-title" className="solution-cards__title">
            Designed for teams shipping security-sensitive flows
          </h2>
        </header>
        <div className="solution-cards__grid">
          {solutionCards.map((solution) => {
            const props = linkProps(solution.to);
            return (
              <a
                key={solution.title}
                className="solution-cards__item"
                href={props.href}
                onClick={props.onClick}
              >
                <h3>{solution.title}</h3>
                <p>{solution.description}</p>
              </a>
            );
          })}
        </div>
      </div>
    </section>
  );
}

export default ProductCards;
