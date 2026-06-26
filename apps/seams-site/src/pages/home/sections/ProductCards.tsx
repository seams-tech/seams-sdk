import { Fingerprint, ShieldCheck, Wallet } from 'lucide-react';
import { useSiteRouter } from '@/app/router/useSiteRouter';

type MarketingCard = {
  title: string;
  description: string;
  to: string;
  icon?: React.ComponentType<{ className?: string; size?: number; 'aria-hidden'?: boolean }>;
};

const productModules: MarketingCard[] = [
  {
    title: 'Credential-aware auth',
    description: 'Passkeys, Email OTP, and VoiceID feed the same policy and lane model.',
    to: '/docs/concepts/auth-methods/passkeys',
    icon: Fingerprint,
  },
  {
    title: 'Router A/B signing',
    description: 'Threshold signing with split derivation roles and admitted signing sessions.',
    to: '/docs/concepts/threshold-signing/',
    icon: ShieldCheck,
  },
  {
    title: 'Policy-bound execution',
    description: 'Typed intents, mandates, budgets, revocation, and audit before execution.',
    to: '/docs/concepts/architecture',
    icon: Wallet,
  },
];

const solutionCards: MarketingCard[] = [
  {
    title: 'Consumer Apps',
    description: 'Keep wallet and credential flows inside your product experience.',
    to: '/docs/concepts/custody/wallet-iframe',
  },
  {
    title: 'Stablecoin Payments',
    description: 'Bind approvals, budgets, and signatures to exact payment intents.',
    to: '/docs/concepts/sessions/wallet-sessions',
  },
  {
    title: 'Agentic Commerce',
    description: 'Delegate narrow authority to agents through signed mandates.',
    to: '/docs/concepts/policy/mandates',
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
            Composable key, credential, and policy building blocks
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
