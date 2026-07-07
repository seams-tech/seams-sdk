import Github from '@/components/icons/Github';
import { ArrowRightAnim } from '@/components/ArrowRightAnim';
import { useSiteRouter } from '@/app/router/useSiteRouter';

export function FinalCTA(): React.JSX.Element {
  const { linkProps } = useSiteRouter();
  const getStartedProps = linkProps('/docs/concepts/');
  const contactProps = linkProps('/contact/');

  return (
    <section
      className="final-cta gradient-lilac-warm-drift gradient-lilac-warm-drift-overlay"
      aria-labelledby="final-cta-title"
    >
      <div className="final-cta__content">
        <p className="final-cta__eyebrow">Get started</p>
        <h2 id="final-cta-title" className="final-cta__title">
          Ship embedded wallets with real custody boundaries
        </h2>
        <p className="final-cta__description">
          Integrate in an afternoon. Talk to us when you&rsquo;re ready for production.
        </p>
      </div>
      <div className="final-cta__actions">
        <a
          className="final-cta__button final-cta__button--solid"
          href={getStartedProps.href}
          onClick={getStartedProps.onClick}
        >
          <span>Get Started</span>
          <ArrowRightAnim size={20} />
        </a>
        <a
          className="final-cta__button final-cta__button--outline"
          href={contactProps.href}
          onClick={contactProps.onClick}
        >
          <span>Contact Sales</span>
          <ArrowRightAnim size={20} />
        </a>
        <a
          className="final-cta__button final-cta__button--ghost"
          href="https://github.com/web3-authn/seams"
          target="_blank"
          rel="noopener noreferrer"
        >
          <Github size={20} aria-hidden />
          <strong>GitHub</strong>
          <ArrowRightAnim size={20} />
        </a>
      </div>
    </section>
  );
}

export default FinalCTA;
