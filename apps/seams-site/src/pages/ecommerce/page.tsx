import React from 'react';
import NavbarStatic from '@/components/Navbar/NavbarStatic';
import { ArrowRightAnim } from '@/components/ArrowRightAnim';
import { useSiteRouter } from '@/app/router/useSiteRouter';
import { H2Bento, H2Cases, H2Footer } from '@/components/h2/sections';
import '@/styles/h2.css';

/* Ecommerce Agents product page (ICP: commerce automation buyers). The
   workflow canvas in H2Cases is the hero visual placeholder until the
   interactive resizable-panels build and video assets exist. */

function EcommerceHero(): React.JSX.Element {
  const { linkProps } = useSiteRouter();
  const startProps = linkProps('/docs/concepts/policy/mandates');
  const contactProps = linkProps('/contact/');
  const walletProps = linkProps('/wallet');

  return (
    <header className="h2-hero-simple" aria-labelledby="h2-eco-hero-title">
      <div className="h2-shell">
        <p className="h2-kicker">Seams · Ecommerce Agents</p>
        <h1 id="h2-eco-hero-title" className="h2-display h2-hero-simple__title">
          AI agents that run your store &mdash; inside policy
        </h1>
        <p className="h2-hero-simple__sub">
          The Seams Harness gives every agent its own identity and scoped credentials: limits,
          approvals, and expiry checked before anything executes, with an evidence trail for every
          decision.
        </p>
        <div className="h2-hero-simple__ctas">
          <a
            className="h2-btn h2-btn--primary h2-btn--lg"
            href={startProps.href}
            onClick={startProps.onClick}
          >
            Start building
          </a>
          <a
            className="h2-btn h2-btn--outline h2-btn--lg"
            href={contactProps.href}
            onClick={contactProps.onClick}
          >
            Talk to us
          </a>
        </div>
        {/* div, not p: ArrowRightAnim renders a div, which can't nest in a p */}
        <div className="h2-hero-simple__cross">
          Need the wallet layer?{' '}
          <a className="h2-fork" href={walletProps.href} onClick={walletProps.onClick}>
            Embedded Wallet
            <ArrowRightAnim size={12} />
          </a>
        </div>
      </div>
    </header>
  );
}

export function EcommercePage(): React.JSX.Element {
  return (
    <div className="h2-page h2-page--zoom">
      <NavbarStatic appearance="light" />
      <div className="h2-col">
        <EcommerceHero />
        <H2Cases />
        <H2Bento />
        <H2Footer />
      </div>
    </div>
  );
}

export default EcommercePage;
