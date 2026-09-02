import React from 'react';
import { useSiteRouter } from '@/app/router/useSiteRouter';
import './Footer.css';
import SeamsLogo from './icons/SeamsLogo';

type FooterLink = {
  label: string;
  to: string;
  external?: boolean;
};

type FooterGroup = {
  heading: string;
  links: FooterLink[];
};

const footerGroups: FooterGroup[] = [
  {
    heading: 'Products',
    links: [
      { label: 'Wallet SDK', to: '/wallet' },
      { label: 'E-commerce', to: '/ecommerce' },
      { label: 'Passkeys', to: '/docs/concepts/auth-methods/passkeys' },
      { label: 'Threshold Signing', to: '/docs/concepts/threshold-signing/' },
      { label: 'Wallet Sessions', to: '/docs/concepts/sessions/wallet-sessions' },
    ],
  },
  {
    heading: 'Solutions',
    links: [
      { label: 'Consumer Apps', to: '/wallet' },
      { label: 'Stablecoin Payments', to: '/ecommerce' },
      { label: 'Agentic Commerce', to: '/docs/concepts/policy/mandates' },
      { label: 'Custody Model', to: '/docs/concepts/custody/' },
    ],
  },
  {
    heading: 'Developers',
    links: [
      { label: 'Documentation', to: '/docs/' },
      { label: 'Architecture', to: '/docs/concepts/architecture' },
      { label: 'Auth Methods', to: '/docs/concepts/auth-methods/' },
      { label: 'Wallet Iframe', to: '/docs/concepts/custody/wallet-iframe' },
      { label: 'Concepts', to: '/docs/concepts/' },
    ],
  },
  {
    heading: 'Resources',
    links: [
      { label: 'Guides', to: '/docs/guides/' },
      { label: 'Use Cases', to: '/docs/use-cases/' },
      { label: 'Help Center', to: '/docs/concepts/' },
    ],
  },
  {
    heading: 'Socials',
    links: [
      { label: 'X', to: 'https://x.com/lowerarchy', external: true },
      { label: 'GitHub', to: 'https://github.com/web3-authn/seams', external: true },
    ],
  },
  {
    heading: 'Company',
    links: [
      { label: 'About', to: '/company/' },
      { label: 'Blog', to: '/company/#blog' },
      { label: 'Pricing', to: '/pricing/' },
      { label: 'Contact Sales', to: '/contact/' },
    ],
  },
];

export function Footer(): React.JSX.Element {
  const { linkProps } = useSiteRouter();
  const homeProps = linkProps('/');

  return (
    <footer className="app-footer" aria-label="Site footer">
      <div className="app-footer__inner">
        <div className="app-footer__lead">
          <a
            className="app-footer__brand"
            href={homeProps.href}
            onClick={homeProps.onClick}
            aria-label="Seams home"
          >
            <SeamsLogo size={32} />
            <span>Seams</span>
          </a>
          <p className="app-footer__legal">
            Copyright © {new Date().getFullYear()} Seams Technologies KK. All rights reserved.
          </p>
        </div>

        <nav className="app-footer__nav" aria-label="Footer navigation">
          {footerGroups.map((group) => (
            <section className="app-footer__col" key={group.heading}>
              <h3 className="app-footer__heading">{group.heading}</h3>
              {group.links.map((link) => {
                const props = linkProps(link.to);
                return (
                  <a
                    key={link.label}
                    href={props.href}
                    onClick={props.onClick}
                    {...(link.external ? { target: '_blank', rel: 'noopener noreferrer' } : null)}
                  >
                    {link.label}
                  </a>
                );
              })}
            </section>
          ))}
        </nav>
      </div>
    </footer>
  );
}

export default Footer;
