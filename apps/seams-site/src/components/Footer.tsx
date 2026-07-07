import React from 'react';
import { useSiteRouter } from '@/app/router/useSiteRouter';
import './Footer.css';
import Github from './icons/Github';
import SeamsLogo from './icons/SeamsLogo';
import Twitter from './icons/Twitter';

type FooterLink = {
  label: string;
  to: string;
};

type FooterGroup = {
  heading: string;
  links: FooterLink[];
};

const footerGroups: FooterGroup[] = [
  {
    heading: 'Products',
    links: [
      { label: 'Key Infrastructure', to: '/docs/concepts/architecture' },
      { label: 'Threshold Signing', to: '/docs/concepts/threshold-signing/' },
      { label: 'Auth Methods', to: '/docs/concepts/auth-methods/' },
      { label: 'Developer Docs', to: '/docs/concepts/' },
    ],
  },
  {
    heading: 'Solutions',
    links: [
      { label: 'Consumer Apps', to: '/docs/concepts/custody/wallet-iframe' },
      { label: 'Stablecoin Payments', to: '/docs/concepts/sessions/wallet-sessions' },
      { label: 'Agentic Commerce', to: '/docs/concepts/policy/mandates' },
    ],
  },
  {
    heading: 'Support',
    links: [
      { label: 'Help Center', to: '/docs/concepts/' },
      { label: 'Contact Sales', to: '/contact/' },
      { label: 'Custody Model', to: '/docs/concepts/custody/' },
      { label: 'Architecture', to: '/docs/concepts/architecture' },
    ],
  },
  {
    heading: 'Company',
    links: [
      { label: 'About', to: '/company/' },
      { label: 'Pricing', to: '/pricing/' },
      { label: 'Documentation', to: '/docs/concepts/' },
      { label: 'Get in Touch', to: '/contact/' },
    ],
  },
];

export function Footer(): React.JSX.Element {
  const { linkProps } = useSiteRouter();
  const homeProps = linkProps('/');

  return (
    <footer className="app-footer" aria-label="Site footer">
      <div className="app-footer__bg-glow app-footer__bg-glow--left" aria-hidden />
      <div className="app-footer__bg-glow app-footer__bg-glow--right" aria-hidden />

      <div className="app-footer__inner">
        <div className="app-footer__lead">
          <a
            className="app-footer__brand"
            href={homeProps.href}
            onClick={homeProps.onClick}
            aria-label="Seams home"
          >
            <SeamsLogo size={40} />
            <span>Seams</span>
          </a>
        </div>

        <nav className="app-footer__nav" aria-label="Footer navigation">
          {footerGroups.map((group) => (
            <section className="app-footer__col" key={group.heading}>
              <h3 className="app-footer__heading">{group.heading}</h3>
              {group.links.map((link) => {
                const props = linkProps(link.to);
                return (
                  <a key={link.label} href={props.href} onClick={props.onClick}>
                    {link.label}
                  </a>
                );
              })}
            </section>
          ))}
        </nav>

        <div className="app-footer__bottom">
          <div className="app-footer__socials" aria-label="Social links">
            <a
              href="https://x.com/lowerarchy"
              target="_blank"
              rel="noopener noreferrer"
              aria-label="X"
            >
              <Twitter size={16} aria-hidden />
            </a>
            <a
              href="https://github.com/web3-authn/seams"
              target="_blank"
              rel="noopener noreferrer"
              aria-label="GitHub"
            >
              <Github size={16} aria-hidden />
            </a>
          </div>

          <div className="app-footer__legal">
            <p>Copyright © {new Date().getFullYear()} Seams, Inc. All rights reserved.</p>
          </div>
        </div>
      </div>
    </footer>
  );
}

export default Footer;
