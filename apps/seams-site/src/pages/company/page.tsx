import React from 'react';
import { ArrowRightAnim } from '@/components/ArrowRightAnim';
import NavbarStatic from '@/components/Navbar/NavbarStatic';
import { H2Footer } from '@/components/h2/sections';
import { useSiteRouter } from '@/app/router/useSiteRouter';
import '@/styles/h2.css';
import './styles.css';

type CompanyFocus = {
  title: string;
  copy: string;
};

type CompanyPrinciple = {
  label: string;
  title: string;
  copy: string;
};

type CompanyResource = {
  title: string;
  copy: string;
  href: string;
  external: boolean;
};

const focusAreas: CompanyFocus[] = [
  {
    title: 'Policy-bound wallets',
    copy: 'Passkey-secured embedded wallets with recovery, session controls, and user-owned signing boundaries.',
  },
  {
    title: 'Threshold signing',
    copy: 'Router A/B, split key material, and hardened signing sessions built for production custody models.',
  },
  {
    title: 'Agent credentials',
    copy: 'Mandates, permissions, and delegated access for teams and AI agents acting on commerce accounts.',
  },
];

const principles: CompanyPrinciple[] = [
  {
    label: '01',
    title: 'Custody must be explicit',
    copy: 'Users, apps, devices, relayers, and agents each get a precise role in the signing path.',
  },
  {
    label: '02',
    title: 'Policy runs before execution',
    copy: 'Limits, approvals, origin checks, and session state are evaluated before any credential can act.',
  },
  {
    label: '03',
    title: 'Developer surfaces stay small',
    copy: 'The SDK exposes high-leverage primitives without making teams rebuild key infrastructure.',
  },
];

const resources: CompanyResource[] = [
  {
    title: 'Architecture',
    copy: 'Read the custody and runtime model.',
    href: '/docs/concepts/architecture',
    external: false,
  },
  {
    title: 'Overview',
    copy: 'Start with the Seams concepts.',
    href: '/docs/concepts/',
    external: false,
  },
  {
    title: 'GitHub',
    copy: 'Browse the open-source repository.',
    href: 'https://github.com/web3-authn/seams',
    external: true,
  },
];

type InternalAnchorProps = {
  to: string;
  className: string;
  children: React.ReactNode;
};

function InternalAnchor(props: InternalAnchorProps): React.JSX.Element {
  const { linkProps } = useSiteRouter();
  const anchorProps = linkProps(props.to);

  return (
    <a className={props.className} href={anchorProps.href} onClick={anchorProps.onClick}>
      {props.children}
    </a>
  );
}

function renderFocusArea(area: CompanyFocus): React.JSX.Element {
  return (
    <article className="company-focus-card" key={area.title}>
      <h2>{area.title}</h2>
      <p>{area.copy}</p>
    </article>
  );
}

function renderPrinciple(principle: CompanyPrinciple): React.JSX.Element {
  return (
    <article className="company-principle" key={principle.label}>
      <span>{principle.label}</span>
      <div>
        <h3>{principle.title}</h3>
        <p>{principle.copy}</p>
      </div>
    </article>
  );
}

function renderResource(resource: CompanyResource): React.JSX.Element {
  if (resource.external) {
    return (
      <a
        className="company-resource"
        href={resource.href}
        target="_blank"
        rel="noopener noreferrer"
        key={resource.title}
      >
        <span>
          <strong>{resource.title}</strong>
          <small>{resource.copy}</small>
        </span>
        <ArrowRightAnim size={13} />
      </a>
    );
  }

  return (
    <InternalAnchor className="company-resource" to={resource.href} key={resource.title}>
      <span>
        <strong>{resource.title}</strong>
        <small>{resource.copy}</small>
      </span>
      <ArrowRightAnim size={13} />
    </InternalAnchor>
  );
}

export function CompanyPage(): React.JSX.Element {
  return (
    <div className="h2-page company-page">
      <NavbarStatic appearance="light" />
      <div className="h2-col">
        <main className="company-main" aria-labelledby="company-page-title">
          <header className="company-hero h2-rule">
            <div className="h2-shell company-hero__inner">
              <p className="h2-kicker">Seams · Tokyo</p>
              <h1 id="company-page-title" className="h2-display company-hero__title">
                Seams
              </h1>
              <p className="company-hero__copy">
                Developer-first account infrastructure for people, teams, and AI agents. We build
                secure wallet, credential, and policy systems with explicit custody boundaries.
              </p>
              <div className="company-hero__ctas">
                <InternalAnchor className="h2-btn h2-btn--primary h2-btn--lg" to="/docs/concepts/">
                  Start building
                </InternalAnchor>
                <InternalAnchor className="h2-btn h2-btn--outline h2-btn--lg" to="/contact/">
                  Contact sales
                </InternalAnchor>
              </div>
            </div>
          </header>

          <section className="company-statement h2-rule">
            <div className="h2-shell">
              <p>
                Seams is for teams that need account actions to be accountable: every sign-in,
                wallet operation, delegated task, and agent instruction should have a policy
                boundary before it can move value or change state.
              </p>
            </div>
          </section>

          <section className="company-focus h2-rule" aria-labelledby="company-focus-title">
            <div className="h2-shell">
              <div className="h2-split-head company-section-head">
                <p className="h2-kicker">Focus areas</p>
                <h2 id="company-focus-title" className="h2-display">
                  Infrastructure for controlled account access
                </h2>
                <p className="h2-split-head__copy">
                  The product sits below app UX and above chain execution, where custody, policy,
                  and credentials meet.
                </p>
              </div>
              <div className="company-focus__grid">{focusAreas.map(renderFocusArea)}</div>
            </div>
          </section>

          <section
            className="company-principles h2-rule"
            aria-labelledby="company-principles-title"
          >
            <div className="h2-shell company-principles__grid">
              <div>
                <p className="h2-kicker">Operating principles</p>
                <h2 id="company-principles-title" className="h2-display">
                  Build the control plane before the shortcut
                </h2>
              </div>
              <div className="company-principles__list">{principles.map(renderPrinciple)}</div>
            </div>
          </section>

          <section className="company-resources h2-rule" aria-labelledby="company-resources-title">
            <div className="h2-shell company-resources__grid">
              <div>
                <p className="h2-kicker">Open source</p>
                <h2 id="company-resources-title" className="h2-display">
                  Inspect the model, then build against it
                </h2>
              </div>
              <div className="company-resources__list">{resources.map(renderResource)}</div>
            </div>
          </section>
        </main>
        <H2Footer />
      </div>
    </div>
  );
}

export default CompanyPage;
