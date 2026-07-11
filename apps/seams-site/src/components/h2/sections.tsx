import React from 'react';
import {
  BarChart3,
  ChevronLeft,
  ChevronRight,
  CreditCard,
  Fingerprint,
  Github,
  KeyRound,
  LifeBuoy,
  ListChecks,
  Lock,
  Mail,
  Package,
  ScrollText,
  Share2,
  ShieldCheck,
  Store,
  Twitter,
  Wallet,
} from 'lucide-react';
import { Theme, useSeams, type AuthMenuMode, type WalletShapeId } from '@seams/sdk/react';
import SeamsWordmark from '@/components/icons/SeamsWordmark';
import { useSiteRouter } from '@/app/router/useSiteRouter';
import { useRevealOnIdle } from '@/shared/hooks/useRevealOnIdle';
import {
  DEMO_THEME_PRESETS,
  demoIframeAppearance,
  demoReactTokens,
  type DemoThemeId,
} from '@/context/app-themes';
import '@/styles/h2.css';

/* Shared section library for the h2 marketing pages (/, /wallet, /ecommerce).
   Every component renders inside a `.h2-page > .h2-col` wrapper and styles
   itself from src/styles/h2.css. */

// Defer the live passkey demo until after first paint/idle.
const DemoPasskeyColumnLazy = React.lazy(() =>
  import('@/components/DemoPasskeyColumn').then((m) => ({ default: m.DemoPasskeyColumn })),
);

/* ---------- demo hero (headline left, live product right) ---------- */

const demoPageNames = ['Login', 'Transactions', 'Account recovery'];

/* Compact product forks under the CTAs. Chips reuse the case-cover gradients
   so each product keeps one fabric. */
const productForks = [
  { label: 'Wallet', to: '/wallet', chip: 'h2-fork__chip--wallet' },
  { label: 'Harness', to: '/ecommerce', chip: 'h2-fork__chip--harness' },
  { label: 'API', to: '/docs/concepts/', chip: 'h2-fork__chip--api' },
];

export type H2DemoHeroProps = {
  kicker?: string;
  title?: React.ReactNode;
  sub?: React.ReactNode;
  authDefaultModeWhenNoDetectedAccount?: AuthMenuMode;
};

export function H2DemoHero({
  kicker = 'Seams · Commerce account infrastructure',
  title = (
    <>
      {/* non-breaking hyphen keeps "policy-based" on one line */}
      Secure commerce accounts with policy{'‑'}based permissions
    </>
  ),
  sub = (
    <>
      One SDK for authentication, wallets, credentials, and delegated access, wherever
      people and AI agents act on your store. Register with a passkey right here and you have a
      working account: wallet included, recovery built in, every action signed.
    </>
  ),
  authDefaultModeWhenNoDetectedAccount,
}: H2DemoHeroProps = {}): React.JSX.Element {
  const show = useRevealOnIdle();
  const { linkProps } = useSiteRouter();
  const { seams, loginState } = useSeams();
  const [demoPage, setDemoPage] = React.useState(0);
  const [demoTheme, setDemoTheme] = React.useState<DemoThemeId>('paper');
  // corner shape is orthogonal to the color theme: any palette, sharp or rounded
  const [demoShape, setDemoShape] = React.useState<WalletShapeId>('square');
  const activePreset = DEMO_THEME_PRESETS.find((t) => t.id === demoTheme) ?? DEMO_THEME_PRESETS[0];
  const activeWalletId = loginState?.isLoggedIn ? loginState.walletId || '' : '';
  const startProps = linkProps('/docs/concepts/');
  const authProps = linkProps('/docs/concepts/auth-methods/');

  // Push the selected theme's tokens to the wallet iframe so embedded SDK
  // components (tx confirmer, etc.) re-theme to match the React auth card.
  React.useEffect(() => {
    try {
      seams.setAppearance(demoIframeAppearance(activePreset, demoShape));
    } catch {}
  }, [seams, activePreset, demoShape, loginState?.isLoggedIn, activeWalletId]);

  // The Transactions / Account recovery screens need an unlocked wallet,
  // mirroring the carousel's own page gating.
  const maxPage = loginState?.isLoggedIn ? demoPageNames.length - 1 : 0;

  return (
    <header className="h2-hero" aria-labelledby="h2-hero-title">
      <div className="h2-hero__split">
        <div className="h2-hero__main">
          <p className="h2-kicker">{kicker}</p>
          <h1 id="h2-hero-title" className="h2-display h2-hero__title">
            {title}
          </h1>
          <p className="h2-hero__sub">{sub}</p>
          <div className="h2-hero__ctas">
            <a
              className="h2-btn h2-btn--primary h2-btn--lg"
              href={startProps.href}
              onClick={startProps.onClick}
            >
              Start building
            </a>
            <a className="h2-btn h2-btn--outline" href={authProps.href} onClick={authProps.onClick}>
              How auth works
            </a>
          </div>
          <div className="h2-hero__forks" aria-label="Products">
            {productForks.map((fork) => {
              const forkProps = linkProps(fork.to);
              return (
                <a
                  key={fork.label}
                  className="h2-fork"
                  href={forkProps.href}
                  onClick={forkProps.onClick}
                >
                  <span className={`h2-fork__chip ${fork.chip}`} aria-hidden />
                  {fork.label}
                </a>
              );
            })}
          </div>
          <p className="h2-hero__note">Open SDK &middot; Non-custodial by design</p>
        </div>

        <div className="h2-hero__demo">
          <p className="h2-demo-label">Live Demo</p>
          {/* Feed the selected preset to the auth menu via the SDK theme context */}
          <Theme
            theme={activePreset.mode}
            tokens={demoReactTokens(activePreset, demoShape)}
            tag="div"
            className="h2-demo-theme-root"
            style={{ display: 'contents' }}
          >
            {show ? (
              <React.Suspense fallback={<div className="h2-demo__placeholder" />}>
                <DemoPasskeyColumnLazy
                  currentPage={demoPage}
                  onCurrentPageChange={setDemoPage}
                  defaultModeWhenNoDetectedAccount={authDefaultModeWhenNoDetectedAccount}
                />
              </React.Suspense>
            ) : (
              <div className="h2-demo__placeholder" />
            )}
          </Theme>
          <div className="h2-themeswitch" role="group" aria-label="Preview theme">
            {DEMO_THEME_PRESETS.map((t) => (
              <button
                key={t.id}
                type="button"
                className={`h2-themeswitch__btn${demoTheme === t.id ? ' is-active' : ''}`}
                aria-pressed={demoTheme === t.id}
                onClick={() => setDemoTheme(t.id)}
              >
                <span className="h2-themeswitch__swatch" style={{ background: t.swatch }} />
                {t.label}
              </button>
            ))}
          </div>
          <div
            className="h2-themeswitch h2-themeswitch--shape"
            role="group"
            aria-label="Corner shape"
          >
            <span className="h2-themeswitch__label">Corners</span>
            {(
              [
                { id: 'square', label: 'Sharp' },
                { id: 'rounded', label: 'Rounded' },
              ] as const
            ).map((s) => (
              <button
                key={s.id}
                type="button"
                className={`h2-themeswitch__btn${demoShape === s.id ? ' is-active' : ''}`}
                aria-pressed={demoShape === s.id}
                onClick={() => setDemoShape(s.id)}
              >
                {s.label}
              </button>
            ))}
          </div>
        </div>

        {/* Pager lives at the split level so it sits on the divider/border junction */}
        <div className="h2-pager" role="group" aria-label="Demo screens">
          <button
            type="button"
            className="h2-pager__btn"
            aria-label="Previous demo screen"
            disabled={demoPage === 0}
            onClick={() => setDemoPage((p) => Math.max(0, p - 1))}
          >
            <ChevronLeft aria-hidden />
          </button>
          <span className="h2-pager__dots">
            {demoPageNames.map((name, i) => (
              <span
                key={name}
                className={`h2-pager__dot${i === demoPage ? ' is-active' : ''}`}
                title={name}
              />
            ))}
          </span>
          <button
            type="button"
            className="h2-pager__btn"
            aria-label="Next demo screen"
            disabled={demoPage >= maxPage}
            onClick={() => setDemoPage((p) => Math.min(maxPage, p + 1))}
          >
            <ChevronRight aria-hidden />
          </button>
        </div>
      </div>
    </header>
  );
}

/* ---------- ecosystem (commerce-stack lattice + networks) ---------- */

const networks = ['Ethereum', 'Stripe Tempo', 'Circle Arc', 'NEAR', 'Hyperliquid', 'Polygon'];

/* Tool categories stand in for brand logos until real integrations ship. */
const stackCategories = [
  { label: 'Storefronts', icon: Store, x: 10, y: 30 },
  { label: 'Payments', icon: CreditCard, x: 27, y: 66 },
  { label: 'Email & messaging', icon: Mail, x: 46, y: 26 },
  { label: 'Support desk', icon: LifeBuoy, x: 63, y: 64 },
  { label: 'Fulfillment', icon: Package, x: 78, y: 30 },
  { label: 'Analytics', icon: BarChart3, x: 90, y: 62 },
];

export function H2Ecosystem(): React.JSX.Element {
  const { linkProps } = useSiteRouter();
  const docsProps = linkProps('/docs/concepts/');

  return (
    <section className="h2-section h2-rule" aria-labelledby="h2-eco-title">
      <div className="h2-shell">
        <div className="h2-eco__head">
          <div>
            <p className="h2-kicker" style={{ marginBottom: 12 }}>
              Ecosystem
            </p>
            <h2 id="h2-eco-title" className="h2-display h2-eco__title">
              Plugs into the tools stores already run
            </h2>
            <p className="h2-eco__copy">
              Storefronts, payments, messaging, and support, connected through scoped
              credentials, so every action stays inside policy.
            </p>
          </div>
          <a className="h2-btn h2-btn--outline" href={docsProps.href} onClick={docsProps.onClick}>
            Read the docs
          </a>
        </div>
        <div className="h2-lattice" role="img" aria-label="Commerce tool categories Seams connects">
          {stackCategories.map((c) => {
            const Icon = c.icon;
            return (
              <span
                key={c.label}
                className="h2-lattice__chip"
                style={{ left: `${c.x}%`, top: `${c.y}%` }}
              >
                <Icon aria-hidden />
                {c.label}
              </span>
            );
          })}
        </div>
        <p className="h2-networks-line">
          <span className="h2-networks-line__label">Networks</span>
          {networks.join(' · ')}
        </p>
      </div>
    </section>
  );
}

export function H2Trusted(): React.JSX.Element {
  return (
    <section className="h2-section h2-rule h2-trusted" aria-labelledby="h2-trusted-title">
      <div className="h2-shell">
        <h2 id="h2-trusted-title" className="h2-display h2-trusted__title">
          Built for teams shipping the future of commerce
        </h2>
        <p className="h2-trusted__copy">
          Seams gives merchants and platforms secure accounts, scoped credentials, and wallet
          access, with approval rules and an audit trail for every action.
        </p>
      </div>
    </section>
  );
}

/* ---------- platform pillars ---------- */

/* Two-lane MPC diagram: the shares converge through a policy gate into the
   one green output. Drawn in the security section's line-art language; the
   dashed connectors stitch-flow on panel hover (.h2-mpc__flow in h2.css). */
export function MpcSplitDiagram(): React.JSX.Element {
  return (
    <svg
      className="h2-mpc"
      viewBox="0 0 560 300"
      role="img"
      aria-label="share_a on the user's device and share_b on your infrastructure combine through a policy check into a signature"
    >
      {/* input lanes */}
      <text className="h2-mpc__kicker" x="28" y="54">
        USER{'’'}S DEVICE
      </text>
      <rect className="h2-mpc__node" x="24" y="64" width="128" height="44" rx="12" />
      <text className="h2-mpc__label" x="88" y="91" textAnchor="middle">
        share_a
      </text>

      <text className="h2-mpc__kicker" x="28" y="196">
        YOUR INFRASTRUCTURE
      </text>
      <rect className="h2-mpc__node" x="24" y="206" width="128" height="44" rx="12" />
      <text className="h2-mpc__label" x="88" y="233" textAnchor="middle">
        share_b
      </text>

      {/* dashed connectors converging on the gate */}
      <path className="h2-mpc__flow" d="M152 86 C214 86 226 148 268 151" />
      <path className="h2-mpc__flow" d="M152 228 C214 228 226 166 268 159" />

      {/* policy gate */}
      <path
        className="h2-mpc__gate"
        d="M300 122 L328 132 V152 C328 168 316 180 300 186 C284 180 272 168 272 152 V132 Z"
      />
      <path className="h2-mpc__gate-check" d="M290 152 L297 159 L311 143" />
      <text className="h2-mpc__gatelabel" x="300" y="206" textAnchor="middle">
        policy check
      </text>

      {/* signed output: the only green element */}
      <path className="h2-mpc__out" d="M334 154 H414" />
      <path className="h2-mpc__out" d="M408 148 L415 154 L408 160" />
      <rect
        className="h2-mpc__node h2-mpc__node--result"
        x="420"
        y="132"
        width="128"
        height="44"
        rx="12"
      />
      <text className="h2-mpc__label h2-mpc__label--result" x="484" y="159" textAnchor="middle">
        signature
      </text>

      <text className="h2-mpc__note" x="280" y="284" textAnchor="middle">
        2-of-2 threshold {'·'} neither share signs alone
      </text>
    </svg>
  );
}

type Pillar = {
  id: string;
  label: string;
  icon: React.ComponentType<{ 'aria-hidden'?: boolean }>;
  copy: React.ReactNode;
  mock: React.ReactNode;
};

const pillars: Pillar[] = [
  {
    id: 'auth',
    label: 'Authentication',
    icon: Fingerprint,
    copy: (
      <>
        <strong>Passkeys, biometric login, and account recovery.</strong> One identity layer for
        merchants, staff, and the agents working on their behalf.
      </>
    ),
    mock: (
      <div className="h2-mockcard" role="img" aria-label="Sign-in methods list">
        <p className="h2-mockcard__title">Sign in to your store</p>
        <div className="h2-mockrow">
          <span className="h2-mockrow__main">
            Passkey
            <small>face_id · this device</small>
          </span>
          <span className="h2-chip h2-chip--green">Ready</span>
        </div>
        <div className="h2-mockrow">
          <span className="h2-mockrow__main">
            Email one-time code
            <small>otp · 10 min expiry</small>
          </span>
          <span className="h2-chip h2-chip--plain">Fallback</span>
        </div>
        <div className="h2-mockrow">
          <span className="h2-mockrow__main">
            Account recovery
            <small>email + linked device</small>
          </span>
          <span className="h2-chip h2-chip--plain">Configured</span>
        </div>
      </div>
    ),
  },
  {
    id: 'wallets',
    label: 'Embedded Wallets',
    icon: Wallet,
    copy: (
      <>
        <strong>Non-custodial embedded wallets and signed customer actions.</strong> Keys are split
        between the user&rsquo;s device and your infrastructure: neither can sign alone.
      </>
    ),
    mock: <MpcSplitDiagram />,
  },
  {
    id: 'permissions',
    label: 'Credentials & permissions',
    icon: ListChecks,
    copy: (
      <>
        <strong>Limits, approvals, roles, and audit.</strong> Configurable policy decides what each
        credential can do before anything executes.
      </>
    ),
    mock: (
      <div className="h2-mockcard" role="img" aria-label="Policy rules list">
        <p className="h2-mockcard__title">Store policy</p>
        <div className="h2-mockrow">
          <span className="h2-mockrow__main">
            Discounts up to 10%
            <small>role: support</small>
          </span>
          <span className="h2-chip h2-chip--green">Allowed</span>
        </div>
        <div className="h2-mockrow">
          <span className="h2-mockrow__main">
            Refunds over ¥50,000
            <small>role: any</small>
          </span>
          <span className="h2-chip h2-chip--amber">Needs approval</span>
        </div>
        <div className="h2-mockrow">
          <span className="h2-mockrow__main">
            Price changes
            <small>role: owner only</small>
          </span>
          <span className="h2-chip h2-chip--amber">Step-up auth</span>
        </div>
      </div>
    ),
  },
  {
    id: 'delegated',
    label: 'Delegated access',
    icon: Share2,
    copy: (
      <>
        <strong>Credential delegation for staff, and agent identity for attribution.</strong> The
        Seams Harness gives every agent its own scoped credentials and a full evidence trail.
      </>
    ),
    mock: (
      <div className="h2-mockcard" role="img" aria-label="Delegated credentials list">
        <p className="h2-mockcard__title">Delegated credentials</p>
        <div className="h2-mockrow">
          <span className="h2-mockrow__main">
            Support agent (AI)
            <small>emails + refunds ≤ ¥10,000</small>
          </span>
          <span className="h2-chip h2-chip--green">Active</span>
        </div>
        <div className="h2-mockrow">
          <span className="h2-mockrow__main">
            Ops staff: Kenji
            <small>listings + inventory</small>
          </span>
          <span className="h2-chip h2-chip--green">Active</span>
        </div>
        <div className="h2-mockrow">
          <span className="h2-mockrow__main">
            Pricing agent (AI)
            <small>expired 2 days ago</small>
          </span>
          <span className="h2-chip h2-chip--plain">Revoked</span>
        </div>
      </div>
    ),
  },
];

export function H2Pillars(): React.JSX.Element {
  const [active, setActive] = React.useState(0);
  const pillar = pillars[active];

  return (
    <section className="h2-section h2-rule" aria-labelledby="h2-pillars-title">
      <div className="h2-shell">
        <div className="h2-split-head">
          <p className="h2-kicker">Platform</p>
          <h2 id="h2-pillars-title" className="h2-display">
            One SDK for the whole account stack
          </h2>
          <p className="h2-split-head__copy">
            Authentication, wallets, credentials, and delegated access share one policy model, so
            nothing acts on your store outside the rules you set.
          </p>
        </div>
        <div className="h2-pillars">
          <div className="h2-pillars__list" role="tablist" aria-label="Platform pillars">
            {pillars.map((p, i) => {
              const Icon = p.icon;
              return (
                <button
                  key={p.id}
                  type="button"
                  role="tab"
                  aria-selected={i === active}
                  className={`h2-pillar${i === active ? ' is-active' : ''}`}
                  onClick={() => setActive(i)}
                >
                  <span className="h2-pillar__icon" aria-hidden>
                    <Icon />
                  </span>
                  {p.label}
                </button>
              );
            })}
          </div>
          <div className="h2-pillars__panel" role="tabpanel" aria-label={pillar.label}>
            <p className="h2-pillars__panel-copy">{pillar.copy}</p>
            <div className="h2-pillars__mock">{pillar.mock}</div>
          </div>
        </div>
      </div>
    </section>
  );
}

/* ---------- bento band (control plane) ---------- */

function PreflightMock(): React.JSX.Element {
  return (
    <div className="h2-mockcard" role="img" aria-label="Preflight checks before an agent action">
      <p className="h2-mockcard__title">Preflight checks: send discount offer</p>
      <div className="h2-mockrow">
        <span className="h2-mockrow__main">Credentials valid</span>
        <span className="h2-chip h2-chip--green">Pass</span>
      </div>
      <div className="h2-mockrow">
        <span className="h2-mockrow__main">Agent identity verified</span>
        <span className="h2-chip h2-chip--green">Pass</span>
      </div>
      <div className="h2-mockrow">
        <span className="h2-mockrow__main">Discount permission</span>
        <span className="h2-chip h2-chip--amber">Admin approval</span>
      </div>
      <div className="h2-mockbtns" aria-hidden>
        <span className="h2-mockbtn h2-mockbtn--approve">Approve</span>
        <span className="h2-mockbtn h2-mockbtn--cancel">Cancel</span>
      </div>
    </div>
  );
}

function ApprovalGateMock(): React.JSX.Element {
  return (
    <div className="h2-mockcard" role="img" aria-label="Approval gate requiring passkey">
      <p className="h2-mockcard__title">Approval gate</p>
      <div className="h2-mockrow">
        <span className="h2-mockrow__main">
          Order inventory restock
          <small>¥180,000 · supplier: Kyoto Craft Co.</small>
        </span>
        <span className="h2-chip h2-chip--amber">Held</span>
      </div>
      <div className="h2-mockrow">
        <span className="h2-mockrow__main">
          Confirm with passkey
          <small>owner presence required</small>
        </span>
        <span className="h2-chip h2-chip--plain">Waiting</span>
      </div>
      <div className="h2-mockrow">
        <span className="h2-mockrow__main">
          Decision logged to audit trail
          <small>evidence retained</small>
        </span>
        <span className="h2-chip h2-chip--plain">Auto</span>
      </div>
    </div>
  );
}

export function H2Bento(): React.JSX.Element {
  return (
    <section className="h2-section h2-section--bento h2-rule" aria-labelledby="h2-bento-title">
      <div className="h2-shell">
        <div className="h2-split-head">
          <p className="h2-kicker">Control plane</p>
          <h2 id="h2-bento-title" className="h2-display">
            Agents act only inside policy
          </h2>
          <p className="h2-split-head__copy">
            Every action from an agent or staff member runs through the same checks: permissions,
            limits, thresholds, expiry. Risky actions route to a human.
          </p>
        </div>
        <div className="h2-bento">
          <div className="h2-bento__card h2-bento__card--lg">
            <div className="h2-bento__visual">
              <PreflightMock />
            </div>
            <div>
              <h3 className="h2-bento__title">Checks before execution</h3>
              <p className="h2-bento__copy">
                The Seams harness verifies credentials, identity, and permissions before an action
                runs and emits a log either way.
              </p>
            </div>
          </div>
          <div className="h2-bento__card h2-bento__card--lg">
            <div className="h2-bento__visual">
              <ApprovalGateMock />
            </div>
            <div>
              <h3 className="h2-bento__title">Human approval where it matters</h3>
              <p className="h2-bento__copy">
                Funds, pricing, and public actions can require passkey or biometric confirmation
                from the owner before they go through.
              </p>
            </div>
          </div>
          <div className="h2-bento__card h2-bento__card--sm">
            <span className="h2-bento__icon h2-bento__icon--blue-red" aria-hidden>
              <ListChecks />
            </span>
            <div>
              <h3 className="h2-bento__title">Roles &amp; limits</h3>
              <p className="h2-bento__copy">
                Scope what support, ops, and agents can each do: amounts, actions, expiry.
              </p>
            </div>
          </div>
          <div className="h2-bento__card h2-bento__card--sm">
            <span className="h2-bento__icon h2-bento__icon--ember-moss" aria-hidden>
              <ScrollText />
            </span>
            <div>
              <h3 className="h2-bento__title">Audit trail</h3>
              <p className="h2-bento__copy">
                Every decision, allowed, held, or blocked, lands in an evidence trail
                you can export.
              </p>
            </div>
          </div>
          <div className="h2-bento__card h2-bento__card--sm">
            <span className="h2-bento__icon h2-bento__icon--sage-charcoal" aria-hidden>
              <KeyRound />
            </span>
            <div>
              <h3 className="h2-bento__title">Recovery built in</h3>
              <p className="h2-bento__copy">
                Accounts recover through email and linked devices: no seed phrases, no
                lockouts.
              </p>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

/* ---------- workflows (canvas + use-case covers) ---------- */

const useCases = [
  {
    title: 'Automate storefront ops',
    coverClass: 'h2-case__cover--ops',
    coverLabel: 'Storefront ops',
    copy: 'Let an agent watch cart abandonment, inventory alerts, and support tickets, then follow up, prepare refunds, and update listings inside the limits you set.',
  },
  {
    title: 'Delegate to staff safely',
    coverClass: 'h2-case__cover--staff',
    coverLabel: 'Staff delegation',
    copy: 'Give part-time staff and contractors scoped credentials instead of shared logins. Limits and roles apply automatically; access expires on schedule.',
  },
  {
    title: 'Agent checkout with mandates',
    coverClass: 'h2-case__cover--checkout',
    coverLabel: 'Agent checkout',
    copy: 'Buyer-side agents purchase under signed mandates with per-week budgets: merchants see verified identity and a clean audit trail on every order.',
  },
];

export function H2WorkflowCanvas(): React.JSX.Element {
  return (
    <div className="h2-flow">
      <div
        className="h2-flow__canvas"
        role="img"
        aria-label="A storefront event flowing through preflight checks into a signed action"
      >
        <span className="h2-flow__tag">Seams Harness &middot; cart-recovery flow</span>
        <div className="h2-flow__row">
          <div className="h2-mockcard h2-flow__node h2-flow__node--first">
            <p className="h2-mockcard__title">Storefront event</p>
            <div className="h2-mockrow">
              <span className="h2-mockrow__main">
                Cart abandoned
                <small>3 items &middot; ¥12,400</small>
              </span>
              <span className="h2-chip h2-chip--plain">New</span>
            </div>
          </div>
          <span className="h2-flow__link" aria-hidden />
          <div className="h2-mockcard h2-flow__node">
            <p className="h2-mockcard__title">Preflight checks</p>
            <div className="h2-mockrow">
              <span className="h2-mockrow__main">Credentials valid</span>
              <span className="h2-chip h2-chip--green">Pass</span>
            </div>
            <div className="h2-mockrow">
              <span className="h2-mockrow__main">Agent identity</span>
              <span className="h2-chip h2-chip--green">Pass</span>
            </div>
            <div className="h2-mockrow">
              <span className="h2-mockrow__main">Discount 10%</span>
              <span className="h2-chip h2-chip--amber">Owner approval</span>
            </div>
          </div>
          <span className="h2-flow__link" aria-hidden />
          <div className="h2-mockcard h2-flow__node h2-flow__node--last">
            <p className="h2-mockcard__title">Action</p>
            <div className="h2-mockrow">
              <span className="h2-mockrow__main">
                Offer email sent
                <small>sig 0x8c31…f27</small>
              </span>
              <span className="h2-chip h2-chip--green">Signed</span>
            </div>
            <div className="h2-mockrow">
              <span className="h2-mockrow__main">Logged to audit trail</span>
              <span className="h2-chip h2-chip--plain">Auto</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export function H2Cases(): React.JSX.Element {
  return (
    <section className="h2-section h2-rule" aria-labelledby="h2-cases-title">
      <div className="h2-shell">
        <div className="h2-split-head">
          <p className="h2-kicker">Workflows</p>
          <h2 id="h2-cases-title" className="h2-display">
            Turn store operations into governed workflows
          </h2>
          <p className="h2-split-head__copy">
            The Seams harness turns commerce events into policy-checked actions: agents watch the
            store, prepare responses, and act inside the limits you set, with human approval
            where it matters.
          </p>
        </div>

        <H2WorkflowCanvas />

        <div className="h2-cases">
          {useCases.map((c) => (
            <div className="h2-case" key={c.title}>
              <div className={`h2-case__cover ${c.coverClass}`} aria-hidden>
                <span>{c.coverLabel}</span>
              </div>
              <h3 className="h2-case__title">{c.title}</h3>
              <p className="h2-case__copy">{c.copy}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ---------- security ---------- */

function LineArt({ children }: { children: React.ReactNode }): React.JSX.Element {
  return (
    <svg viewBox="0 0 100 100" fill="none" stroke="currentColor" aria-hidden>
      {children}
    </svg>
  );
}

export function H2Security(): React.JSX.Element {
  return (
    <section className="h2-section h2-rule" aria-labelledby="h2-security-title">
      <div className="h2-shell">
        <div className="h2-security">
          <div>
            <p className="h2-kicker" style={{ marginBottom: 22 }}>
              Security
            </p>
            <h2 id="h2-security-title" className="h2-display h2-security__title">
              Custody and control, engineered in
            </h2>
            <div className="h2-security__item">
              <h3>
                <Lock aria-hidden />
                Non-custodial by design
              </h3>
              <p>
                Signing authority is split between the user&rsquo;s device and your infrastructure.
                Neither can sign alone, and export always requires a fresh authorized flow.
              </p>
            </div>
            <div className="h2-security__item">
              <h3>
                <ShieldCheck aria-hidden />
                Policy before execution
              </h3>
              <p>
                Approvals, budgets, revocation state, and replay checks run before signatures,
                payments, or API actions execute for people and agents alike.
              </p>
            </div>
            <div className="h2-security__item">
              <h3>
                <ScrollText aria-hidden />
                Evidence for every decision
              </h3>
              <p>
                Allowed, held, or blocked: each decision is attributed to a verified identity
                and retained in the audit trail.
              </p>
            </div>
          </div>
          <div className="h2-security__grid">
            <div className="h2-security__cell">
              {/* nested isometric cube: dashed hidden edges, faint-filled inner cube */}
              <LineArt>
                <path d="M50 12 L80 27 L80 63 L50 78 L20 63 L20 27 Z" />
                <path
                  d="M50 12 L50 48 M50 48 L20 63 M50 48 L80 63"
                  strokeDasharray="2.5 3"
                  opacity="0.5"
                />
                <path
                  d="M50 36 L63 42.5 L63 58 L50 64.5 L37 58 L37 42.5 Z"
                  fill="var(--h2-taupe)"
                />
                <path d="M37 42.5 L50 49 L63 42.5 M50 49 L50 64.5" />
                <path d="M20 27 L50 42 L80 27 M50 42 L50 78" />
              </LineArt>
              <span>Split-key custody</span>
            </div>
            <div className="h2-security__cell">
              {/* double-outline shield on a dotted axis */}
              <LineArt>
                <path d="M50 4 V96" strokeDasharray="2.5 3" opacity="0.4" />
                <path
                  d="M50 12 L81 22 V48 C81 66 68 78 50 86 C32 78 19 66 19 48 V22 Z"
                  fill="var(--h2-bg)"
                />
                <path
                  d="M50 20 L74 28 V48 C74 61 64 71 50 77 C36 71 26 61 26 48 V28 Z"
                  opacity="0.7"
                />
                <path d="M38 48 L47 57 L63 39" />
              </LineArt>
              <span>Policy engine</span>
            </div>
            <div className="h2-security__cell">
              {/* technical key: concentric head, construction circle + crosshair */}
              <LineArt>
                <path d="M36 8 V68 M6 38 H66" strokeDasharray="2.5 3" opacity="0.4" />
                <circle cx="36" cy="38" r="22" strokeDasharray="2.5 3" opacity="0.4" />
                <circle cx="36" cy="38" r="15" fill="var(--h2-bg)" />
                <circle cx="36" cy="38" r="8" />
                <path d="M47 49 L82 84 M62 64 L71 55 M71 73 L80 64" />
              </LineArt>
              <span>Scoped credentials</span>
            </div>
            <div className="h2-security__cell">
              {/* layered ledger: offset sheets with dashed projection guides */}
              <LineArt>
                <path d="M34 10 H78 V74 H34 Z" opacity="0.7" />
                <path
                  d="M34 10 L24 24 M78 10 L68 24 M78 74 L68 88 M34 74 L24 88"
                  strokeDasharray="2.5 3"
                  opacity="0.5"
                />
                <path d="M24 24 H68 V88 H24 Z" fill="var(--h2-bg)" />
                <path d="M32 40 H60 M32 49 H60 M32 58 H60 M32 67 H50" />
              </LineArt>
              <span>Audit log</span>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

/* ---------- get started band (stacked two-column rows) ---------- */

export function H2Start(): React.JSX.Element {
  const { linkProps } = useSiteRouter();
  const dashboardProps = linkProps('/dashboard');
  const docsProps = linkProps('/docs/concepts/');
  const contactProps = linkProps('/contact/');

  return (
    <section className="h2-section h2-rule" aria-labelledby="h2-start-title">
      <div className="h2-shell">
        <div className="h2-eco__head h2-starthead">
          <div>
            <p className="h2-kicker" style={{ marginBottom: 12 }}>
              Get started
            </p>
            <h2 id="h2-start-title" className="h2-display h2-eco__title">
              Start in the dashboard, or build it into your product
            </h2>
          </div>
          <a className="h2-btn h2-btn--outline" href={docsProps.href} onClick={docsProps.onClick}>
            Explore docs
          </a>
        </div>
      </div>

      {/* row 1: merchant dashboard */}
      <div className="h2-startrow h2-rule">
        <div className="h2-shell h2-startrow__grid">
          <div className="h2-startrow__text">
            <h3>Merchant dashboard</h3>
            <p>
              Create a store account, set policy, and invite staff and agents, no code
              required. Planning a marketplace or fleet rollout? We&rsquo;ll help.
            </p>
            <div className="h2-startrow__ctas">
              <a
                className="h2-btn h2-btn--primary"
                href={dashboardProps.href}
                onClick={dashboardProps.onClick}
              >
                Open dashboard
              </a>
              <a
                className="h2-btn h2-btn--outline"
                href={contactProps.href}
                onClick={contactProps.onClick}
              >
                Talk to us
              </a>
            </div>
          </div>
          <div className="h2-startrow__visual">
            <div className="h2-mockcard h2-mockcard--wide">
              <p className="h2-mockcard__title">Store overview</p>
              <div className="h2-mockrow">
                <span className="h2-mockrow__main">Store policy</span>
                <span className="h2-chip h2-chip--green">Active</span>
              </div>
              <div className="h2-mockrow">
                <span className="h2-mockrow__main">2 agents · 3 staff</span>
                <span className="h2-chip h2-chip--plain">Scoped</span>
              </div>
              <div className="h2-mockrow">
                <span className="h2-mockrow__main">Pending approvals</span>
                <span className="h2-chip h2-chip--amber">1</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* row 2: accounts & wallets API */}
      <div className="h2-startrow h2-rule">
        <div className="h2-shell h2-startrow__grid">
          <div className="h2-startrow__text">
            <h3>Accounts &amp; Wallets API</h3>
            <p>
              Register a passkey and get a working account: non-custodial wallet included, recovery
              built in, every action signed.
            </p>
            <div className="h2-startrow__notes">
              <div>
                <strong>Passkey register</strong>
                <span>One call to a working wallet</span>
              </div>
              <div>
                <strong>Recovery</strong>
                <span>Email + linked devices, no seed phrases</span>
              </div>
            </div>
          </div>
          <div className="h2-code h2-code--lg" aria-label="Register a wallet with the SDK">
            <span className="tok-kw">import</span>
            {' { SeamsClient } '}
            <span className="tok-kw">from</span> <span className="tok-str">'@seams/sdk'</span>
            {';\n\n'}
            <span className="tok-kw">const</span>
            {' seams = '}
            <span className="tok-kw">new</span>
            {' SeamsClient({ apiKey: '}
            <span className="tok-str">'YOUR_API_KEY'</span>
            {' });\n\n'}
            <span className="tok-kw">const</span>
            {' account = '}
            <span className="tok-kw">await</span>
            {' seams.register({\n  method: '}
            <span className="tok-str">'passkey'</span>
            {',\n  policy: '}
            <span className="tok-str">'starter-store'</span>
            {',\n});'}
          </div>
        </div>
      </div>

      {/* row 3: policy & delegation API */}
      <div className="h2-startrow h2-rule">
        <div className="h2-shell h2-startrow__grid">
          <div className="h2-startrow__text">
            <h3>Policy &amp; Delegation API</h3>
            <p>
              Grant staff and agents scoped credentials with limits and expiry. Risky actions route
              to the owner for passkey approval.
            </p>
            <div className="h2-startrow__notes">
              <div>
                <strong>Scoped credentials</strong>
                <span>Per-action limits and expiry</span>
              </div>
              <div>
                <strong>Approval gates</strong>
                <span>Owner passkey for risky actions</span>
              </div>
            </div>
          </div>
          <div className="h2-code h2-code--lg" aria-label="Grant a scoped credential with the SDK">
            <span className="tok-kw">const</span>
            {' grant = '}
            <span className="tok-kw">await</span>
            {' seams.delegation.grant({\n  to: '}
            <span className="tok-str">'support-agent'</span>
            {',\n  scopes: ['}
            <span className="tok-str">'refunds:issue'</span>
            {', '}
            <span className="tok-str">'emails:send'</span>
            {'],\n  limit: { perAction: '}
            <span className="tok-str">'¥10,000'</span>
            {', expires: '}
            <span className="tok-str">'30d'</span>
            {' },\n});\n\n'}
            <span className="tok-cm">{'// risky actions route to the owner\n'}</span>
            <span className="tok-kw">await</span>
            {' seams.approvals.require('}
            <span className="tok-str">'discounts:over-10'</span>
            {');'}
          </div>
        </div>
      </div>
    </section>
  );
}

/* ---------- FAQ ---------- */

const faqs = [
  {
    q: 'What is Seams?',
    a: 'Seams is key and credential infrastructure for ecommerce: one SDK for authentication, non-custodial wallets, a credentials and permissions layer, and delegated access for staff and AI agents.',
  },
  {
    q: 'Is Seams custodial?',
    a: 'No. Signing keys are split between the user’s device and your infrastructure: neither side can sign alone, and exporting a key always requires a fresh authorized flow from the owner.',
  },
  {
    q: 'What can AI agents do with Seams?',
    a: 'Agents get their own identity and scoped credentials. They can act on commerce events: follow-ups, refunds, listing updates, but only inside the merchant’s policy. Risky actions route to a human approval gate with passkey or biometric confirmation.',
  },
  {
    q: 'How do merchants stay in control?',
    a: 'Policy runs before anything executes: roles, amount limits, thresholds, expiry, and revocation. Every decision is attributed and logged, and delegated credentials can be revoked at any time.',
  },
  {
    q: 'How do we get started?',
    a: 'The SDK is self-serve: install it, register an account with a passkey, and apply a policy template. For marketplaces and merchant fleets, contact us and we’ll plan the rollout together.',
  },
  {
    q: 'How does API authentication work?',
    a: 'Your backend authenticates with API keys; end users and agents authenticate with passkeys and scoped credentials. Signing always requires the user-side key share, so API keys alone can never move funds or export keys.',
  },
  {
    q: 'Which networks does Seams support?',
    a: 'Ethereum and EVM networks, NEAR, Stripe Tempo, Circle Arc, Hyperliquid, and Polygon today, with more networks added as merchant demand grows.',
  },
  {
    q: 'How is usage metered?',
    a: 'Plans are based on monthly active wallets, with overage pricing as you grow: from a free tier for launch through usage-based Growth and Professional plans. See the pricing page for details.',
  },
];

export function H2Faq(): React.JSX.Element {
  return (
    <section className="h2-section h2-rule" aria-labelledby="h2-faq-title">
      <div className="h2-shell">
        <div className="h2-faq">
          <h2 id="h2-faq-title" className="h2-display h2-faq__title">
            Frequently asked questions
          </h2>
          <div className="h2-faq__list">
            {faqs.map((item) => (
              <details key={item.q}>
                <summary>{item.q}</summary>
                <p>{item.a}</p>
              </details>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}

/* ---------- footer ---------- */

const footerGroups = [
  {
    heading: 'Products',
    links: [
      { label: 'Embedded Wallet', to: '/wallet' },
      { label: 'Ecommerce Agents', to: '/ecommerce' },
      { label: 'Custody Model', to: '/docs/concepts/custody/' },
    ],
  },
  {
    heading: 'Platform',
    links: [
      { label: 'Authentication', to: '/docs/concepts/auth-methods/' },
      { label: 'Wallets & Signatures', to: '/docs/concepts/threshold-signing/' },
      { label: 'Permissions & Policy', to: '/docs/concepts/policy/mandates' },
    ],
  },
  {
    heading: 'Developers',
    links: [
      { label: 'Documentation', to: '/docs/concepts/' },
      { label: 'Architecture', to: '/docs/concepts/architecture' },
      { label: 'Pricing', to: '/pricing/' },
    ],
  },
  {
    heading: 'Company',
    links: [
      { label: 'About', to: '/company/' },
      { label: 'Contact', to: '/contact/' },
    ],
  },
];

export function H2Footer(): React.JSX.Element {
  const { linkProps } = useSiteRouter();
  const homeProps = linkProps('/');

  return (
    <footer className="h2-footer h2-rule" aria-label="Site footer">
      <div className="h2-footer__inner">
        <div className="h2-footer__grid">
          <div className="h2-footer__brand">
            <a href={homeProps.href} onClick={homeProps.onClick} aria-label="Seams home">
              {/* the page is always light; pin the light wordmark */}
              <SeamsWordmark height={22} theme="light" />
            </a>
          </div>
          {footerGroups.map((group) => (
            <div className="h2-footer__col" key={group.heading}>
              <h3>{group.heading}</h3>
              {group.links.map((link) => {
                const props = linkProps(link.to);
                return (
                  <a key={link.label} href={props.href} onClick={props.onClick}>
                    {link.label}
                  </a>
                );
              })}
            </div>
          ))}
        </div>
        <div className="h2-footer__bottom">
          <span>Copyright © {new Date().getFullYear()} Seams Technologies KK. Tokyo.</span>
          <span className="h2-footer__socials">
            <a
              href="https://x.com/lowerarchy"
              target="_blank"
              rel="noopener noreferrer"
              aria-label="X"
            >
              <Twitter size={16} aria-hidden />
            </a>
            <a
              href="https://github.com/seams-tech"
              target="_blank"
              rel="noopener noreferrer"
              aria-label="GitHub"
            >
              <Github size={16} aria-hidden />
            </a>
          </span>
        </div>
      </div>
    </footer>
  );
}
