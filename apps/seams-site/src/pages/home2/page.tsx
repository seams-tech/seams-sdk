import React from 'react';
import {
  ArrowRight,
  Bot,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  Fingerprint,
  Hash,
  Home,
  ListChecks,
  ScrollText,
  ShieldCheck,
  Slack,
  Send,
  ShoppingCart,
  Store,
  Wallet,
} from 'lucide-react';
import { AuthMenuMode, SeamsAuthMenuSkeletonInner } from '@seams/sdk/react';
import { DEMO_THEME_PRESETS } from '@/context/app-themes';
import NavbarStatic from '@/components/Navbar/NavbarStatic';
import SeamsWordmark from '@/components/icons/SeamsWordmark';
import { ArrowRightAnim } from '@/components/ArrowRightAnim';
import { useSiteRouter } from '@/app/router/useSiteRouter';
import {
  H2Ecosystem,
  H2Faq,
  H2Footer,
  H2Pillars,
  MpcSplitDiagram,
} from '@/components/h2/sections';
import '@/styles/h2.css';

/* Umbrella front page: a simple headline, then a paged two-panel scene band
   showing the products (mock placeholders with the same footprint as the real
   screenshots/videos that will replace them), a trusted-by strip, and the
   two-platforms split that routes each ICP to its page. */

/* ---------- hero scene mocks (placeholders for real product imagery) ---------- */

function DashboardWindow(): React.JSX.Element {
  return (
    <div className="h2-window" role="img" aria-label="Seams merchant dashboard overview">
      <div className="h2-window__side">
        <div className="h2-window__brand">
          <SeamsWordmark height={15} theme="light" />
        </div>
        <div className="h2-window__navitem is-active">
          <Home aria-hidden /> Home
        </div>
        <div className="h2-window__navitem">
          <Bot aria-hidden /> Agents
        </div>
        <div className="h2-window__navitem">
          <ListChecks aria-hidden /> Policies
        </div>
        <div className="h2-window__navitem">
          <ShieldCheck aria-hidden /> Approvals
        </div>
        <div className="h2-window__navitem">
          <ScrollText aria-hidden /> Audit
        </div>
      </div>
      <div className="h2-window__main">
        <p className="h2-window__title">Store overview</p>
        <div className="h2-stats">
          <span className="h2-stat">
            <small>Actions today</small>
            <strong>1,284</strong>
          </span>
          <span className="h2-stat">
            <small>Held for approval</small>
            <strong>3</strong>
          </span>
          <span className="h2-stat">
            <small>Agents active</small>
            <strong>2</strong>
          </span>
        </div>
        <div className="h2-mockrow">
          <span className="h2-mockrow__main">
            Support agent (AI)
            <small>emails + refunds ≤ ¥10,000</small>
          </span>
          <span className="h2-chip h2-chip--green">Active</span>
        </div>
        <div className="h2-mockrow">
          <span className="h2-mockrow__main">
            Discount 12% · cart #8841
            <small>waiting on owner approval</small>
          </span>
          <span className="h2-chip h2-chip--amber">Held</span>
        </div>
        <div className="h2-mockrow">
          <span className="h2-mockrow__main">
            Restock order signed
            <small>sig 0x8c31…f27</small>
          </span>
          <span className="h2-chip h2-chip--plain">Logged</span>
        </div>
        <div className="h2-mockrow">
          <span className="h2-mockrow__main">
            Support inbox triaged
            <small>14 tickets · 2 escalated to owner</small>
          </span>
          <span className="h2-chip h2-chip--plain">Logged</span>
        </div>
        <div className="h2-mockrow">
          <span className="h2-mockrow__main">
            Price update · autumn catalog
            <small>runs 06:00 JST · within ±5% band</small>
          </span>
          <span className="h2-chip h2-chip--green">Scheduled</span>
        </div>
      </div>
    </div>
  );
}

function IntegrationsWindow(): React.JSX.Element {
  return (
    <div
      className="h2-window"
      role="img"
      aria-label="Approval request delivered to a Slack channel"
    >
      <div className="h2-window__side h2-window__side--slack">
        <div className="h2-window__brand">Kanda Goods</div>
        <div className="h2-window__navitem">
          <Hash aria-hidden /> general
        </div>
        <div className="h2-window__navitem is-active">
          <Hash aria-hidden /> store-ops
        </div>
        <div className="h2-window__navitem">
          <Hash aria-hidden /> support
        </div>
        <div className="h2-window__navitem">
          <Hash aria-hidden /> restocks
        </div>
      </div>
      <div className="h2-window__main">
        <p className="h2-window__title"># store-ops</p>
        <div className="h2-chat">
          <div className="h2-chat__bubble">
            <small>Seams Harness · APP · 09:14</small>
            Held for approval: support agent wants to send a 12% discount for cart #8841
            (¥12,400). Policy: discounts over 10% need an owner.
          </div>
          <div className="h2-chat__bubble">
            <small>Seams Harness · APP · 09:14</small>
            Approve with your passkey to release the action.
          </div>
          <div className="h2-chat__bubble h2-chat__bubble--reply">
            Approved ✓ signed sig 0x8c31…f27, offer email sent
          </div>
          <div className="h2-chat__bubble">
            <small>Seams Harness · APP · 09:31</small>
            Daily digest: 1,284 actions inside policy, 3 held, 0 declined. Full audit trail on the
            dashboard.
          </div>
        </div>
      </div>
    </div>
  );
}

/* The real SeamsAuthMenu shell, inert: the SDK's skeleton renders identical
   markup/CSS with all controls disabled and no wallet logic. The Inner export
   reads no theme context; the Paper palette is pinned as CSS variables on the
   wrapper so the card can't inherit the site theme (which may be dark or
   Rosé Pine). pointer-events off so clicks fall through to the panel link. */
const paperPreset = DEMO_THEME_PRESETS.find((t) => t.id === 'paper') ?? DEMO_THEME_PRESETS[0];
const paperShellVars = Object.fromEntries(
  Object.entries(paperPreset.colors).map(([key, value]) => [`--w3a-colors-${key}`, value]),
) as React.CSSProperties;

function WalletShellCard(): React.JSX.Element {
  return (
    <div
      className="h2-heroscene__shell"
      aria-hidden
      data-w3a-theme="light"
      style={paperShellVars}
    >
      {/* Login mode shows the full method stack (passkey, SSO, other options) */}
      <SeamsAuthMenuSkeletonInner defaultMode={AuthMenuMode.Login} />
    </div>
  );
}

type DemoWalletTransaction = {
  merchant: string;
  amount: string;
  token: string;
  network: string;
  method: string;
  recipient: string;
  policy: string;
  fee: string;
  signer: string;
  digest: string;
};

type HeroWalletPreview =
  | {
      kind: 'signIn';
      sub: string;
      transaction?: never;
    }
  | {
      kind: 'transactionConfirm';
      sub: string;
      transaction: DemoWalletTransaction;
    };

const demoWalletTransaction: DemoWalletTransaction = {
  merchant: 'Kanda Goods',
  amount: '¥12,400',
  token: 'USDC',
  network: 'Tempo testnet',
  method: 'sendDiscountCredit',
  recipient: 'cart #8841',
  policy: 'Owner approval required over 10%',
  fee: '< ¥0.01',
  signer: 'wallet_8c31...f27',
  digest: '0x91f3...8ad2',
};

const signInWalletPreview: HeroWalletPreview = {
  kind: 'signIn',
  sub: 'Non-custodial wallets, opened with a passkey',
};

const transactionWalletPreview: HeroWalletPreview = {
  kind: 'transactionConfirm',
  sub: 'Review a demo transaction before signing',
  transaction: demoWalletTransaction,
};

function assertNever(value: never): never {
  throw new Error(`Unhandled hero wallet preview: ${String(value)}`);
}

function WalletTransactionPreview(props: {
  transaction: DemoWalletTransaction;
}): React.JSX.Element {
  const transaction = props.transaction;

  return (
    <div
      className="h2-wallet-confirm h2-fadein"
      role="img"
      aria-label={`${transaction.merchant} transaction confirmation preview`}
    >
      <div className="h2-wallet-confirm__top">
        <span className="h2-wallet-confirm__icon" aria-hidden>
          <Fingerprint />
        </span>
        <div>
          <p className="h2-wallet-confirm__eyebrow">Wallet confirmation</p>
          <h3 className="h2-wallet-confirm__title">Confirm transaction</h3>
        </div>
      </div>

      <div className="h2-wallet-confirm__summary">
        <span className="h2-wallet-confirm__merchant">
          <ShoppingCart aria-hidden />
          {transaction.merchant}
        </span>
        <span className="h2-wallet-confirm__amount">
          {transaction.amount}
          <small>{transaction.token}</small>
        </span>
      </div>

      <div className="h2-wallet-confirm__details" aria-label="Demo transaction details">
        <span className="h2-wallet-confirm__row">
          <small>Network</small>
          <strong>{transaction.network}</strong>
        </span>
        <span className="h2-wallet-confirm__row">
          <small>Method</small>
          <strong>{transaction.method}</strong>
        </span>
        <span className="h2-wallet-confirm__row">
          <small>Recipient</small>
          <strong>{transaction.recipient}</strong>
        </span>
        <span className="h2-wallet-confirm__row">
          <small>Estimated fee</small>
          <strong>{transaction.fee}</strong>
        </span>
      </div>

      <div className="h2-wallet-confirm__policy">
        <ShieldCheck aria-hidden />
        <span>{transaction.policy}</span>
      </div>

      <div className="h2-wallet-confirm__signer">
        <span>
          <small>Signer</small>
          <strong>{transaction.signer}</strong>
        </span>
        <span>
          <small>Intent digest</small>
          <strong>{transaction.digest}</strong>
        </span>
      </div>

      <div className="h2-wallet-confirm__actions" aria-hidden>
        <span className="h2-wallet-confirm__action h2-wallet-confirm__action--secondary">
          Cancel
        </span>
        <span className="h2-wallet-confirm__action h2-wallet-confirm__action--primary">
          <CheckCircle2 />
          Confirm
        </span>
      </div>

      <div className="h2-wallet-confirm__drawer" aria-hidden>
        <span className="h2-wallet-confirm__drawer-grip" />
        <span>
          <Send />
          Ready for passkey signature
        </span>
        <ArrowRight />
      </div>
    </div>
  );
}

function renderHeroWalletPreview(preview: HeroWalletPreview): React.JSX.Element {
  switch (preview.kind) {
    case 'signIn':
      return <WalletShellCard />;
    case 'transactionConfirm':
      return <WalletTransactionPreview transaction={preview.transaction} />;
    default:
      return assertNever(preview);
  }
}

/* ---------- hero: headline + paged scenes ---------- */

type HeroScene = {
  id: string;
  icon: React.ComponentType<{ 'aria-hidden'?: boolean }>;
  title: string;
  sub: string;
  left: React.ReactNode;
  wallet: HeroWalletPreview;
};

/* Left column pages through views of the agents product; the wallet shell
   stays fixed in the right column, like the reference hero's assistant card. */
const heroScenes: HeroScene[] = [
  {
    id: 'dashboard',
    icon: Store,
    title: 'Ecommerce Agents',
    sub: 'Agents run your store: limits, approvals, and audit built in',
    left: <DashboardWindow />,
    wallet: signInWalletPreview,
  },
  {
    id: 'integrations',
    icon: Slack,
    title: 'Integrations',
    sub: 'Approvals land where your team already works',
    left: <IntegrationsWindow />,
    wallet: transactionWalletPreview,
  },
];

function HomeHeroCurrent(): React.JSX.Element {
  const { linkProps } = useSiteRouter();
  const startProps = linkProps('/docs/concepts/');
  const contactProps = linkProps('/contact/');
  const agentsProps = linkProps('/ecommerce');
  const walletProps = linkProps('/wallet');
  const [page, setPage] = React.useState(0);
  const scene = heroScenes[page];

  return (
    <>
      <header className="h2-hero-simple" aria-labelledby="h2-home-title">
        <div className="h2-shell">
          <h1 id="h2-home-title" className="h2-display h2-hero-simple__title">
            Commerce accounts for people and AI agents
          </h1>
          <p className="h2-hero-simple__sub">
            Auth, wallets, credentials, and delegated access in one SDK. Policy checks every action
            before it runs.
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
              Contact sales
            </a>
          </div>
        </div>
      </header>

      <section className="h2-heroscene h2-rule" aria-label="Product tour">
        <div className="h2-heroscene__split">
          {/* whole panel navigates; the pager is a sibling so it stays clickable */}
          <a
            className="h2-heroscene__stage"
            href={agentsProps.href}
            onClick={agentsProps.onClick}
            aria-label="Explore Ecommerce Agents"
          >
            <div className="h2-heroscene__intro h2-fadein" key={`intro-${scene.id}`}>
              <span className="h2-heroscene__intro-icon" aria-hidden>
                <scene.icon />
              </span>
              <div>
                <p className="h2-heroscene__intro-title">{scene.title}</p>
                <p className="h2-heroscene__intro-sub">{scene.sub}</p>
              </div>
            </div>
            <div className="h2-heroscene__frame h2-fadein" key={`frame-${scene.id}`}>
              {scene.left}
            </div>
          </a>

          <a
            className="h2-heroscene__aside"
            href={walletProps.href}
            onClick={walletProps.onClick}
            aria-label="Explore Embedded Wallet"
          >
            <div className="h2-heroscene__intro">
              <span className="h2-heroscene__intro-icon" aria-hidden>
                <Wallet />
              </span>
              <div>
                <p className="h2-heroscene__intro-title">Embedded Wallet</p>
                <p className="h2-heroscene__intro-sub">{scene.wallet.sub}</p>
              </div>
            </div>
            <div className="h2-heroscene__aside-body" key={`wallet-${scene.wallet.kind}`}>
              {renderHeroWalletPreview(scene.wallet)}
            </div>
          </a>

          {/* Pager sits on the divider/border junction, like the demo hero's */}
          <div className="h2-pager" role="group" aria-label="Product views">
            <button
              type="button"
              className="h2-pager__btn"
              aria-label="Previous product view"
              disabled={page === 0}
              onClick={() => setPage((p) => Math.max(0, p - 1))}
            >
              <ChevronLeft aria-hidden />
            </button>
            <span className="h2-pager__dots">
              {heroScenes.map((s, i) => (
                <span
                  key={s.id}
                  className={`h2-pager__dot${i === page ? ' is-active' : ''}`}
                  title={s.title}
                />
              ))}
            </span>
            <button
              type="button"
              className="h2-pager__btn"
              aria-label="Next product view"
              disabled={page >= heroScenes.length - 1}
              onClick={() => setPage((p) => Math.min(heroScenes.length - 1, p + 1))}
            >
              <ChevronRight aria-hidden />
            </button>
          </div>
        </div>
      </section>
    </>
  );
}

type AgentMediaItemId = 'operations' | 'wallet' | 'approval' | 'audit';

type AgentMediaItem = {
  id: AgentMediaItemId;
  icon: React.ComponentType<{ 'aria-hidden'?: boolean }>;
  image: string;
  label: string;
  title: string;
  copy: string;
};

const defaultAgentMediaItemId: AgentMediaItemId = 'operations';

const agentMediaItems: readonly AgentMediaItem[] = [
  {
    id: 'operations',
    icon: ListChecks,
    image: '/gradients/web/ember-moss.jpg',
    label: 'Store operations',
    title: 'Discount request held',
    copy: 'Agent proposes 12% off cart #8841. Policy routes it to owner approval.',
  },
  {
    id: 'wallet',
    icon: Wallet,
    image: '/gradients/web/sage-charcoal.jpg',
    label: 'Wallet signing',
    title: 'Passkey unlock',
    copy: 'The right user and key approve the signature before any wallet action runs.',
  },
  {
    id: 'approval',
    icon: ShieldCheck,
    image: '/gradients/web/aqua-evergreen.jpg',
    label: 'Approval',
    title: 'Policy gate',
    copy: 'High-risk actions pause for owner review while routine work keeps moving.',
  },
  {
    id: 'audit',
    icon: ScrollText,
    image: '/gradients/web/dusk-blue-mauve.jpg',
    label: 'Audit',
    title: 'Action receipt',
    copy: 'Every agent action records who delegated it, what ran, and which policy approved it.',
  },
];

function parseAgentMediaItemId(value: string | undefined): AgentMediaItemId | null {
  switch (value) {
    case 'operations':
    case 'wallet':
    case 'approval':
    case 'audit':
      return value;
    default:
      return null;
  }
}

function readAgentMediaItemId(target: EventTarget | null): AgentMediaItemId | null {
  if (!(target instanceof Element)) {
    return null;
  }

  const button = target.closest<HTMLButtonElement>('[data-agent-media-id]');
  return parseAgentMediaItemId(button?.dataset.agentMediaId);
}

function renderAgentMediaCard(
  item: AgentMediaItem,
  activeMediaItemId: AgentMediaItemId,
): React.JSX.Element {
  const Icon = item.icon;
  const isActive = item.id === activeMediaItemId;

  return (
    <button
      key={item.id}
      type="button"
      className={`h2-agent-card ${isActive ? 'is-active' : 'is-collapsed'}`}
      data-agent-media-id={item.id}
      aria-label={`Show ${item.label}`}
      aria-pressed={isActive}
    >
      <img src={item.image} alt="" />
      <span className="h2-agent-card__label">
        <Icon aria-hidden />
        {item.label}
      </span>
      <span className="h2-agent-card__caption">
        <strong>{item.title}</strong>
        {item.copy}
      </span>
    </button>
  );
}

function HomeHeroMedia(): React.JSX.Element {
  const { linkProps } = useSiteRouter();
  const startProps = linkProps('/docs/concepts/');
  const contactProps = linkProps('/contact/');
  const agentsProps = linkProps('/ecommerce');
  const [activeMediaItemId, setActiveMediaItemId] =
    React.useState<AgentMediaItemId>(defaultAgentMediaItemId);
  const handleMediaRailClick = React.useCallback((event: React.MouseEvent<HTMLDivElement>) => {
    const itemId = readAgentMediaItemId(event.target);

    if (itemId === null) {
      return;
    }

    setActiveMediaItemId(itemId);
  }, []);

  return (
    <>
      <header className="h2-hero-media" aria-labelledby="h2-home2-title">
        <div className="h2-shell h2-hero-media__split">
          <div className="h2-hero-media__main">
            <p className="h2-hero-media__product">
              <img
                src="/seams-v9/png/gradient-fabric/seams-mark-gradient-fabric-256.png"
                alt=""
              />
              <span>Seams Agents</span>
            </p>
            <h1 id="h2-home2-title" className="h2-display h2-hero-media__title">
              Commerce agents that stay inside policy
            </h1>
            <div className="h2-hero-media__ctas">
              <a
                className="h2-btn h2-btn--primary h2-btn--lg"
                href={startProps.href}
                onClick={startProps.onClick}
              >
                Create an agent
              </a>
              <a
                className="h2-btn h2-btn--outline h2-btn--lg"
                href={contactProps.href}
                onClick={contactProps.onClick}
              >
                Talk to sales
              </a>
            </div>
          </div>
          <aside className="h2-hero-media__copy" aria-label="Seams agent account summary">
            <p>
              Configure, deploy, and monitor AI agents for store operations. Seams gives every
              agent scoped credentials, spending limits, owner approvals, and an audit trail.
            </p>
          </aside>
        </div>
      </header>

      <section className="h2-agent-media h2-rule" aria-label="Seams agent use cases">
        <div className="h2-shell">
          <div
            className={`h2-agent-media__rail is-active-${activeMediaItemId}`}
            onClick={handleMediaRailClick}
          >
            {agentMediaItems.map((item) => renderAgentMediaCard(item, activeMediaItemId))}
          </div>

          <div className="h2-agent-chat-pill" aria-hidden="true">
            <img src="/seams-v9/png/gradient-fabric/seams-mark-gradient-fabric-256.png" alt="" />
            <span>
              Try a Seams agent
              <small>Policy checked before execution</small>
            </span>
          </div>

          <div className="h2-agent-media__footer" aria-label="Agent platform capabilities">
            <span>Scoped credentials</span>
            <span>Owner approvals</span>
            <span>Action receipts</span>
            <a href={agentsProps.href} onClick={agentsProps.onClick}>
              Explore Ecommerce Agents
              <ArrowRightAnim size={13} />
            </a>
          </div>
        </div>
      </section>
    </>
  );
}

/* ---------- trusted-by: fictional merchant wordmarks (placeholders) ---------- */

const merchantLogos = [
  { name: 'Kanda Goods', variant: 'h2-logo--bold' },
  { name: 'AOYAMA ATELIER', variant: 'h2-logo--caps' },
  { name: 'Ginza Table', variant: 'h2-logo--serif' },
  { name: 'shirokane supply', variant: 'h2-logo--mono' },
  { name: 'Yūgen Prints', variant: 'h2-logo--light' },
];

function HomeTrusted(): React.JSX.Element {
  return (
    <section className="h2-section h2-rule h2-logos" aria-labelledby="h2-trusted-title">
      <div className="h2-shell">
        <div className="h2-logos__row" aria-label="Merchants building on Seams">
          {merchantLogos.map((logo) => (
            <span key={logo.name} className={`h2-logo ${logo.variant}`}>
              {logo.name}
            </span>
          ))}
        </div>
        <div className="h2-logos__head">
          <h2 id="h2-trusted-title" className="h2-display">
            Trusted by merchants shipping the future of commerce
          </h2>
          <p className="h2-logos__copy">
            Stores and platforms use Seams for secure accounts, scoped credentials, and wallet
            access, with approval rules and an audit trail for every action.
          </p>
        </div>
      </div>
    </section>
  );
}

/* ---------- two products, one account layer ---------- */

function HomeDuo(): React.JSX.Element {
  const { linkProps } = useSiteRouter();
  const walletProps = linkProps('/wallet');
  const agentsProps = linkProps('/ecommerce');

  return (
    <section className="h2-section h2-section--snug h2-rule" aria-labelledby="h2-duo-title">
      <div className="h2-shell">
        <div className="h2-duo__head">
          <h2 id="h2-duo-title" className="h2-display">
            Two products, one account layer
          </h2>
          <p className="h2-duo__copy">
            Built on the same keys, credentials, and policy engine: one product for embedding
            wallets, another for putting agents to work on your store.
          </p>
        </div>
        <div className="h2-duo__grid">
          <a className="h2-duo__panel" href={walletProps.href} onClick={walletProps.onClick}>
            <h3 className="h2-duo__title">
              <Wallet aria-hidden />
              Embedded Wallet
            </h3>
            <p className="h2-duo__panel-copy">
              Passkey-secured, non-custodial wallets for your users: recovery built in, every
              action signed, keys split so neither side can sign alone.
            </p>
            {/* MPC diagram instead of a second auth card: the hero already
                shows the real wallet shell */}
            <div className="h2-duo__visual">
              <MpcSplitDiagram />
            </div>
            <span className="h2-duo__cta">
              Explore Embedded Wallet
              <ArrowRightAnim size={13} />
            </span>
          </a>
          <a className="h2-duo__panel" href={agentsProps.href} onClick={agentsProps.onClick}>
            <h3 className="h2-duo__title">
              <Bot aria-hidden />
              Ecommerce Agents
            </h3>
            <p className="h2-duo__panel-copy">
              Give AI agents and staff scoped credentials to run your store: limits, approvals,
              and an audit trail on every action.
            </p>
            <div className="h2-duo__visual">
              <div className="h2-chat" style={{ maxWidth: 360 }}>
                <div className="h2-chat__bubble">
                  <small>Seams Harness · 09:14</small>
                  Held: 12% discount for cart #8841 needs owner approval.
                </div>
                <div className="h2-chat__bubble h2-chat__bubble--reply">
                  Approved ✓ signed and sent
                </div>
              </div>
            </div>
            <span className="h2-duo__cta">
              Explore Ecommerce Agents
              <ArrowRightAnim size={13} />
            </span>
          </a>
        </div>
      </div>
    </section>
  );
}

type HomeFrameProps = {
  hero: React.JSX.Element;
};

function HomeFrame({ hero }: HomeFrameProps): React.JSX.Element {
  return (
    <div className="h2-page h2-page--zoom">
      <NavbarStatic appearance="light" />
      <div className="h2-col">
        {hero}
        <HomeTrusted />
        <HomeDuo />
        <H2Ecosystem />
        <H2Pillars />
        <H2Faq />
        <H2Footer />
      </div>
    </div>
  );
}

export function HomePage(): React.JSX.Element {
  return <HomeFrame hero={<HomeHeroCurrent />} />;
}

export function Home2Page(): React.JSX.Element {
  return <HomeFrame hero={<HomeHeroMedia />} />;
}

export default Home2Page;
