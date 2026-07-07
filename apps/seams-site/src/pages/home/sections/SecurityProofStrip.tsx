import { useSiteRouter } from '@/app/router/useSiteRouter';
import {
  SecurityCustodyDiagram,
  SecurityDefenseDiagram,
  SecurityScaleDiagram,
  SecurityFrictionDiagram,
  type SecurityDiagramProps,
} from '@/components/SecurityDiagrams';
import './SecurityProofStrip.css';

type SecurityCard = {
  id: 'custody' | 'defense' | 'scale' | 'friction';
  label: string;
  detail: string;
  diagramAlt: string;
  Diagram: React.ElementType;
};

const securityCards: SecurityCard[] = [
  {
    id: 'custody',
    label: 'Non-custodial custody boundary',
    detail:
      'Signing authority is split between the user’s device and your infrastructure — neither can sign alone, and export always requires a fresh authorized flow.',
    diagramAlt: 'Wireframe cube over a perspective security grid',
    Diagram: SecurityCustodyDiagram,
  },
  {
    id: 'defense',
    label: 'Policy before execution',
    detail:
      'Approvals, mandates, revocation state, budgets, and replay checks run before signatures, payments, or API actions execute.',
    diagramAlt: 'Wireframe terrain peaks over a mesh grid',
    Diagram: SecurityDefenseDiagram,
  },
  {
    id: 'scale',
    label: 'Separation of duties',
    detail:
      'Key creation and everyday signing run in separately isolated services, so no single compromised service can mint or use keys.',
    diagramAlt: 'System workflow boxes connected across a horizontal graph',
    Diagram: SecurityScaleDiagram,
  },
  {
    id: 'friction',
    label: 'Step-up where it matters',
    detail:
      'Passkeys, Email OTP, VoiceID, and linked devices can gate sensitive exports, rotations, new recipients, and delegated permissions.',
    diagramAlt: 'Stacked secure device panels connected by policy rails',
    Diagram: SecurityFrictionDiagram,
  },
];

const securityDiagramThemeColors: Record<SecurityCard['id'], SecurityDiagramProps> = {
  custody: {
    glowColor: 'color-mix(in srgb, var(--site-brand) 64%, var(--site-accent) 36%)',
    nodeColor: 'color-mix(in srgb, var(--site-accent) 58%, var(--site-text-primary) 42%)',
    lineColor: 'color-mix(in srgb, var(--site-border) 44%, var(--site-brand) 56%)',
    canvasColor: 'color-mix(in srgb, var(--site-surface-strong) 76%, var(--site-canvas) 24%)',
  },
  defense: {
    glowColor: 'color-mix(in srgb, var(--site-brand-hover) 60%, var(--site-accent) 40%)',
    nodeColor: 'color-mix(in srgb, var(--site-accent) 54%, var(--site-text-primary) 46%)',
    lineColor: 'color-mix(in srgb, var(--site-border) 42%, var(--site-brand-hover) 58%)',
    canvasColor: 'color-mix(in srgb, var(--site-surface-strong) 74%, var(--site-canvas) 26%)',
  },
  scale: {
    glowColor: 'color-mix(in srgb, var(--site-accent) 58%, var(--site-brand) 42%)',
    nodeColor: 'color-mix(in srgb, var(--site-brand-hover) 56%, var(--site-text-primary) 44%)',
    lineColor: 'color-mix(in srgb, var(--site-text-primary) 82%, var(--site-brand) 18%)',
    canvasColor: 'color-mix(in srgb, var(--site-surface-strong) 72%, var(--site-canvas) 28%)',
  },
  friction: {
    glowColor: 'color-mix(in srgb, var(--site-brand) 70%, var(--site-brand-hover) 30%)',
    nodeColor: 'color-mix(in srgb, var(--site-brand-hover) 62%, var(--site-text-primary) 38%)',
    lineColor: 'color-mix(in srgb, var(--site-text-primary) 72%, var(--site-brand) 28%)',
    canvasColor: 'color-mix(in srgb, var(--site-surface-strong) 78%, var(--site-canvas) 22%)',
  },
};

export function SecurityProofStrip(): React.JSX.Element {
  const { linkProps } = useSiteRouter();
  const docsProps = linkProps('/docs/concepts/custody/');

  return (
    <section
      className="security-diagrams gradient-lilac-warm gradient-lilac-warm-corners"
      aria-labelledby="security-diagrams-title"
    >
      <header className="security-diagrams__header">
        <h2 id="security-diagrams-title" className="security-diagrams__title">
          Security boundaries built into the control plane.
        </h2>
        <p className="security-diagrams__subtitle">
          Custody, policy, session, and delegation checks are separate so broad app access cannot
          become signing authority.
        </p>
        <a
          className="security-diagrams__learn-more"
          href={docsProps.href}
          onClick={docsProps.onClick}
        >
          Learn more
          <span aria-hidden="true"> &rarr;</span>
        </a>
      </header>

      <div className="security-diagrams__grid">
        {securityCards.map((item) => (
          <article
            key={item.label}
            className={`security-diagrams__card security-diagrams__card--${item.id}`}
            aria-label={item.label}
          >
            <div className={`security-diagrams__art-wrap security-diagrams__art-wrap--${item.id}`}>
              <item.Diagram
                className="security-diagrams__art"
                alt={item.diagramAlt}
                {...securityDiagramThemeColors[item.id]}
              />
            </div>
            <div className="security-diagrams__body">
              <h3>{item.label}</h3>
              <p>{item.detail}</p>
            </div>
          </article>
        ))}
      </div>
    </section>
  );
}

export default SecurityProofStrip;
