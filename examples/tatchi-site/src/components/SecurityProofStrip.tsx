import { useSiteRouter } from '../hooks/useSiteRouter'
import {
  SecurityCustodyDiagram,
  SecurityDefenseDiagram,
  SecurityScaleDiagram,
  SecurityFrictionDiagram,
} from './SecurityDiagrams'

type SecurityCard = {
  id: 'custody' | 'defense' | 'scale' | 'friction'
  label: string
  detail: string
  diagramAlt: string
  Diagram: React.ElementType
}

const securityCards: SecurityCard[] = [
  {
    id: 'custody',
    label: 'Hardware-isolated self custody',
    detail: 'Keys are sharded, end-to-end encrypted, and distributed across isolated services. Wallets are only reconstructed in secure hardware environments.',
    diagramAlt: 'Wireframe cube over a perspective security grid',
    Diagram: SecurityCustodyDiagram,
  },
  {
    id: 'defense',
    label: 'Defense in depth',
    detail: 'Secure enclaves protect keys, encrypted networks safeguard data, and RBAC with micro-segmentation enforces least privilege.',
    diagramAlt: 'Wireframe terrain peaks over a mesh grid',
    Diagram: SecurityDefenseDiagram,
  },
  {
    id: 'scale',
    label: 'Battle-tested at scale',
    detail: 'Core cryptography libraries are widely used and audited, with resilient orchestration paths built for high-throughput transaction pipelines.',
    diagramAlt: 'System workflow boxes connected across a horizontal graph',
    Diagram: SecurityScaleDiagram,
  },
  {
    id: 'friction',
    label: 'Friction where it matters',
    detail: 'Add defenses like passkey signing, wallet policies, and transaction MFA without breaking checkout and core product flows.',
    diagramAlt: 'Stacked secure device panels connected by policy rails',
    Diagram: SecurityFrictionDiagram,
  },
]

const frictionDiagramThemeColors = {
  glowColor: 'color-mix(in srgb, var(--site-brand) 70%, var(--site-brand-hover) 30%)',
  nodeColor: 'color-mix(in srgb, var(--site-brand-hover) 62%, var(--site-text-primary) 38%)',
  lineColor: 'color-mix(in srgb, var(--site-border) 36%, transparent)',
  canvasColor: 'color-mix(in srgb, var(--site-surface-strong) 78%, var(--site-canvas) 22%)',
}

export function SecurityProofStrip(): React.JSX.Element {
  const { linkProps } = useSiteRouter()
  const docsProps = linkProps('/docs/concepts/security-model')

  return (
    <section className="security-diagrams gradient-lilac-warm gradient-lilac-warm-corners" aria-labelledby="security-diagrams-title">
      <header className="security-diagrams__header">
        <h2 id="security-diagrams-title" className="security-diagrams__title">Enterprise-grade security.</h2>
        <p className="security-diagrams__subtitle">
          Security is the backbone across architecture and workflows. All engineering is security engineering.
        </p>
        <a className="security-diagrams__learn-more" href={docsProps.href} onClick={docsProps.onClick}>
          Learn more
          <span aria-hidden="true"> &rarr;</span>
        </a>
      </header>

      <div className="security-diagrams__grid">
        {securityCards.map((item) => (
          <article key={item.label} className={`security-diagrams__card security-diagrams__card--${item.id}`} aria-label={item.label}>
            <div className={`security-diagrams__art-wrap security-diagrams__art-wrap--${item.id}`}>
              <item.Diagram
                className="security-diagrams__art"
                alt={item.diagramAlt}
                {...(item.id === 'friction' ? frictionDiagramThemeColors : {})}
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
  )
}

export default SecurityProofStrip
