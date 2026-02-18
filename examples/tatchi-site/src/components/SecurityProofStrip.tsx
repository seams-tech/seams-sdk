import { useSiteRouter } from '../hooks/useSiteRouter'
import { ThemedSecuritySvg } from './ThemedSecuritySvg'

type SecurityCard = {
  id: 'custody' | 'defense' | 'scale' | 'friction'
  label: string
  detail: string
  diagramSrc: string
  diagramAlt: string
}

const securityCards: SecurityCard[] = [
  {
    id: 'custody',
    label: 'Hardware-isolated self custody',
    detail: 'Keys are sharded, end-to-end encrypted, and distributed across isolated services. Wallets are only reconstructed in secure hardware environments.',
    diagramSrc: '/diagrams/security-custody.svg',
    diagramAlt: 'Wireframe cube over a perspective security grid',
  },
  {
    id: 'defense',
    label: 'Defense in depth',
    detail: 'Secure enclaves protect keys, encrypted networks safeguard data, and RBAC with micro-segmentation enforces least privilege.',
    diagramSrc: '/diagrams/security-defense.svg',
    diagramAlt: 'Wireframe terrain peaks over a mesh grid',
  },
  {
    id: 'scale',
    label: 'Battle-tested at scale',
    detail: 'Core cryptography libraries are widely used and audited, with resilient orchestration paths built for high-throughput transaction pipelines.',
    diagramSrc: '/diagrams/security-scale.svg',
    diagramAlt: 'System workflow boxes connected across a horizontal graph',
  },
  {
    id: 'friction',
    label: 'Friction where it matters',
    detail: 'Add defenses like passkey signing, wallet policies, and transaction MFA without breaking checkout and core product flows.',
    diagramSrc: '/diagrams/security-friction.svg',
    diagramAlt: 'Stacked secure device panels connected by policy rails',
  },
]

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
              <ThemedSecuritySvg
                className="security-diagrams__art"
                src={item.diagramSrc}
                alt={item.diagramAlt}
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
