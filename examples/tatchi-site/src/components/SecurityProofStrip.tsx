import { useSiteRouter } from '../hooks/useSiteRouter'

type SecurityCard = {
  label: string
  detail: string
  diagramDarkSrc: string
  diagramLightSrc: string
  diagramAlt: string
}

const securityCards: SecurityCard[] = [
  {
    label: 'Hardware-isolated self custody',
    detail: 'Keys are sharded, end-to-end encrypted, and distributed across isolated services. Wallets are only reconstructed in secure hardware environments.',
    diagramDarkSrc: '/diagrams/security-custody-dark.png',
    diagramLightSrc: '/diagrams/security-custody-light.png',
    diagramAlt: 'Wireframe cube over a perspective security grid',
  },
  {
    label: 'Defense in depth',
    detail: 'Secure enclaves protect keys, encrypted networks safeguard data, and RBAC with micro-segmentation enforces least privilege.',
    diagramDarkSrc: '/diagrams/security-defense-dark.png',
    diagramLightSrc: '/diagrams/security-defense-light.png',
    diagramAlt: 'Wireframe terrain peaks over a mesh grid',
  },
  {
    label: 'Battle-tested at scale',
    detail: 'Core cryptography libraries are widely used and audited, with resilient orchestration paths built for high-throughput transaction pipelines.',
    diagramDarkSrc: '/diagrams/security-scale-dark.png',
    diagramLightSrc: '/diagrams/security-scale-light.png',
    diagramAlt: 'System workflow boxes connected across a horizontal graph',
  },
  {
    label: 'Friction where it matters',
    detail: 'Add defenses like passkey signing, wallet policies, and transaction MFA without breaking checkout and core product flows.',
    diagramDarkSrc: '/diagrams/security-friction-dark.png',
    diagramLightSrc: '/diagrams/security-friction-light.png',
    diagramAlt: 'Stacked secure device panels connected by policy rails',
  },
]

export function SecurityProofStrip(): React.JSX.Element {
  const { linkProps } = useSiteRouter()
  const docsProps = linkProps('/docs/concepts/security-model')

  return (
    <section className="security-diagrams" aria-labelledby="security-diagrams-title">
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
          <article key={item.label} className="security-diagrams__card" aria-label={item.label}>
            <div className="security-diagrams__art-wrap">
              <img
                className="security-diagrams__art security-diagrams__art--dark"
                src={item.diagramDarkSrc}
                alt={item.diagramAlt}
                loading="lazy"
              />
              <img
                className="security-diagrams__art security-diagrams__art--light"
                src={item.diagramLightSrc}
                alt=""
                aria-hidden="true"
                loading="lazy"
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
