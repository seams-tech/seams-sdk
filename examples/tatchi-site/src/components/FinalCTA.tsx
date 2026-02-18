import { ArrowRight } from 'lucide-react'
import Github from './icons/Github'
import { ArrowRightAnim } from './ArrowRightAnim'
import { useSiteRouter } from '../hooks/useSiteRouter'

export function FinalCTA(): React.JSX.Element {
  const { linkProps } = useSiteRouter()
  const getStartedProps = linkProps('/docs/getting-started/installation')
  const contactProps = linkProps('/contact/')

  return (
    <section className="final-cta gradient-lilac-warm-drift gradient-lilac-warm-drift-overlay" aria-labelledby="final-cta-title">
      <div className="final-cta__content">
        <p className="final-cta__eyebrow">Start your evaluation</p>
        <h2 id="final-cta-title" className="final-cta__title">Ship embedded wallet UX with clear security boundaries</h2>
        <p className="final-cta__description">
          Pick a self-serve path for integration or start a sales conversation for architecture and rollout planning.
        </p>
      </div>
      <div className="final-cta__actions">
        <a className="final-cta__button final-cta__button--solid" href={getStartedProps.href} onClick={getStartedProps.onClick}>
          <span>Get Started</span>
          <ArrowRightAnim size={16} />
        </a>
        <a className="final-cta__button final-cta__button--outline" href={contactProps.href} onClick={contactProps.onClick}>
          <span>Contact Sales</span>
          <ArrowRightAnim size={16} />
        </a>
        <a
          className="final-cta__button final-cta__button--ghost"
          href="https://github.com/web3-authn/tatchi"
          target="_blank"
          rel="noopener noreferrer"
        >
          <Github size={16} aria-hidden />
          <span>GitHub</span>
          <ArrowRight size={16} aria-hidden />
        </a>
      </div>
    </section>
  )
}

export default FinalCTA
