import { useState } from 'react';
import CopyButton from '@/components/CopyButton';
import { ArrowRightAnim } from '@/components/ArrowRightAnim';
import SeamsLogo from '@/components/icons/SeamsLogo';
import { useSiteRouter } from '@/app/router/useSiteRouter';
import { mobilePressHandlers } from '@/shared/utils/press';

type PackageManager = 'npm' | 'pnpm' | 'bun';

function getInstallCommand(packageManager: PackageManager): string {
  switch (packageManager) {
    case 'npm':
      return 'npm install @seams/sdk';
    case 'pnpm':
      return 'pnpm add @seams/sdk';
    case 'bun':
      return 'bun add @seams/sdk';
    default: {
      const exhaustive: never = packageManager;
      throw new Error(`Unsupported package manager: ${exhaustive}`);
    }
  }
}

function highlightInstallCommand(command: string): string {
  return command
    .replace(/^(npm|pnpm|bun)/, '<span class="code-kw-pm">$1</span>')
    .replace(/(@seams\/sdk)/, '<span class="code-kw-pkg">$1</span>');
}

export function HomeHero(): React.JSX.Element {
  const [packageManager, setPackageManager] = useState<PackageManager>('npm');
  const { linkProps } = useSiteRouter();

  const installBlockCmd = getInstallCommand(packageManager);
  const highlightedInstall = highlightInstallCommand(installBlockCmd);
  const getStartedProps = linkProps('/docs/getting-started/installation');
  const contactSalesProps = linkProps('/contact/');

  return (
    <>
      <section className="hero" aria-labelledby="hero-title">
        <h1 id="hero-title" className="hero-title">
          <span className="hero-title-text">Simple Embedded Wallets, Secured by Passkeys + MPC</span>
          <span className="hero-title-brand-mark" aria-hidden="true">
            <SeamsLogo variant="transparent-mark" size={148} />
          </span>
        </h1>
        <h2 className="hero-subtitle">
          Use biometrics and passkeys for human verification, with embedded wallets that integrate
          directly into your existing app.
        </h2>
        <p className="hero-description">
          Ship on web today and iOS soon, with threshold-signature (MPC) sessions for secure signing
          across NEAR, Tempo, and EVM.
        </p>
        <p className="hero-proof">
          No lock-in by design: start hosted, then migrate to self-hosted wallet infrastructure when
          you are ready.
        </p>
        <div className="hero-ctas">
          <a
            className="cta-button cta-primary cta-3"
            href={getStartedProps.href}
            onClick={getStartedProps.onClick}
            aria-label="Get started with Seams documentation"
          >
            <span>Get Started</span>
            <ArrowRightAnim size={16} />
          </a>
          <a
            className="cta-button cta-secondary cta-3"
            href={contactSalesProps.href}
            onClick={contactSalesProps.onClick}
            aria-label="Contact sales"
          >
            <span>Contact Sales</span>
            <ArrowRightAnim size={16} />
          </a>
        </div>
      </section>

      <section className="hero-intro" aria-label="Install the SDK">
        <div className="install-panel" role="group" aria-label="Install command (CLI)">
          <div className="install-header">
            <div className="install-header-left">
              <div className="install-tabs" role="tablist" aria-label="Package managers (CLI)">
                {(['npm', 'pnpm', 'bun'] as const).map((k) => (
                  <button
                    key={k}
                    role="tab"
                    aria-selected={packageManager === k}
                    className={`install-tab${packageManager === k ? ' active' : ''}`}
                    {...mobilePressHandlers(() => setPackageManager(k))}
                  >
                    {k}
                  </button>
                ))}
              </div>
            </div>
            <CopyButton text={installBlockCmd} size={16} ariaLabel="Copy install command" />
          </div>
          <div className="install-body">
            <pre className="code-block code-block--dark">
              <code dangerouslySetInnerHTML={{ __html: highlightedInstall }} />
            </pre>
          </div>
        </div>
      </section>
    </>
  );
}
