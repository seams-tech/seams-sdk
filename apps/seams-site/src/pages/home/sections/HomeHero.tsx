import { useState } from 'react';
import CopyButton from '@/components/CopyButton';
import { ArrowRightAnim } from '@/components/ArrowRightAnim';
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
  const getStartedProps = linkProps('/docs/concepts/');
  const contactSalesProps = linkProps('/contact/');

  return (
    <>
      <section className="hero" aria-labelledby="hero-title">
        <h1 id="hero-title" className="hero-title">
          <span className="hero-title-text">Embedded wallets with policy-enforced signing</span>
        </h1>
        <h2 className="hero-subtitle">
          Authenticate users, devices, and AI agents. Every signature, payment, and API call is
          checked against your policy before it executes.
        </h2>
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
        <p className="hero-proof">
          Non-custodial by design: keys are split between the user&rsquo;s device and your
          infrastructure &mdash; neither can sign alone.
        </p>
      </section>
    </>
  );
}
