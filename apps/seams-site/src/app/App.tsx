import React from 'react';
import { SeamsWebProvider } from '@seams/sdk/react/provider';
import { useTheme } from '@seams/sdk/react';

import { Home2Page, HomePage } from '@/pages/home2/page';
import { WalletPage } from '@/pages/wallet/page';
import { EcommercePage } from '@/pages/ecommerce/page';
import { PricingPage } from '@/pages/pricing/page';
import { CompanyPage } from '@/pages/company/page';
import { ContactPage } from '@/pages/contact/page';
import { DashboardPage } from '@/pages/dashboard/page';
import { DashboardLoginPage } from '@/pages/dashboard/login/page';
import { IntendedBehaviourE2EPage } from '@/pages/intended-e2e/page';
import { NearLoginPage } from '@/pages/near-login/page';
import { NotFoundPage } from '@/pages/not-found/page';
import { ToasterThemed } from '@/components/ToasterThemed';
import { useSiteTheme } from '@/shared/hooks/useSiteTheme';
import { useBodyLoginStateBridge } from '@/shared/hooks/useBodyLoginStateBridge';
import { useExportKeyCancelToast } from '@/shared/hooks/useExportKeyCancelToast';
import { normalizePathname } from '@/app/router/siteRouting';
import { SITE_APPEARANCE, SITE_THEME_TOKEN_OVERRIDES } from '@/context/siteThemeOverrides';
import { FRONTEND_CONFIG } from '@/config';

type ThemeTokens = ReturnType<typeof useTheme>['tokens'];

const INTENDED_E2E_ECDSA_PRESIGNATURE_POOL = {
  enabled: true,
  targetDepth: 1,
  lowWatermark: 0,
  maxRefillInFlight: 1,
  refillAttemptTimeoutMs: 30_000,
} as const;

function tokensToCssVars(tokens: ThemeTokens): Record<string, string> {
  const vars: Record<string, string> = {};
  Object.entries(tokens.colors).forEach(([key, value]) => {
    vars[`--w3a-colors-${key}`] = String(value);
  });
  Object.entries(tokens.spacing).forEach(([key, value]) => {
    vars[`--w3a-spacing-${key}`] = String(value);
  });
  Object.entries(tokens.borderRadius).forEach(([key, value]) => {
    vars[`--w3a-border-radius-${key}`] = String(value);
  });
  Object.entries(tokens.shadows).forEach(([key, value]) => {
    vars[`--w3a-shadows-${key}`] = String(value);
  });
  return vars;
}

const DocumentThemeTokenBridge: React.FC = () => {
  const { theme, tokens } = useTheme();
  const vars = React.useMemo(() => tokensToCssVars(tokens), [tokens]);

  React.useEffect(() => {
    if (typeof document === 'undefined') return;
    const root = document.documentElement;
    root.setAttribute('data-w3a-theme', theme);
    Object.entries(vars).forEach(([name, value]) => {
      root.style.setProperty(name, value);
    });
  }, [theme, vars]);

  return null;
};

function usePathname(): string {
  const read = React.useCallback(() => {
    if (typeof window === 'undefined') return '/';
    return normalizePathname(window.location.pathname);
  }, []);
  const [pathname, setPathname] = React.useState<string>(read);

  React.useEffect(() => {
    const onChange = () => setPathname(read());
    window.addEventListener('popstate', onChange);
    window.addEventListener('site:navigate', onChange as EventListener);
    return () => {
      window.removeEventListener('popstate', onChange);
      window.removeEventListener('site:navigate', onChange as EventListener);
    };
  }, [read]);

  return pathname;
}

export const App: React.FC = () => {
  const { theme, setTheme } = useSiteTheme();
  const pathname = usePathname();
  const signingSessionPersistenceMode = FRONTEND_CONFIG.signingSessionPersistenceMode;
  const signingSessionSealShamirPrimeB64u = FRONTEND_CONFIG.signingSessionSealShamirPrimeB64u;
  const signingSessionSealKeyVersion = FRONTEND_CONFIG.signingSessionSealKeyVersion;

  const VitepressStateSync: React.FC = () => {
    useBodyLoginStateBridge();
    useExportKeyCancelToast();
    return null;
  };

  const page = React.useMemo(() => {
    switch (pathname) {
      case '/':
        return <HomePage />;
      case '/home2':
        return <Home2Page />;
      case '/wallet':
        return <WalletPage />;
      case '/ecommerce':
        return <EcommercePage />;
      case '/pricing':
        return <PricingPage />;
      case '/company':
        return <CompanyPage />;
      case '/contact':
        return <ContactPage />;
      case '/dashboard/login':
        return <DashboardLoginPage />;
      case '/__intended-e2e':
        return FRONTEND_CONFIG.enableIntendedE2E ? <IntendedBehaviourE2EPage /> : <NotFoundPage />;
      default:
        if (
          pathname === '/dashboard' ||
          pathname.startsWith('/dashboard/') ||
          pathname.startsWith('/platform/')
        ) {
          return <DashboardPage pathname={pathname} />;
        }
        return <NotFoundPage />;
    }
  }, [pathname]);

  if (pathname === '/near-login') {
    return (
      <>
        <NearLoginPage />
        <ToasterThemed />
      </>
    );
  }

  return (
    <SeamsWebProvider
      eager
      theme={{ theme, setTheme, tokens: SITE_THEME_TOKEN_OVERRIDES }}
      config={{
        appearance: SITE_APPEARANCE,
        iframeWallet: {
          walletOrigin: FRONTEND_CONFIG.walletOrigin,
          walletServicePath: FRONTEND_CONFIG.walletServicePath,
          rpIdOverride: FRONTEND_CONFIG.rpIdBase,
          sdkBasePath: FRONTEND_CONFIG.sdkBasePath,
        },
        signingSessionDefaults: {
          ttlMs: FRONTEND_CONFIG.signingSessionDefaults.ttlMs,
          remainingUses: FRONTEND_CONFIG.signingSessionDefaults.remainingUses,
        },
        signingSessionPersistenceMode,
        ...(signingSessionPersistenceMode === 'sealed_refresh_v1'
          ? {
              signingSessionSeal: {
                ...(signingSessionSealKeyVersion
                  ? { keyVersion: signingSessionSealKeyVersion }
                  : {}),
                ...(signingSessionSealShamirPrimeB64u
                  ? { shamirPrimeB64u: signingSessionSealShamirPrimeB64u }
                  : {}),
              },
            }
          : {}),
        ...(FRONTEND_CONFIG.routerAb ? { routerAb: FRONTEND_CONFIG.routerAb } : {}),
        ...(FRONTEND_CONFIG.enableIntendedE2E
          ? { routerAbEcdsaHssPresignaturePool: INTENDED_E2E_ECDSA_PRESIGNATURE_POOL }
          : {}),
        chains: FRONTEND_CONFIG.chains,
        relayer: {
          url: FRONTEND_CONFIG.relayerUrl!,
        },
        ...(FRONTEND_CONFIG.managedRegistration
          ? {
              registration: FRONTEND_CONFIG.managedRegistration,
            }
          : {}),
      }}
    >
      <DocumentThemeTokenBridge />
      {page}
      <VitepressStateSync />
      <ToasterThemed />
    </SeamsWebProvider>
  );
};

export default App;
