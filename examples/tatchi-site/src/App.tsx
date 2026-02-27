import React from 'react';
import { TatchiPasskeyProvider } from '@tatchi-xyz/sdk/react/provider';
import { useTheme } from '@tatchi-xyz/sdk/react';
import type { DesignTokens } from '@tatchi-xyz/sdk/react';

import { HomePage } from './pages/HomePage';
import { PricingPage } from './pages/PricingPage';
import { CompanyPage } from './pages/CompanyPage';
import { ContactPage } from './pages/ContactPage';
import { DashboardPage } from './pages/DashboardPage';
import { NotFoundPage } from './pages/NotFoundPage';
import { ToasterThemed } from './components/ToasterThemed';
import { useSiteTheme } from './hooks/useSiteTheme';
import { useBodyLoginStateBridge } from './hooks/useBodyLoginStateBridge';
import { useExportKeyCancelToast } from './hooks/useExportKeyCancelToast';
import { normalizePathname } from './utils/siteRouting';
import { SITE_APPEARANCE, SITE_THEME_TOKEN_OVERRIDES } from './theme/siteThemeOverrides';
import { FRONTEND_CONFIG } from './config';

function tokensToCssVars(tokens: DesignTokens): Record<string, string> {
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

  const VitepressStateSync: React.FC = () => {
    useBodyLoginStateBridge();
    useExportKeyCancelToast();
    return null;
  };

  const page = React.useMemo(() => {
    switch (pathname) {
      case '/':
        return <HomePage />;
      case '/pricing':
        return <PricingPage />;
      case '/company':
        return <CompanyPage />;
      case '/contact':
        return <ContactPage />;
      default:
        if (pathname === '/dashboard' || pathname.startsWith('/dashboard/')) {
          return <DashboardPage pathname={pathname} />;
        }
        return <NotFoundPage />;
    }
  }, [pathname]);

  return (
    <TatchiPasskeyProvider
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
        // Demo default: require threshold signing for NEAR actions in docs flows
        signerMode: {
          mode: 'threshold-signer',
          behavior: 'strict',
        },
        signingSessionDefaults: {
          ttlMs: FRONTEND_CONFIG.signingSessionDefaults.ttlMs,
          remainingUses: FRONTEND_CONFIG.signingSessionDefaults.remainingUses,
        },
        chains: FRONTEND_CONFIG.chains,
        relayer: {
          url: FRONTEND_CONFIG.relayerUrl!,
        },
      }}
    >
      <DocumentThemeTokenBridge />
      {page}
      <VitepressStateSync />
      <ToasterThemed />
    </TatchiPasskeyProvider>
  );
};

export default App;
