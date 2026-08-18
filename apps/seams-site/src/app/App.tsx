import React from 'react';
import { useTheme } from '@seams/wallet/react';

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
import {
  FrontendRuntimeProvider,
  FrontendSdkProvider,
  useFrontendRuntime,
} from '@/context/frontendRuntime';

type ThemeTokens = ReturnType<typeof useTheme>['tokens'];

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
    root.classList.remove('dark');
    root.setAttribute('data-w3a-theme', theme);
    document.body.setAttribute('data-w3a-theme', theme);
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
  return (
    <FrontendRuntimeProvider>
      <AppRuntimeBoundary />
    </FrontendRuntimeProvider>
  );
};

const AppRuntimeBoundary: React.FC = () => {
  const { theme } = useSiteTheme();
  const pathname = usePathname();
  const runtime = useFrontendRuntime();

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

  const dashboardRoute =
    pathname === '/dashboard/login' ||
    pathname === '/dashboard' ||
    pathname.startsWith('/dashboard/') ||
    pathname.startsWith('/platform/');
  const sdkNetwork = dashboardRoute ? runtime.selectedNetwork : 'testnet';

  return (
    <FrontendSdkProvider
      eager
      network={sdkNetwork}
      appearance={SITE_APPEARANCE}
      theme={{ theme, tokens: SITE_THEME_TOKEN_OVERRIDES }}
    >
      <DocumentThemeTokenBridge />
      {page}
      <VitepressStateSync />
      <ToasterThemed />
    </FrontendSdkProvider>
  );
};

export default App;
