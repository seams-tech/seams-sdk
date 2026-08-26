import React from 'react';
import { useTheme } from '@seams/wallet/react';

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

const HomePage = React.lazy(() =>
  import('@/pages/home2/page').then((module) => ({ default: module.HomePage })),
);
const Home2Page = React.lazy(() =>
  import('@/pages/home2/page').then((module) => ({ default: module.Home2Page })),
);
const WalletPage = React.lazy(() =>
  import('@/pages/wallet/page').then((module) => ({ default: module.WalletPage })),
);
const EcommercePage = React.lazy(() =>
  import('@/pages/ecommerce/page').then((module) => ({ default: module.EcommercePage })),
);
const PricingPage = React.lazy(() =>
  import('@/pages/pricing/page').then((module) => ({ default: module.PricingPage })),
);
const CompanyPage = React.lazy(() =>
  import('@/pages/company/page').then((module) => ({ default: module.CompanyPage })),
);
const ContactPage = React.lazy(() =>
  import('@/pages/contact/page').then((module) => ({ default: module.ContactPage })),
);
const IntendedBehaviourE2EPage = React.lazy(() =>
  import('@/pages/intended-e2e/page').then((module) => ({
    default: module.IntendedBehaviourE2EPage,
  })),
);
const NearLoginPage = React.lazy(() =>
  import('@/pages/near-login/page').then((module) => ({ default: module.NearLoginPage })),
);
const NotFoundPage = React.lazy(() =>
  import('@/pages/not-found/page').then((module) => ({ default: module.NotFoundPage })),
);

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
      case '/__intended-e2e':
        return FRONTEND_CONFIG.enableIntendedE2E ? <IntendedBehaviourE2EPage /> : <NotFoundPage />;
      default:
        return <NotFoundPage />;
    }
  }, [pathname]);

  if (pathname === '/near-login') {
    return (
      <React.Suspense fallback={null}>
        <NearLoginPage />
        <ToasterThemed />
      </React.Suspense>
    );
  }

  const sdkNetwork = 'testnet';

  return (
    <FrontendSdkProvider
      eager
      network={sdkNetwork}
      appearance={SITE_APPEARANCE}
      theme={{ theme, tokens: SITE_THEME_TOKEN_OVERRIDES }}
    >
      <DocumentThemeTokenBridge />
      <React.Suspense fallback={null}>{page}</React.Suspense>
      <VitepressStateSync />
      <ToasterThemed />
    </FrontendSdkProvider>
  );
};

export default App;
