import React from 'react';
import { TatchiPasskeyProvider } from '@tatchi-xyz/sdk/react/provider';

import { HomePage } from './pages/HomePage';
import { ProductsPage } from './pages/ProductsPage';
import { SolutionsPage } from './pages/SolutionsPage';
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

function usePathname(): string {
  const read = React.useCallback(() => {
    if (typeof window === 'undefined') return '/'
    return normalizePathname(window.location.pathname)
  }, [])
  const [pathname, setPathname] = React.useState<string>(read)

  React.useEffect(() => {
    const onChange = () => setPathname(read())
    window.addEventListener('popstate', onChange)
    window.addEventListener('site:navigate', onChange as EventListener)
    return () => {
      window.removeEventListener('popstate', onChange)
      window.removeEventListener('site:navigate', onChange as EventListener)
    }
  }, [read])

  return pathname
}

export const App: React.FC = () => {
  const env = import.meta.env;
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
        return <HomePage />
      case '/products':
        return <ProductsPage />
      case '/solutions':
        return <SolutionsPage />
      case '/pricing':
        return <PricingPage />
      case '/company':
        return <CompanyPage />
      case '/contact':
        return <ContactPage />
      case '/dashboard':
        return <DashboardPage />
      default:
        return <NotFoundPage />
    }
  }, [pathname])

  return (
    <TatchiPasskeyProvider
      theme={{ theme, setTheme }}
      config={{
        iframeWallet: {
          walletOrigin: env.VITE_WALLET_ORIGIN,
          walletServicePath: env.VITE_WALLET_SERVICE_PATH,
          rpIdOverride: env.VITE_RP_ID_BASE,
          sdkBasePath: env.VITE_SDK_BASE_PATH,
        },
        // Demo default: require threshold signing for NEAR actions in docs flows
        signerMode: {
          mode: 'threshold-signer',
          behavior: 'strict',
        },
        nearRpcUrl: env.VITE_NEAR_RPC_URL || 'https://test.rpc.fastnear.com',
        relayer: {
          url: env.VITE_RELAYER_URL!,
        },
      }}
    >
      {page}
      <VitepressStateSync />
      <ToasterThemed />
    </TatchiPasskeyProvider>
  );
};

export default App;
