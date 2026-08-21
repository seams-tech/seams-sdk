import React from 'react';
import { DashboardPage } from '@core/dashboard/page';
import { DashboardLoginPage } from '@core/dashboard/login/page';
import { DashboardToaster } from '@core/dashboard/components/DashboardToaster';

// Static composition of the customer Console: core routes plus the Wallet
// Console route group registered in dashboardConfig. No SeamsWebProvider,
// no Wallet theme bridge — the Console owns its shell.
function usePathname(): string {
  const [pathname, setPathname] = React.useState(() =>
    typeof window === 'undefined' ? '/' : window.location.pathname,
  );
  React.useEffect(() => {
    const onNavigate = () => setPathname(window.location.pathname);
    window.addEventListener('popstate', onNavigate);
    window.addEventListener('site:navigate', onNavigate);
    return () => {
      window.removeEventListener('popstate', onNavigate);
      window.removeEventListener('site:navigate', onNavigate);
    };
  }, []);
  return pathname;
}

function AppRoute({ pathname }: { pathname: string }): React.JSX.Element {
  if (pathname === '/dashboard/login') {
    return <DashboardLoginPage />;
  }
  if (
    pathname === '/dashboard' ||
    pathname.startsWith('/dashboard/') ||
    pathname.startsWith('/platform/')
  ) {
    return <DashboardPage pathname={pathname} />;
  }
  if (typeof window !== 'undefined') {
    window.location.replace('/dashboard/overview');
  }
  return <></>;
}

export function App(): React.JSX.Element {
  const pathname = usePathname();
  return (
    <>
      <AppRoute pathname={pathname} />
      <DashboardToaster />
    </>
  );
}
