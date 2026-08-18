import React from 'react';
import { DashboardPage } from '@core/dashboard/page';
import { DashboardLoginPage } from '@core/dashboard/login/page';

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

export function App(): React.JSX.Element {
  const pathname = usePathname();

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
