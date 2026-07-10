import React from 'react';
import NavbarProfileOverlay from './Navbar/NavbarProfileOverlay';
import { preloadSeamsAuthMenu, useSeams, useTheme, type AuthMenuMode } from '@seams/sdk/react';

import { GlassBorder } from './GlassBorder';
import { CarouselProvider } from './Carousel/CarouselProvider';
import { Carousel } from './Carousel/Carousel';

// Lazily load the most common flows to shrink the initial bundle.
const PasskeyLoginMenu = React.lazy(() =>
  import('@/flows/demo/PasskeyLoginMenu').then((m) => ({ default: m.PasskeyLoginMenu })),
);
const DemoPage = React.lazy(() =>
  import('@/flows/demo/DemoPage').then((m) => ({ default: m.DemoPage })),
);
const SyncAccount = React.lazy(() =>
  import('@/flows/demo/SyncAccount').then((m) => ({ default: m.SyncAccount })),
);
import { AuthMenuControlProvider } from '@/context/AuthMenuControl';
import { ProfileMenuControlProvider } from '@/context/ProfileMenuControl';

type DemoToastThemeVar = (typeof DEMO_TOAST_THEME_VARS)[number];
type DemoThemeTokens = ReturnType<typeof useTheme>['tokens'];

const DEMO_TOAST_THEME_ATTR = 'data-site-toast-theme';
const DEMO_TOAST_THEME_VARS = [
  '--site-toast-background',
  '--site-toast-border',
  '--site-toast-text-primary',
  '--site-toast-text-secondary',
  '--site-toast-link',
  '--site-toast-icon',
  '--site-toast-success',
  '--site-toast-info',
  '--site-toast-warning',
  '--site-toast-error',
  '--site-toast-close-bg',
  '--site-toast-close-hover-bg',
  '--site-toast-shadow',
] as const;

function demoToastThemeVars(
  theme: 'light' | 'dark',
  tokens: DemoThemeTokens,
): Record<DemoToastThemeVar, string> {
  const colors = tokens.colors;
  return {
    '--site-toast-background': colors.surface,
    '--site-toast-border': colors.borderPrimary,
    '--site-toast-text-primary': colors.textPrimary,
    '--site-toast-text-secondary': colors.textSecondary,
    '--site-toast-link': colors.primary,
    '--site-toast-icon': colors.textSecondary,
    '--site-toast-success': colors.success,
    '--site-toast-info': colors.info,
    '--site-toast-warning': colors.warning,
    '--site-toast-error': colors.error,
    '--site-toast-close-bg': colors.surface2,
    '--site-toast-close-hover-bg': colors.surface3,
    '--site-toast-shadow':
      theme === 'dark'
        ? '0 16px 40px -24px rgba(0, 0, 0, 0.88)'
        : '0 16px 40px -24px rgba(15, 23, 42, 0.28)',
  };
}

function applyDemoToastTheme(theme: 'light' | 'dark', tokens: DemoThemeTokens): void {
  if (typeof document === 'undefined') return;
  const root = document.documentElement;
  const vars = demoToastThemeVars(theme, tokens);
  root.setAttribute(DEMO_TOAST_THEME_ATTR, theme);
  DEMO_TOAST_THEME_VARS.forEach((name) => {
    root.style.setProperty(name, vars[name]);
  });
}

function clearDemoToastTheme(): void {
  if (typeof document === 'undefined') return;
  const root = document.documentElement;
  root.removeAttribute(DEMO_TOAST_THEME_ATTR);
  DEMO_TOAST_THEME_VARS.forEach((name) => {
    root.style.removeProperty(name);
  });
}

function DemoToastThemeBridge(): null {
  const { theme, tokens } = useTheme();
  React.useEffect(() => {
    applyDemoToastTheme(theme, tokens);
    return clearDemoToastTheme;
  }, [theme, tokens]);
  return null;
}

export type DemoPasskeyColumnProps = {
  /** Controlled page index — pass with onCurrentPageChange to drive the carousel externally. */
  currentPage?: number;
  onCurrentPageChange?: (page: number) => void;
  defaultModeWhenNoDetectedAccount?: AuthMenuMode;
};

export function DemoPasskeyColumn({
  currentPage: controlledPage,
  onCurrentPageChange,
  defaultModeWhenNoDetectedAccount,
}: DemoPasskeyColumnProps = {}) {
  const { loginState } = useSeams();
  const [internalPage, setInternalPage] = React.useState(0);
  const currentPage = controlledPage ?? internalPage;
  const setCurrentPage = React.useCallback(
    (page: number) => {
      setInternalPage(page);
      onCurrentPageChange?.(page);
    },
    [onCurrentPageChange],
  );
  const prefetchPasskeyMenu = React.useCallback(() => {
    void preloadSeamsAuthMenu().catch(() => {});
  }, []);

  // After unlock, jump to Demo Tx page (index 1). On lock, go back to login page (index 0).
  React.useEffect(() => {
    setCurrentPage(loginState?.isLoggedIn ? 1 : 0);
  }, [loginState?.isLoggedIn, setCurrentPage]);

  const pages = React.useMemo(
    () => [
      {
        key: 'demo-auth',
        title: 'Login',
        element: () => (
          <>
            <PrefetchOnIntent onIntent={prefetchPasskeyMenu}>
              <React.Suspense fallback={<SuspenseFallback />}>
                <PasskeyLoginMenu
                  defaultModeWhenNoDetectedAccount={defaultModeWhenNoDetectedAccount}
                />
              </React.Suspense>
            </PrefetchOnIntent>
          </>
        ),
      },
      {
        key: 'transactions',
        title: 'Transactions',
        disabled: !loginState?.isLoggedIn,
        element: () => (
          <>
            <GlassBorder
              className="demo-transaction-shell"
              /* fixed width: content-sized width made the card snap wider when
                 the testnet-setup expander revealed its long address row */
              style={{ width: 'min(480px, calc(100vw - 2rem))', marginTop: '1rem' }}
            >
              <React.Suspense fallback={<SuspenseFallback />}>
                <DemoPage />
              </React.Suspense>
            </GlassBorder>
          </>
        ),
      },
      {
        key: 'sync-account',
        title: 'Account Recovery',
        disabled: !loginState?.isLoggedIn,
        element: () => (
          <>
            <React.Suspense fallback={<SuspenseFallback />}>
              <SyncAccount />
            </React.Suspense>
          </>
        ),
      },
    ],
    [defaultModeWhenNoDetectedAccount, loginState?.isLoggedIn, prefetchPasskeyMenu],
  );

  return (
    <ProfileMenuControlProvider>
      <DemoToastThemeBridge />
      <div
        className={`passkey-demo${loginState?.isLoggedIn ? ' passkey-demo--with-profile' : ''}`}
      >
        {loginState?.isLoggedIn ? <NavbarProfileOverlay /> : null}
        <AuthMenuControlProvider>
          <CarouselProvider
            pages={pages}
            initialKey="login"
            defaultTransition="fade"
            showBreadcrumbs={false}
            currentPage={currentPage}
            onCurrentPageChange={setCurrentPage}
            rootStyle={{
              // padding-bottom for tooltip so it's not clipped
              display: 'grid',
              placeContent: 'center',
            }}
          >
            <Carousel />
          </CarouselProvider>
        </AuthMenuControlProvider>
      </div>
    </ProfileMenuControlProvider>
  );
}

const SuspenseFallback = () => (
  <div
    className={'suspense-fallback'}
    style={{ height: 320, width: 'min(480px, calc(100vw - 2rem))' }}
  />
);

function PrefetchOnIntent(props: { onIntent: () => void; children: React.ReactNode }) {
  const didPrefetchRef = React.useRef(false);
  const onIntentOnce = React.useCallback(() => {
    if (didPrefetchRef.current) return;
    didPrefetchRef.current = true;
    props.onIntent();
  }, [props.onIntent]);

  return (
    <div
      style={{ display: 'contents' }}
      onPointerOver={onIntentOnce}
      onMouseOver={onIntentOnce}
      onFocusCapture={onIntentOnce}
      onTouchStart={onIntentOnce}
    >
      {props.children}
    </div>
  );
}
