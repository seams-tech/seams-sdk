import React from 'react';
import { SeamsAuthMenuSkeletonInner } from './skeleton';
import { SeamsAuthMenuThemeScope } from './themeScope';
import { AuthMenuMode, type SeamsAuthMenuProps } from './types';
import { useTheme } from '../theme';
import { preloadSeamsAuthMenu } from './preload';
import { SeamsAuthMenuHydrationContext } from './hydrationContext';

const useIsomorphicLayoutEffect =
  typeof window !== 'undefined' ? React.useLayoutEffect : React.useEffect;

type SeamsAuthMenuClientComponent = React.ComponentType<SeamsAuthMenuProps>;

const clientLazyCache = new Map<number, React.LazyExoticComponent<SeamsAuthMenuClientComponent>>();

let didClientMountOnce = false;

let didAutoPreloadClientChunk = false;
function autoPreloadClientChunk() {
  if (didAutoPreloadClientChunk) return;
  didAutoPreloadClientChunk = true;
  void preloadSeamsAuthMenu();
}

// If this module is imported in a browser bundle, start fetching the client chunk immediately.
// This reduces the chance of a first-mount Suspense fallback flash without affecting SSR.
if (typeof window !== 'undefined' && typeof document !== 'undefined') {
  autoPreloadClientChunk();
}

function getClientLazy(retryKey: number): React.LazyExoticComponent<SeamsAuthMenuClientComponent> {
  const existing = clientLazyCache.get(retryKey);
  if (existing) return existing;

  const next = React.lazy(() =>
    import('./client').then((m) => ({ default: m.SeamsAuthMenuClient })),
  ) as unknown as React.LazyExoticComponent<SeamsAuthMenuClientComponent>;

  clientLazyCache.set(retryKey, next);
  return next;
}

function invalidateClientLazy(retryKey: number) {
  clientLazyCache.delete(retryKey);
}

class LazyErrorBoundary extends React.Component<
  {
    fallback: (args: { error: Error; retry: () => void }) => React.ReactNode;
    onRetry: () => void;
    onError?: (error: Error) => void;
    children: React.ReactNode;
  },
  { error: Error | null }
> {
  state: { error: Error | null } = { error: null };

  static getDerivedStateFromError(error: Error): { error: Error } {
    return { error };
  }

  retry = () => {
    this.setState({ error: null });
    this.props.onRetry();
  };

  componentDidCatch(error: Error) {
    this.props.onError?.(error);
  }

  render() {
    if (this.state.error) {
      return this.props.fallback({ error: this.state.error, retry: this.retry });
    }
    return this.props.children;
  }
}

/**
 * `SeamsAuthMenu` — SSR-safe shell.
 *
 * - Server: renders a skeleton only.
 * - Client: lazy-loads the full implementation after mount.
 */
export const SeamsAuthMenu: React.FC<SeamsAuthMenuProps> = (props) => {
  const [isClient, setIsClient] = React.useState(() => {
    if (typeof window === 'undefined') return false;
    return didClientMountOnce;
  });
  const forceInitialRegisterRef = React.useRef(
    !didClientMountOnce && props.defaultMode === AuthMenuMode.Register,
  );
  const [retryKey, setRetryKey] = React.useState(0);
  const ClientLazy = React.useMemo(() => getClientLazy(retryKey), [retryKey]);

  // Align with the SDK Theme boundary when present (SeamsWebProvider wraps one by default).
  // Falls back to system preference when used standalone.
  const { theme, tokens } = useTheme();

  useIsomorphicLayoutEffect(() => {
    didClientMountOnce = true;
    setIsClient(true);
    // Start fetching the client chunk immediately; the skeleton remains as the Suspense fallback.
    autoPreloadClientChunk();
  }, []);

  const skeleton = (
    <SeamsAuthMenuSkeletonInner
      className={props.className}
      style={props.style}
      defaultMode={props.defaultMode}
      headings={props.headings}
      emailOtpAuthPolicy={props.emailOtpAuthPolicy}
      registrationAccountInput={props.registrationAccountInput}
      showRegistrationInput={props.showRegistrationInput}
    />
  );

  return (
    <SeamsAuthMenuThemeScope theme={theme} tokens={tokens}>
      {isClient ? (
        <SeamsAuthMenuHydrationContext.Provider value={forceInitialRegisterRef.current}>
          <LazyErrorBoundary
            onRetry={() => setRetryKey((k) => k + 1)}
            onError={() => invalidateClientLazy(retryKey)}
            fallback={({ retry }) => (
              <div>
                {skeleton}
                <div style={{ marginTop: 10, fontSize: 12, textAlign: 'center', opacity: 0.9 }}>
                  Failed to load menu.{' '}
                  <button type="button" onClick={retry} style={{ textDecoration: 'underline' }}>
                    Retry
                  </button>
                </div>
              </div>
            )}
          >
            <React.Suspense fallback={skeleton}>
              <ClientLazy {...props} />
            </React.Suspense>
          </LazyErrorBoundary>
        </SeamsAuthMenuHydrationContext.Provider>
      ) : (
        skeleton
      )}
    </SeamsAuthMenuThemeScope>
  );
};

export default SeamsAuthMenu;
