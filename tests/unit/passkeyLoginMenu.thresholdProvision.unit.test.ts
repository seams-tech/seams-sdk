import { expect, test } from '@playwright/test';
import type { Page } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  passkeyLoginMenu: '/src/flows/demo/PasskeyLoginMenu.tsx',
} as const;

type FlowMode = 'register' | 'login' | 'sync';

async function runFlow(
  page: Page,
  args: { flow: FlowMode },
): Promise<{
  loggedInCalls: string[];
  loginCalls: string[];
  loginError: string | null;
  syncCalls: string[];
  syncError: string | null;
}> {
  return page.evaluate(
    async ({ paths, flow }) => {
      const viteReactPath = '/node_modules/.vite/deps/react.js' as string;
      const viteReactDomClientPath = '/node_modules/.vite/deps/react-dom_client.js' as string;
      const viteReactDomPath = '/node_modules/.vite/deps/react-dom.js' as string;
      const React =
        ((await import(viteReactPath).catch(() => null)) as any) || (await import('react'));
      const ReactRuntime = (React as any).default || React;
      const ReactDOMClient =
        ((await import(viteReactDomClientPath).catch(() => null)) as any) ||
        (await import('react-dom/client'));
      const ReactDOMClientRuntime = (ReactDOMClient as any).default || ReactDOMClient;
      const ReactDOM =
        ((await import(viteReactDomPath).catch(() => null)) as any) || (await import('react-dom'));
      const ReactDOMRuntime = (ReactDOM as any).default || ReactDOM;
      const menuMod = await import(paths.passkeyLoginMenu);
      const PasskeyLoginMenu = (menuMod as any).PasskeyLoginMenu || (menuMod as any).default;
      if (!PasskeyLoginMenu) {
        throw new Error('Failed to load PasskeyLoginMenu module export');
      }

      const counters = {
        loggedInCalls: [] as string[],
        loginCalls: [] as string[],
        loginError: null as string | null,
        syncCalls: [] as string[],
        syncError: null as string | null,
      };

      const menuPropsRef: { current: Record<string, unknown> | null } = { current: null };
      const renderErrors: string[] = [];

      function FakePasskeyAuthMenu(props: Record<string, unknown>) {
        menuPropsRef.current = props;
        return ReactRuntime.createElement('div', { id: 'passkey-menu-test-double' });
      }

      class ErrorBoundary extends ReactRuntime.Component<
        { children: React.ReactNode },
        { hasError: boolean }
      > {
        constructor(props: { children: React.ReactNode }) {
          super(props);
          this.state = { hasError: false };
        }

        static getDerivedStateFromError() {
          return { hasError: true };
        }

        componentDidCatch(error: unknown) {
          const message = error instanceof Error ? error.message : String(error || 'unknown error');
          renderErrors.push(message);
        }

        render() {
          if (this.state.hasError) {
            return ReactRuntime.createElement('div', { id: 'passkey-login-menu-render-error' });
          }
          return this.props.children;
        }
      }

      function useSeamsHook() {
        const walletId = 'frost-giant-8n1lfz';
        const nearAccountId = '13f209913f2d5d9cd8d7ec99a9a93f8c7b';
        return {
          accountInputState: {
            targetWalletId: walletId,
            targetAccountId: nearAccountId,
            accountExists: true,
          },
          unlock: async (selectedWalletId: string) => {
            counters.loginCalls.push(String(selectedWalletId || ''));
            return {
              success: true,
              walletId: String(selectedWalletId || walletId),
              nearAccountId,
              jwt: 'mock-jwt-token',
            };
          },
          registerPasskey: async () => ({
            success: true,
            walletId,
            nearAccountId,
            transactionId: 'mock-registration-tx',
          }),
          seams: {
            recovery: {
              syncAccount: async (args?: { walletId?: string }) => {
                counters.syncCalls.push(String(args?.walletId || ''));
                return {
                  success: true,
                  accountId: nearAccountId,
                  walletId,
                  publicKey: 'ed25519:mock-synced',
                  message: 'synced',
                  loginState: { isLoggedIn: true },
                };
              },
            },
          },
        };
      }

      const mount = document.createElement('div');
      mount.id = 'passkey-login-menu-threshold-mount';
      document.body.appendChild(mount);

      const root = ReactDOMClientRuntime.createRoot(mount);
      ReactDOMRuntime.flushSync(() => {
        root.render(
          ReactRuntime.createElement(
            ErrorBoundary,
            null,
            ReactRuntime.createElement(PasskeyLoginMenu, {
              onLoggedIn: (nearAccountId?: string) => {
                counters.loggedInCalls.push(String(nearAccountId || ''));
              },
              __testOverrides: {
                useSeamsHook,
                useAuthMenuControlHook: () => ({
                  defaultModeOverride: undefined,
                  remountKey: 0,
                  setDefaultModeOverride: () => undefined,
                  bumpRemount: () => undefined,
                  setAndRemount: () => undefined,
                }),
                PasskeyAuthMenuComponent: FakePasskeyAuthMenu,
              },
            }),
          ),
        );
      });

      const menuProps = menuPropsRef.current;
      if (!menuProps) {
        const moduleKeys = Object.keys(menuMod || {});
        const html = mount.innerHTML || '';
        throw new Error(
          `PasskeyAuthMenu props were not captured (module keys: ${moduleKeys.join(', ')}; errors: ${renderErrors.join(' | ')}; html: ${html.slice(0, 200)})`,
        );
      }

      if (flow === 'register') {
        const onRegister = menuProps.onRegister as (() => Promise<unknown>) | undefined;
        if (!onRegister) throw new Error('Missing onRegister callback');
        await onRegister();
      } else if (flow === 'login') {
        const onLogin = menuProps.onLogin as (() => Promise<unknown>) | undefined;
        if (!onLogin) throw new Error('Missing onLogin callback');
        try {
          await onLogin();
        } catch (error: unknown) {
          counters.loginError = String(
            error && typeof error === 'object' && 'message' in error
              ? (error as { message?: unknown }).message
              : error || '',
          );
        }
      } else {
        const onSyncAccount = menuProps.onSyncAccount as (() => Promise<unknown>) | undefined;
        if (!onSyncAccount) throw new Error('Missing onSyncAccount callback');
        try {
          await onSyncAccount();
        } catch (error: unknown) {
          counters.syncError = String(
            error && typeof error === 'object' && 'message' in error
              ? (error as { message?: unknown }).message
              : error || '',
          );
        }
      }

      root.unmount();
      return counters;
    },
    { paths: IMPORT_PATHS, flow: args.flow },
  );
}

test.describe('PasskeyLoginMenu threshold signer auto-provision', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
  });

  test('register flow does not auto-provision Tempo/EVM signers', async ({ page }) => {
    const result = await runFlow(page, { flow: 'register' });
    expect(result.loggedInCalls).toEqual(['13f209913f2d5d9cd8d7ec99a9a93f8c7b']);
    expect(result.loginCalls).toEqual([]);
    expect(result.loginError).toBeNull();
    expect(result.syncCalls).toEqual([]);
    expect(result.syncError).toBeNull();
  });

  test('login flow succeeds with a basic successful login result', async ({ page }) => {
    const result = await runFlow(page, { flow: 'login' });
    expect(result.loggedInCalls).toEqual(['13f209913f2d5d9cd8d7ec99a9a93f8c7b']);
    expect(result.loginCalls).toEqual(['frost-giant-8n1lfz']);
    expect(result.loginError).toBeNull();
    expect(result.syncCalls).toEqual([]);
    expect(result.syncError).toBeNull();
  });

  test('sync flow is wired to recovery.syncAccount', async ({ page }) => {
    const result = await runFlow(page, { flow: 'sync' });
    expect(result.loggedInCalls).toEqual(['13f209913f2d5d9cd8d7ec99a9a93f8c7b']);
    expect(result.loginCalls).toEqual([]);
    expect(result.loginError).toBeNull();
    expect(result.syncCalls).toEqual(['frost-giant-8n1lfz']);
    expect(result.syncError).toBeNull();
  });

});
