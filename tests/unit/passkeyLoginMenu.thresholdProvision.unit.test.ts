import { expect, test } from '@playwright/test';
import type { Page } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  passkeyLoginMenu: '/src/components/PasskeyLoginMenu.tsx',
} as const;

type FlowMode = 'register' | 'login';

async function runFlow(
  page: Page,
  args: { flow: FlowMode },
): Promise<{ loggedInCalls: string[]; loginError: string | null }> {
  return page.evaluate(
    async ({ paths, flow }) => {
      const viteReactPath = '/node_modules/.vite/deps/react.js' as string;
      const viteReactDomClientPath = '/node_modules/.vite/deps/react-dom_client.js' as string;
      const viteReactDomPath = '/node_modules/.vite/deps/react-dom.js' as string;
      const React =
        ((await import(viteReactPath).catch(() => null)) as any) ||
        (await import('react'));
      const ReactRuntime = (React as any).default || React;
      const ReactDOMClient =
        ((await import(viteReactDomClientPath).catch(() => null)) as any) ||
        (await import('react-dom/client'));
      const ReactDOMClientRuntime = (ReactDOMClient as any).default || ReactDOMClient;
      const ReactDOM =
        ((await import(viteReactDomPath).catch(() => null)) as any) ||
        (await import('react-dom'));
      const ReactDOMRuntime = (ReactDOM as any).default || ReactDOM;
      const menuMod = await import(paths.passkeyLoginMenu);
      const PasskeyLoginMenu = (menuMod as any).PasskeyLoginMenu || (menuMod as any).default;
      if (!PasskeyLoginMenu) {
        throw new Error('Failed to load PasskeyLoginMenu module export');
      }

      const counters = {
        loggedInCalls: [] as string[],
        loginError: null as string | null,
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

      function useTatchiHook() {
        return {
          accountInputState: { targetAccountId: 'alice.testnet', accountExists: true },
          loginAndCreateSession: async () => ({
            success: true,
            nearAccountId: 'alice.testnet',
            jwt: 'mock-jwt-token',
          }),
          registerPasskey: async () => ({
            success: true,
            nearAccountId: 'alice.testnet',
            transactionId: 'mock-registration-tx',
          }),
          tatchi: {},
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
                useTatchiHook,
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
      } else {
        const onLogin = menuProps.onLogin as (() => Promise<unknown>) | undefined;
        if (!onLogin) throw new Error('Missing onLogin callback');
        try {
          await onLogin();
        } catch (error: unknown) {
          counters.loginError = String(
            (error && typeof error === 'object' && 'message' in error)
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
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('register flow does not auto-provision Tempo/EVM signers', async ({ page }) => {
    const result = await runFlow(page, { flow: 'register' });
    expect(result.loggedInCalls).toEqual([]);
    expect(result.loginError).toBeNull();
  });

  test('login flow succeeds with a basic successful login result', async ({ page }) => {
    const result = await runFlow(page, { flow: 'login' });
    expect(result.loggedInCalls).toEqual(['alice.testnet']);
    expect(result.loginError).toBeNull();
  });
});
