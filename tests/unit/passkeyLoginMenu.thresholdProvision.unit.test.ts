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
): Promise<{ loggedInCalls: string[]; cacheWrites: string[] }> {
  return page.evaluate(
    async ({ paths, flow }) => {
      const React =
        ((await import('/node_modules/.vite/deps/react.js').catch(() => null)) as any) ||
        (await import('react'));
      const ReactRuntime = (React as any).default || React;
      const ReactDOMClient =
        ((await import('/node_modules/.vite/deps/react-dom_client.js').catch(() => null)) as any) ||
        (await import('react-dom/client'));
      const ReactDOMClientRuntime = (ReactDOMClient as any).default || ReactDOMClient;
      const ReactDOM =
        ((await import('/node_modules/.vite/deps/react-dom.js').catch(() => null)) as any) ||
        (await import('react-dom'));
      const ReactDOMRuntime = (ReactDOM as any).default || ReactDOM;
      const menuMod = await import(paths.passkeyLoginMenu);
      const PasskeyLoginMenu = (menuMod as any).PasskeyLoginMenu || (menuMod as any).default;
      if (!PasskeyLoginMenu) {
        throw new Error('Failed to load PasskeyLoginMenu module export');
      }

      const counters = {
        loggedInCalls: [] as string[],
        cacheWrites: [] as string[],
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
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: 'alice.testnet',
              relayerUrl: 'https://relay.example',
              relayerKeyId: 'secp-mock-key',
              clientVerifyingShareB64u: 'mock-client-share',
            },
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
                writeCachedThresholdKeyRef: (nearAccountId: string, chain: string) => {
                  counters.cacheWrites.push(`${nearAccountId}:${chain}`);
                },
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
        await onLogin();
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
    expect(result.cacheWrites).toEqual(['alice.testnet:evm', 'alice.testnet:tempo']);
  });

  test('login flow skips provisioning when both chain keyRefs are already cached', async ({
    page,
  }) => {
    const result = await runFlow(page, { flow: 'login' });
    expect(result.loggedInCalls).toEqual(['alice.testnet']);
    expect(result.cacheWrites).toEqual([]);
  });

  test('login flow does not auto-provision Tempo/EVM signers when cache is missing', async ({ page }) => {
    const result = await runFlow(page, { flow: 'login' });
    expect(result.loggedInCalls).toEqual(['alice.testnet']);
    expect(result.cacheWrites).toEqual([]);
  });
});
