import { expect, test } from '@playwright/test';
import type { Page } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  passkeyLoginMenu: '/src/flows/demo/PasskeyLoginMenu.tsx',
} as const;

type FlowMode = 'register' | 'login' | 'sync';

type GoogleSsoRerollResult = {
  exchanges: Array<{
    accountMode: string;
    rerollRegistrationAttempt: boolean;
  }>;
  enrollmentChallenges: Array<{
    nearAccountId: string;
    appSessionJwt: string;
  }>;
  loginChallenges: Array<{
    nearAccountId: string;
    appSessionJwt: string;
  }>;
  rerollResult: {
    username?: string;
    accountId?: string;
    codeDelivery?: 'sent' | 'reused';
  };
  registrationCalls: Array<{
    nearAccountId: string;
    challengeId: string;
    appSessionJwt: string;
  }>;
  loginCapabilityCalls: Array<{
    challengeId: string;
    appSessionJwt: string;
    walletSession: {
      walletId: string;
      walletSessionUserId: string;
    };
    chainTarget: {
      kind: string;
      chainId: number;
      networkSlug: string;
    };
  }>;
  refreshLoginStateCalls: string[];
  loggedInCalls: string[];
};

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
        return {
          accountInputState: { targetAccountId: 'alice.testnet', accountExists: true },
          unlock: async (nearAccountId: string) => {
            counters.loginCalls.push(String(nearAccountId || ''));
            return {
              success: true,
              nearAccountId: String(nearAccountId || 'alice.testnet'),
              jwt: 'mock-jwt-token',
            };
          },
          registerPasskey: async () => ({
            success: true,
            nearAccountId: 'alice.testnet',
            transactionId: 'mock-registration-tx',
          }),
          seams: {
            recovery: {
              syncAccount: async (args?: { accountId?: string }) => {
                counters.syncCalls.push(String(args?.accountId || ''));
                return {
                  success: true,
                  accountId: 'alice.testnet',
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

type GoogleSsoRerollScenario = 'register_to_login' | 'login_to_register';

async function runGoogleSsoRegisterRerollFlow(
  page: Page,
  scenario: GoogleSsoRerollScenario,
): Promise<GoogleSsoRerollResult> {
  return page.evaluate(
    async ({ paths, scenario }) => {
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

      let googleCallback: ((response: { credential?: string }) => void) | null = null;
      (window as any).google = {
        accounts: {
          id: {
            initialize(config: { callback: (response: { credential?: string }) => void }) {
              googleCallback = config.callback;
            },
            prompt() {
              googleCallback?.({ credential: 'google-id-token' });
            },
            cancel() {},
          },
        },
      };

      const originalFetch = window.fetch.bind(window);
      window.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url.includes('/auth/google/options')) {
          return new Response(
            JSON.stringify({ ok: true, configured: true, clientId: 'google-client-id' }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          );
        }
        return await originalFetch(input, init);
      }) as typeof fetch;

      const calls: GoogleSsoRerollResult = {
        exchanges: [],
        enrollmentChallenges: [],
        loginChallenges: [],
        rerollResult: {},
        registrationCalls: [],
        loginCapabilityCalls: [],
        refreshLoginStateCalls: [],
        loggedInCalls: [],
      };
      const menuPropsRef: { current: Record<string, unknown> | null } = { current: null };
      let exchangeCount = 0;

      function FakePasskeyAuthMenu(props: Record<string, unknown>) {
        menuPropsRef.current = props;
        return ReactRuntime.createElement('div', { id: 'passkey-menu-test-double' });
      }

      function useSeamsHook() {
        return {
          accountInputState: { targetAccountId: 'alice.testnet', accountExists: false },
          unlock: async () => ({ success: true, nearAccountId: 'alice.testnet' }),
          registerPasskey: async () => ({
            success: true,
            nearAccountId: 'alice.testnet',
          }),
          refreshLoginState: async (walletId: string) => {
            calls.refreshLoginStateCalls.push(String(walletId || ''));
          },
          seams: {
            auth: {
              exchangeGoogleEmailOtpSession: async (args: {
                accountMode: string;
                rerollRegistrationAttempt?: boolean;
              }) => {
                calls.exchanges.push({
                  accountMode: String(args.accountMode || ''),
                  rerollRegistrationAttempt: args.rerollRegistrationAttempt === true,
                });
                exchangeCount += 1;
                const firstIsRegistration = scenario === 'register_to_login';
                const shouldReturnRegistration =
                  exchangeCount === 1 ? firstIsRegistration : !firstIsRegistration;
                if (shouldReturnRegistration) {
                  return {
                    jwt: 'jwt-register',
                    session: {
                      userId: 'wallet-new-user',
                      walletId: 'wallet-new.testnet',
                      email: 'alice@example.test',
                      googleEmailOtpResolution: { mode: 'register_started' },
                    },
                  };
                }
                return {
                  jwt: 'jwt-login',
                  session: {
                    userId: 'wallet-existing-user',
                    walletId: 'wallet-existing.testnet',
                    email: 'alice@example.test',
                    googleEmailOtpResolution: { mode: 'existing_wallet' },
                  },
                };
              },
              requestEmailOtpEnrollmentChallenge: async (args: {
                nearAccountId: string;
                appSessionJwt?: string;
              }) => {
                calls.enrollmentChallenges.push({
                  nearAccountId: String(args.nearAccountId || ''),
                  appSessionJwt: String(args.appSessionJwt || ''),
                });
                return {
                  challengeId: 'registration-challenge-1',
                  otpChannel: 'email',
                  emailHint: 'alice@example.test',
                };
              },
              requestEmailOtpChallenge: async (args: {
                nearAccountId: string;
                appSessionJwt?: string;
              }) => {
                calls.loginChallenges.push({
                  nearAccountId: String(args.nearAccountId || ''),
                  appSessionJwt: String(args.appSessionJwt || ''),
                });
                return {
                  challengeId: 'login-challenge-1',
                  otpChannel: 'email',
                  emailHint: 'alice@example.test',
                };
              },
              loginWithEmailOtpEcdsaCapability: async (args: {
                challengeId: string;
                appSessionJwt?: string;
                walletSession: {
                  walletId: string;
                  walletSessionUserId: string;
                };
                chainTarget: {
                  kind: string;
                  chainId: number;
                  networkSlug: string;
                };
              }) => {
                calls.loginCapabilityCalls.push({
                  challengeId: String(args.challengeId || ''),
                  appSessionJwt: String(args.appSessionJwt || ''),
                  walletSession: {
                    walletId: String(args.walletSession?.walletId || ''),
                    walletSessionUserId: String(args.walletSession?.walletSessionUserId || ''),
                  },
                  chainTarget: {
                    kind: String(args.chainTarget?.kind || ''),
                    chainId: Number(args.chainTarget?.chainId),
                    networkSlug: String(args.chainTarget?.networkSlug || ''),
                  },
                });
                return { success: true };
              },
              getWalletSession: async () => ({ login: { isLoggedIn: true } }),
            },
            near: {
              registerNearWallet: async (args: {
                nearAccountId?: string;
                authMethod?: {
                  challengeId?: string;
                  appSessionJwt?: string;
                };
              }) => {
                calls.registrationCalls.push({
                  nearAccountId: String(args.nearAccountId || ''),
                  challengeId: String(args.authMethod?.challengeId || ''),
                  appSessionJwt: String(args.authMethod?.appSessionJwt || ''),
                });
                return { success: true };
              },
            },
            recovery: {
              syncAccount: async () => ({ success: true, accountId: 'alice.testnet' }),
            },
          },
        };
      }

      const mount = document.createElement('div');
      mount.id = 'passkey-login-menu-google-reroll-mount';
      document.body.appendChild(mount);
      const root = ReactDOMClientRuntime.createRoot(mount);
      try {
        ReactDOMRuntime.flushSync(() => {
          root.render(
            ReactRuntime.createElement(PasskeyLoginMenu, {
              onLoggedIn: (nearAccountId?: string) => {
                calls.loggedInCalls.push(String(nearAccountId || ''));
              },
              __testOverrides: {
                useSeamsHook,
                useAuthMenuControlHook: () => ({
                  defaultModeOverride: 0,
                  remountKey: 0,
                  setDefaultModeOverride: () => undefined,
                  bumpRemount: () => undefined,
                  setAndRemount: () => undefined,
                }),
                PasskeyAuthMenuComponent: FakePasskeyAuthMenu,
              },
            }),
          );
        });

        const menuProps = menuPropsRef.current;
        const googleHandler = (menuProps?.socialLogin as { google?: Function } | undefined)
          ?.google;
        if (typeof googleHandler !== 'function') {
          throw new Error('Missing Google social login handler');
        }
        const socialResult = await googleHandler({
          mode: 0,
          emailOtpAuthPolicy: 'session',
        });
        if (!socialResult?.otpPrompt?.onRerollAccount || !socialResult.otpPrompt.onSubmit) {
          throw new Error('Google social login did not return an OTP prompt');
        }

        calls.rerollResult = await socialResult.otpPrompt.onRerollAccount();
        await socialResult.otpPrompt.onSubmit('123456');
        return calls;
      } finally {
        root.unmount();
        window.fetch = originalFetch;
      }
    },
    { paths: IMPORT_PATHS, scenario },
  );
}

test.describe('PasskeyLoginMenu threshold signer auto-provision', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('register flow does not auto-provision Tempo/EVM signers', async ({ page }) => {
    const result = await runFlow(page, { flow: 'register' });
    expect(result.loggedInCalls).toEqual(['alice.testnet']);
    expect(result.loginCalls).toEqual([]);
    expect(result.loginError).toBeNull();
    expect(result.syncCalls).toEqual([]);
    expect(result.syncError).toBeNull();
  });

  test('login flow succeeds with a basic successful login result', async ({ page }) => {
    const result = await runFlow(page, { flow: 'login' });
    expect(result.loggedInCalls).toEqual(['alice.testnet']);
    expect(result.loginCalls).toEqual(['alice.testnet']);
    expect(result.loginError).toBeNull();
    expect(result.syncCalls).toEqual([]);
    expect(result.syncError).toBeNull();
  });

  test('sync flow is wired to recovery.syncAccount', async ({ page }) => {
    const result = await runFlow(page, { flow: 'sync' });
    expect(result.loggedInCalls).toEqual(['alice.testnet']);
    expect(result.loginCalls).toEqual([]);
    expect(result.loginError).toBeNull();
    expect(result.syncCalls).toEqual(['alice.testnet']);
    expect(result.syncError).toBeNull();
  });

  test('Google SSO reroll refreshes the challenge when registration resolves to login', async ({
    page,
  }) => {
    const result = await runGoogleSsoRegisterRerollFlow(page, 'register_to_login');

    expect(result.exchanges).toEqual([
      { accountMode: 'register', rerollRegistrationAttempt: false },
      { accountMode: 'register', rerollRegistrationAttempt: true },
    ]);
    expect(result.enrollmentChallenges).toEqual([
      { nearAccountId: 'wallet-new.testnet', appSessionJwt: 'jwt-register' },
    ]);
    expect(result.loginChallenges).toEqual([
      { nearAccountId: 'wallet-existing.testnet', appSessionJwt: 'jwt-login' },
    ]);
    expect(result.rerollResult).toMatchObject({
      username: 'wallet-existing.testnet',
      accountId: 'wallet-existing.testnet',
      codeDelivery: 'sent',
    });
    expect(result.registrationCalls).toEqual([]);
    expect(result.loginCapabilityCalls).toHaveLength(1);
    expect(result.loginCapabilityCalls[0]).toMatchObject({
      challengeId: 'login-challenge-1',
      appSessionJwt: 'jwt-login',
      walletSession: {
        walletId: 'wallet-existing.testnet',
        walletSessionUserId: 'wallet-existing-user',
      },
      chainTarget: {
        kind: 'tempo',
        chainId: 42431,
        networkSlug: 'tempo-testnet',
      },
    });
    expect(result.refreshLoginStateCalls).toEqual(['wallet-existing.testnet']);
    expect(result.loggedInCalls).toEqual(['wallet-existing.testnet']);
  });

  test('Google SSO reroll reuses the existing OTP when login resolves to registration', async ({
    page,
  }) => {
    const result = await runGoogleSsoRegisterRerollFlow(page, 'login_to_register');

    expect(result.exchanges).toEqual([
      { accountMode: 'register', rerollRegistrationAttempt: false },
      { accountMode: 'register', rerollRegistrationAttempt: true },
    ]);
    expect(result.loginChallenges).toEqual([
      { nearAccountId: 'wallet-existing.testnet', appSessionJwt: 'jwt-login' },
    ]);
    expect(result.enrollmentChallenges).toEqual([]);
    expect(result.rerollResult).toMatchObject({
      username: 'wallet-new.testnet',
      accountId: 'wallet-new.testnet',
      codeDelivery: 'reused',
    });
    expect(result.registrationCalls).toEqual([
      {
        nearAccountId: 'wallet-new.testnet',
        challengeId: 'login-challenge-1',
        appSessionJwt: 'jwt-register',
      },
    ]);
    expect(result.loginCapabilityCalls).toEqual([]);
    expect(result.refreshLoginStateCalls).toEqual(['wallet-new.testnet']);
    expect(result.loggedInCalls).toEqual(['wallet-new.testnet']);
  });
});
