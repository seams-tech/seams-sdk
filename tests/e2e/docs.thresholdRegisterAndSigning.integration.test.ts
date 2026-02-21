import { expect, test } from '@playwright/test';
import type { Page } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  passkeyLoginMenu: '/src/components/PasskeyLoginMenu.tsx',
  demoPage: '/src/components/DemoPage.tsx',
} as const;

async function mountRegisterToSigningHarness(page: Page): Promise<void> {
  await page.evaluate(async ({ paths }) => {
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

    const [menuMod, demoMod] = await Promise.all([
      import(paths.passkeyLoginMenu),
      import(paths.demoPage),
    ]);
    const PasskeyLoginMenu = (menuMod as any).PasskeyLoginMenu || (menuMod as any).default;
    const DemoPage = (demoMod as any).DemoPage || (demoMod as any).default;
    if (!PasskeyLoginMenu || !DemoPage) {
      throw new Error('Failed to load docs component exports for integration harness');
    }

    const accountId = 'alice.testnet';
    const counters = {
      registerCalls: 0,
      loginCalls: 0,
      bootstrapCalls: [] as string[],
      tempoSigns: 0,
      evmSigns: 0,
    };
    (window as any).__docsRegisterFlowCounters = counters;

    function buildKeyRef(chain: 'evm' | 'tempo', keySuffix: number) {
      return {
        type: 'threshold-ecdsa-secp256k1',
        userId: accountId,
        relayerUrl: 'https://relay.example',
        relayerKeyId: `${chain}-relayer-key-${keySuffix}`,
        clientVerifyingShareB64u: `${chain}-client-share-${keySuffix}`,
      };
    }

    const TatchiContext = ReactRuntime.createContext(null as any);

    function useTatchiHook() {
      const value = ReactRuntime.useContext(TatchiContext);
      if (!value) throw new Error('Missing Tatchi context value in integration harness');
      return value;
    }

    function useSetGreetingHook() {
      return {
        onchainGreeting: 'hello',
        isLoading: false,
        fetchGreeting: async () => undefined,
        error: null,
      };
    }

    function FakePasskeyAuthMenu(props: Record<string, unknown>) {
      return ReactRuntime.createElement(
        'div',
        { id: 'passkey-auth-menu-double' },
        ReactRuntime.createElement(
          'button',
          {
            type: 'button',
            'data-testid': 'docs-register-btn',
            onClick: () => {
              const onRegister = props.onRegister as (() => Promise<unknown>) | undefined;
              void onRegister?.();
            },
          },
          'Register',
        ),
        ReactRuntime.createElement(
          'button',
          {
            type: 'button',
            'data-testid': 'docs-login-btn',
            onClick: () => {
              const onLogin = props.onLogin as (() => Promise<unknown>) | undefined;
              void onLogin?.();
            },
          },
          'Login',
        ),
      );
    }

    function IntegrationHarness() {
      const [loginState, setLoginState] = ReactRuntime.useState({
        isLoggedIn: false,
        nearAccountId: undefined as string | undefined,
      });

      const tatchi = ReactRuntime.useMemo(
        () => ({
          registerPasskey: async () => {
            counters.registerCalls += 1;
            return {
              success: true,
              nearAccountId: accountId,
              transactionId: 'mock-registration-tx',
            };
          },
          loginAndCreateSession: async () => {
            counters.loginCalls += 1;
            setLoginState({ isLoggedIn: true, nearAccountId: accountId });
            return {
              success: true,
              nearAccountId: accountId,
              jwt: 'mock-jwt-token',
            };
          },
          auth: {
            getSession: async () => ({
              signingSession: {
                sessionId: 'session-1',
                status: 'active',
                remainingUses: 3,
                expiresAtMs: Date.now() + 60_000,
                createdAtMs: Date.now(),
              },
            }),
            login: async () => ({ success: true }),
          },
          near: {
            executeAction: async () => ({ success: true }),
            signDelegateAction: async () => ({ hash: 'mock-hash', signedDelegate: {} }),
            sendDelegateActionViaRelayer: async () => ({
              ok: true,
              relayerTxHash: 'mock-relayer-tx',
            }),
          },
          tempo: {
            bootstrapEcdsaSession: async ({
              nearAccountId,
              options,
            }: {
              nearAccountId: string;
              options?: { chain?: 'evm' | 'tempo' };
            }) => {
              const chain = options?.chain === 'tempo' ? 'tempo' : 'evm';
              counters.bootstrapCalls.push(`${nearAccountId}:${chain}`);
              const keySuffix = counters.bootstrapCalls.length;
              return {
                thresholdEcdsaKeyRef: buildKeyRef(chain, keySuffix),
              };
            },
            signTempo: async () => {
              counters.tempoSigns += 1;
              return {
                kind: 'tempoTransaction' as const,
                senderHashHex: `0x${'ab'.repeat(32)}`,
                rawTxHex: `0x${'12'.repeat(64)}`,
              };
            },
            signTempoWithThresholdEcdsa: async () => {
              counters.evmSigns += 1;
              return {
                kind: 'eip1559' as const,
                txHashHex: `0x${'cd'.repeat(32)}`,
                rawTxHex: `0x${'34'.repeat(64)}`,
              };
            },
          },
          configs: {
            relayer: {
              url: 'https://relay.example',
            },
          },
        }),
        [],
      );

      const contextValue = ReactRuntime.useMemo(
        () => ({
          accountInputState: { targetAccountId: accountId, accountExists: true },
          loginAndCreateSession: tatchi.loginAndCreateSession,
          registerPasskey: tatchi.registerPasskey,
          loginState,
          tatchi,
        }),
        [loginState, tatchi],
      );

      return ReactRuntime.createElement(
        TatchiContext.Provider,
        { value: contextValue },
        ReactRuntime.createElement(
          'div',
          { id: 'docs-register-to-signing-root' },
          ReactRuntime.createElement(PasskeyLoginMenu, {
            onLoggedIn: (nearAccountId?: string) => {
              setLoginState({
                isLoggedIn: true,
                nearAccountId: String(nearAccountId || accountId),
              });
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
          ReactRuntime.createElement(DemoPage, {
            __testOverrides: {
              useTatchiHook,
              useSetGreetingHook,
            },
          }),
        ),
      );
    }

    const mount = document.createElement('div');
    mount.id = 'docs-register-to-signing-mount';
    document.body.appendChild(mount);

    const root = ReactDOMClientRuntime.createRoot(mount);
    ReactDOMRuntime.flushSync(() => {
      root.render(ReactRuntime.createElement(IntegrationHarness));
    });
  }, { paths: IMPORT_PATHS });
}

async function mountTempoRetryHarness(page: Page): Promise<void> {
  await page.evaluate(async ({ paths }) => {
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

    const demoMod = await import(paths.demoPage);
    const DemoPage = (demoMod as any).DemoPage || (demoMod as any).default;
    if (!DemoPage) {
      throw new Error('Failed to load DemoPage for retry harness');
    }

    const accountId = 'alice.testnet';
    const counters = {
      resolveCalls: [] as Array<{ chain: string; forceReprovision: boolean }>,
      tempoSignAttempts: 0,
    };
    (window as any).__docsTempoRetryCounters = counters;

    function makeKeyRef(label: string) {
      return {
        type: 'threshold-ecdsa-secp256k1',
        userId: accountId,
        relayerUrl: 'https://relay.example',
        relayerKeyId: `${label}-relayer-key`,
        clientVerifyingShareB64u: `${label}-client-share`,
      };
    }

    const stableLoginState = {
      isLoggedIn: true,
      nearAccountId: accountId,
    };
    const stableTatchi = {
      auth: {
        getSession: async () => ({
          signingSession: {
            sessionId: 'session-1',
            status: 'active',
            remainingUses: 3,
            expiresAtMs: Date.now() + 60_000,
            createdAtMs: Date.now(),
          },
        }),
        login: async () => ({ success: true }),
      },
      near: {
        executeAction: async () => ({ success: true }),
        signDelegateAction: async () => ({ hash: 'mock-hash', signedDelegate: {} }),
        sendDelegateActionViaRelayer: async () => ({
          ok: true,
          relayerTxHash: 'mock-relayer-tx',
        }),
      },
      tempo: {
        signTempo: async () => {
          counters.tempoSignAttempts += 1;
          if (counters.tempoSignAttempts === 1) {
            throw new Error('threshold session expired');
          }
          return {
            kind: 'tempoTransaction' as const,
            senderHashHex: `0x${'ab'.repeat(32)}`,
            rawTxHex: `0x${'12'.repeat(64)}`,
          };
        },
        signTempoWithThresholdEcdsa: async () => ({
          kind: 'eip1559' as const,
          txHashHex: `0x${'cd'.repeat(32)}`,
          rawTxHex: `0x${'34'.repeat(64)}`,
        }),
      },
      configs: {
        relayer: {
          url: 'https://relay.example',
        },
      },
    };
    const stableHookValue = {
      loginState: stableLoginState,
      tatchi: stableTatchi,
    };

    function useTatchiHook() {
      return stableHookValue;
    }

    function useSetGreetingHook() {
      return {
        onchainGreeting: 'hello',
        isLoading: false,
        fetchGreeting: async () => undefined,
        error: null,
      };
    }

    const mount = document.createElement('div');
    mount.id = 'docs-tempo-retry-mount';
    document.body.appendChild(mount);

    const root = ReactDOMClientRuntime.createRoot(mount);
    ReactDOMRuntime.flushSync(() => {
      root.render(
        ReactRuntime.createElement(DemoPage, {
          __testOverrides: {
            useTatchiHook,
            useSetGreetingHook,
            readCachedThresholdKeyRef: () => null,
            resolveThresholdKeyRef: async ({ chain, forceReprovision }: any) => {
              counters.resolveCalls.push({
                chain: String(chain || ''),
                forceReprovision: Boolean(forceReprovision),
              });
              if (chain === 'evm') return makeKeyRef('evm') as any;
              return makeKeyRef(forceReprovision ? 'tempo-refreshed' : 'tempo-initial') as any;
            },
          },
        }),
      );
    });
  }, { paths: IMPORT_PATHS });
}

async function mountProvisionUiHarness(page: Page): Promise<void> {
  await page.evaluate(async ({ paths }) => {
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

    const demoMod = await import(paths.demoPage);
    const DemoPage = (demoMod as any).DemoPage || (demoMod as any).default;
    if (!DemoPage) {
      throw new Error('Failed to load DemoPage for provisioning UI harness');
    }

    const accountId = 'alice.testnet';
    const counters = {
      resolveCalls: 0,
      tempoSignCalls: 0,
    };
    (window as any).__docsProvisionUiCounters = counters;

    let releaseProvision: null | (() => void) = null;
    (window as any).__releaseDocsProvision = () => {
      releaseProvision?.();
    };

    function makeKeyRef(chain: 'evm' | 'tempo') {
      return {
        type: 'threshold-ecdsa-secp256k1',
        userId: accountId,
        relayerUrl: 'https://relay.example',
        relayerKeyId: `${chain}-relayer-key`,
        clientVerifyingShareB64u: `${chain}-client-share`,
      };
    }

    const stableLoginState = {
      isLoggedIn: true,
      nearAccountId: accountId,
    };
    const stableTatchi = {
      auth: {
        getSession: async () => ({
          signingSession: {
            sessionId: 'session-1',
            status: 'active',
            remainingUses: 3,
            expiresAtMs: Date.now() + 60_000,
            createdAtMs: Date.now(),
          },
        }),
        login: async () => ({ success: true }),
      },
      near: {
        executeAction: async () => ({ success: true }),
        signDelegateAction: async () => ({ hash: 'mock-hash', signedDelegate: {} }),
        sendDelegateActionViaRelayer: async () => ({
          ok: true,
          relayerTxHash: 'mock-relayer-tx',
        }),
      },
      tempo: {
        signTempo: async () => {
          counters.tempoSignCalls += 1;
          return {
            kind: 'tempoTransaction' as const,
            senderHashHex: `0x${'ab'.repeat(32)}`,
            rawTxHex: `0x${'12'.repeat(64)}`,
          };
        },
        signTempoWithThresholdEcdsa: async () => ({
          kind: 'eip1559' as const,
          txHashHex: `0x${'cd'.repeat(32)}`,
          rawTxHex: `0x${'34'.repeat(64)}`,
        }),
      },
      configs: {
        relayer: {
          url: 'https://relay.example',
        },
      },
    };
    const stableHookValue = {
      loginState: stableLoginState,
      tatchi: stableTatchi,
    };

    function useTatchiHook() {
      return stableHookValue;
    }

    function useSetGreetingHook() {
      return {
        onchainGreeting: 'hello',
        isLoading: false,
        fetchGreeting: async () => undefined,
        error: null,
      };
    }

    const mount = document.createElement('div');
    mount.id = 'docs-provision-ui-mount';
    document.body.appendChild(mount);

    const root = ReactDOMClientRuntime.createRoot(mount);
    ReactDOMRuntime.flushSync(() => {
      root.render(
        ReactRuntime.createElement(DemoPage, {
          __testOverrides: {
            useTatchiHook,
            useSetGreetingHook,
            readCachedThresholdKeyRef: () => null,
            resolveThresholdKeyRef: async ({ chain }: { chain: 'evm' | 'tempo' }) => {
              counters.resolveCalls += 1;
              return await new Promise((resolve) => {
                releaseProvision = () => {
                  resolve(makeKeyRef(chain) as any);
                };
              });
            },
          },
        }),
      );
    });
  }, { paths: IMPORT_PATHS });
}

test.describe('docs frontend register + threshold signing integration', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('register/login keeps signers unprovisioned until first sign, then signs Tempo and EVM', async ({
    page,
  }) => {
    await mountRegisterToSigningHarness(page);

    const scope = page.locator('#docs-register-to-signing-root');

    await expect(scope.getByRole('button', { name: 'Sign Tempo Threshold Transaction' })).toHaveCount(0);

    await scope.getByRole('button', { name: 'Register' }).evaluate((el: HTMLElement) => el.click());

    await page.waitForFunction(() => {
      const counters = (window as any).__docsRegisterFlowCounters;
      return counters && counters.registerCalls === 1;
    });

    const afterRegister = await page.evaluate(() => (window as any).__docsRegisterFlowCounters);
    expect(afterRegister.registerCalls).toBe(1);
    expect(afterRegister.loginCalls).toBe(0);
    expect(afterRegister.bootstrapCalls).toEqual([]);

    await scope.getByRole('button', { name: 'Login' }).evaluate((el: HTMLElement) => el.click());

    const tempoButton = scope.getByRole('button', { name: 'Sign Tempo Threshold Transaction' });
    const evmButton = scope.getByRole('button', {
      name: 'Sign EVM Threshold EIP-1559 Transaction',
    });

    await expect(tempoButton).toBeVisible();
    await expect(evmButton).toBeVisible();

    await expect(scope.getByText(/EVM signer:\s*not provisioned/i)).toBeVisible();
    await expect(scope.getByText(/Tempo signer:\s*not provisioned/i)).toBeVisible();

    await tempoButton.evaluate((el: HTMLElement) => el.click());
    await expect(scope.getByText(/Tempo sender hash:/i)).toBeVisible();
    await evmButton.evaluate((el: HTMLElement) => el.click());
    await expect(scope.getByText(/EIP-1559 tx hash:/i)).toBeVisible();

    await page.waitForFunction(() => {
      const counters = (window as any).__docsRegisterFlowCounters;
      return (
        counters &&
        counters.loginCalls === 1 &&
        counters.bootstrapCalls.length === 2 &&
        counters.tempoSigns === 1 &&
        counters.evmSigns === 1
      );
    });

    await expect(scope.getByText(/EVM signer:\s*ready/i)).toBeVisible();
    await expect(scope.getByText(/Tempo signer:\s*ready/i)).toBeVisible();

    const finalCounters = await page.evaluate(() => (window as any).__docsRegisterFlowCounters);
    expect(finalCounters).toEqual({
      registerCalls: 1,
      loginCalls: 1,
      bootstrapCalls: ['alice.testnet:tempo', 'alice.testnet:evm'],
      tempoSigns: 1,
      evmSigns: 1,
    });
  });

  test('tempo threshold signing retries with forced reprovision when warm session expires', async ({
    page,
  }) => {
    await mountTempoRetryHarness(page);

    const scope = page.locator('#docs-tempo-retry-mount');
    const tempoButton = scope.getByRole('button', { name: 'Sign Tempo Threshold Transaction' });
    await expect(tempoButton).toBeVisible();

    await tempoButton.evaluate((el: HTMLElement) => el.click());

    await page.waitForFunction(() => {
      const counters = (window as any).__docsTempoRetryCounters;
      if (!counters) return false;
      if (counters.tempoSignAttempts !== 2) return false;
      if (!Array.isArray(counters.resolveCalls) || counters.resolveCalls.length !== 2) return false;
      return counters.resolveCalls[1].forceReprovision === true;
    });

    const counters = await page.evaluate(() => (window as any).__docsTempoRetryCounters);
    expect(counters.tempoSignAttempts).toBe(2);
    expect(counters.resolveCalls).toEqual([
      { chain: 'tempo', forceReprovision: false },
      { chain: 'tempo', forceReprovision: true },
    ]);
    await expect(scope.getByText(/Tempo sender hash:/i)).toBeVisible();
  });

  test('lazy provisioning shows signing busy state and updates signer readiness when complete', async ({
    page,
  }) => {
    await mountProvisionUiHarness(page);

    const scope = page.locator('#docs-provision-ui-mount');
    const tempoButton = scope.getByRole('button', { name: 'Sign Tempo Threshold Transaction' });

    await expect(scope.getByText(/EVM signer:\s*not provisioned/i)).toBeVisible();
    await expect(scope.getByText(/Tempo signer:\s*not provisioned/i)).toBeVisible();
    await expect(tempoButton).toBeVisible();

    await tempoButton.evaluate((el: HTMLElement) => el.click());

    const busyButton = scope.getByRole('button', { name: 'Signing...' });
    await expect(busyButton).toBeVisible();
    await expect(busyButton).toBeDisabled();

    const countersDuringProvision = await page.evaluate(() => (window as any).__docsProvisionUiCounters);
    expect(countersDuringProvision.resolveCalls).toBe(1);
    expect(countersDuringProvision.tempoSignCalls).toBe(0);

    await page.evaluate(() => {
      (window as any).__releaseDocsProvision?.();
    });

    await expect(scope.getByText(/Tempo signer:\s*ready/i)).toBeVisible();
    await expect(scope.getByText(/EVM signer:\s*not provisioned/i)).toBeVisible();
    await expect(scope.getByText(/Tempo sender hash:/i)).toBeVisible();
    await expect(tempoButton).toBeVisible();
    await expect(tempoButton).toBeEnabled();

    const countersAfterProvision = await page.evaluate(() => (window as any).__docsProvisionUiCounters);
    expect(countersAfterProvision.resolveCalls).toBe(1);
    expect(countersAfterProvision.tempoSignCalls).toBe(1);
  });
});
