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
      tempoDispatches: 0,
      evmDispatches: 0,
      tempoReceiptPolls: 0,
      evmReceiptPolls: 0,
    };
    (window as any).__docsRegisterFlowCounters = counters;

    const greetings = {
      tempo: 'Hello, world!',
      evm: 'Hello, world!',
    };
    const txHashes = {
      tempo: `0x${'11'.repeat(32)}`,
      evm: `0x${'22'.repeat(32)}`,
    };
    const txHashesSeen = new Set<string>();

    const encodeAbiString = (value: string): string => {
      const bytes = new TextEncoder().encode(value);
      const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
      const paddedHexLength = Math.ceil(bytes.length / 32) * 64;
      return `0x${(32).toString(16).padStart(64, '0')}${bytes.length
        .toString(16)
        .padStart(64, '0')}${hex.padEnd(paddedHexLength, '0')}`;
    };

    const originalFetch = window.fetch.bind(window);
    window.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === 'string'
        ? input
        : input instanceof URL
          ? input.href
          : input.url;
      const method = String(init?.method || 'GET').toUpperCase();
      const isTempoRpc = url.includes('rpc.moderato.tempo.xyz');
      const isArcRpc = url.includes('rpc.testnet.arc.network');
      if (method !== 'POST' || (!isTempoRpc && !isArcRpc)) {
        return await originalFetch(input, init);
      }

      const chain = isTempoRpc ? 'tempo' : 'evm';
      let body: Record<string, unknown> = {};
      try {
        body = JSON.parse(String(init?.body || '{}')) as Record<string, unknown>;
      } catch {}

      const rpcMethod = String(body.method || '');
      const rpcParams = Array.isArray(body.params) ? body.params : [];
      const id = body.id ?? Date.now();

      if (rpcMethod === 'eth_call') {
        return new Response(
          JSON.stringify({
            jsonrpc: '2.0',
            id,
            result: encodeAbiString(greetings[chain]),
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      if (rpcMethod === 'eth_gasPrice') {
        return new Response(
          JSON.stringify({
            jsonrpc: '2.0',
            id,
            result: '0x4a817c800',
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }

      if (rpcMethod === 'eth_sendRawTransaction') {
        if (chain === 'tempo') {
          counters.tempoDispatches += 1;
          greetings.tempo = 'Tempo greeting updated';
        } else {
          counters.evmDispatches += 1;
          greetings.evm = 'Arc greeting updated';
        }
        txHashesSeen.add(txHashes[chain]);
        return new Response(
          JSON.stringify({ jsonrpc: '2.0', id, result: txHashes[chain] }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }

      if (rpcMethod === 'eth_getTransactionReceipt') {
        const txHash = String(rpcParams[0] || '');
        const receiptChain = txHash === txHashes.tempo ? 'tempo' : txHash === txHashes.evm ? 'evm' : chain;
        if (!txHashesSeen.has(txHash)) {
          return new Response(JSON.stringify({ jsonrpc: '2.0', id, result: null }), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          });
        }

        if (receiptChain === 'tempo') {
          counters.tempoReceiptPolls += 1;
          if (counters.tempoReceiptPolls < 2) {
            return new Response(JSON.stringify({ jsonrpc: '2.0', id, result: null }), {
              status: 200,
              headers: { 'content-type': 'application/json' },
            });
          }
        } else {
          counters.evmReceiptPolls += 1;
          if (counters.evmReceiptPolls < 2) {
            return new Response(JSON.stringify({ jsonrpc: '2.0', id, result: null }), {
              status: 200,
              headers: { 'content-type': 'application/json' },
            });
          }
        }

        return new Response(
          JSON.stringify({
            jsonrpc: '2.0',
            id,
            result: {
              transactionHash: txHash,
              blockNumber: '0x1',
              status: '0x1',
            },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }

      return await originalFetch(input, init);
    }) as typeof fetch;

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
            counters.bootstrapCalls.push(`${accountId}:tempo`);
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
            bootstrapEcdsaSession: async () => ({
              keygen: { ok: true },
              session: {
                ok: true,
                sessionId: 'tempo-session-1',
                expiresAtMs: Date.now() + 60_000,
                remainingUses: 3,
              },
            }),
            signTempo: async (args: any) => {
              if (args?.request?.kind === 'eip1559') {
                counters.evmSigns += 1;
                return {
                  kind: 'eip1559' as const,
                  txHashHex: `0x${'cd'.repeat(32)}`,
                  rawTxHex: `0x${'34'.repeat(64)}`,
                };
              }
              counters.tempoSigns += 1;
              return {
                kind: 'tempoTransaction' as const,
                senderHashHex: `0x${'ab'.repeat(32)}`,
                rawTxHex: `0x${'12'.repeat(64)}`,
              };
            },
          },
          evm: {
            bootstrapEcdsaSession: async () => ({
              keygen: { ok: true },
              session: {
                ok: true,
                sessionId: 'evm-session-1',
                expiresAtMs: Date.now() + 60_000,
                remainingUses: 3,
              },
            }),
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

test.describe('docs frontend register + threshold signing integration', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('register/login provisions threshold signers during login, then signs Tempo and EVM', async ({
    page,
  }) => {
    await mountRegisterToSigningHarness(page);

    const scope = page.locator('#docs-register-to-signing-root');

    await expect(scope.getByRole('button', { name: 'Sign Tempo Transaction' })).toHaveCount(0);

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

    const tempoButton = scope.getByRole('button', { name: 'Sign Tempo Transaction' });
    const evmButton = scope.getByRole('button', {
      name: 'Sign EVM Transaction',
    });

    await expect(tempoButton).toBeVisible();
    await expect(evmButton).toBeVisible();
    await expect(scope.getByText(/Tempo Greeting/i)).toBeVisible();
    await expect(scope.getByText(/Arc Greeting/i)).toBeVisible();

    await tempoButton.evaluate((el: HTMLElement) => el.click());
    await evmButton.evaluate((el: HTMLElement) => el.click());

    await page.waitForFunction(() => {
      const counters = (window as any).__docsRegisterFlowCounters;
      return (
        counters &&
        counters.loginCalls === 1 &&
        counters.bootstrapCalls.length === 1 &&
        counters.tempoSigns >= 1 &&
        counters.evmSigns >= 1 &&
        counters.tempoDispatches >= 1 &&
        counters.evmDispatches >= 1 &&
        counters.tempoReceiptPolls >= 2 &&
        counters.evmReceiptPolls >= 2
      );
    });

    const finalCounters = await page.evaluate(() => (window as any).__docsRegisterFlowCounters);
    expect(finalCounters.registerCalls).toBe(1);
    expect(finalCounters.loginCalls).toBe(1);
    expect(finalCounters.bootstrapCalls).toEqual(['alice.testnet:tempo']);
    expect(finalCounters.tempoSigns).toBeGreaterThanOrEqual(1);
    expect(finalCounters.evmSigns).toBeGreaterThanOrEqual(1);
    expect(finalCounters.tempoDispatches).toBeGreaterThanOrEqual(1);
    expect(finalCounters.evmDispatches).toBeGreaterThanOrEqual(1);
    expect(finalCounters.tempoReceiptPolls).toBeGreaterThanOrEqual(2);
    expect(finalCounters.evmReceiptPolls).toBeGreaterThanOrEqual(2);

    await expect(scope.getByText('Tempo greeting updated')).toBeVisible();
    await expect(scope.getByText('Arc greeting updated')).toBeVisible();
  });
});
