import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  demoPage: '/src/flows/demo/DemoPage.tsx',
} as const;

const TEMPO_GREETING_CONTRACT = '0xBB442B54c85efBa2D7B81eA52990ad638cDbA483';
const ARC_TESTNET_GREETING_CONTRACT = '0xeB7aB5A6F761072C96147A54B8a15F012e836691';
const SET_GREETING_SELECTOR = '0xa4136862';

test.describe('docs frontend signing actions smoke', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('logged-in demo invokes NEAR action + Tempo/EVM threshold signing actions', async ({
    page,
  }) => {
    await page.evaluate(
      async ({ paths }) => {
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
          ((await import(viteReactDomPath).catch(() => null)) as any) ||
          (await import('react-dom'));
        const ReactDOMRuntime = (ReactDOM as any).default || ReactDOM;
        const demoMod = await import(paths.demoPage);
        const DemoPage = (demoMod as any).DemoPage || (demoMod as any).default;
        if (!DemoPage) {
          throw new Error('Failed to load DemoPage module export');
        }

        const counters = {
          nearActions: 0,
          tempoSigns: 0,
          evmSigns: 0,
          tempoDispatches: 0,
          evmDispatches: 0,
          tempoReceiptPolls: 0,
          evmReceiptPolls: 0,
        };
        (window as any).__docsSigningSmokeCounters = counters;
        (window as any).__docsSigningSmokeRequests = {
          tempo: null,
          evm: null,
          tempoRawTx: null,
          evmRawTx: null,
        };

        const greetings = {
          tempo: 'Hello, world!',
          evm: 'Hello, world!',
        };
        const thresholdEvmAddress = '0x1111111111111111111111111111111111111111';
        const tempoFeeToken = '0x20c0000000000000000000000000000000000001';
        const txHashes = {
          tempo: `0x${'11'.repeat(32)}`,
          evm: `0x${'22'.repeat(32)}`,
        };

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
          const url =
            typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
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
            const call =
              rpcParams[0] && typeof rpcParams[0] === 'object'
                ? (rpcParams[0] as Record<string, unknown>)
                : {};
            const callData = String(call.data || '').toLowerCase();
            if (callData.startsWith('0xed498fa8')) {
              return new Response(
                JSON.stringify({
                  jsonrpc: '2.0',
                  id,
                  result: `0x${'0'.repeat(24)}${tempoFeeToken.slice(2)}`,
                }),
                { status: 200, headers: { 'content-type': 'application/json' } },
              );
            }
            if (callData.startsWith('0x70a08231')) {
              return new Response(
                JSON.stringify({
                  jsonrpc: '2.0',
                  id,
                  result: '0xde0b6b3a7640000',
                }),
                { status: 200, headers: { 'content-type': 'application/json' } },
              );
            }
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
          if (rpcMethod === 'eth_getBlockByNumber') {
            return new Response(
              JSON.stringify({
                jsonrpc: '2.0',
                id,
                result: {
                  number: '0x1',
                  baseFeePerGas: '0x3b9aca00',
                },
              }),
              { status: 200, headers: { 'content-type': 'application/json' } },
            );
          }

          return await originalFetch(input, init);
        }) as typeof fetch;

        function useSeamsHook() {
          return {
            loginState: {
              isLoggedIn: true,
              nearAccountId: 'alice.testnet',
            },
            seams: {
              auth: {
                getWalletSession: async () => ({
                  login: {
                    thresholdEcdsaEthereumAddress: thresholdEvmAddress,
                    publicKey: `ed25519:${'1'.repeat(64)}`,
                  },
                  signingSession: {
                    sessionId: 'session-1',
                    status: 'active',
                    remainingUses: 3,
                    expiresAtMs: Date.now() + 60_000,
                    createdAtMs: Date.now(),
                  },
                }),
                getSession: async () => ({
                  login: {
                    thresholdEcdsaEthereumAddress: thresholdEvmAddress,
                  },
                  signingSession: {
                    sessionId: 'session-1',
                    status: 'active',
                    remainingUses: 3,
                    expiresAtMs: Date.now() + 60_000,
                    createdAtMs: Date.now(),
                  },
                }),
                unlock: async () => ({ success: true }),
                login: async () => ({ success: true }),
              },
              near: {
                signAndSendTransactions: async (args: any) => {
                  counters.nearActions += 1;
                  args?.options?.afterCall?.(true, [
                    {
                      success: true,
                      transactionId: 'mock-near-tx',
                    },
                  ]);
                  return { success: true };
                },
                executeAction: async (args: any) => {
                  counters.nearActions += 1;
                  args?.options?.afterCall?.(true, {
                    success: true,
                    transactionId: 'mock-near-tx',
                  });
                  return { success: true };
                },
                signDelegateAction: async () => ({
                  hash: 'mock-hash',
                  signedDelegate: {},
                }),
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
                executeEvmFamilyTransaction: async (args: any) => {
                  const kind = String(args?.request?.kind || '').trim();
                  const chain = String(args?.request?.chain || '').trim();
                  const chainId = Number(args?.request?.tx?.chainId ?? 0);
                  const to = String(args?.request?.tx?.to ?? '');
                  const data = String(args?.request?.tx?.data ?? '');

                  if (kind === 'eip1559') {
                    if (chainId === 42431) {
                      counters.tempoSigns += 1;
                      counters.tempoDispatches += 1;
                      counters.tempoReceiptPolls += 2;
                      (window as any).__docsSigningSmokeRequests.tempo = {
                        chain,
                        kind,
                        chainId,
                        to,
                        data,
                      };
                      greetings.tempo = 'Tempo greeting updated';
                    } else {
                      counters.evmSigns += 1;
                      counters.evmDispatches += 1;
                      counters.evmReceiptPolls += 2;
                      (window as any).__docsSigningSmokeRequests.evm = {
                        chain,
                        kind,
                        chainId,
                        to,
                        data,
                      };
                      greetings.evm = 'Arc greeting updated';
                    }
                    await args?.postFinalizationCheck?.();
                    return {
                      txHash: chainId === 42431 ? txHashes.tempo : txHashes.evm,
                      signedResult: {
                        kind: 'eip1559',
                        txHashHex: `0x${'cd'.repeat(32)}`,
                        rawTxHex: `0x02${'34'.repeat(31)}`,
                      },
                      payloadVerification: {
                        verified: true,
                        reason: 'matched',
                      },
                    };
                  }

                  throw new Error(`Unsupported request kind in smoke mock: ${kind}`);
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
              configs: { relayer: { url: 'https://relay.example' } },
            },
          };
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
        mount.id = 'demo-page-test-mount';
        document.body.appendChild(mount);

        const root = ReactDOMClientRuntime.createRoot(mount);
        ReactDOMRuntime.flushSync(() => {
          root.render(
            ReactRuntime.createElement(DemoPage, {
              __testOverrides: {
                useSeamsHook,
                useSetGreetingHook,
              },
            }),
          );
        });
      },
      { paths: IMPORT_PATHS },
    );

    const scope = page.locator('#demo-page-test-mount');
    const nearActionButton = scope.getByRole('button', { name: 'Set Greeting' });
    const tempoButton = scope.getByRole('button', { name: 'Sign Tempo Transaction' });
    const evmButton = scope.getByRole('button', { name: 'Sign EVM Transaction' });

    await expect(nearActionButton).toBeVisible();
    await expect(tempoButton).toBeVisible();
    await expect(evmButton).toBeVisible();

    await nearActionButton.evaluate((el: HTMLElement) => el.click());
    await tempoButton.evaluate((el: HTMLElement) => el.click());
    await evmButton.evaluate((el: HTMLElement) => el.click());

    await page.waitForFunction(() => {
      const counters = (window as any).__docsSigningSmokeCounters;
      return (
        counters &&
        counters.nearActions === 1 &&
        counters.tempoSigns >= 1 &&
        counters.evmSigns >= 1 &&
        counters.tempoDispatches >= 1 &&
        counters.evmDispatches >= 1 &&
        counters.tempoReceiptPolls >= 2 &&
        counters.evmReceiptPolls >= 2
      );
    });

    const counters = await page.evaluate(() => (window as any).__docsSigningSmokeCounters);
    expect(counters.nearActions).toBe(1);
    expect(counters.tempoSigns).toBeGreaterThanOrEqual(1);
    expect(counters.evmSigns).toBeGreaterThanOrEqual(1);
    expect(counters.tempoDispatches).toBeGreaterThanOrEqual(1);
    expect(counters.evmDispatches).toBeGreaterThanOrEqual(1);
    expect(counters.tempoReceiptPolls).toBeGreaterThanOrEqual(2);
    expect(counters.evmReceiptPolls).toBeGreaterThanOrEqual(2);

    const requests = await page.evaluate(() => (window as any).__docsSigningSmokeRequests);
    expect(requests.evm).toMatchObject({
      chain: 'evm',
      kind: 'eip1559',
      chainId: 5042002,
      to: ARC_TESTNET_GREETING_CONTRACT,
    });
    expect(requests.evm.data.startsWith(SET_GREETING_SELECTOR)).toBe(true);
    expect(requests.tempo).toMatchObject({
      chain: 'evm',
      kind: 'eip1559',
      chainId: 42431,
      to: TEMPO_GREETING_CONTRACT,
    });
    expect(requests.tempo.data.startsWith(SET_GREETING_SELECTOR)).toBe(true);

    await expect(scope.getByText('Tempo greeting updated')).toBeVisible();
    await expect(scope.getByText('Arc greeting updated')).toBeVisible();
  });

  test('demo Tempo signing surfaces post-finalization mismatch through UI error path', async ({
    page,
  }) => {
    await page.evaluate(
      async ({ paths }) => {
        const viteReactPath = '/node_modules/.vite/deps/react.js' as string;
        const viteReactDomClientPath = '/node_modules/.vite/deps/react-dom_client.js' as string;
        const viteReactDomPath = '/node_modules/.vite/deps/react-dom.js' as string;
        const viteSonnerPath = '/node_modules/.vite/deps/sonner.js' as string;
        const React =
          ((await import(viteReactPath).catch(() => null)) as any) || (await import('react'));
        const ReactRuntime = (React as any).default || React;
        const ReactDOMClient =
          ((await import(viteReactDomClientPath).catch(() => null)) as any) ||
          (await import('react-dom/client'));
        const ReactDOMClientRuntime = (ReactDOMClient as any).default || ReactDOMClient;
        const ReactDOM =
          ((await import(viteReactDomPath).catch(() => null)) as any) ||
          (await import('react-dom'));
        const ReactDOMRuntime = (ReactDOM as any).default || ReactDOM;
        const sonnerMod =
          ((await import(viteSonnerPath).catch(() => null)) as any) || (await import('sonner'));
        const Toaster = (sonnerMod as any).Toaster;
        const demoMod = await import(paths.demoPage);
        const DemoPage = (demoMod as any).DemoPage || (demoMod as any).default;
        if (!DemoPage) {
          throw new Error('Failed to load DemoPage module export');
        }

        const greetings = {
          tempo: 'Hello, world!',
          evm: 'Hello, world!',
        };
        const thresholdEvmAddress = '0x1111111111111111111111111111111111111111';

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
          const url =
            typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
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
          if (rpcMethod === 'eth_getBlockByNumber') {
            return new Response(
              JSON.stringify({
                jsonrpc: '2.0',
                id,
                result: {
                  number: '0x1',
                  baseFeePerGas: '0x3b9aca00',
                },
              }),
              { status: 200, headers: { 'content-type': 'application/json' } },
            );
          }

          return await originalFetch(input, init);
        }) as typeof fetch;

        function useSeamsHook() {
          return {
            loginState: {
              isLoggedIn: true,
              nearAccountId: 'alice.testnet',
            },
            seams: {
              auth: {
                getWalletSession: async () => ({
                  login: {
                    thresholdEcdsaEthereumAddress: thresholdEvmAddress,
                    publicKey: `ed25519:${'1'.repeat(64)}`,
                  },
                  signingSession: {
                    sessionId: 'session-1',
                    status: 'active',
                    remainingUses: 3,
                    expiresAtMs: Date.now() + 60_000,
                    createdAtMs: Date.now(),
                  },
                }),
                unlock: async () => ({ success: true }),
              },
              near: {
                signAndSendTransactions: async () => ({ success: true }),
                executeAction: async () => ({ success: true }),
                signDelegateAction: async () => ({
                  hash: 'mock-hash',
                  signedDelegate: {},
                }),
                sendDelegateActionViaRelayer: async () => ({
                  ok: true,
                  relayerTxHash: 'mock-relayer-tx',
                }),
              },
              tempo: {
                executeEvmFamilyTransaction: async (args: any) => {
                  const chainId = Number(args?.request?.tx?.chainId ?? 0);
                  if (chainId === 42431) {
                    const err = new Error('stale payload detected after finalization') as Error & {
                      code?: string;
                    };
                    err.code = 'post_finalization_state_mismatch';
                    throw err;
                  }
                  greetings.evm = 'Arc greeting updated';
                  await args?.postFinalizationCheck?.();
                  return {
                    txHash: `0x${'22'.repeat(32)}`,
                    payloadVerification: { verified: true, reason: 'matched' },
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
              configs: { relayer: { url: 'https://relay.example' } },
            },
          };
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
        mount.id = 'demo-page-post-finalization-mismatch-mount';
        document.body.appendChild(mount);

        const root = ReactDOMClientRuntime.createRoot(mount);
        ReactDOMRuntime.flushSync(() => {
          root.render(
            ReactRuntime.createElement(
              ReactRuntime.Fragment,
              null,
              ReactRuntime.createElement(Toaster),
              ReactRuntime.createElement(DemoPage, {
                __testOverrides: {
                  useSeamsHook,
                  useSetGreetingHook,
                },
              }),
            ),
          );
        });
      },
      { paths: IMPORT_PATHS },
    );

    const scope = page.locator('#demo-page-post-finalization-mismatch-mount');
    const tempoButton = scope.getByRole('button', { name: 'Sign Tempo Transaction' });
    await expect(tempoButton).toBeVisible();
    await tempoButton.evaluate((el: HTMLElement) => el.click());

    await expect(
      page.getByText(/Tempo transaction finalized, but post-finalization refresh failed:/i),
    ).toBeVisible();
    await expect(tempoButton).toBeEnabled();
  });
});
