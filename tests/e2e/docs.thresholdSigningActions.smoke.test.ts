import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  demoPage: '/src/components/DemoPage.tsx',
} as const;

const TEMPO_GREETING_CONTRACT = '0x96cFE92241481954AdA6410409a86AcB6E76a00e';
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

          if (rpcMethod === 'eth_sendRawTransaction') {
            const rawTxHex = String(rpcParams[0] || '');
            if (chain === 'tempo') {
              counters.tempoDispatches += 1;
              greetings.tempo = 'Tempo greeting updated';
              (window as any).__docsSigningSmokeRequests.tempoRawTx = rawTxHex;
            } else {
              counters.evmDispatches += 1;
              greetings.evm = 'Arc greeting updated';
              (window as any).__docsSigningSmokeRequests.evmRawTx = rawTxHex;
            }
            txHashesSeen.add(txHashes[chain]);
            return new Response(JSON.stringify({ jsonrpc: '2.0', id, result: txHashes[chain] }), {
              status: 200,
              headers: { 'content-type': 'application/json' },
            });
          }

          if (rpcMethod === 'eth_getTransactionReceipt') {
            const txHash = String(rpcParams[0] || '');
            const receiptChain =
              txHash === txHashes.tempo ? 'tempo' : txHash === txHashes.evm ? 'evm' : chain;
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

        function useTatchiHook() {
          return {
            loginState: {
              isLoggedIn: true,
              nearAccountId: 'alice.testnet',
            },
            tatchi: {
              auth: {
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
                signTempo: async (args: any) => {
                  const kind = String(args?.request?.kind || '').trim();
                  const chain = String(args?.request?.chain || '').trim();

                  if (kind === 'eip1559') {
                    counters.evmSigns += 1;
                    (window as any).__docsSigningSmokeRequests.evm = {
                      chain,
                      kind,
                      chainId: String(args?.request?.tx?.chainId ?? ''),
                      to: String(args?.request?.tx?.to ?? ''),
                      data: String(args?.request?.tx?.data ?? ''),
                    };
                    return {
                      kind: 'eip1559',
                      txHashHex: `0x${'cd'.repeat(32)}`,
                      rawTxHex: `0x02${'34'.repeat(31)}`,
                    };
                  }

                  counters.tempoSigns += 1;
                  (window as any).__docsSigningSmokeRequests.tempo = {
                    chain,
                    kind,
                    chainId: String(args?.request?.tx?.chainId ?? ''),
                    calls: Array.isArray(args?.request?.tx?.calls)
                      ? args.request.tx.calls.map((call: any) => ({
                          to: String(call?.to ?? ''),
                          input: String(call?.input ?? ''),
                        }))
                      : [],
                  };
                  return {
                    kind: 'tempoTransaction',
                    senderHashHex: `0x${'ab'.repeat(32)}`,
                    rawTxHex: `0x76${'12'.repeat(31)}`,
                  };
                },
                reportBroadcastResult: async () => ({ ok: true }),
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
                useTatchiHook,
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
      chain: 'tempo',
      kind: 'tempoTransaction',
      chainId: 42431,
    });
    expect(requests.tempo.calls).toHaveLength(1);
    expect(requests.tempo.calls[0]).toMatchObject({ to: TEMPO_GREETING_CONTRACT });
    expect(requests.tempo.calls[0].input.startsWith(SET_GREETING_SELECTOR)).toBe(true);
    expect(String(requests.tempoRawTx || '').startsWith('0x')).toBe(true);
    expect(String(requests.evmRawTx || '').startsWith('0x')).toBe(true);

    await expect(scope.getByText('Tempo greeting updated')).toBeVisible();
    await expect(scope.getByText('Arc greeting updated')).toBeVisible();
  });
});
