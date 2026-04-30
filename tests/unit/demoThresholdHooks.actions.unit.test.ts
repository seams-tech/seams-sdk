import { expect, test } from '@playwright/test';

import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  demoHelpers: '/src/flows/demo/demoEvmHelpers.ts',
  tempoFeeTokenHook: '/src/flows/demo/hooks/useDemoTempoFeeTokenActions.tsx',
  tempoSigningHook: '/src/flows/demo/hooks/useDemoTempoSigningActions.tsx',
  arcSigningHook: '/src/flows/demo/hooks/useDemoArcSigningActions.tsx',
} as const;

const TEMPO_RPC = 'rpc.moderato.tempo.xyz';
const ARC_RPC = 'rpc.testnet.arc.network';
const ARC_TESTNET_GREETING_CONTRACT = '0xeB7aB5A6F761072C96147A54B8a15F012e836691';

test.describe('demo threshold action hooks', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('useDemoTempoFeeTokenActions signs and broadcasts setUserToken flow', async ({ page }) => {
    const result = await page.evaluate(async ({ paths, tempoRpcHost }) => {
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
      const mod = await import(paths.tempoFeeTokenHook);
      const useDemoTempoFeeTokenActions = (mod as any).useDemoTempoFeeTokenActions;
      if (!useDemoTempoFeeTokenActions) {
        throw new Error('Failed to load useDemoTempoFeeTokenActions export');
      }

      const counters = {
        executeEvmFamilyTransactionCalls: 0,
        refreshTokenCalls: 0,
        refreshBalanceCalls: 0,
        requestChain: '',
        requestKind: '',
        requestChainId: 0,
        requestTo: '',
        requestData: '',
      };

      const thresholdSender = '0x1111111111111111111111111111111111111111';
      const selectedToken = '0x20c0000000000000000000000000000000000001';
      const txHash = `0x${'22'.repeat(32)}`;

      const originalFetch = window.fetch.bind(window);
      window.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
        const url =
          typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
        if (!url.includes(tempoRpcHost) || String(init?.method || 'GET').toUpperCase() !== 'POST') {
          return await originalFetch(input, init);
        }

        let body: Record<string, unknown> = {};
        try {
          body = JSON.parse(String(init?.body || '{}')) as Record<string, unknown>;
        } catch {}
        const id = body.id ?? Date.now();
        const method = String(body.method || '');
        const params = Array.isArray(body.params) ? body.params : [];
        const call =
          params[0] && typeof params[0] === 'object' ? (params[0] as Record<string, unknown>) : {};
        const callData = String(call.data || '').toLowerCase();

        if (method === 'eth_getBalance') {
          return new Response(JSON.stringify({ jsonrpc: '2.0', id, result: '0xde0b6b3a7640000' }), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          });
        }
        if (method === 'eth_call') {
          if (callData.startsWith('0x70a08231')) {
            return new Response(
              JSON.stringify({ jsonrpc: '2.0', id, result: '0xde0b6b3a7640000' }),
              { status: 200, headers: { 'content-type': 'application/json' } },
            );
          }
          const paddedToken = `0x${'0'.repeat(24)}${selectedToken.slice(2)}`;
          return new Response(JSON.stringify({ jsonrpc: '2.0', id, result: paddedToken }), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          });
        }
        if (method === 'eth_getBlockByNumber') {
          return new Response(
            JSON.stringify({
              jsonrpc: '2.0',
              id,
              result: { number: '0x1', baseFeePerGas: '0x3b9aca00' },
            }),
            { status: 200, headers: { 'content-type': 'application/json' } },
          );
        }

        return await originalFetch(input, init);
      }) as typeof fetch;

      let hookApi: any = null;
      function Harness() {
        hookApi = useDemoTempoFeeTokenActions({
          isLoggedIn: true,
          nearAccountId: 'alice.testnet',
          seams: {
            tempo: {
              executeEvmFamilyTransaction: async (args: any) => {
                counters.executeEvmFamilyTransactionCalls += 1;
                counters.requestChain = String(args?.request?.chain || '');
                counters.requestKind = String(args?.request?.kind || '');
                counters.requestChainId = Number(args?.request?.tx?.chainId || 0);
                counters.requestTo = String(args?.request?.tx?.to || '');
                counters.requestData = String(args?.request?.tx?.data || '');
                await args?.postFinalizationCheck?.();
                return {
                  txHash,
                  signedResult: {
                    kind: 'eip1559',
                    txHashHex: `0x${'cd'.repeat(32)}`,
                    rawTxHex: `0x02${'34'.repeat(31)}`,
                  },
                  payloadVerification: { verified: true, reason: 'matched' as const },
                };
              },
            },
          },
          tempoEip1559FeeCaps: {
            maxPriorityFeePerGas: 2_000_000_000n,
            maxFeePerGas: 40_000_000_000n,
          },
          resolveThresholdSenderForEvmFamily: async () => thresholdSender,
          refreshTempoUserFeeToken: async () => {
            counters.refreshTokenCalls += 1;
            return selectedToken;
          },
          refreshTempoUserFeeTokenBalance: async () => {
            counters.refreshBalanceCalls += 1;
            return 1n;
          },
        });
        return ReactRuntime.createElement('div', null);
      }

      const mount = document.createElement('div');
      document.body.appendChild(mount);
      const root = ReactDOMClientRuntime.createRoot(mount);
      ReactDOMRuntime.flushSync(() => {
        root.render(ReactRuntime.createElement(Harness));
      });

      await hookApi.handleSetTempoFeeTokenAlphaUsd();
      await new Promise((resolve) => window.setTimeout(resolve, 0));
      const stateAfter = {
        loading: Boolean(hookApi.tempoFeeTokenConfigLoading),
        target: hookApi.tempoFeeTokenConfigTarget,
      };
      root.unmount();
      return { counters, stateAfter };
    }, { paths: IMPORT_PATHS, tempoRpcHost: TEMPO_RPC });

    expect(result.counters.executeEvmFamilyTransactionCalls).toBe(1);
    expect(result.counters.refreshTokenCalls).toBeGreaterThanOrEqual(1);
    expect(result.counters.refreshBalanceCalls).toBeGreaterThanOrEqual(1);
    expect(result.counters.requestChain).toBe('evm');
    expect(result.counters.requestKind).toBe('eip1559');
    expect(result.counters.requestChainId).toBe(42431);
    expect(result.counters.requestTo).toBe('0xfeec000000000000000000000000000000000000');
    expect(result.counters.requestData).toMatch(/^0xe7897444/i);
    expect(result.counters.requestData.toLowerCase()).toContain(
      '20c0000000000000000000000000000000000001',
    );
    expect(result.stateAfter.loading).toBe(false);
    expect(result.stateAfter.target).toBeNull();
  });

  test('useDemoTempoSigningActions runs drip + tempo sign paths', async ({ page }) => {
    const result = await page.evaluate(async ({ paths, tempoRpcHost }) => {
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
      const mod = await import(paths.tempoSigningHook);
      const useDemoTempoSigningActions = (mod as any).useDemoTempoSigningActions;
      if (!useDemoTempoSigningActions) {
        throw new Error('Failed to load useDemoTempoSigningActions export');
      }

      const counters = {
        executeEvmFamilyTransactionCalls: 0,
        fetchTempoGreetingCalls: 0,
        refreshFundingAddressCalls: 0,
        refreshBalanceCalls: 0,
        requestChainIds: [] as number[],
        dripIdempotencyKeys: [] as string[],
        dripWalletAddresses: [] as string[],
        dripCallData: [] as string[],
      };
      const thresholdSender = '0x1111111111111111111111111111111111111111';
      const txHashBase = `0x${'33'.repeat(31)}`;
      const tempoGreetingInput = 'Hello from extracted tempo hook';
      let txCounter = 0;
      let dripCounter = 0;
      const originalFetch = window.fetch.bind(window);
      window.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
        const url =
          typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
        if (url.includes('/sponsorships/evm/call') && String(init?.method || 'GET').toUpperCase() === 'POST') {
          let body: Record<string, unknown> = {};
          try {
            body = JSON.parse(String(init?.body || '{}')) as Record<string, unknown>;
          } catch {}
          counters.dripIdempotencyKeys.push(String(body.idempotencyKey || ''));
          counters.dripWalletAddresses.push(String(body.walletAddress || ''));
          const call =
            body.call && typeof body.call === 'object' ? (body.call as Record<string, unknown>) : {};
          counters.dripCallData.push(String(call.data || ''));
          dripCounter += 1;
          const dripTxHash = `${`0x${'44'.repeat(31)}`}${String(dripCounter).padStart(2, '0')}`.slice(0, 66);
          return new Response(
            JSON.stringify({
              ok: true,
              txHash: dripTxHash,
              policyId: 'policy_tempo_drip',
            }),
            { status: 200, headers: { 'content-type': 'application/json' } },
          );
        }
        if (!url.includes(tempoRpcHost) || String(init?.method || 'GET').toUpperCase() !== 'POST') {
          return await originalFetch(input, init);
        }
        let body: Record<string, unknown> = {};
        try {
          body = JSON.parse(String(init?.body || '{}')) as Record<string, unknown>;
        } catch {}
        const id = body.id ?? Date.now();
        const method = String(body.method || '');
        const params = Array.isArray(body.params) ? body.params : [];
        const call =
          params[0] && typeof params[0] === 'object' ? (params[0] as Record<string, unknown>) : {};
        const callData = String(call.data || '').toLowerCase();

        if (method === 'eth_getBalance') {
          return new Response(JSON.stringify({ jsonrpc: '2.0', id, result: '0xde0b6b3a7640000' }), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          });
        }
        if (method === 'eth_call') {
          if (callData.startsWith('0x70a08231')) {
            return new Response(
              JSON.stringify({ jsonrpc: '2.0', id, result: '0xde0b6b3a7640000' }),
              { status: 200, headers: { 'content-type': 'application/json' } },
            );
          }
          return new Response(JSON.stringify({ jsonrpc: '2.0', id, result: '0x' }), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          });
        }
        if (method === 'eth_getBlockByNumber') {
          return new Response(
            JSON.stringify({
              jsonrpc: '2.0',
              id,
              result: { number: '0x1', baseFeePerGas: '0x3b9aca00' },
            }),
            { status: 200, headers: { 'content-type': 'application/json' } },
          );
        }
        return await originalFetch(input, init);
      }) as typeof fetch;

      let hookApi: any = null;
      function Harness() {
        hookApi = useDemoTempoSigningActions({
          isLoggedIn: true,
          nearAccountId: 'alice.testnet',
          seams: {
            tempo: {
              executeEvmFamilyTransaction: async (args: any) => {
                counters.executeEvmFamilyTransactionCalls += 1;
                counters.requestChainIds.push(Number(args?.request?.tx?.chainId || 0));
                await args?.postFinalizationCheck?.();
                txCounter += 1;
                const txHash = `${txHashBase}${String(txCounter).padStart(2, '0')}`.slice(0, 66);
                return {
                  txHash: txHash as `0x${string}`,
                  signedResult: {
                    kind: 'eip1559',
                    txHashHex: `0x${'ef'.repeat(32)}`,
                    rawTxHex: `0x02${'56'.repeat(31)}`,
                  },
                  payloadVerification: { verified: true, reason: 'matched' as const },
                };
              },
            },
          },
          canSignTempo: true,
          frontendConfig: {
            managedRegistration: {
              mode: 'managed',
              environmentId: 'env-tempo-sponsor-prod',
              publishableKey: 'pk_test_tempo',
            },
            relayerUrl: 'https://localhost:9444',
            tempoExplorerUrl: 'https://explore.tempo.xyz',
            tempoRpcUrl: `https://${tempoRpcHost}`,
          },
          tempoGreetingInput,
          tempoEip1559FeeCaps: {
            maxPriorityFeePerGas: 2_000_000_000n,
            maxFeePerGas: 40_000_000_000n,
          },
          tempoUserFeeToken: null,
          resolveThresholdSenderForEvmFamily: async () => thresholdSender,
          refreshTempoUserFeeTokenBalance: async () => {
            counters.refreshBalanceCalls += 1;
            return 1n;
          },
          fetchTempoGreeting: async () => {
            counters.fetchTempoGreetingCalls += 1;
            return tempoGreetingInput;
          },
          refreshThresholdEvmFundingAddress: async () => {
            counters.refreshFundingAddressCalls += 1;
            return thresholdSender;
          },
        });
        return ReactRuntime.createElement('div', null);
      }

      const mount = document.createElement('div');
      document.body.appendChild(mount);
      const root = ReactDOMClientRuntime.createRoot(mount);
      ReactDOMRuntime.flushSync(() => {
        root.render(ReactRuntime.createElement(Harness));
      });

      await hookApi.handleTempoDripToken();
      await hookApi.handleTempoDripToken();
      await hookApi.handleSignTempoThresholdTx();
      await new Promise((resolve) => window.setTimeout(resolve, 0));
      const stateAfter = {
        tempoDripLoading: Boolean(hookApi.tempoDripLoading),
        tempoThresholdSignLoading: Boolean(hookApi.tempoThresholdSignLoading),
      };
      root.unmount();
      return { counters, stateAfter };
    }, { paths: IMPORT_PATHS, tempoRpcHost: TEMPO_RPC });

    expect(result.counters.executeEvmFamilyTransactionCalls).toBe(1);
    expect(result.counters.refreshBalanceCalls).toBeGreaterThanOrEqual(2);
    expect(result.counters.fetchTempoGreetingCalls).toBe(1);
    expect(result.counters.refreshFundingAddressCalls).toBe(1);
    expect(result.counters.requestChainIds).toEqual([42431]);
    expect(result.counters.dripIdempotencyKeys).toHaveLength(2);
    expect(result.counters.dripIdempotencyKeys[0]).toContain('tempo_drip_click:');
    expect(result.counters.dripIdempotencyKeys[1]).toContain('tempo_drip_click:');
    expect(result.counters.dripIdempotencyKeys[0]).not.toBe(result.counters.dripIdempotencyKeys[1]);
    expect(result.counters.dripWalletAddresses).toEqual([
      '0x1111111111111111111111111111111111111111',
      '0x1111111111111111111111111111111111111111',
    ]);
    expect(result.counters.dripCallData[0]).toMatch(/^0x867ae9d4/i);
    expect(result.counters.dripCallData[0]?.toLowerCase()).toContain(
      '1111111111111111111111111111111111111111',
    );
    expect(result.stateAfter.tempoDripLoading).toBe(false);
    expect(result.stateAfter.tempoThresholdSignLoading).toBe(false);
  });

  test('useDemoArcSigningActions signs and finalizes arc transaction via SDK lifecycle', async ({
    page,
  }) => {
    const result = await page.evaluate(async ({ paths, arcRpcHost }) => {
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
      const mod = await import(paths.arcSigningHook);
      const useDemoArcSigningActions = (mod as any).useDemoArcSigningActions;
      if (!useDemoArcSigningActions) {
        throw new Error('Failed to load useDemoArcSigningActions export');
      }

      const counters = {
        executeEvmFamilyTransactionCalls: 0,
        fetchArcGreetingCalls: 0,
        refreshFundingAddressCalls: 0,
        requestKind: '',
        requestChainId: 0,
        requestTo: '',
      };
      const txHash = `0x${'44'.repeat(32)}`;
      const expectedArcGreeting = 'Hello from arc hook';

      const originalFetch = window.fetch.bind(window);
      window.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
        const url =
          typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
        if (!url.includes(arcRpcHost) || String(init?.method || 'GET').toUpperCase() !== 'POST') {
          return await originalFetch(input, init);
        }
        let body: Record<string, unknown> = {};
        try {
          body = JSON.parse(String(init?.body || '{}')) as Record<string, unknown>;
        } catch {}
        const id = body.id ?? Date.now();
        const method = String(body.method || '');
        if (method === 'eth_getBlockByNumber') {
          return new Response(
            JSON.stringify({
              jsonrpc: '2.0',
              id,
              result: { number: '0x1', baseFeePerGas: '0x3b9aca00' },
            }),
            { status: 200, headers: { 'content-type': 'application/json' } },
          );
        }
        return await originalFetch(input, init);
      }) as typeof fetch;

      let hookApi: any = null;
      function Harness() {
        hookApi = useDemoArcSigningActions({
          canSignEvm: true,
          nearAccountId: 'alice.testnet',
          seams: {
            tempo: {
              executeEvmFamilyTransaction: async (args: any) => {
                counters.executeEvmFamilyTransactionCalls += 1;
                counters.requestKind = String(args?.request?.kind || '');
                counters.requestChainId = Number(args?.request?.tx?.chainId || 0);
                counters.requestTo = String(args?.request?.tx?.to || '');
                await args?.postFinalizationCheck?.();
                return {
                  txHash,
                  signedResult: {
                    kind: 'eip1559',
                    txHashHex: `0x${'ab'.repeat(32)}`,
                    rawTxHex: `0x02${'78'.repeat(31)}`,
                  },
                  payloadVerification: { verified: true, reason: 'matched' as const },
                };
              },
            },
          },
          arcGreetingInput: expectedArcGreeting,
          arcEip1559FeeCaps: {
            maxPriorityFeePerGas: 2_000_000_000n,
            maxFeePerGas: 40_000_000_000n,
          },
          fetchArcGreeting: async () => {
            counters.fetchArcGreetingCalls += 1;
            return 'ok';
          },
          refreshThresholdEvmFundingAddress: async () => {
            counters.refreshFundingAddressCalls += 1;
            return '0x1111111111111111111111111111111111111111';
          },
        });
        return ReactRuntime.createElement('div', null);
      }

      const mount = document.createElement('div');
      document.body.appendChild(mount);
      const root = ReactDOMClientRuntime.createRoot(mount);
      ReactDOMRuntime.flushSync(() => {
        root.render(ReactRuntime.createElement(Harness));
      });

      await hookApi.handleSignEvmThresholdTx();
      await new Promise((resolve) => window.setTimeout(resolve, 0));
      const stateAfter = {
        evmThresholdSignLoading: Boolean(hookApi.evmThresholdSignLoading),
      };
      root.unmount();
      return { counters, stateAfter };
    }, { paths: IMPORT_PATHS, arcRpcHost: ARC_RPC });

    expect(result.counters.executeEvmFamilyTransactionCalls).toBe(1);
    expect(result.counters.fetchArcGreetingCalls).toBe(1);
    expect(result.counters.refreshFundingAddressCalls).toBe(1);
    expect(result.counters.requestKind).toBe('eip1559');
    expect(result.counters.requestChainId).toBe(5042002);
    expect(result.counters.requestTo).toBe(ARC_TESTNET_GREETING_CONTRACT);
    expect(result.stateAfter.evmThresholdSignLoading).toBe(false);
  });

  test('useDemoArcSigningActions handles post-finalization mismatch from SDK', async ({ page }) => {
    const result = await page.evaluate(async ({ paths, arcRpcHost }) => {
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
      const mod = await import(paths.arcSigningHook);
      const useDemoArcSigningActions = (mod as any).useDemoArcSigningActions;
      if (!useDemoArcSigningActions) {
        throw new Error('Failed to load useDemoArcSigningActions export');
      }

      const counters = {
        executeEvmFamilyTransactionCalls: 0,
        fetchArcGreetingCalls: 0,
        consoleMarkers: [] as string[],
      };
      const expectedArcGreeting = 'Hello from arc fallback test';
      const originalConsoleError = console.error.bind(console);
      console.error = (...args: unknown[]) => {
        counters.consoleMarkers.push(String(args[0] || ''));
      };

      const originalFetch = window.fetch.bind(window);
      window.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
        const url =
          typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
        if (!url.includes(arcRpcHost) || String(init?.method || 'GET').toUpperCase() !== 'POST') {
          return await originalFetch(input, init);
        }
        let body: Record<string, unknown> = {};
        try {
          body = JSON.parse(String(init?.body || '{}')) as Record<string, unknown>;
        } catch {}
        const id = body.id ?? Date.now();
        const method = String(body.method || '');
        if (method === 'eth_getBlockByNumber') {
          return new Response(
            JSON.stringify({
              jsonrpc: '2.0',
              id,
              result: { number: '0x1', baseFeePerGas: '0x3b9aca00' },
            }),
            { status: 200, headers: { 'content-type': 'application/json' } },
          );
        }
        return await originalFetch(input, init);
      }) as typeof fetch;

      let hookApi: any = null;
      function Harness() {
        hookApi = useDemoArcSigningActions({
          canSignEvm: true,
          nearAccountId: 'alice.testnet',
          seams: {
            tempo: {
              executeEvmFamilyTransaction: async (args: any) => {
                counters.executeEvmFamilyTransactionCalls += 1;
                await args?.postFinalizationCheck?.();
                const err = new Error('post-finalization mismatch') as Error & { code?: string };
                err.code = 'post_finalization_state_mismatch';
                throw err;
              },
            },
          },
          arcGreetingInput: expectedArcGreeting,
          arcEip1559FeeCaps: {
            maxPriorityFeePerGas: 2_000_000_000n,
            maxFeePerGas: 40_000_000_000n,
          },
          fetchArcGreeting: async () => {
            counters.fetchArcGreetingCalls += 1;
            return expectedArcGreeting;
          },
          refreshThresholdEvmFundingAddress: async () =>
            '0x1111111111111111111111111111111111111111',
        });
        return ReactRuntime.createElement('div', null);
      }

      const mount = document.createElement('div');
      document.body.appendChild(mount);
      const root = ReactDOMClientRuntime.createRoot(mount);
      ReactDOMRuntime.flushSync(() => {
        root.render(ReactRuntime.createElement(Harness));
      });

      await hookApi.handleSignEvmThresholdTx();
      await new Promise((resolve) => window.setTimeout(resolve, 0));
      const stateAfter = {
        evmThresholdSignLoading: Boolean(hookApi.evmThresholdSignLoading),
      };
      root.unmount();
      console.error = originalConsoleError;
      return { counters, stateAfter };
    }, { paths: IMPORT_PATHS, arcRpcHost: ARC_RPC });

    expect(result.counters.executeEvmFamilyTransactionCalls).toBe(1);
    expect(result.counters.fetchArcGreetingCalls).toBe(1);
    expect(result.counters.consoleMarkers).toContain('[DemoPage][ArcPostFinalizationSyncError]');
    expect(result.stateAfter.evmThresholdSignLoading).toBe(false);
  });

  test('useDemoTempoFeeTokenActions handles user cancellation without broadcast report', async ({
    page,
  }) => {
    const result = await page.evaluate(async ({ paths }) => {
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
      const mod = await import(paths.tempoFeeTokenHook);
      const useDemoTempoFeeTokenActions = (mod as any).useDemoTempoFeeTokenActions;
      if (!useDemoTempoFeeTokenActions) {
        throw new Error('Failed to load useDemoTempoFeeTokenActions export');
      }

      const counters = {
        executeEvmFamilyTransactionCalls: 0,
      };

      let hookApi: any = null;
      function Harness() {
        hookApi = useDemoTempoFeeTokenActions({
          isLoggedIn: true,
          nearAccountId: 'alice.testnet',
          seams: {
            tempo: {
              executeEvmFamilyTransaction: async () => {
                counters.executeEvmFamilyTransactionCalls += 1;
                throw new Error('User rejected request');
              },
            },
          },
          tempoEip1559FeeCaps: {
            maxPriorityFeePerGas: 2_000_000_000n,
            maxFeePerGas: 40_000_000_000n,
          },
          resolveThresholdSenderForEvmFamily: async () =>
            '0x1111111111111111111111111111111111111111',
          refreshTempoUserFeeToken: async () => null,
          refreshTempoUserFeeTokenBalance: async () => null,
        });
        return ReactRuntime.createElement('div', null);
      }

      const mount = document.createElement('div');
      document.body.appendChild(mount);
      const root = ReactDOMClientRuntime.createRoot(mount);
      ReactDOMRuntime.flushSync(() => {
        root.render(ReactRuntime.createElement(Harness));
      });

      await hookApi.handleSetTempoFeeTokenAlphaUsd();
      await new Promise((resolve) => window.setTimeout(resolve, 0));
      const stateAfter = {
        loading: Boolean(hookApi.tempoFeeTokenConfigLoading),
        target: hookApi.tempoFeeTokenConfigTarget,
      };
      root.unmount();
      return { counters, stateAfter };
    }, { paths: IMPORT_PATHS });

    expect(result.counters.executeEvmFamilyTransactionCalls).toBe(1);
    expect(result.stateAfter.loading).toBe(false);
    expect(result.stateAfter.target).toBeNull();
  });

  test('useDemoTempoSigningActions handles SDK execution failure and clears loading state', async ({
    page,
  }) => {
    const result = await page.evaluate(async ({ paths, tempoRpcHost }) => {
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
      const mod = await import(paths.tempoSigningHook);
      const useDemoTempoSigningActions = (mod as any).useDemoTempoSigningActions;
      if (!useDemoTempoSigningActions) {
        throw new Error('Failed to load useDemoTempoSigningActions export');
      }

      const counters = {
        executeEvmFamilyTransactionCalls: 0,
        consoleErrors: 0,
      };
      const originalConsoleError = console.error.bind(console);
      console.error = () => {
        counters.consoleErrors += 1;
      };

      const originalFetch = window.fetch.bind(window);
      window.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
        const url =
          typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
        if (!url.includes(tempoRpcHost) || String(init?.method || 'GET').toUpperCase() !== 'POST') {
          return await originalFetch(input, init);
        }
        let body: Record<string, unknown> = {};
        try {
          body = JSON.parse(String(init?.body || '{}')) as Record<string, unknown>;
        } catch {}
        const id = body.id ?? Date.now();
        const method = String(body.method || '');
        if (method === 'eth_getBlockByNumber') {
          return new Response(
            JSON.stringify({
              jsonrpc: '2.0',
              id,
              result: { number: '0x1', baseFeePerGas: '0x3b9aca00' },
            }),
            { status: 200, headers: { 'content-type': 'application/json' } },
          );
        }
        return await originalFetch(input, init);
      }) as typeof fetch;

      let hookApi: any = null;
      function Harness() {
        hookApi = useDemoTempoSigningActions({
          isLoggedIn: true,
          nearAccountId: 'alice.testnet',
          seams: {
            tempo: {
              executeEvmFamilyTransaction: async () => {
                counters.executeEvmFamilyTransactionCalls += 1;
                throw new Error('mock send error');
              },
            },
          },
          canSignTempo: true,
          tempoGreetingInput: 'hello',
          tempoEip1559FeeCaps: {
            maxPriorityFeePerGas: 2_000_000_000n,
            maxFeePerGas: 40_000_000_000n,
          },
          tempoUserFeeToken: null,
          resolveThresholdSenderForEvmFamily: async () =>
            '0x1111111111111111111111111111111111111111',
          refreshTempoUserFeeTokenBalance: async () => 1n,
          fetchTempoGreeting: async () => 'hello',
          refreshThresholdEvmFundingAddress: async () =>
            '0x1111111111111111111111111111111111111111',
        });
        return ReactRuntime.createElement('div', null);
      }

      const mount = document.createElement('div');
      document.body.appendChild(mount);
      const root = ReactDOMClientRuntime.createRoot(mount);
      ReactDOMRuntime.flushSync(() => {
        root.render(ReactRuntime.createElement(Harness));
      });

      await hookApi.handleSignTempoThresholdTx();
      await new Promise((resolve) => window.setTimeout(resolve, 0));
      const stateAfter = {
        loading: Boolean(hookApi.tempoThresholdSignLoading),
      };
      root.unmount();
      console.error = originalConsoleError;
      return { counters, stateAfter };
    }, { paths: IMPORT_PATHS, tempoRpcHost: TEMPO_RPC });

    expect(result.counters.executeEvmFamilyTransactionCalls).toBe(1);
    expect(result.counters.consoleErrors).toBeGreaterThanOrEqual(1);
    expect(result.stateAfter.loading).toBe(false);
  });

  test('useDemoTempoSigningActions handles post-finalization mismatch from SDK', async ({
    page,
  }) => {
    const result = await page.evaluate(async ({ paths, tempoRpcHost }) => {
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
      const mod = await import(paths.tempoSigningHook);
      const useDemoTempoSigningActions = (mod as any).useDemoTempoSigningActions;
      if (!useDemoTempoSigningActions) {
        throw new Error('Failed to load useDemoTempoSigningActions export');
      }

      const counters = {
        executeEvmFamilyTransactionCalls: 0,
        fetchTempoGreetingCalls: 0,
        consoleMarkers: [] as string[],
      };
      const originalConsoleError = console.error.bind(console);
      console.error = (...args: unknown[]) => {
        counters.consoleMarkers.push(String(args[0] || ''));
      };

      const originalFetch = window.fetch.bind(window);
      window.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
        const url =
          typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
        if (!url.includes(tempoRpcHost) || String(init?.method || 'GET').toUpperCase() !== 'POST') {
          return await originalFetch(input, init);
        }
        let body: Record<string, unknown> = {};
        try {
          body = JSON.parse(String(init?.body || '{}')) as Record<string, unknown>;
        } catch {}
        const id = body.id ?? Date.now();
        const method = String(body.method || '');
        if (method === 'eth_getBlockByNumber') {
          return new Response(
            JSON.stringify({
              jsonrpc: '2.0',
              id,
              result: { number: '0x1', baseFeePerGas: '0x3b9aca00' },
            }),
            { status: 200, headers: { 'content-type': 'application/json' } },
          );
        }
        return await originalFetch(input, init);
      }) as typeof fetch;

      let hookApi: any = null;
      function Harness() {
        hookApi = useDemoTempoSigningActions({
          isLoggedIn: true,
          nearAccountId: 'alice.testnet',
          seams: {
            tempo: {
              executeEvmFamilyTransaction: async (args: any) => {
                counters.executeEvmFamilyTransactionCalls += 1;
                await args?.postFinalizationCheck?.();
                const err = new Error('mock greeting refresh failure') as Error & { code?: string };
                err.code = 'post_finalization_state_mismatch';
                throw err;
              },
            },
          },
          canSignTempo: true,
          tempoGreetingInput: 'hello',
          tempoEip1559FeeCaps: {
            maxPriorityFeePerGas: 2_000_000_000n,
            maxFeePerGas: 40_000_000_000n,
          },
          tempoUserFeeToken: null,
          resolveThresholdSenderForEvmFamily: async () =>
            '0x1111111111111111111111111111111111111111',
          refreshTempoUserFeeTokenBalance: async () => 1n,
          fetchTempoGreeting: async () => {
            counters.fetchTempoGreetingCalls += 1;
            return 'hello';
          },
          refreshThresholdEvmFundingAddress: async () =>
            '0x1111111111111111111111111111111111111111',
        });
        return ReactRuntime.createElement('div', null);
      }

      const mount = document.createElement('div');
      document.body.appendChild(mount);
      const root = ReactDOMClientRuntime.createRoot(mount);
      ReactDOMRuntime.flushSync(() => {
        root.render(ReactRuntime.createElement(Harness));
      });

      await hookApi.handleSignTempoThresholdTx();
      await new Promise((resolve) => window.setTimeout(resolve, 0));
      const stateAfter = {
        loading: Boolean(hookApi.tempoThresholdSignLoading),
      };
      root.unmount();
      console.error = originalConsoleError;
      return { counters, stateAfter };
    }, { paths: IMPORT_PATHS, tempoRpcHost: TEMPO_RPC });

    expect(result.counters.executeEvmFamilyTransactionCalls).toBe(1);
    expect(result.counters.fetchTempoGreetingCalls).toBe(1);
    expect(result.counters.consoleMarkers).toContain('[DemoPage][TempoPostFinalizationSyncError]');
    expect(result.stateAfter.loading).toBe(false);
  });

  test('useDemoArcSigningActions handles SDK execution failure and clears loading state', async ({
    page,
  }) => {
    const result = await page.evaluate(async ({ paths, arcRpcHost }) => {
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
      const mod = await import(paths.arcSigningHook);
      const useDemoArcSigningActions = (mod as any).useDemoArcSigningActions;
      if (!useDemoArcSigningActions) {
        throw new Error('Failed to load useDemoArcSigningActions export');
      }

      const counters = {
        executeEvmFamilyTransactionCalls: 0,
        consoleErrors: 0,
      };
      const originalConsoleError = console.error.bind(console);
      console.error = () => {
        counters.consoleErrors += 1;
      };

      const originalFetch = window.fetch.bind(window);
      window.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
        const url =
          typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
        if (!url.includes(arcRpcHost) || String(init?.method || 'GET').toUpperCase() !== 'POST') {
          return await originalFetch(input, init);
        }
        let body: Record<string, unknown> = {};
        try {
          body = JSON.parse(String(init?.body || '{}')) as Record<string, unknown>;
        } catch {}
        const id = body.id ?? Date.now();
        const method = String(body.method || '');
        if (method === 'eth_getBlockByNumber') {
          return new Response(
            JSON.stringify({
              jsonrpc: '2.0',
              id,
              result: { number: '0x1', baseFeePerGas: '0x3b9aca00' },
            }),
            { status: 200, headers: { 'content-type': 'application/json' } },
          );
        }
        return await originalFetch(input, init);
      }) as typeof fetch;

      let hookApi: any = null;
      function Harness() {
        hookApi = useDemoArcSigningActions({
          canSignEvm: true,
          nearAccountId: 'alice.testnet',
          seams: {
            tempo: {
              executeEvmFamilyTransaction: async () => {
                counters.executeEvmFamilyTransactionCalls += 1;
                throw new Error('mock send error');
              },
            },
          },
          arcGreetingInput: 'hello',
          arcEip1559FeeCaps: {
            maxPriorityFeePerGas: 2_000_000_000n,
            maxFeePerGas: 40_000_000_000n,
          },
          fetchArcGreeting: async () => 'ok',
          refreshThresholdEvmFundingAddress: async () =>
            '0x1111111111111111111111111111111111111111',
        });
        return ReactRuntime.createElement('div', null);
      }

      const mount = document.createElement('div');
      document.body.appendChild(mount);
      const root = ReactDOMClientRuntime.createRoot(mount);
      ReactDOMRuntime.flushSync(() => {
        root.render(ReactRuntime.createElement(Harness));
      });

      await hookApi.handleSignEvmThresholdTx();
      await new Promise((resolve) => window.setTimeout(resolve, 0));
      const stateAfter = {
        loading: Boolean(hookApi.evmThresholdSignLoading),
      };
      root.unmount();
      console.error = originalConsoleError;
      return { counters, stateAfter };
    }, { paths: IMPORT_PATHS, arcRpcHost: ARC_RPC });

    expect(result.counters.executeEvmFamilyTransactionCalls).toBe(1);
    expect(result.counters.consoleErrors).toBe(0);
    expect(result.stateAfter.loading).toBe(false);
  });

  test('waitForExpectedGreeting retries until the requested greeting is observed', async ({
    page,
  }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const mod = await import(paths.demoHelpers);
      const waitForExpectedGreeting = (mod as any).waitForExpectedGreeting as (args: {
        fetchGreeting: (opts?: { silent?: boolean }) => Promise<string | null>;
        expectedGreeting: string;
        timeoutMs?: number;
        pollIntervalMs?: number;
      }) => Promise<string | null>;
      const observations = ['Hello 44', 'Hello 44', 'Hello 5'];
      let calls = 0;

      const greeting = await waitForExpectedGreeting({
        fetchGreeting: async () => {
          const value = observations[Math.min(calls, observations.length - 1)] || null;
          calls += 1;
          return value;
        },
        expectedGreeting: 'Hello 5',
        timeoutMs: 1_000,
        pollIntervalMs: 1,
      });

      return { calls, greeting };
    }, { paths: IMPORT_PATHS });

    expect(result.calls).toBeGreaterThanOrEqual(3);
    expect(result.greeting).toBe('Hello 5');
  });

  test('isUserCancellationError classifies cancellation signals', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const mod = await import(paths.demoHelpers);
      const isUserCancellationError = (mod as any).isUserCancellationError as (
        value: unknown,
      ) => boolean;
      return {
        code4001: isUserCancellationError({ code: 4001 }),
        actionRejected: isUserCancellationError({ code: 'action_rejected' }),
        messageRejected: isUserCancellationError(new Error('User rejected request')),
      };
    }, { paths: IMPORT_PATHS });
    expect(result.code4001).toBe(true);
    expect(result.actionRejected).toBe(true);
    expect(result.messageRejected).toBe(true);
  });

  test('isUserCancellationError keeps non-cancel RPC failures classified as false', async ({
    page,
  }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const mod = await import(paths.demoHelpers);
      const isUserCancellationError = (mod as any).isUserCancellationError as (
        value: unknown,
      ) => boolean;
      return {
        insufficientFunds: isUserCancellationError(
          new Error('insufficient funds for gas * price + value'),
        ),
        rpcRevert: isUserCancellationError({
          code: -32000,
          message: 'execution reverted: custom error',
        }),
      };
    }, { paths: IMPORT_PATHS });
    expect(result.insufficientFunds).toBe(false);
    expect(result.rpcRevert).toBe(false);
  });
});
