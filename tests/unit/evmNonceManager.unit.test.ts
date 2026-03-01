import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  nonceManager: '/sdk/esm/core/rpcClients/evm/nonceManager.js',
} as const;

const TEST_SENDER = `0x${'11'.repeat(20)}`;

test.describe('EvmNonceManager', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
  });

  test('reserveNextNonce is monotonic and unique under concurrency', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths, sender }) => {
        const mod = await import(paths.nonceManager);
        const manager = mod.createEvmNonceManager({
          chains: [
            {
              network: 'arc-testnet',
              rpcUrl: 'https://rpc.example.test',
              explorerUrl: 'https://explorer.example.test',
              chainId: 11155111,
            },
          ],
          fetchImpl: async () => {
            await new Promise((resolve) => setTimeout(resolve, 10));
            return new Response(JSON.stringify({ jsonrpc: '2.0', id: '1', result: '0x7' }), {
              status: 200,
              headers: { 'content-type': 'application/json' },
            });
          },
        });

        const baseInput = {
          chain: 'evm' as const,
          networkKey: 'evm:11155111',
          chainId: 11155111,
          sender: sender as `0x${string}`,
          nearAccountId: 'alice.testnet',
        };

        const reserved = await Promise.all([
          manager.reserveNextNonce(baseInput),
          manager.reserveNextNonce(baseInput),
          manager.reserveNextNonce(baseInput),
        ]);

        manager.markBroadcastRejected({ ...baseInput, nonce: reserved[1] });
        const afterRelease = await manager.reserveNextNonce(baseInput);

        return {
          reserved: reserved.map((value) => value.toString()),
          afterRelease: afterRelease.toString(),
        };
      },
      { paths: IMPORT_PATHS, sender: TEST_SENDER },
    );

    const sortedReserved = [...result.reserved].sort((a, b) => Number(a) - Number(b));
    expect(sortedReserved).toEqual(['7', '8', '9']);
    expect(result.afterRelease).toBe('10');
  });

  test('reconcileLane reports chain nonce and reserve uses warmed state', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths, sender }) => {
        const mod = await import(paths.nonceManager);
        let fetchCalls = 0;

        const manager = mod.createEvmNonceManager({
          chains: [
            {
              network: 'arc-testnet',
              rpcUrl: 'https://rpc.example.test',
              explorerUrl: 'https://explorer.example.test',
              chainId: 1,
            },
          ],
          fetchImpl: async () => {
            fetchCalls += 1;
            await new Promise((resolve) => setTimeout(resolve, 20));
            return new Response(JSON.stringify({ jsonrpc: '2.0', id: '1', result: '0xc' }), {
              status: 200,
              headers: { 'content-type': 'application/json' },
            });
          },
        });

        const input = {
          chain: 'evm' as const,
          networkKey: 'evm:1',
          chainId: 1,
          sender: sender as `0x${string}`,
        };

        const refreshed = await manager.reconcileLane(input);
        const next = await manager.reserveNextNonce(input);

        return {
          fetchCalls,
          refreshed: {
            chainNextNonce: refreshed.chainNextNonce.toString(),
            unresolvedInFlightNonces: refreshed.unresolvedInFlightNonces.map((value: bigint) =>
              value.toString(),
            ),
            blocked: refreshed.blocked,
          },
          next: next.toString(),
        };
      },
      { paths: IMPORT_PATHS, sender: TEST_SENDER },
    );

    expect(result.fetchCalls).toBe(1);
    expect(result.refreshed).toEqual({
      chainNextNonce: '12',
      unresolvedInFlightNonces: [],
      blocked: false,
    });
    expect(result.next).toBe('12');
  });

  test('releasing last reservation refreshes chain nonce but preserves monotonic progression', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths, sender }) => {
        const mod = await import(paths.nonceManager);
        let fetchCalls = 0;

        const manager = mod.createEvmNonceManager({
          chains: [
            {
              network: 'tempo-testnet',
              rpcUrl: 'https://tempo-rpc.example.test',
              explorerUrl: 'https://tempo-explorer.example.test',
              chainId: 42_431,
            },
          ],
          fetchImpl: async () => {
            fetchCalls += 1;
            // Simulate chain still reporting the same pending nonce after rejection.
            return new Response(JSON.stringify({ jsonrpc: '2.0', id: '1', result: '0x1' }), {
              status: 200,
              headers: { 'content-type': 'application/json' },
            });
          },
        });

        const input = {
          chain: 'tempo' as const,
          networkKey: 'tempo-testnet',
          chainId: 42_431,
          sender: sender as `0x${string}`,
          nonceKey: 0n,
          nearAccountId: 'alice.testnet',
        };

        const first = await manager.reserveNextNonce(input);
        manager.markBroadcastRejected({ ...input, nonce: first });
        const second = await manager.reserveNextNonce(input);

        return {
          fetchCalls,
          first: first.toString(),
          second: second.toString(),
        };
      },
      { paths: IMPORT_PATHS, sender: TEST_SENDER },
    );

    expect(result.fetchCalls).toBe(2);
    expect(result.first).toBe('1');
    expect(result.second).toBe('2');
  });

  test('clearForAccount drops cached reservation state for that account', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths, sender }) => {
        const mod = await import(paths.nonceManager);
        let fetchCalls = 0;

        const manager = mod.createEvmNonceManager({
          chains: [
            {
              network: 'arc-testnet',
              rpcUrl: 'https://rpc.example.test',
              explorerUrl: 'https://explorer.example.test',
              chainId: 1,
            },
          ],
          fetchImpl: async () => {
            fetchCalls += 1;
            return new Response(JSON.stringify({ jsonrpc: '2.0', id: '1', result: '0x14' }), {
              status: 200,
              headers: { 'content-type': 'application/json' },
            });
          },
        });

        const input = {
          chain: 'evm' as const,
          networkKey: 'evm:1',
          chainId: 1,
          sender: sender as `0x${string}`,
          nearAccountId: 'alice.testnet',
        };

        const first = await manager.reserveNextNonce(input);
        manager.clearForAccount('alice.testnet');
        const second = await manager.reserveNextNonce(input);

        return {
          fetchCalls,
          first: first.toString(),
          second: second.toString(),
        };
      },
      { paths: IMPORT_PATHS, sender: TEST_SENDER },
    );

    expect(result.fetchCalls).toBe(2);
    expect(result.first).toBe('20');
    expect(result.second).toBe('20');
  });

  test('same sender reserves independent sequences across Arc and Ethereum networks', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths, sender }) => {
        const mod = await import(paths.nonceManager);

        const manager = mod.createEvmNonceManager({
          chains: [
            {
              network: 'arc-testnet',
              rpcUrl: 'https://arc-rpc.example.test',
              explorerUrl: 'https://arc-explorer.example.test',
              chainId: 5_042_002,
            },
            {
              network: 'ethereum-sepolia',
              rpcUrl: 'https://sepolia-rpc.example.test',
              explorerUrl: 'https://sepolia-explorer.example.test',
              chainId: 11_155_111,
            },
          ],
          fetchImpl: async (url: unknown) => {
            const rpcUrl = String(url || '');
            const resultHex = rpcUrl.includes('arc-rpc') ? '0x9' : '0x3';
            return new Response(JSON.stringify({ jsonrpc: '2.0', id: '1', result: resultHex }), {
              status: 200,
              headers: { 'content-type': 'application/json' },
            });
          },
        });

        const base = {
          chain: 'evm' as const,
          sender: sender as `0x${string}`,
          nearAccountId: 'alice.testnet',
        };

        const arcInput = {
          ...base,
          networkKey: 'arc-testnet',
          chainId: 5_042_002,
        };
        const sepoliaInput = {
          ...base,
          networkKey: 'ethereum-sepolia',
          chainId: 11_155_111,
        };

        const arcNonce1 = await manager.reserveNextNonce(arcInput);
        const sepoliaNonce1 = await manager.reserveNextNonce(sepoliaInput);
        const arcNonce2 = await manager.reserveNextNonce(arcInput);
        const sepoliaNonce2 = await manager.reserveNextNonce(sepoliaInput);

        return {
          arc: [arcNonce1.toString(), arcNonce2.toString()],
          sepolia: [sepoliaNonce1.toString(), sepoliaNonce2.toString()],
        };
      },
      { paths: IMPORT_PATHS, sender: TEST_SENDER },
    );

    expect(result.arc).toEqual(['9', '10']);
    expect(result.sepolia).toEqual(['3', '4']);
  });

  test('evm nonce resolution falls back to unique configured chainId across families', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths, sender }) => {
        const mod = await import(paths.nonceManager);

        const manager = mod.createEvmNonceManager({
          chains: [
            {
              network: 'arc-testnet',
              rpcUrl: 'https://arc-rpc.example.test',
              explorerUrl: 'https://arc-explorer.example.test',
              chainId: 5_042_002,
            },
            {
              network: 'tempo-testnet',
              rpcUrl: 'https://tempo-rpc.example.test',
              explorerUrl: 'https://tempo-explorer.example.test',
              chainId: 42_431,
            },
          ],
          fetchImpl: async (url: unknown) => {
            const rpcUrl = String(url || '');
            const resultHex = rpcUrl.includes('tempo-rpc') ? '0x15' : '0x9';
            return new Response(JSON.stringify({ jsonrpc: '2.0', id: '1', result: resultHex }), {
              status: 200,
              headers: { 'content-type': 'application/json' },
            });
          },
        });

        // Simulate eip1559 request routed through signTempo path for chainId=42431.
        const input = {
          chain: 'evm' as const,
          networkKey: 'evm:42431',
          chainId: 42_431,
          sender: sender as `0x${string}`,
          nearAccountId: 'alice.testnet',
        };

        const nonce = await manager.reserveNextNonce(input);
        return { nonce: nonce.toString() };
      },
      { paths: IMPORT_PATHS, sender: TEST_SENDER },
    );

    // `0x15` from tempo-rpc proves cross-family chainId fallback selected tempo RPC.
    expect(result.nonce).toBe('21');
  });

  test('fails closed when networkKey matches but chainId mismatches configured chain', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths, sender }) => {
        const mod = await import(paths.nonceManager);
        const manager = mod.createEvmNonceManager({
          chains: [
            {
              network: 'arc-testnet',
              rpcUrl: 'https://arc-rpc.example.test',
              explorerUrl: 'https://arc-explorer.example.test',
              chainId: 5_042_002,
            },
          ],
          fetchImpl: async () =>
            new Response(JSON.stringify({ jsonrpc: '2.0', id: '1', result: '0x0' }), {
              status: 200,
              headers: { 'content-type': 'application/json' },
            }),
        });
        try {
          await manager.reserveNextNonce({
            chain: 'evm' as const,
            networkKey: 'arc-testnet',
            chainId: 11_155_111,
            sender: sender as `0x${string}`,
          });
          return { ok: true, message: '' };
        } catch (error: unknown) {
          return { ok: false, message: String((error as { message?: unknown })?.message || error) };
        }
      },
      { paths: IMPORT_PATHS, sender: TEST_SENDER },
    );

    expect(result.ok).toBe(false);
    expect(result.message).toContain('chainId mismatch');
  });

  test('fails closed on ambiguous chainId routing across configured networks', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths, sender }) => {
        const mod = await import(paths.nonceManager);
        const manager = mod.createEvmNonceManager({
          chains: [
            {
              network: 'arc-testnet',
              rpcUrl: 'https://arc-rpc.example.test',
              explorerUrl: 'https://arc-explorer.example.test',
              chainId: 42_431,
            },
            {
              network: 'tempo-testnet',
              rpcUrl: 'https://tempo-rpc.example.test',
              explorerUrl: 'https://tempo-explorer.example.test',
              chainId: 42_431,
            },
          ],
          fetchImpl: async () =>
            new Response(JSON.stringify({ jsonrpc: '2.0', id: '1', result: '0x0' }), {
              status: 200,
              headers: { 'content-type': 'application/json' },
            }),
        });
        try {
          await manager.reserveNextNonce({
            chain: 'evm' as const,
            networkKey: 'evm:42431',
            chainId: 42_431,
            sender: sender as `0x${string}`,
          });
          return { ok: true, message: '' };
        } catch (error: unknown) {
          return { ok: false, message: String((error as { message?: unknown })?.message || error) };
        }
      },
      { paths: IMPORT_PATHS, sender: TEST_SENDER },
    );

    expect(result.ok).toBe(false);
    expect(result.message).toContain('ambiguous chainId routing');
  });
});
