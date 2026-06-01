import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  nonceBackend: '/sdk/esm/core/rpcClients/evm/nonceBackend.js',
} as const;

const TEST_SENDER = `0x${'11'.repeat(20)}`;

test.describe('EvmNonceBackend', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
  });

  test('fetchChainNonce reads the pending chain nonce through the configured RPC', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths, sender }) => {
        const mod = await import(paths.nonceBackend);
        const requests: Array<{ url: string; body: unknown }> = [];
        const backend = mod.createEvmNonceBackend({
          chains: [
            {
              network: 'ethereum-sepolia',
              rpcUrl: 'https://sepolia-rpc.example.test',
              explorerUrl: 'https://sepolia-explorer.example.test',
              chainId: 11155111,
            },
          ],
          fetchImpl: async (url: string, init?: RequestInit) => {
            requests.push({
              url,
              body: JSON.parse(String(init?.body || '{}')),
            });
            return new Response(JSON.stringify({ jsonrpc: '2.0', id: '1', result: '0xc' }), {
              status: 200,
              headers: { 'content-type': 'application/json' },
            });
          },
        });

        const nonce = await backend.fetchChainNonce(mod.reserveNonceInputFromBoundary({
          chain: 'evm',
          networkKey: 'ethereum-sepolia',
          chainId: 11155111,
          sender: sender as `0x${string}`,
          walletId: 'alice.testnet',
        }));

        return {
          nonce: nonce.toString(),
          requests,
        };
      },
      { paths: IMPORT_PATHS, sender: TEST_SENDER },
    );

    expect(result.nonce).toBe('12');
    expect(result.requests).toEqual([
      {
        url: 'https://sepolia-rpc.example.test',
        body: {
          jsonrpc: '2.0',
          id: 'evm-nonce-backend',
          method: 'eth_getTransactionCount',
          params: [TEST_SENDER, 'pending'],
        },
      },
    ]);
  });

  test('routes duplicate chain ids by requested chain family and network key', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths, sender }) => {
        const mod = await import(paths.nonceBackend);
        const urls: string[] = [];
        const backend = mod.createEvmNonceBackend({
          chains: [
            {
              network: 'tempo-testnet',
              rpcUrl: 'https://tempo-rpc.example.test',
              explorerUrl: 'https://tempo-explorer.example.test',
              chainId: 42431,
            },
            {
              network: 'ethereum-sepolia',
              rpcUrl: 'https://sepolia-rpc.example.test',
              explorerUrl: 'https://sepolia-explorer.example.test',
              chainId: 42431,
            },
          ],
          fetchImpl: async (url: string) => {
            urls.push(url);
            return new Response(JSON.stringify({ jsonrpc: '2.0', id: '1', result: '0x1' }), {
              status: 200,
              headers: { 'content-type': 'application/json' },
            });
          },
        });

        await backend.fetchChainNonce(mod.reserveNonceInputFromBoundary({
          chain: 'tempo',
          networkKey: 'tempo-testnet',
          chainId: 42431,
          sender: sender as `0x${string}`,
          nonceKey: 0n,
          walletId: 'alice.testnet',
        }));
        await backend.fetchChainNonce(mod.reserveNonceInputFromBoundary({
          chain: 'evm',
          networkKey: 'ethereum-sepolia',
          chainId: 42431,
          sender: sender as `0x${string}`,
          walletId: 'alice.testnet',
        }));

        return urls;
      },
      { paths: IMPORT_PATHS, sender: TEST_SENDER },
    );

    expect(result).toEqual([
      'https://tempo-rpc.example.test',
      'https://sepolia-rpc.example.test',
    ]);
  });

  test('backend instances expose only fetch-chain-nonce behavior', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths, sender }) => {
        const mod = await import(paths.nonceBackend);
        const backend = mod.createEvmNonceBackend({
          chains: [
            {
              network: 'tempo-testnet',
              rpcUrl: 'https://tempo-rpc.example.test',
              explorerUrl: 'https://tempo-explorer.example.test',
              chainId: 42431,
            },
          ],
          fetchImpl: async () =>
            new Response(JSON.stringify({ jsonrpc: '2.0', id: '1', result: '0x5' }), {
              status: 200,
              headers: { 'content-type': 'application/json' },
            }),
        });

        const nonce = await backend.fetchChainNonce(mod.reserveNonceInputFromBoundary({
          chain: 'tempo',
          networkKey: ' Tempo-Testnet ' as any,
          chainId: 42431,
          sender: sender.toUpperCase() as `0x${string}`,
          nonceKey: '7' as any,
          walletId: 'alice.testnet',
        }));

        return {
          nonce: nonce.toString(),
          backendKeys: Object.keys(backend).sort(),
          moduleKeys: Object.keys(mod).sort(),
        };
      },
      { paths: IMPORT_PATHS, sender: TEST_SENDER },
    );

    expect(result).toEqual({
      nonce: '5',
      backendKeys: ['fetchChainNonce'],
      moduleKeys: [
        'createEvmNonceBackend',
        'fromManagedNonceReservationSnapshot',
        'reserveNonceInputFromBoundary',
        'toManagedNonceReservationSnapshot',
      ],
    });
  });

  test('managed nonce snapshots fail closed on unknown chain families', async ({ page }) => {
    const message = await page.evaluate(
      async ({ paths, sender }) => {
        const mod = await import(paths.nonceBackend);
        try {
          mod.fromManagedNonceReservationSnapshot({
            chain: 'solana',
            networkKey: 'ethereum-sepolia',
            chainId: 11155111,
            sender,
            nonce: '1',
            walletId: 'alice.testnet',
          });
          return 'unexpected success';
        } catch (error: unknown) {
          return error instanceof Error ? error.message : String(error);
        }
      },
      { paths: IMPORT_PATHS, sender: TEST_SENDER },
    );

    expect(message).toContain('invalid managed nonce snapshot: chain');
  });
});
