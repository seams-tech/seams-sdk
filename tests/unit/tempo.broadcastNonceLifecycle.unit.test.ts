import { expect, test } from '@playwright/test';

const IMPORT_PATHS = {
  tempoSigningApi: '/sdk/esm/core/signingEngine/api/tempoSigning.js',
} as const;

test.describe('tempo broadcast nonce lifecycle', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('commits managed nonce on successful broadcast', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { reportTempoBroadcastResult } = await import(paths.tempoSigningApi);
        const calls: Array<{ fn: string; input: any }> = [];

        await reportTempoBroadcastResult(
          {
            evmNonceManager: {
              reserveNextNonce: async () => 1n,
              commitBroadcast: async (input: any) => {
                calls.push({ fn: 'commitBroadcast', input });
              },
              releaseReservation: (input: any) => {
                calls.push({ fn: 'releaseReservation', input });
              },
              refreshFromChain: async (input: any) => {
                calls.push({ fn: 'refreshFromChain', input });
                return 0n;
              },
              clearForAccount: () => undefined,
            },
          } as any,
          {
            nearAccountId: 'alice.testnet',
            status: 'success',
            txHash: `0x${'ab'.repeat(32)}` as `0x${string}`,
            signedResult: {
              chain: 'evm',
              kind: 'eip1559',
              txHashHex: `0x${'cd'.repeat(32)}` as `0x${string}`,
              rawTxHex: '0x02',
              managedNonce: {
                chain: 'evm',
                networkKey: 'arc-testnet',
                chainId: 11155111,
                sender: `0x${'11'.repeat(20)}` as `0x${string}`,
                nonce: '8',
                nearAccountId: 'alice.testnet',
              },
            },
          },
        );

        return calls;
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toHaveLength(1);
    expect(result[0]?.fn).toBe('commitBroadcast');
    expect(String(result[0]?.input?.nonce || '')).toBe('8');
    expect(String(result[0]?.input?.chainId || '')).toBe('11155111');
    expect(result[0]?.input?.networkKey).toBe('arc-testnet');
  });

  test('releases reservation on broadcast failure', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { reportTempoBroadcastResult } = await import(paths.tempoSigningApi);
        const calls: Array<{ fn: string; input: any }> = [];

        await reportTempoBroadcastResult(
          {
            evmNonceManager: {
              reserveNextNonce: async () => 1n,
              commitBroadcast: async (input: any) => {
                calls.push({ fn: 'commitBroadcast', input });
              },
              releaseReservation: (input: any) => {
                calls.push({ fn: 'releaseReservation', input });
              },
              refreshFromChain: async (input: any) => {
                calls.push({ fn: 'refreshFromChain', input });
                return 0n;
              },
              clearForAccount: () => undefined,
            },
          } as any,
          {
            nearAccountId: 'alice.testnet',
            status: 'failure',
            error: { message: 'execution reverted' },
            signedResult: {
              chain: 'tempo',
              kind: 'tempoTransaction',
              senderHashHex: `0x${'ef'.repeat(32)}` as `0x${string}`,
              rawTxHex: '0x76',
              managedNonce: {
                chain: 'tempo',
                networkKey: 'tempo-testnet',
                chainId: 42431,
                sender: `0x${'11'.repeat(20)}` as `0x${string}`,
                nonceKey: '1',
                nonce: '12',
                nearAccountId: 'alice.testnet',
              },
            },
          },
        );

        return calls;
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.map((entry: any) => entry.fn)).toEqual(['releaseReservation']);
    expect(String(result[0]?.input?.nonce || '')).toBe('12');
    expect(String(result[0]?.input?.nonceKey || '')).toBe('1');
  });

  test('refreshes nonce state and throws retryable code on nonce-conflict failure', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { reportTempoBroadcastResult } = await import(paths.tempoSigningApi);
        const calls: Array<{ fn: string; input: any }> = [];
        try {
          await reportTempoBroadcastResult(
            {
              evmNonceManager: {
                reserveNextNonce: async () => 1n,
                commitBroadcast: async (input: any) => {
                  calls.push({ fn: 'commitBroadcast', input });
                },
                releaseReservation: (input: any) => {
                  calls.push({ fn: 'releaseReservation', input });
                },
                refreshFromChain: async (input: any) => {
                  calls.push({ fn: 'refreshFromChain', input });
                  return 99n;
                },
                clearForAccount: () => undefined,
              },
            } as any,
            {
              nearAccountId: 'alice.testnet',
              status: 'failure',
              error: { message: 'replacement transaction underpriced' },
              signedResult: {
                chain: 'evm',
                kind: 'eip1559',
                txHashHex: `0x${'cd'.repeat(32)}` as `0x${string}`,
                rawTxHex: '0x02',
                managedNonce: {
                  chain: 'evm',
                  networkKey: 'arc-testnet',
                  chainId: 11155111,
                  sender: `0x${'11'.repeat(20)}` as `0x${string}`,
                  nonce: '9',
                  nearAccountId: 'alice.testnet',
                },
              },
            },
          );
          return { ok: true, calls };
        } catch (error: any) {
          return {
            ok: false,
            code: String(error?.code || ''),
            retryable: Boolean(error?.retryable),
            message: String(error?.message || ''),
            calls,
          };
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.ok).toBe(false);
    expect(result.code).toBe('nonce_conflict_retryable');
    expect(result.retryable).toBe(true);
    expect(result.message).toContain('nonce conflict');
    expect(result.calls.map((entry: any) => entry.fn)).toEqual([
      'releaseReservation',
      'refreshFromChain',
    ]);
  });
});
