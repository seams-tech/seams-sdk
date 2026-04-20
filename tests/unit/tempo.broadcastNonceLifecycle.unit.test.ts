import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  tempoSigningApi: '/sdk/esm/core/signingEngine/api/tempoSigning.js',
} as const;

test.describe('tempo broadcast nonce lifecycle', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('marks managed nonce as in-flight on broadcast acceptance', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { reportTempoBroadcastAccepted } = await import(paths.tempoSigningApi);
        const calls: Array<{ fn: string; input: any }> = [];

        await reportTempoBroadcastAccepted(
          {
            evmNonceManager: {
              reserveNextNonce: async () => 1n,
              markBroadcastAccepted: async (input: any) => {
                calls.push({ fn: 'markBroadcastAccepted', input });
              },
              markBroadcastRejected: (input: any) => {
                calls.push({ fn: 'markBroadcastRejected', input });
              },
              markFinalized: async (input: any) => {
                calls.push({ fn: 'markFinalized', input });
              },
              markDroppedOrReplaced: async (input: any) => {
                calls.push({ fn: 'markDroppedOrReplaced', input });
              },
              reconcileLane: async (input: any) => {
                calls.push({ fn: 'reconcileLane', input });
                return { chainNextNonce: 0n, unresolvedInFlightNonces: [], blocked: false };
              },
              clearForAccount: () => undefined,
            },
          } as any,
          {
            nearAccountId: 'alice.testnet',
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
    expect(result[0]?.fn).toBe('markBroadcastAccepted');
    expect(String(result[0]?.input?.nonce || '')).toBe('8');
    expect(String(result[0]?.input?.chainId || '')).toBe('11155111');
    expect(result[0]?.input?.networkKey).toBe('arc-testnet');
  });

  test('marks managed nonce reservation rejected on broadcast failure', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { reportTempoBroadcastRejected } = await import(paths.tempoSigningApi);
        const calls: Array<{ fn: string; input: any }> = [];

        await reportTempoBroadcastRejected(
          {
            evmNonceManager: {
              reserveNextNonce: async () => 1n,
              markBroadcastAccepted: async (input: any) => {
                calls.push({ fn: 'markBroadcastAccepted', input });
              },
              markBroadcastRejected: (input: any) => {
                calls.push({ fn: 'markBroadcastRejected', input });
              },
              markFinalized: async (input: any) => {
                calls.push({ fn: 'markFinalized', input });
              },
              markDroppedOrReplaced: async (input: any) => {
                calls.push({ fn: 'markDroppedOrReplaced', input });
              },
              reconcileLane: async (input: any) => {
                calls.push({ fn: 'reconcileLane', input });
                return { chainNextNonce: 0n, unresolvedInFlightNonces: [], blocked: false };
              },
              clearForAccount: () => undefined,
            },
          } as any,
          {
            nearAccountId: 'alice.testnet',
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

    expect(result.map((entry: any) => entry.fn)).toEqual(['markBroadcastRejected']);
    expect(String(result[0]?.input?.nonce || '')).toBe('12');
    expect(String(result[0]?.input?.nonceKey || '')).toBe('1');
  });

  test('marks managed nonce finalized on chain finalization', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { reportTempoFinalized } = await import(paths.tempoSigningApi);
        const calls: Array<{ fn: string; input: any }> = [];
        const events: any[] = [];

        await reportTempoFinalized(
          {
            evmNonceManager: {
              reserveNextNonce: async () => 1n,
              markBroadcastAccepted: async (input: any) => {
                calls.push({ fn: 'markBroadcastAccepted', input });
              },
              markBroadcastRejected: (input: any) => {
                calls.push({ fn: 'markBroadcastRejected', input });
              },
              markFinalized: async (input: any) => {
                calls.push({ fn: 'markFinalized', input });
              },
              markDroppedOrReplaced: async (input: any) => {
                calls.push({ fn: 'markDroppedOrReplaced', input });
              },
              reconcileLane: async (input: any) => {
                calls.push({ fn: 'reconcileLane', input });
                return { chainNextNonce: 0n, unresolvedInFlightNonces: [], blocked: false };
              },
              clearForAccount: () => undefined,
            },
          } as any,
          {
            nearAccountId: 'alice.testnet',
            txHash: `0x${'aa'.repeat(32)}` as `0x${string}`,
            receiptStatus: 'success',
            onEvent: (event: any) => events.push(event),
            signedResult: {
              chain: 'evm',
              kind: 'eip1559',
              txHashHex: `0x${'bb'.repeat(32)}` as `0x${string}`,
              rawTxHex: '0x02',
              managedNonce: {
                chain: 'evm',
                networkKey: 'arc-testnet',
                chainId: 11155111,
                sender: `0x${'11'.repeat(20)}` as `0x${string}`,
                nonce: '13',
                nearAccountId: 'alice.testnet',
              },
            },
          },
        );

        return { calls, events };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.calls.map((entry: any) => entry.fn)).toEqual(['markFinalized']);
    expect(String(result.calls[0]?.input?.nonce || '')).toBe('13');
    expect(result.events).toEqual([]);
  });

  test('marks managed nonce dropped with reason and tx hash', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { reportTempoDroppedOrReplaced } = await import(paths.tempoSigningApi);
        const calls: Array<{ fn: string; input: any }> = [];

        await reportTempoDroppedOrReplaced(
          {
            evmNonceManager: {
              reserveNextNonce: async () => 1n,
              markBroadcastAccepted: async (input: any) => {
                calls.push({ fn: 'markBroadcastAccepted', input });
              },
              markBroadcastRejected: (input: any) => {
                calls.push({ fn: 'markBroadcastRejected', input });
              },
              markFinalized: async (input: any) => {
                calls.push({ fn: 'markFinalized', input });
              },
              markDroppedOrReplaced: async (input: any) => {
                calls.push({ fn: 'markDroppedOrReplaced', input });
              },
              reconcileLane: async (input: any) => {
                calls.push({ fn: 'reconcileLane', input });
                return { chainNextNonce: 0n, unresolvedInFlightNonces: [], blocked: false };
              },
              clearForAccount: () => undefined,
            },
          } as any,
          {
            nearAccountId: 'alice.testnet',
            reason: 'dropped',
            txHash: `0x${'cc'.repeat(32)}` as `0x${string}`,
            signedResult: {
              chain: 'tempo',
              kind: 'tempoTransaction',
              senderHashHex: `0x${'dd'.repeat(32)}` as `0x${string}`,
              rawTxHex: '0x76',
              managedNonce: {
                chain: 'tempo',
                networkKey: 'tempo-testnet',
                chainId: 42431,
                sender: `0x${'11'.repeat(20)}` as `0x${string}`,
                nonceKey: '7',
                nonce: '4',
                nearAccountId: 'alice.testnet',
              },
            },
          },
        );

        return calls;
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.map((entry: any) => entry.fn)).toEqual(['markDroppedOrReplaced']);
    expect(result[0]?.input?.reason).toBe('dropped');
    expect(String(result[0]?.input?.nonceKey || '')).toBe('7');
    expect(String(result[0]?.input?.nonce || '')).toBe('4');
  });

  test('marks managed nonce replaced with reason and replacement hash', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { reportTempoDroppedOrReplaced } = await import(paths.tempoSigningApi);
        const calls: Array<{ fn: string; input: any }> = [];

        await reportTempoDroppedOrReplaced(
          {
            evmNonceManager: {
              reserveNextNonce: async () => 1n,
              markBroadcastAccepted: async (input: any) => {
                calls.push({ fn: 'markBroadcastAccepted', input });
              },
              markBroadcastRejected: (input: any) => {
                calls.push({ fn: 'markBroadcastRejected', input });
              },
              markFinalized: async (input: any) => {
                calls.push({ fn: 'markFinalized', input });
              },
              markDroppedOrReplaced: async (input: any) => {
                calls.push({ fn: 'markDroppedOrReplaced', input });
              },
              reconcileLane: async (input: any) => {
                calls.push({ fn: 'reconcileLane', input });
                return { chainNextNonce: 0n, unresolvedInFlightNonces: [], blocked: false };
              },
              clearForAccount: () => undefined,
            },
          } as any,
          {
            nearAccountId: 'alice.testnet',
            reason: 'replaced',
            txHash: `0x${'ee'.repeat(32)}` as `0x${string}`,
            signedResult: {
              chain: 'evm',
              kind: 'eip1559',
              txHashHex: `0x${'ff'.repeat(32)}` as `0x${string}`,
              rawTxHex: '0x02',
              managedNonce: {
                chain: 'evm',
                networkKey: 'arc-testnet',
                chainId: 11155111,
                sender: `0x${'11'.repeat(20)}` as `0x${string}`,
                nonce: '19',
                nearAccountId: 'alice.testnet',
              },
            },
          },
        );

        return calls;
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.map((entry: any) => entry.fn)).toEqual(['markDroppedOrReplaced']);
    expect(result[0]?.input?.reason).toBe('replaced');
    expect(String(result[0]?.input?.nonce || '')).toBe('19');
    expect(String(result[0]?.input?.txHash || '')).toBe(`0x${'ee'.repeat(32)}`);
  });

  test('reconcile returns lane status and throws when lane is blocked', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { reconcileTempoNonceLane } = await import(paths.tempoSigningApi);
        const calls: Array<{ fn: string; input: any }> = [];
        let first: any = null;
        let secondError: any = null;

        const laneStatuses = [
          {
            chainNextNonce: 15n,
            unresolvedInFlightNonces: [15n],
            blocked: false,
          },
          {
            chainNextNonce: 15n,
            unresolvedInFlightNonces: [15n],
            blocked: true,
            blockedNonce: 15n,
          },
        ];

        const deps: any = {
          evmNonceManager: {
            reserveNextNonce: async () => 1n,
            markBroadcastAccepted: async (input: any) => {
              calls.push({ fn: 'markBroadcastAccepted', input });
            },
            markBroadcastRejected: (input: any) => {
              calls.push({ fn: 'markBroadcastRejected', input });
            },
            markFinalized: async (input: any) => {
              calls.push({ fn: 'markFinalized', input });
            },
            markDroppedOrReplaced: async (input: any) => {
              calls.push({ fn: 'markDroppedOrReplaced', input });
            },
            reconcileLane: async (input: any) => {
              calls.push({ fn: 'reconcileLane', input });
              return laneStatuses.shift() || laneStatuses[0];
            },
            clearForAccount: () => undefined,
          },
        };
        const args: any = {
          nearAccountId: 'alice.testnet',
          signedResult: {
            chain: 'evm',
            kind: 'eip1559',
            txHashHex: `0x${'ee'.repeat(32)}` as `0x${string}`,
            rawTxHex: '0x02',
            managedNonce: {
              chain: 'evm',
              networkKey: 'arc-testnet',
              chainId: 11155111,
              sender: `0x${'11'.repeat(20)}` as `0x${string}`,
              nonce: '15',
              nearAccountId: 'alice.testnet',
            },
          },
        };

        first = await reconcileTempoNonceLane(deps, args);
        try {
          await reconcileTempoNonceLane(deps, args);
        } catch (error: any) {
          secondError = {
            code: String(error?.code || ''),
            retryable: Boolean(error?.retryable),
            blockedNonce: String(error?.details?.blockedNonce || ''),
          };
        }
        return { calls, first, secondError };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.calls.map((entry: any) => entry.fn)).toEqual(['reconcileLane', 'reconcileLane']);
    expect(result.first).toEqual({
      chainNextNonce: '15',
      unresolvedInFlightNonces: ['15'],
      blocked: false,
    });
    expect(result.secondError).toEqual({
      code: 'nonce_lane_blocked',
      retryable: true,
      blockedNonce: '15',
    });
  });

  test('reconciles lane and throws retryable code on nonce-conflict failure', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { reportTempoBroadcastRejected } = await import(paths.tempoSigningApi);
        const calls: Array<{ fn: string; input: any }> = [];
        try {
          await reportTempoBroadcastRejected(
            {
              evmNonceManager: {
                reserveNextNonce: async () => 1n,
                markBroadcastAccepted: async (input: any) => {
                  calls.push({ fn: 'markBroadcastAccepted', input });
                },
                markBroadcastRejected: (input: any) => {
                  calls.push({ fn: 'markBroadcastRejected', input });
                },
                markFinalized: async (input: any) => {
                  calls.push({ fn: 'markFinalized', input });
                },
                markDroppedOrReplaced: async (input: any) => {
                  calls.push({ fn: 'markDroppedOrReplaced', input });
                },
                reconcileLane: async (input: any) => {
                  calls.push({ fn: 'reconcileLane', input });
                  return { chainNextNonce: 99n, unresolvedInFlightNonces: [], blocked: false };
                },
                clearForAccount: () => undefined,
              },
            } as any,
            {
              nearAccountId: 'alice.testnet',
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
      'markBroadcastRejected',
      'reconcileLane',
    ]);
  });
});
