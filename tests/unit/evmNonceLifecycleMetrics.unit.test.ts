import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  tempoSigningApi: '/_test-sdk/esm/core/signingEngine/flows/signEvmFamily/signEvmFamily.js',
} as const;

test.describe('evm nonce lifecycle metrics', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
  });

  test('emits broadcast_accepted metric with lane tags', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { reportTempoBroadcastAccepted } = await import(paths.tempoSigningApi);
        const entries: Array<Record<string, unknown>> = [];
        const originalDebug = console.debug;
        console.debug = (...args: any[]) => {
          if (args[0] === '[nonce-lifecycle-metrics]' && args[1] && typeof args[1] === 'object') {
            entries.push(args[1] as Record<string, unknown>);
          }
        };
        try {
          await reportTempoBroadcastAccepted(
            {
              nonceCoordinator: {
                markBroadcastAccepted: async () => undefined,
                markBroadcastRejected: async () => undefined,
                markFinalized: async () => undefined,
                markDroppedOrReplaced: async () => undefined,
                reconcile: async () => ({
                  chainNextNonce: 0n,
                  unresolvedInFlightNonces: [],
                  blocked: false,
                }),
                reserve: async () => {
                  throw new Error('not used');
                },
                release: async () => undefined,
                markSigned: async () => undefined,
                clearForAccount: () => undefined,
              },
            } as any,
            {
              walletId: 'alice.testnet',
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
                  leaseId: 'nonce-lease-metrics',
                  operationId: 'operation-metrics',
                  operationFingerprint: 'sha256:metrics',
                },
              },
            },
          );
        } finally {
          console.debug = originalDebug;
        }
        return entries;
      },
      { paths: IMPORT_PATHS },
    );

    const accepted = result.find((entry: any) => entry?.metric === 'broadcast_accepted');
    expect(accepted).toBeTruthy();
    expect(String(accepted?.chainTarget || '')).toBe('evm:eip155:11155111');
    expect(String(accepted?.networkKey || '')).toBe('arc-testnet');
    expect(String(accepted?.chainId || '')).toBe('11155111');
    expect(String(accepted?.sender || '')).toBe(`0x${'11'.repeat(20)}`);
    expect(String(accepted?.nonce || '')).toBe('8');
    expect(String(accepted?.txHash || '')).toBe(`0x${'ab'.repeat(32)}`);
    expect(Number(accepted?.atMs || 0)).toBeGreaterThan(0);
  });

  test('emits lane_blocked metric when reconcile reports blocked lane', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { reconcileTempoNonceLane } = await import(paths.tempoSigningApi);
        const entries: Array<Record<string, unknown>> = [];
        const originalDebug = console.debug;
        console.debug = (...args: any[]) => {
          if (args[0] === '[nonce-lifecycle-metrics]' && args[1] && typeof args[1] === 'object') {
            entries.push(args[1] as Record<string, unknown>);
          }
        };
        let errorCode = '';
        try {
          await reconcileTempoNonceLane(
            {
              nonceCoordinator: {
                markBroadcastAccepted: async () => undefined,
                markBroadcastRejected: async () => undefined,
                markFinalized: async () => undefined,
                markDroppedOrReplaced: async () => undefined,
                reconcile: async () => ({
                  chainNextNonce: 15n,
                  unresolvedInFlightNonces: [15n],
                  blocked: true,
                  blockedNonce: 15n,
                }),
                reserve: async () => {
                  throw new Error('not used');
                },
                release: async () => undefined,
                markSigned: async () => undefined,
                clearForAccount: () => undefined,
              },
            } as any,
            {
              walletId: 'alice.testnet',
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
                  leaseId: 'nonce-lease-metrics',
                  operationId: 'operation-metrics',
                  operationFingerprint: 'sha256:metrics',
                },
              },
            },
          );
        } catch (error: any) {
          errorCode = String(error?.code || '');
        } finally {
          console.debug = originalDebug;
        }
        return { entries, errorCode };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.errorCode).toBe('nonce_lane_blocked');
    const reconciled = result.entries.filter((entry: any) => entry?.metric === 'reconciled');
    expect(reconciled).toHaveLength(1);
    const blocked = result.entries.find((entry: any) => entry?.metric === 'lane_blocked');
    expect(String(blocked?.blockedNonce || '')).toBe('15');
  });
});
