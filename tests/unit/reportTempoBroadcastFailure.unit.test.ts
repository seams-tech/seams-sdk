import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const HELPER_IMPORT_PATH = '/src/flows/demo/hooks/reportTempoBroadcastFailure.ts' as const;

test.describe('reportTempoBroadcastFailure', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('marks accepted stale nonce lanes as dropped when reconcile reports lane_blocked', async ({
    page,
  }) => {
    const result = await page.evaluate(async ({ helperPath }) => {
      const { reportTempoBroadcastFailure } = await import(helperPath);
      const txHash = `0x${'ab'.repeat(32)}` as `0x${string}`;
      const calls = {
        reconcile: 0,
        dropped: 0,
        rejected: 0,
        droppedReason: '',
        droppedTxHash: '',
      };

      await reportTempoBroadcastFailure({
        tatchi: {
          tempo: {
            reconcileNonceLane: async () => {
              calls.reconcile += 1;
              const blocked = new Error('Nonce lane blocked while reconciling');
              (blocked as Error & { code?: string }).code = 'nonce_lane_blocked';
              throw blocked;
            },
            reportDroppedOrReplaced: async (input: any) => {
              calls.dropped += 1;
              calls.droppedReason = String(input?.reason || '');
              calls.droppedTxHash = String(input?.txHash || '');
            },
            reportBroadcastRejected: async () => {
              calls.rejected += 1;
            },
          },
        } as any,
        nearAccountId: 'alice.testnet',
        signedResult: {
          chain: 'evm',
          kind: 'eip1559',
          txHashHex: `0x${'11'.repeat(32)}` as `0x${string}`,
          rawTxHex: '0x02',
          managedNonce: {
            chain: 'evm',
            networkKey: 'tempo-testnet',
            chainId: 42431,
            sender: `0x${'22'.repeat(20)}` as `0x${string}`,
            nonce: '9',
            nearAccountId: 'alice.testnet',
          },
        } as any,
        error: new Error('Unable to confirm finalization'),
        flow: 'tempo-sign',
        broadcastAccepted: true,
        txHash,
      });

      return calls;
    }, {
      helperPath: HELPER_IMPORT_PATH,
    });

    expect(result.reconcile).toBe(1);
    expect(result.dropped).toBe(1);
    expect(result.rejected).toBe(0);
    expect(result.droppedReason).toBe('dropped');
    expect(result.droppedTxHash).toBe(`0x${'ab'.repeat(32)}`);
  });

  test('keeps accepted lanes untouched when reconcile succeeds', async ({ page }) => {
    const result = await page.evaluate(async ({ helperPath }) => {
      const { reportTempoBroadcastFailure } = await import(helperPath);
      const calls = {
        reconcile: 0,
        dropped: 0,
        rejected: 0,
      };

      await reportTempoBroadcastFailure({
        tatchi: {
          tempo: {
            reconcileNonceLane: async () => {
              calls.reconcile += 1;
              return {
                chainNextNonce: '10',
                unresolvedInFlightNonces: [],
                blocked: false,
              };
            },
            reportDroppedOrReplaced: async () => {
              calls.dropped += 1;
            },
            reportBroadcastRejected: async () => {
              calls.rejected += 1;
            },
          },
        } as any,
        nearAccountId: 'alice.testnet',
        signedResult: {
          chain: 'evm',
          kind: 'eip1559',
          txHashHex: `0x${'11'.repeat(32)}` as `0x${string}`,
          rawTxHex: '0x02',
        } as any,
        error: new Error('Unable to confirm finalization'),
        flow: 'tempo-sign',
        broadcastAccepted: true,
      });

      return calls;
    }, {
      helperPath: HELPER_IMPORT_PATH,
    });

    expect(result.reconcile).toBe(1);
    expect(result.dropped).toBe(0);
    expect(result.rejected).toBe(0);
  });

  test('reports broadcast rejected when broadcast was not accepted', async ({ page }) => {
    const result = await page.evaluate(async ({ helperPath }) => {
      const { reportTempoBroadcastFailure } = await import(helperPath);
      const calls = {
        reconcile: 0,
        dropped: 0,
        rejected: 0,
      };

      await reportTempoBroadcastFailure({
        tatchi: {
          tempo: {
            reconcileNonceLane: async () => {
              calls.reconcile += 1;
              return {
                chainNextNonce: '0',
                unresolvedInFlightNonces: [],
                blocked: false,
              };
            },
            reportDroppedOrReplaced: async () => {
              calls.dropped += 1;
            },
            reportBroadcastRejected: async () => {
              calls.rejected += 1;
            },
          },
        } as any,
        nearAccountId: 'alice.testnet',
        signedResult: {
          chain: 'evm',
          kind: 'eip1559',
          txHashHex: `0x${'11'.repeat(32)}` as `0x${string}`,
          rawTxHex: '0x02',
        } as any,
        error: new Error('sendRawTransaction failed'),
        flow: 'tempo-sign',
        broadcastAccepted: false,
      });

      return calls;
    }, {
      helperPath: HELPER_IMPORT_PATH,
    });

    expect(result.reconcile).toBe(0);
    expect(result.dropped).toBe(0);
    expect(result.rejected).toBe(1);
  });
});
