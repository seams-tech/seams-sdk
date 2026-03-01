import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATH = '/src/flows/demo/hooks/demoEvmTransactionHandling.ts' as const;

test.describe('demoEvmTransactionHandling', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('reports broadcast failures without blocking the UI path', async ({ page }) => {
    const result = await page.evaluate(async ({ importPath }) => {
      const { reportDemoEvmBroadcastFailure } = await import(importPath);
      const calls = {
        reconcileStarted: 0,
        reconcileFinished: 0,
      };
      let resolveReconcile: (() => void) | null = null;
      const reconcileGate = new Promise<void>((resolve) => {
        resolveReconcile = resolve;
      });

      let continuedImmediately = false;
      reportDemoEvmBroadcastFailure({
        tatchi: {
          tempo: {
            reconcileNonceLane: async () => {
              calls.reconcileStarted += 1;
              await reconcileGate;
              calls.reconcileFinished += 1;
              return {
                chainNextNonce: '10',
                unresolvedInFlightNonces: [],
                blocked: false,
              };
            },
            reportDroppedOrReplaced: async () => undefined,
            reportBroadcastRejected: async () => undefined,
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
            networkKey: 'arc-testnet',
            chainId: 5042002,
            sender: `0x${'22'.repeat(20)}` as `0x${string}`,
            nonce: '9',
            nearAccountId: 'alice.testnet',
          },
        } as any,
        error: new Error('Timed out waiting for tx receipt'),
        flow: 'evm-sign',
        broadcastAccepted: true,
        txHash: `0x${'aa'.repeat(32)}` as `0x${string}`,
      });
      continuedImmediately = true;

      await new Promise((resolve) => window.setTimeout(resolve, 0));
      const startedBeforeResolve = calls.reconcileStarted;
      const finishedBeforeResolve = calls.reconcileFinished;

      resolveReconcile?.();
      await new Promise((resolve) => window.setTimeout(resolve, 0));

      return {
        continuedImmediately,
        startedBeforeResolve,
        finishedBeforeResolve,
        startedAfterResolve: calls.reconcileStarted,
        finishedAfterResolve: calls.reconcileFinished,
      };
    }, { importPath: IMPORT_PATH });

    expect(result.continuedImmediately).toBe(true);
    expect(result.startedBeforeResolve).toBe(1);
    expect(result.finishedBeforeResolve).toBe(0);
    expect(result.startedAfterResolve).toBe(1);
    expect(result.finishedAfterResolve).toBe(1);
  });
});
