import { expect, test } from '@playwright/test';
import {
  reconcileTempoNonceLane,
  reportTempoBroadcastAccepted,
  reportTempoBroadcastRejected,
  reportTempoDroppedOrReplaced,
  reportTempoFinalized,
} from '@/core/signingEngine/flows/signEvmFamily/signEvmFamily';

const TEST_SENDER = `0x${'11'.repeat(20)}` as const;

function createDeps(calls: Array<{ fn: string; input: any }>, laneStatuses?: any[]): any {
  return {
    nonceCoordinator: {
      markBroadcastAccepted: async (input: any) => {
        calls.push({ fn: 'markBroadcastAccepted', input });
      },
      markBroadcastRejected: async (input: any) => {
        calls.push({ fn: 'markBroadcastRejected', input });
      },
      markFinalized: async (input: any) => {
        calls.push({ fn: 'markFinalized', input });
      },
      markDroppedOrReplaced: async (input: any) => {
        calls.push({ fn: 'markDroppedOrReplaced', input });
      },
      reconcile: async ({ lane }: any) => {
        calls.push({ fn: 'reconcile', input: lane });
        return (
          laneStatuses?.shift() || {
            chainNextNonce: 0n,
            unresolvedInFlightNonces: [],
            blocked: false,
          }
        );
      },
      reserve: async () => {
        throw new Error('not used');
      },
      release: async () => undefined,
      markSigned: async () => undefined,
      clearForAccount: () => undefined,
    },
  };
}

function managedNonce(overrides?: Record<string, unknown>) {
  return {
    chain: 'tempo',
    networkKey: 'tempo-testnet',
    chainId: 42_431,
    sender: TEST_SENDER,
    nonceKey: '1',
    nonce: '12',
    walletId: 'alice.testnet',
    leaseId: 'nonce-lease-test',
    operationId: 'operation-test',
    operationFingerprint: 'sha256:test',
    ...overrides,
  };
}

function tempoSignedResult(overrides?: Record<string, unknown>): any {
  return {
    chain: 'tempo',
    kind: 'tempoTransaction',
    senderHashHex: `0x${'ef'.repeat(32)}` as `0x${string}`,
    rawTxHex: '0x76',
    managedNonce: managedNonce(),
    ...overrides,
  };
}

function evmSignedResult(overrides?: Record<string, unknown>): any {
  return {
    chain: 'evm',
    kind: 'eip1559',
    txHashHex: `0x${'cd'.repeat(32)}` as `0x${string}`,
    rawTxHex: '0x02',
    managedNonce: managedNonce({
      chain: 'evm',
      networkKey: 'arc-testnet',
      chainId: 11_155_111,
      nonceKey: undefined,
      nonce: '8',
    }),
    ...overrides,
  };
}

test.describe('tempo broadcast nonce lifecycle', () => {
  test('marks managed nonce lease as broadcast accepted', async () => {
    const calls: Array<{ fn: string; input: any }> = [];

    await reportTempoBroadcastAccepted(createDeps(calls), {
      walletId: 'alice.testnet',
      txHash: `0x${'ab'.repeat(32)}` as `0x${string}`,
      signedResult: evmSignedResult(),
    });

    expect(calls).toEqual([
      {
        fn: 'markBroadcastAccepted',
        input: {
          leaseId: 'nonce-lease-test',
          operationId: 'operation-test',
          txHash: `0x${'ab'.repeat(32)}`,
        },
      },
    ]);
  });

  test('fails closed when signed result is missing managed nonce metadata', async () => {
    await expect(
      reportTempoBroadcastAccepted(createDeps([]), {
        walletId: 'alice.testnet',
        txHash: `0x${'ab'.repeat(32)}` as `0x${string}`,
        signedResult: {
          chain: 'evm',
          kind: 'eip1559',
          txHashHex: `0x${'cd'.repeat(32)}` as `0x${string}`,
          rawTxHex: '0x02',
        } as any,
      }),
    ).rejects.toThrow('managedNonce is required');
  });

  test('fails closed when managed nonce lease metadata is missing', async () => {
    await expect(
      reportTempoBroadcastAccepted(createDeps([]), {
        walletId: 'alice.testnet',
        txHash: `0x${'ab'.repeat(32)}` as `0x${string}`,
        signedResult: evmSignedResult({
          managedNonce: managedNonce({
            leaseId: undefined,
            operationId: undefined,
          }),
        }),
      }),
    ).rejects.toThrow('managedNonce lease metadata is required');
  });

  test('marks managed nonce lease rejected on broadcast failure', async () => {
    const calls: Array<{ fn: string; input: any }> = [];

    await reportTempoBroadcastRejected(createDeps(calls), {
      walletId: 'alice.testnet',
      error: { message: 'execution reverted' },
      signedResult: tempoSignedResult(),
    });

    expect(calls).toEqual([
      {
        fn: 'markBroadcastRejected',
        input: {
          leaseId: 'nonce-lease-test',
          operationId: 'operation-test',
          error: { message: 'execution reverted' },
        },
      },
    ]);
  });

  test('marks managed nonce lease finalized on chain finalization', async () => {
    const calls: Array<{ fn: string; input: any }> = [];

    await reportTempoFinalized(createDeps(calls), {
      walletId: 'alice.testnet',
      txHash: `0x${'aa'.repeat(32)}` as `0x${string}`,
      receiptStatus: 'success',
      signedResult: evmSignedResult({
        managedNonce: managedNonce({
          chain: 'evm',
          networkKey: 'arc-testnet',
          chainId: 11_155_111,
          nonce: '13',
        }),
      }),
    });

    expect(calls).toEqual([
      {
        fn: 'markFinalized',
        input: {
          leaseId: 'nonce-lease-test',
          operationId: 'operation-test',
          txHash: `0x${'aa'.repeat(32)}`,
        },
      },
    ]);
  });

  test('marks managed nonce lease dropped with reason and tx hash', async () => {
    const calls: Array<{ fn: string; input: any }> = [];

    await reportTempoDroppedOrReplaced(createDeps(calls), {
      walletId: 'alice.testnet',
      reason: 'dropped',
      txHash: `0x${'cc'.repeat(32)}` as `0x${string}`,
      signedResult: tempoSignedResult({
        managedNonce: managedNonce({
          nonceKey: '7',
          nonce: '4',
        }),
      }),
    });

    expect(calls).toEqual([
      {
        fn: 'markDroppedOrReplaced',
        input: {
          leaseId: 'nonce-lease-test',
          operationId: 'operation-test',
          reason: 'dropped',
          txHash: `0x${'cc'.repeat(32)}`,
        },
      },
    ]);
  });

  test('marks managed nonce lease replaced with reason and replacement hash', async () => {
    const calls: Array<{ fn: string; input: any }> = [];

    await reportTempoDroppedOrReplaced(createDeps(calls), {
      walletId: 'alice.testnet',
      reason: 'replaced',
      txHash: `0x${'ee'.repeat(32)}` as `0x${string}`,
      signedResult: evmSignedResult({
        managedNonce: managedNonce({
          chain: 'evm',
          networkKey: 'arc-testnet',
          chainId: 11_155_111,
          nonce: '19',
        }),
      }),
    });

    expect(calls).toEqual([
      {
        fn: 'markDroppedOrReplaced',
        input: {
          leaseId: 'nonce-lease-test',
          operationId: 'operation-test',
          reason: 'replaced',
          txHash: `0x${'ee'.repeat(32)}`,
        },
      },
    ]);
  });

  test('reconcile returns lane status and throws when lane is blocked', async () => {
    const calls: Array<{ fn: string; input: any }> = [];
    const deps = createDeps(calls, [
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
    ]);
    const args = {
      walletId: 'alice.testnet',
      signedResult: evmSignedResult({
        managedNonce: managedNonce({
          chain: 'evm',
          networkKey: 'arc-testnet',
          chainId: 11_155_111,
          nonce: '15',
        }),
      }),
    };

    const first = await reconcileTempoNonceLane(deps, args);
    let secondError: any = null;
    try {
      await reconcileTempoNonceLane(deps, args);
    } catch (error: any) {
      secondError = {
        code: String(error?.code || ''),
        retryable: Boolean(error?.retryable),
        blockedNonce: String(error?.details?.blockedNonce || ''),
      };
    }

    expect(calls.map((entry) => entry.fn)).toEqual(['reconcile', 'reconcile']);
    expect(first).toEqual({
      chainNextNonce: '15',
      unresolvedInFlightNonces: ['15'],
      blocked: false,
    });
    expect(secondError).toEqual({
      code: 'nonce_lane_blocked',
      retryable: true,
      blockedNonce: '15',
    });
  });

  test('reconciles lane and throws retryable code on nonce-conflict failure', async () => {
    const calls: Array<{ fn: string; input: any }> = [];

    await expect(
      reportTempoBroadcastRejected(createDeps(calls), {
        walletId: 'alice.testnet',
        error: { message: 'replacement transaction underpriced' },
        signedResult: evmSignedResult({
          managedNonce: managedNonce({
            chain: 'evm',
            networkKey: 'arc-testnet',
            chainId: 11_155_111,
            nonce: '9',
          }),
        }),
      }),
    ).rejects.toMatchObject({
      code: 'nonce_conflict_retryable',
      retryable: true,
    });
    expect(calls.map((entry) => entry.fn)).toEqual(['markBroadcastRejected', 'reconcile']);
  });
});
