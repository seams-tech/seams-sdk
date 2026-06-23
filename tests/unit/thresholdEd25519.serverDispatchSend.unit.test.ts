import { expect, test } from '@playwright/test';
import { ActionType } from '@/core/types/actions';
import { SignedTransaction } from '@/core/rpcClients/near/NearClient';
import { executeActionInternal, sendTransaction } from '@/SeamsWeb/operations/near/actions';
import type { SeamsWebContext } from '@/SeamsWeb/signingSurface/types';
import type { NonceLeaseRef } from '@/core/signingEngine/interfaces/nonceLease';
import { walletSessionRefFromSession } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

test('sendTransaction returns server-dispatched result without rebroadcasting', async () => {
  const nonceEvents: string[] = [];
  const nonceLease: NonceLeaseRef = {
    leaseId: 'lease-1',
    operationId: 'operation-1',
    operationFingerprint: 'fingerprint-1',
  } as NonceLeaseRef;
  const signedTransaction = new SignedTransaction({
    transaction: { signerId: 'alice.testnet' } as never,
    signature: { keyType: 0, signatureData: [1] } as never,
    borsh_bytes: [2],
    nonceLease,
    serverDispatch: {
      transactionHash: 'tx-hash',
      rpcResult: { status: 'ok' },
    },
  });
  const context = {
    nearClient: {
      sendTransaction: async () => {
        throw new Error('client RPC broadcast should not run');
      },
    },
    signingEngine: {
      getNonceCoordinator: () => ({
        markBroadcastAccepted: async () => {
          nonceEvents.push('accepted');
        },
        markFinalized: async () => {
          nonceEvents.push('finalized');
        },
      }),
    },
  } as unknown as SeamsWebContext;
  const walletSession = walletSessionRefFromSession({
    walletId: 'alice.testnet',
    walletSessionUserId: 'alice.testnet',
  });

  const result = await sendTransaction({
    context,
    nearAccountId: 'alice.testnet',
    walletSession,
    signedTransaction,
  });

  expect(result).toEqual({
    success: true,
    transactionId: 'tx-hash',
    result: { status: 'ok' },
  });
  expect(nonceEvents).toEqual(['accepted', 'finalized']);
});

test('sendTransaction rejects direct broadcast without nonce readiness', async () => {
  let broadcastCalled = false;
  const signedTransaction = new SignedTransaction({
    transaction: { signerId: 'alice.testnet' } as never,
    signature: { keyType: 0, signatureData: [1] } as never,
    borsh_bytes: [2],
  });
  const context = {
    nearClient: {
      sendTransaction: async () => {
        broadcastCalled = true;
        return { transaction: { hash: 'tx-hash' } };
      },
    },
    signingEngine: {
      getNonceCoordinator: () => ({
        markBroadcastAccepted: async () => {},
        markFinalized: async () => {},
        markBroadcastRejected: async () => {},
      }),
    },
  } as unknown as SeamsWebContext;
  const walletSession = walletSessionRefFromSession({
    walletId: 'alice.testnet',
    walletSessionUserId: 'alice.testnet',
  });

  await expect(
    sendTransaction({
      context,
      nearAccountId: 'alice.testnet',
      walletSession,
      signedTransaction,
    }),
  ).rejects.toThrow('nonce readiness');
  expect(broadcastCalled).toBe(false);
});

test('executeActionInternal forwards the original signing error to afterCall', async () => {
  const afterCalls: Array<{ ok: boolean; error?: string }> = [];
  const onErrors: string[] = [];
  const context = {
    configs: {
      network: {
        chains: [{ network: 'near-testnet', rpcUrl: 'https://rpc.testnet.near.org' }],
      },
    },
    signingEngine: {
      signNear: async () => {
        throw new Error('synthetic NEAR signing failure');
      },
    },
  } as unknown as SeamsWebContext;

  const result = await executeActionInternal({
    context,
    nearAccountId: 'alice.testnet',
    walletSession: walletSessionRefFromSession({
      walletId: 'alice.testnet',
      walletSessionUserId: 'alice.testnet',
    }),
    receiverId: 'contract.testnet',
    actionArgs: {
      type: ActionType.Transfer,
      amount: '1',
    },
    options: {
      afterCall: (ok: boolean, _result?: unknown, error?: Error) => {
        afterCalls.push({ ok, ...(error ? { error: error.message } : {}) });
      },
      onError: (error: Error) => {
        onErrors.push(error.message);
      },
    },
  });

  expect(result).toMatchObject({
    success: false,
    error: 'synthetic NEAR signing failure',
  });
  expect(afterCalls).toEqual([
    { ok: false, error: 'synthetic NEAR signing failure' },
  ]);
  expect(onErrors).toContain('synthetic NEAR signing failure');
});
