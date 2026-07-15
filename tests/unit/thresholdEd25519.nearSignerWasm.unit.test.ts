import { expect, test } from '@playwright/test';
import {
  buildThresholdEd25519NearTxUnsignedBorshWasm,
  computeThresholdEd25519DelegateSigningDigestWasm,
  computeThresholdEd25519Nep413SigningDigestWasm,
  decodeThresholdEd25519SignedNearTxBorshWasm,
} from '../../packages/sdk-web/src/core/signingEngine/chains/near/nearSignerWasm';
import {
  NearSignerWorkerCustomRequestType,
  type DelegatePayload,
} from '../../packages/sdk-web/src/core/types/signer-worker';
import type { WorkerOperationContext } from '../../packages/sdk-web/src/core/signingEngine/workerManager/executeWorkerOperation';

function recordingWorkerCtx(result: unknown, calls: unknown[]): WorkerOperationContext {
  return {
    requestWorkerOperation: async (args) => {
      calls.push(args);
      return result as never;
    },
  };
}

test.describe('threshold Ed25519 near signer WASM wrappers', () => {
  test('computes signature-only signing digests through the near signer worker', async () => {
    const nep413Calls: unknown[] = [];
    const nep413 = await computeThresholdEd25519Nep413SigningDigestWasm({
      sessionId: 'threshold-session',
      message: 'hello',
      recipient: 'wallet.example',
      nonce: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
      state: 'state',
      workerCtx: recordingWorkerCtx({ signingDigestB64u: 'digest-nep413' }, nep413Calls),
    });
    expect(nep413).toEqual({ signingDigestB64u: 'digest-nep413' });
    expect(nep413Calls[0]).toMatchObject({
      request: {
        type: NearSignerWorkerCustomRequestType.ThresholdEd25519ComputeNep413SigningDigest,
        payload: { message: 'hello', recipient: 'wallet.example', state: 'state' },
      },
    });

    const delegate: DelegatePayload = {
      senderId: 'alice.testnet',
      receiverId: 'bob.testnet',
      actions: [],
      nonce: '1',
      maxBlockHeight: '2',
      publicKey: 'ed25519:group',
    };
    const delegateCalls: unknown[] = [];
    const delegateDigest = await computeThresholdEd25519DelegateSigningDigestWasm({
      sessionId: 'threshold-session',
      delegate,
      workerCtx: recordingWorkerCtx({ signingDigestB64u: 'digest-delegate' }, delegateCalls),
    });
    expect(delegateDigest).toEqual({ signingDigestB64u: 'digest-delegate' });
    expect(delegateCalls[0]).toMatchObject({
      request: {
        type: NearSignerWorkerCustomRequestType.ThresholdEd25519ComputeDelegateSigningDigest,
        payload: { delegate },
      },
    });
  });

  test('builds and decodes NEAR transaction BORSH through the near signer worker', async () => {
    const unsignedCalls: unknown[] = [];
    const unsigned = await buildThresholdEd25519NearTxUnsignedBorshWasm({
      sessionId: 'threshold-session',
      txSigningRequest: { nearAccountId: 'alice.testnet', receiverId: 'bob.testnet', actions: [] },
      transactionContext: {
        nearPublicKeyStr: 'ed25519:group',
        accessKeyInfo: {} as never,
        nextNonce: '1',
        txBlockHeight: '2',
        txBlockHash: 'block-hash',
      },
      workerCtx: recordingWorkerCtx(
        [{ unsignedTransactionBorshB64u: 'unsigned-tx', signingDigestB64u: 'digest-tx' }],
        unsignedCalls,
      ),
    });
    expect(unsigned).toEqual({
      unsignedTransactionBorshB64u: 'unsigned-tx',
      signingDigestB64u: 'digest-tx',
    });
    expect(unsignedCalls[0]).toMatchObject({
      request: {
        type: NearSignerWorkerCustomRequestType.ThresholdEd25519BuildNearTxUnsignedBorsh,
        payload: {
          txSigningRequests: [
            { nearAccountId: 'alice.testnet', receiverId: 'bob.testnet', actions: [] },
          ],
        },
      },
    });

    const decodeCalls: unknown[] = [];
    const decoded = await decodeThresholdEd25519SignedNearTxBorshWasm({
      sessionId: 'threshold-session',
      signedTransactionBorshB64u: 'signed-tx',
      workerCtx: recordingWorkerCtx(
        {
          signedTransaction: {
            transaction: { signerId: 'alice.testnet' },
            signature: { keyType: 0, signatureData: [1] },
            borshBytes: [2],
          },
          transactionHash: 'tx-hash',
        },
        decodeCalls,
      ),
    });
    expect(decoded).toMatchObject({
      signedTransaction: {
        transaction: { signerId: 'alice.testnet' },
        signature: { keyType: 0, signatureData: [1] },
        borshBytes: [2],
      },
      transactionHash: 'tx-hash',
    });
    expect(decodeCalls[0]).toMatchObject({
      request: {
        type: NearSignerWorkerCustomRequestType.ThresholdEd25519DecodeSignedNearTxBorsh,
        payload: { signedTransactionBorshB64u: 'signed-tx' },
      },
    });
  });
});
