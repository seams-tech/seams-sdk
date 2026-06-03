import { expect, test } from '@playwright/test';
import {
  buildThresholdEd25519NearTxUnsignedBorshWasm,
  burnThresholdEd25519ClientPresignWasm,
  computeThresholdEd25519DelegateSigningDigestWasm,
  computeThresholdEd25519Nep413SigningDigestWasm,
  createThresholdEd25519ClientPresignWasm,
  decodeThresholdEd25519SignedNearTxBorshWasm,
  signThresholdEd25519ClientPresignWasm,
} from '../../client/src/core/signingEngine/chains/near/nearSignerWasm';
import {
  NearSignerWorkerCustomRequestType,
  type DelegatePayload,
} from '../../client/src/core/types/signer-worker';
import type { WorkerOperationContext } from '../../client/src/core/signingEngine/workerManager/executeWorkerOperation';

function recordingWorkerCtx(result: unknown, calls: unknown[]): WorkerOperationContext {
  return {
    requestWorkerOperation: async (args) => {
      calls.push(args);
      return result as never;
    },
  };
}

test.describe('threshold Ed25519 near signer WASM wrappers', () => {
  test('creates client presign material through the near signer worker', async () => {
    const calls: unknown[] = [];
    const result = await createThresholdEd25519ClientPresignWasm({
      sessionId: 'threshold-session',
      clientParticipantId: 1,
      relayerParticipantId: 2,
      xClientBaseB64u: 'client-base',
      groupPublicKey: 'ed25519:group',
      workerCtx: recordingWorkerCtx(
        {
          clientNonceHandleB64u: 'nonce-handle',
          clientVerifyingShareB64u: 'client-verifying-share',
          clientCommitments: { hiding: 'client-hiding', binding: 'client-binding' },
        },
        calls,
      ),
    });

    expect(result).toEqual({
      clientNonceHandleB64u: 'nonce-handle',
      clientVerifyingShareB64u: 'client-verifying-share',
      clientCommitments: { hiding: 'client-hiding', binding: 'client-binding' },
    });
    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatchObject({
      kind: 'nearSigner',
      request: {
        sessionId: 'threshold-session',
        type: NearSignerWorkerCustomRequestType.ThresholdEd25519ClientPresignCreate,
        payload: {
          clientParticipantId: 1,
          relayerParticipantId: 2,
          xClientBaseB64u: 'client-base',
          groupPublicKey: 'ed25519:group',
        },
      },
    });
  });

  test('signs a reserved client presign through the near signer worker', async () => {
    const calls: unknown[] = [];
    const result = await signThresholdEd25519ClientPresignWasm({
      sessionId: 'threshold-session',
      clientParticipantId: 1,
      relayerParticipantId: 2,
      xClientBaseB64u: 'client-base',
      groupPublicKey: 'ed25519:group',
      signingDigestB64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      clientNonceHandleB64u: 'nonce-handle',
      clientCommitments: { hiding: 'client-hiding', binding: 'client-binding' },
      relayerCommitments: { hiding: 'relayer-hiding', binding: 'relayer-binding' },
      workerCtx: recordingWorkerCtx({ clientSignatureShareB64u: 'client-share' }, calls),
    });

    expect(result).toEqual({ clientSignatureShareB64u: 'client-share' });
    expect(calls[0]).toMatchObject({
      kind: 'nearSigner',
      request: {
        type: NearSignerWorkerCustomRequestType.ThresholdEd25519ClientPresignSign,
        payload: {
          signingDigestB64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          clientNonceHandleB64u: 'nonce-handle',
        },
      },
    });
  });

  test('burns an unused client presign handle through the near signer worker', async () => {
    const calls: unknown[] = [];
    const result = await burnThresholdEd25519ClientPresignWasm({
      sessionId: 'threshold-session',
      clientNonceHandleB64u: 'opaque-nonce-handle',
      workerCtx: recordingWorkerCtx({ burned: true }, calls),
    });

    expect(result).toEqual({ burned: true });
    expect(calls[0]).toMatchObject({
      kind: 'nearSigner',
      request: {
        sessionId: 'threshold-session',
        type: NearSignerWorkerCustomRequestType.ThresholdEd25519ClientPresignBurn,
        payload: {
          clientNonceHandleB64u: 'opaque-nonce-handle',
        },
      },
    });
  });

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
      txSigningRequests: [{ nearAccountId: 'alice.testnet', receiverId: 'bob.testnet', actions: [] }],
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
    expect(unsigned).toEqual([
      { unsignedTransactionBorshB64u: 'unsigned-tx', signingDigestB64u: 'digest-tx' },
    ]);
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
