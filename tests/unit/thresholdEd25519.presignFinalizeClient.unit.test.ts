import { expect, test } from '@playwright/test';
import {
  applyThresholdEd25519PresignRefillResult,
  clearAllThresholdEd25519ClientPresigns,
  scheduleThresholdEd25519ClientPresignPoolRefill,
} from '@/core/signingEngine/threshold/ed25519/presignPool';
import {
  finalizeThresholdEd25519DelegatePresignResult,
  refillThresholdEd25519ClientPresignPool,
  tryFinalizeThresholdEd25519NearTransactionPresign,
  tryFinalizeThresholdEd25519SignatureOnlyPresign,
} from '@/core/signingEngine/flows/signNear/shared/ed25519PresignFinalize';
import {
  NearSignerWorkerCustomRequestType,
  type PrepareThresholdEd25519PresignPoolPayload,
  type DelegatePayload,
} from '@/core/types/signer-worker';
import type { NearSigningRuntimeDeps } from '@/core/signingEngine/interfaces/runtime';
import type { ThresholdEd25519KeyMaterial } from '@/core/accountData/near/types';
import type { ResolvedThresholdEd25519SessionState } from '@/core/signingEngine/flows/signNear/shared/thresholdSessionAuth';
import type {
  SigningOperationFingerprint,
  SigningOperationId,
} from '@/core/signingEngine/session/operationState/types';

const runtimePolicyScope = {
  orgId: 'org-presign-finalize',
  projectId: 'project-presign-finalize',
  envId: 'test',
  signingRootVersion: 'root-v1',
};

const operationId = 'operation-presign-finalize' as SigningOperationId;
const operationFingerprint = 'fingerprint-presign-finalize' as SigningOperationFingerprint;

const thresholdKeyMaterial: ThresholdEd25519KeyMaterial = {
  nearAccountId: 'alice.testnet',
  signerSlot: 0,
  kind: 'threshold_ed25519_v1',
  publicKey: 'ed25519-public-key',
  relayerKeyId: 'relayer-key',
  keyVersion: 'key-v1',
  participants: [
    { id: 1, role: 'client' },
    { id: 2, role: 'relayer' },
  ],
  timestamp: 1,
};

function refillPayload(): PrepareThresholdEd25519PresignPoolPayload {
  return {
    kind: 'prepare_threshold_ed25519_presign_pool_v1',
    sessionKind: 'jwt',
    thresholdSessionAuthToken: 'threshold-session-token',
    relayUrl: 'https://relay.example',
    thresholdSessionId: 'threshold-session-id',
    walletSigningSessionId: 'wallet-signing-session-id',
    relayerKeyId: 'relayer-key',
    nearAccountId: 'alice.testnet',
    nearNetworkId: 'testnet',
    signerPublicKey: 'ed25519-public-key',
    participantIds: [1, 2],
    runtimePolicyScope,
    policy: {
      targetDepth: 2,
      lowWatermark: 1,
      maxAcceptedRefillCount: 8,
      ttlMs: 60_000,
    },
    requestTag: 'background_presign_pool_refill',
    generation: 1,
    clientPresigns: [
      {
        clientPresignId: 'client-presign-1',
        nonceHandle: 'nonce-handle-1',
        clientVerifyingShareB64u: 'client-verifying-share',
        clientCommitments: { hiding: 'client-hiding', binding: 'client-binding' },
      },
    ],
  };
}

function seedReadyPresign(): void {
  const payload = refillPayload();
  const expiresAtMs = Date.now() + 60_000;
  scheduleThresholdEd25519ClientPresignPoolRefill(payload, 1_000);
  applyThresholdEd25519PresignRefillResult({
    payload,
    nowMs: 1_100,
    result: {
      ok: true,
      kind: 'prepare_threshold_ed25519_presign_pool_result_v1',
      generation: 1,
      accepted: [
        {
          presignId: 'server-presign-1',
          clientPresignId: 'client-presign-1',
          relayerCommitments: { hiding: 'relayer-hiding', binding: 'relayer-binding' },
          relayerVerifyingShareB64u: 'relayer-verifying-share',
          expiresAtMs,
        },
      ],
      rejectedClientPresignIds: [],
      expiresAtMs,
    },
  });
}

function sessionState(): ResolvedThresholdEd25519SessionState {
  return {
    sessionKind: 'jwt',
    thresholdSessionAuthToken: 'threshold-session-token',
    thresholdSessionId: 'threshold-session-id',
    walletSigningSessionId: 'wallet-signing-session-id',
    signingLane: {} as ResolvedThresholdEd25519SessionState['signingLane'],
    remainingUses: 3,
    xClientBaseB64u: 'client-base',
    runtimePolicyScope,
    signingRootId: 'project-presign-finalize:test',
    relayerUrl: 'https://relay.example',
    persistClientBase: () => true,
  };
}

function runtimeDeps(calls: unknown[]): NearSigningRuntimeDeps {
  let presignCreateCount = 0;
  const requestWorkerOperation: NearSigningRuntimeDeps['requestWorkerOperation'] = async (args) => {
    calls.push(args);
    const requestType = args.request.type;
    if (requestType === NearSignerWorkerCustomRequestType.ThresholdEd25519ClientPresignCreate) {
      presignCreateCount += 1;
      return {
        clientNonceHandleB64u: `opaque-nonce-handle-${presignCreateCount}`,
        clientVerifyingShareB64u: 'client-verifying-share',
        clientCommitments: {
          hiding: `client-refill-hiding-${presignCreateCount}`,
          binding: `client-refill-binding-${presignCreateCount}`,
        },
      } as never;
    }
    if (requestType === NearSignerWorkerCustomRequestType.ThresholdEd25519ClientPresignSign) {
      return { clientSignatureShareB64u: 'client-share' } as never;
    }
    if (requestType === NearSignerWorkerCustomRequestType.ThresholdEd25519ClientPresignBurn) {
      return { burned: true } as never;
    }
    if (
      requestType === NearSignerWorkerCustomRequestType.ThresholdEd25519BuildNearTxUnsignedBorsh
    ) {
      return [
        {
          unsignedTransactionBorshB64u: 'unsigned-tx-borsh',
          signingDigestB64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        },
      ] as never;
    }
    if (requestType === NearSignerWorkerCustomRequestType.ThresholdEd25519DecodeSignedNearTxBorsh) {
      return {
        signedTransaction: {
          transaction: { signerId: 'alice.testnet' },
          signature: { keyType: 0, signatureData: [1] },
          borshBytes: [2],
        },
        transactionHash: 'tx-hash',
      } as never;
    }
    if (
      requestType ===
      NearSignerWorkerCustomRequestType.ThresholdEd25519FinalizeDelegateFromSignature
    ) {
      return {
        delegateAction: { senderId: 'alice.testnet' },
        signature: { keyType: 0, signatureData: [1] },
        borshBytes: [2],
      } as never;
    }
    throw new Error(`unexpected worker request ${String(requestType)}`);
  };
  const deps: NearSigningRuntimeDeps = {
    touchIdPrompt: {} as NearSigningRuntimeDeps['touchIdPrompt'],
    nearClient: {} as NearSigningRuntimeDeps['nearClient'],
    nearKeyMaterialStore: {} as NearSigningRuntimeDeps['nearKeyMaterialStore'],
    userPreferencesManager: {} as NearSigningRuntimeDeps['userPreferencesManager'],
    nonceCoordinator: {} as NearSigningRuntimeDeps['nonceCoordinator'],
    chains: [
      {
        network: 'near-testnet',
        rpcUrl: 'https://rpc.testnet.near.org',
        explorerUrl: 'https://testnet.nearblocks.io',
      },
    ],
    relayerUrl: 'https://relay.example',
    requestWorkerOperation,
  };
  return deps;
}

async function flushMicrotasks(): Promise<void> {
  for (let index = 0; index < 20; index += 1) {
    await Promise.resolve();
  }
}

test.describe('threshold Ed25519 signature-only presign finalize client helper', () => {
  test.beforeEach(() => {
    clearAllThresholdEd25519ClientPresigns();
  });

  test('finalizes a ready NEP-413 presign through the relayer route', async () => {
    seedReadyPresign();
    const workerCalls: unknown[] = [];
    const fetchCalls: unknown[] = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit) => {
      fetchCalls.push({ url: String(url), init });
      return {
        json: async () => ({
          ok: true,
          kind: 'threshold_ed25519_signature_only_result_v1',
          operationId,
          budgetState: 'consumed',
          remainingSigningUses: 2,
          signatureB64u: 'signature-b64u',
          signerPublicKey: 'ed25519-public-key',
        }),
      } as Response;
    }) as typeof fetch;

    try {
      const result = await tryFinalizeThresholdEd25519SignatureOnlyPresign({
        ctx: runtimeDeps(workerCalls),
        thresholdSessionId: 'threshold-session-id',
        thresholdSessionState: sessionState(),
        thresholdKeyMaterial,
        nearAccountId: 'alice.testnet',
        xClientBaseB64u: 'client-base',
        operationId,
        operationFingerprint,
        purpose: 'nep413_message',
        signingDigestB64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        intent: {
          kind: 'nep413_message_v1',
          message: 'hello',
          recipient: 'recipient.testnet',
          nonce: 'nonce',
        },
      });

      expect(result).toMatchObject({
        signatureB64u: 'signature-b64u',
        signerPublicKey: 'ed25519-public-key',
        remainingSigningUses: 2,
      });
      expect(workerCalls[0]).toMatchObject({
        request: {
          type: NearSignerWorkerCustomRequestType.ThresholdEd25519ClientPresignSign,
          payload: {
            signingDigestB64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
            clientNonceHandleB64u: 'nonce-handle-1',
          },
        },
      });
      expect(fetchCalls[0]).toMatchObject({
        url: 'https://relay.example/threshold-ed25519/sign/finalize-and-dispatch',
      });
      expect(JSON.parse(String((fetchCalls[0] as { init: RequestInit }).init.body))).toMatchObject({
        kind: 'threshold_ed25519_finalize_signature_only_v1',
        presignId: 'server-presign-1',
        requestIntegrityHash: expect.stringMatching(/^sha256:/),
        clientSignatureShareB64u: 'client-share',
        intent: {
          kind: 'nep413_message_v1',
          message: 'hello',
          recipient: 'recipient.testnet',
          nonce: 'nonce',
        },
        operation: {
          operationId,
          operationFingerprint,
          purpose: 'nep413_message',
        },
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('builds a signed delegate result from a relayer presign signature', async () => {
    const workerCalls: unknown[] = [];
    const delegate: DelegatePayload = {
      senderId: 'alice.testnet',
      receiverId: 'bob.testnet',
      actions: [],
      nonce: '1',
      maxBlockHeight: '2',
      publicKey: 'ed25519-public-key',
    };

    const result = await finalizeThresholdEd25519DelegatePresignResult({
      ctx: runtimeDeps(workerCalls),
      thresholdSessionId: 'threshold-session-id',
      delegate,
      signingDigestB64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      presignResult: {
        kind: 'threshold_ed25519_signature_only_presign_result_v1',
        operationId,
        signatureB64u: 'signature-b64u',
        signerPublicKey: 'ed25519-public-key',
        remainingSigningUses: 2,
        budgetState: 'consumed',
      },
    });

    expect(result.hash).toBe('0000000000000000000000000000000000000000000000000000000000000000');
    expect(result.signedDelegate).toMatchObject({
      delegateAction: { senderId: 'alice.testnet' },
      signature: { keyType: 0, signatureData: [1] },
      borshBytes: [2],
    });
    expect(workerCalls[0]).toMatchObject({
      request: {
        type: NearSignerWorkerCustomRequestType.ThresholdEd25519FinalizeDelegateFromSignature,
        payload: {
          delegate,
          signingDigestB64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          signatureB64u: 'signature-b64u',
        },
      },
    });
  });

  test('finalizes and dispatches a ready NEAR transaction presign', async () => {
    seedReadyPresign();
    const workerCalls: unknown[] = [];
    const fetchCalls: unknown[] = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit) => {
      fetchCalls.push({ url: String(url), init });
      if (String(url).endsWith('/threshold-ed25519/presign/refill')) {
        return {
          json: async () => ({
            ok: true,
            kind: 'threshold_ed25519_presign_refill_response_v1',
            accepted: [],
            rejectedClientPresignIds: [],
            serverTimeMs: Date.now(),
          }),
        } as Response;
      }
      return {
        json: async () => ({
          ok: true,
          kind: 'threshold_ed25519_dispatched_near_tx_result_v1',
          operationId,
          budgetState: 'consumed',
          remainingSigningUses: 2,
          signatureB64u: 'signature-b64u',
          signerPublicKey: 'ed25519-public-key',
          signedTransactionBorshB64u: 'signed-tx-borsh',
          transactionHash: 'tx-hash',
          rpcResult: { status: 'ok' },
        }),
      } as Response;
    }) as typeof fetch;

    try {
      const result = await tryFinalizeThresholdEd25519NearTransactionPresign({
        ctx: runtimeDeps(workerCalls),
        thresholdSessionId: 'threshold-session-id',
        thresholdSessionState: sessionState(),
        thresholdKeyMaterial,
        nearAccountId: 'alice.testnet',
        xClientBaseB64u: 'client-base',
        operationId,
        operationFingerprint,
        txSigningRequests: [
          { nearAccountId: 'alice.testnet', receiverId: 'bob.testnet', actions: [] },
        ],
        transactionContext: {
          nearPublicKeyStr: 'ed25519-public-key',
          accessKeyInfo: {} as never,
          nextNonce: '1',
          txBlockHeight: '2',
          txBlockHash: 'block-hash',
        },
      });

      expect(result).toMatchObject({
        transactionHash: 'tx-hash',
        okResponse: {
          payload: {
            success: true,
            transactionHashes: ['tx-hash'],
            signedTransactions: [
              {
                transaction: { signerId: 'alice.testnet' },
                serverDispatch: {
                  transactionHash: 'tx-hash',
                  rpcResult: { status: 'ok' },
                },
              },
            ],
          },
        },
      });
      await flushMicrotasks();
      expect(
        workerCalls.map((call) => (call as { request: { type: unknown } }).request.type),
      ).toEqual([
        NearSignerWorkerCustomRequestType.ThresholdEd25519BuildNearTxUnsignedBorsh,
        NearSignerWorkerCustomRequestType.ThresholdEd25519ClientPresignSign,
        NearSignerWorkerCustomRequestType.ThresholdEd25519DecodeSignedNearTxBorsh,
        NearSignerWorkerCustomRequestType.ThresholdEd25519ClientPresignCreate,
        NearSignerWorkerCustomRequestType.ThresholdEd25519ClientPresignCreate,
        NearSignerWorkerCustomRequestType.ThresholdEd25519ClientPresignBurn,
        NearSignerWorkerCustomRequestType.ThresholdEd25519ClientPresignBurn,
      ]);
      expect(JSON.parse(String((fetchCalls[0] as { init: RequestInit }).init.body))).toMatchObject({
        kind: 'threshold_ed25519_finalize_and_dispatch_near_tx_v1',
        presignId: 'server-presign-1',
        requestIntegrityHash: expect.stringMatching(/^sha256:/),
        transactions: [{ nearAccountId: 'alice.testnet', receiverId: 'bob.testnet', actions: [] }],
        unsignedTransactionBorshB64u: 'unsigned-tx-borsh',
        signingDigestB64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        clientSignatureShareB64u: 'client-share',
        dispatch: { kind: 'near_rpc_configured_default_v1' },
        operation: {
          operationId,
          operationFingerprint: expect.stringMatching(/^sha256:/),
          purpose: 'near_transaction',
        },
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('returns null for NEAR transaction signing when no ready presign exists', async () => {
    const workerCalls: unknown[] = [];
    const fetchCalls: unknown[] = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit) => {
      fetchCalls.push({ url: String(url), init });
      return {
        json: async () => ({
          ok: true,
          kind: 'threshold_ed25519_presign_refill_response_v1',
          accepted: [],
          rejectedClientPresignIds: [],
          serverTimeMs: Date.now(),
        }),
      } as Response;
    }) as typeof fetch;

    try {
      const result = await tryFinalizeThresholdEd25519NearTransactionPresign({
        ctx: runtimeDeps(workerCalls),
        thresholdSessionId: 'threshold-session-id',
        thresholdSessionState: sessionState(),
        thresholdKeyMaterial,
        nearAccountId: 'alice.testnet',
        xClientBaseB64u: 'client-base',
        operationId,
        operationFingerprint,
        txSigningRequests: [
          { nearAccountId: 'alice.testnet', receiverId: 'bob.testnet', actions: [] },
        ],
        transactionContext: {
          nearPublicKeyStr: 'ed25519-public-key',
          accessKeyInfo: {} as never,
          nextNonce: '1',
          txBlockHeight: '2',
          txBlockHash: 'block-hash',
        },
      });

      expect(result).toBeNull();
      await expect.poll(() => fetchCalls.length).toBe(1);
      expect(fetchCalls).toHaveLength(1);
      expect(fetchCalls[0]).toMatchObject({
        url: 'https://relay.example/threshold-ed25519/presign/refill',
      });
      await flushMicrotasks();
      expect(
        workerCalls.map((call) => (call as { request: { type: unknown } }).request.type),
      ).toEqual([
        NearSignerWorkerCustomRequestType.ThresholdEd25519BuildNearTxUnsignedBorsh,
        NearSignerWorkerCustomRequestType.ThresholdEd25519ClientPresignCreate,
        NearSignerWorkerCustomRequestType.ThresholdEd25519ClientPresignCreate,
        NearSignerWorkerCustomRequestType.ThresholdEd25519ClientPresignBurn,
        NearSignerWorkerCustomRequestType.ThresholdEd25519ClientPresignBurn,
      ]);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('keeps multi-transaction batches on the existing signing path', async () => {
    seedReadyPresign();
    const workerCalls: unknown[] = [];
    const result = await tryFinalizeThresholdEd25519NearTransactionPresign({
      ctx: runtimeDeps(workerCalls),
      thresholdSessionId: 'threshold-session-id',
      thresholdSessionState: sessionState(),
      thresholdKeyMaterial,
      nearAccountId: 'alice.testnet',
      xClientBaseB64u: 'client-base',
      operationId,
      operationFingerprint,
      txSigningRequests: [
        { nearAccountId: 'alice.testnet', receiverId: 'bob.testnet', actions: [] },
        { nearAccountId: 'alice.testnet', receiverId: 'carol.testnet', actions: [] },
      ],
      transactionContext: {
        nearPublicKeyStr: 'ed25519-public-key',
        accessKeyInfo: {} as never,
        nextNonce: '1',
        txBlockHeight: '2',
        txBlockHash: 'block-hash',
      },
    });

    expect(result).toBeNull();
    expect(workerCalls).toHaveLength(0);
  });

  test('refills the client presign pool and burns rejected handles', async () => {
    const workerCalls: unknown[] = [];
    const fetchCalls: unknown[] = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit) => {
      fetchCalls.push({ url: String(url), init });
      const body = JSON.parse(String(init?.body || '{}')) as {
        clientPresigns?: { clientPresignId: string }[];
      };
      const acceptedClientPresignId = body.clientPresigns?.[0]?.clientPresignId || '';
      const rejectedClientPresignId = body.clientPresigns?.[1]?.clientPresignId || '';
      return {
        json: async () => ({
          ok: true,
          kind: 'threshold_ed25519_presign_refill_response_v1',
          accepted: [
            {
              presignId: 'server-presign-refill-1',
              clientPresignId: acceptedClientPresignId,
              relayerCommitments: { hiding: 'relayer-hiding', binding: 'relayer-binding' },
              relayerVerifyingShareB64u: 'relayer-verifying-share',
              signerPublicKey: 'ed25519-public-key',
              nearNetworkId: 'testnet',
              participantIds: [1, 2],
              expiresAtMs: Date.now() + 60_000,
            },
          ],
          rejectedClientPresignIds: rejectedClientPresignId ? [rejectedClientPresignId] : [],
          serverTimeMs: Date.now(),
        }),
      } as Response;
    }) as typeof fetch;

    try {
      const result = await refillThresholdEd25519ClientPresignPool({
        ctx: runtimeDeps(workerCalls),
        thresholdSessionId: 'threshold-session-id',
        thresholdSessionState: sessionState(),
        thresholdKeyMaterial,
        nearAccountId: 'alice.testnet',
        xClientBaseB64u: 'client-base',
        requestTag: 'background_presign_pool_refill',
      });

      expect(result?.schedule.scheduled).toBe(true);
      expect(fetchCalls[0]).toMatchObject({
        url: 'https://relay.example/threshold-ed25519/presign/refill',
      });
      expect(
        workerCalls.map((call) => (call as { request: { type: unknown } }).request.type),
      ).toEqual([
        NearSignerWorkerCustomRequestType.ThresholdEd25519ClientPresignCreate,
        NearSignerWorkerCustomRequestType.ThresholdEd25519ClientPresignCreate,
        NearSignerWorkerCustomRequestType.ThresholdEd25519ClientPresignBurn,
      ]);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
