import { resolveNearNetwork } from '@/core/config/chains';
import { PASSKEY_MANAGER_DEFAULT_CONFIGS } from '@/core/config/defaultConfigs';
import type { ThresholdEd25519KeyMaterial } from '@/core/accountData/near/types';
import {
  WorkerRequestType,
  WorkerResponseType,
  type DelegatePayload,
  type PrepareThresholdEd25519PresignPoolPayload,
  type TransactionPayload,
  type ThresholdEd25519ClientPresignWorkerOffer,
  type WasmSignedDelegate,
  type WorkerSuccessResponse,
} from '@/core/types/signer-worker';
import {
  buildThresholdEd25519NearTxUnsignedBorshWasm,
  burnThresholdEd25519ClientPresignWasm,
  createThresholdEd25519ClientPresignWasm,
  decodeThresholdEd25519SignedNearTxBorshWasm,
  finalizeThresholdEd25519DelegateFromSignatureWasm,
  signThresholdEd25519ClientPresignWasm,
} from '@/core/signingEngine/chains/near/nearSignerWasm';
import type { TransactionContext } from '@/core/types/rpc';
import type { SigningRuntimeDeps } from '@/core/signingEngine/interfaces/runtime';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import {
  applyThresholdEd25519PresignRefillResult,
  createThresholdEd25519PresignScopeKey,
  type Ed25519PresignOperationIdentity,
  type Ed25519PresignPoolRefillScheduleResult,
  burnThresholdEd25519ReservedPresign,
  getThresholdEd25519ClientPresignPoolStatus,
  reserveThresholdEd25519ReadyPresignForScope,
  resolveThresholdEd25519PresignPoolPolicy,
  scheduleThresholdEd25519ClientPresignPoolRefill,
} from '@/core/signingEngine/threshold/ed25519/presignPool';
import {
  finalizeThresholdEd25519Presign,
  refillThresholdEd25519PresignPool,
  type ThresholdEd25519FinalizeAndDispatchResponseWire,
  type ThresholdEd25519FinalizeSignatureOnlyIntentWire,
} from '@/core/rpcClients/relayer/thresholdEd25519Presign';
import type {
  SigningOperationFingerprint,
  SigningOperationId,
} from '@/core/signingEngine/session/operationState/types';
import { SigningSessionIds } from '@/core/signingEngine/session/operationState/types';
import type { ResolvedThresholdEd25519SessionState } from './thresholdSessionAuth';
import { emitThresholdEd25519PresignMetric } from './ed25519PresignMetrics';
import { base64UrlDecode } from '@shared/utils/base64';
import {
  parseThresholdEd25519NearTransaction,
  thresholdEd25519FinalizeRequestIntegrityHash,
  thresholdEd25519NearTransactionOperationFingerprint,
} from '@shared/threshold/ed25519OperationFingerprint';

export type ThresholdEd25519SignatureOnlyPresignPurpose = 'nep413_message' | 'delegate_action';

export type ThresholdEd25519SignatureOnlyPresignResult = {
  kind: 'threshold_ed25519_signature_only_presign_result_v1';
  operationId: string;
  signatureB64u: string;
  signerPublicKey: string;
  remainingSigningUses: number;
  budgetState: 'consumed' | 'already_consumed';
};

export type ThresholdEd25519SignatureOnlyPresignDelegateResult =
  ThresholdEd25519SignatureOnlyPresignResult & {
    signedDelegate: WasmSignedDelegate;
    hash: string;
  };

export type ThresholdEd25519NearTransactionPresignResult = {
  kind: 'threshold_ed25519_near_transaction_presign_result_v1';
  okResponse: WorkerSuccessResponse<typeof WorkerRequestType.SignTransactionsWithActions>;
  transactionHash: string;
  rpcResult: unknown;
};

export type ThresholdEd25519PresignRefillRunResult = {
  kind: 'threshold_ed25519_presign_refill_run_result_v1';
  schedule: Ed25519PresignPoolRefillScheduleResult;
  payload: PrepareThresholdEd25519PresignPoolPayload;
};

function resolveRuntimePolicyScope(
  state: ResolvedThresholdEd25519SessionState,
): ThresholdRuntimePolicyScope | null {
  return state.runtimePolicyScope || null;
}

function requireParticipantId(args: {
  thresholdKeyMaterial: ThresholdEd25519KeyMaterial;
  role: 'client' | 'relayer';
}): number {
  const participantId = args.thresholdKeyMaterial.participants.find(
    (participant) => participant.role === args.role,
  )?.id;
  if (!participantId) {
    throw new Error(`threshold-ed25519 presign requires ${args.role} participant id`);
  }
  return participantId;
}

function authFromThresholdSessionState(
  state: ResolvedThresholdEd25519SessionState,
):
  | { sessionKind: 'jwt'; thresholdSessionAuthToken: string }
  | { sessionKind: 'cookie'; useThresholdSessionCookie: true } {
  if (state.sessionKind === 'cookie') {
    return { sessionKind: 'cookie', useThresholdSessionCookie: true };
  }
  return {
    sessionKind: 'jwt',
    thresholdSessionAuthToken: state.thresholdSessionAuthToken,
  };
}

function digestB64uToHex(signingDigestB64u: string): string {
  return [...base64UrlDecode(signingDigestB64u)]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

function normalizeNearNetworkId(ctx: SigningRuntimeDeps): 'testnet' | 'mainnet' {
  return resolveNearNetwork(ctx.chains || PASSKEY_MANAGER_DEFAULT_CONFIGS.network.chains);
}

export async function refillThresholdEd25519ClientPresignPool(args: {
  ctx: SigningRuntimeDeps;
  thresholdSessionId: string;
  thresholdSessionState: ResolvedThresholdEd25519SessionState;
  thresholdKeyMaterial: ThresholdEd25519KeyMaterial;
  nearAccountId: string;
  xClientBaseB64u: string;
  requestTag: 'background_presign_pool_refill' | 'foreground_presign_pool_refill';
}): Promise<ThresholdEd25519PresignRefillRunResult | null> {
  const runtimePolicyScope = resolveRuntimePolicyScope(args.thresholdSessionState);
  if (!runtimePolicyScope) return null;
  const nearNetworkId = normalizeNearNetworkId(args.ctx);
  const participantIds = args.thresholdKeyMaterial.participants.map(
    (participant) => participant.id,
  );
  const policy = resolveThresholdEd25519PresignPoolPolicy(undefined);
  const firstOffer = await createThresholdEd25519PresignOffer(args);
  const scopeKey = createThresholdEd25519PresignScopeKey({
    thresholdSessionId: args.thresholdSessionId,
    walletSigningSessionId: args.thresholdSessionState.walletSigningSessionId,
    relayerKeyId: args.thresholdKeyMaterial.relayerKeyId,
    nearAccountId: args.nearAccountId,
    nearNetworkId,
    signerPublicKey: args.thresholdKeyMaterial.publicKey,
    participantIds,
    runtimePolicyScope,
    clientVerifyingShareB64u: firstOffer.clientVerifyingShareB64u,
  });
  const status = getThresholdEd25519ClientPresignPoolStatus({
    kind: 'get_threshold_ed25519_presign_pool_status_v1',
    scopeKey,
  });
  const needed = Math.max(0, policy.targetDepth - status.readyCount);
  const offers =
    needed > 0
      ? [
          firstOffer,
          ...(await createThresholdEd25519PresignOffers({
            ...args,
            count: Math.max(0, needed - 1),
          })),
        ]
      : [firstOffer];
  const payload: PrepareThresholdEd25519PresignPoolPayload = {
    kind: 'prepare_threshold_ed25519_presign_pool_v1',
    ...authFromThresholdSessionState(args.thresholdSessionState),
    relayUrl: args.thresholdSessionState.relayerUrl,
    thresholdSessionId: args.thresholdSessionId,
    walletSigningSessionId: args.thresholdSessionState.walletSigningSessionId,
    relayerKeyId: args.thresholdKeyMaterial.relayerKeyId,
    nearAccountId: args.nearAccountId,
    nearNetworkId,
    signerPublicKey: args.thresholdKeyMaterial.publicKey,
    participantIds,
    runtimePolicyScope,
    policy,
    requestTag: args.requestTag,
    generation: status.generation || 1,
    clientPresigns: offers,
  };
  const schedule = scheduleThresholdEd25519ClientPresignPoolRefill(payload);
  if (schedule.scheduled) {
    emitThresholdEd25519PresignMetric({
      metric: 'ed25519_presign_refill_in_flight',
      nearAccountId: args.nearAccountId,
      nearNetworkId,
      depth: schedule.depth,
      targetDepth: schedule.targetDepth,
      generation: schedule.generation,
    });
  }
  if (!schedule.scheduled) {
    await burnThresholdEd25519PresignOffers(args.ctx, args.thresholdSessionId, offers);
    return { kind: 'threshold_ed25519_presign_refill_run_result_v1', schedule, payload };
  }
  const refillResult = await refillThresholdEd25519PresignPool(payload);
  applyThresholdEd25519PresignRefillResult({ payload, result: refillResult });
  const acceptedClientIds = new Set(
    refillResult.ok ? refillResult.accepted.map((accepted) => accepted.clientPresignId) : [],
  );
  await burnThresholdEd25519PresignOffers(
    args.ctx,
    args.thresholdSessionId,
    offers.filter((offer) => !acceptedClientIds.has(offer.clientPresignId)),
  );
  return { kind: 'threshold_ed25519_presign_refill_run_result_v1', schedule, payload };
}

function scheduleThresholdEd25519ClientPresignPoolRefillInBackground(args: {
  ctx: SigningRuntimeDeps;
  thresholdSessionId: string;
  thresholdSessionState: ResolvedThresholdEd25519SessionState;
  thresholdKeyMaterial: ThresholdEd25519KeyMaterial;
  nearAccountId: string;
  xClientBaseB64u: string;
  requestTag: 'background_presign_pool_refill' | 'foreground_presign_pool_refill';
}): void {
  void refillThresholdEd25519ClientPresignPool(args).catch((error: unknown) => {
    console.warn('[SigningEngine][near] threshold-ed25519 presign refill failed', {
      error: error instanceof Error ? error.message : String(error || 'unknown error'),
    });
  });
}

async function createThresholdEd25519PresignOffers(args: {
  ctx: SigningRuntimeDeps;
  thresholdSessionId: string;
  thresholdKeyMaterial: ThresholdEd25519KeyMaterial;
  xClientBaseB64u: string;
  count: number;
}): Promise<ThresholdEd25519ClientPresignWorkerOffer[]> {
  const offers: ThresholdEd25519ClientPresignWorkerOffer[] = [];
  for (let index = 0; index < args.count; index += 1) {
    offers.push(await createThresholdEd25519PresignOffer(args));
  }
  return offers;
}

async function createThresholdEd25519PresignOffer(args: {
  ctx: SigningRuntimeDeps;
  thresholdSessionId: string;
  thresholdKeyMaterial: ThresholdEd25519KeyMaterial;
  xClientBaseB64u: string;
}): Promise<ThresholdEd25519ClientPresignWorkerOffer> {
  const created = await createThresholdEd25519ClientPresignWasm({
    sessionId: args.thresholdSessionId,
    clientParticipantId: requireParticipantId({
      thresholdKeyMaterial: args.thresholdKeyMaterial,
      role: 'client',
    }),
    relayerParticipantId: requireParticipantId({
      thresholdKeyMaterial: args.thresholdKeyMaterial,
      role: 'relayer',
    }),
    xClientBaseB64u: args.xClientBaseB64u,
    groupPublicKey: args.thresholdKeyMaterial.publicKey,
    workerCtx: args.ctx,
  });
  return {
    clientPresignId: createClientPresignId(),
    nonceHandle: created.clientNonceHandleB64u,
    clientVerifyingShareB64u: created.clientVerifyingShareB64u,
    clientCommitments: created.clientCommitments,
  };
}

function createClientPresignId(): string {
  const cryptoApi = globalThis.crypto;
  if (cryptoApi && typeof cryptoApi.randomUUID === 'function') {
    return `client-presign-${cryptoApi.randomUUID()}`;
  }
  if (cryptoApi && typeof cryptoApi.getRandomValues === 'function') {
    const bytes = new Uint8Array(16);
    cryptoApi.getRandomValues(bytes);
    return `client-presign-${[...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('')}`;
  }
  return `client-presign-${Date.now()}-${Math.floor(Math.random() * 1_000_000)}`;
}

async function burnThresholdEd25519PresignOffers(
  ctx: SigningRuntimeDeps,
  thresholdSessionId: string,
  offers: readonly ThresholdEd25519ClientPresignWorkerOffer[],
): Promise<void> {
  await Promise.all(
    offers.map((offer) =>
      burnThresholdEd25519ClientPresignWasm({
        sessionId: thresholdSessionId,
        clientNonceHandleB64u: offer.nonceHandle,
        workerCtx: ctx,
      }).catch(() => undefined),
    ),
  );
}

export async function tryFinalizeThresholdEd25519SignatureOnlyPresign(args: {
  ctx: SigningRuntimeDeps;
  thresholdSessionId: string;
  thresholdSessionState: ResolvedThresholdEd25519SessionState;
  thresholdKeyMaterial: ThresholdEd25519KeyMaterial;
  nearAccountId: string;
  xClientBaseB64u: string;
  operationId: SigningOperationId;
  operationFingerprint: SigningOperationFingerprint;
  purpose: ThresholdEd25519SignatureOnlyPresignPurpose;
  signingDigestB64u: string;
  intent: ThresholdEd25519FinalizeSignatureOnlyIntentWire;
}): Promise<ThresholdEd25519SignatureOnlyPresignResult | null> {
  const nearNetworkId = normalizeNearNetworkId(args.ctx);
  const participantIds = args.thresholdKeyMaterial.participants.map(
    (participant) => participant.id,
  );
  const operation: Ed25519PresignOperationIdentity = {
    kind: 'threshold_ed25519_presign_operation_identity_v1',
    operationId: args.operationId,
    operationFingerprint: args.operationFingerprint,
    purpose: args.purpose,
  };
  const runtimePolicyScope = resolveRuntimePolicyScope(args.thresholdSessionState);
  if (!runtimePolicyScope) return null;
  const reservation = reserveThresholdEd25519ReadyPresignForScope({
    thresholdSessionId: args.thresholdSessionId,
    walletSigningSessionId: args.thresholdSessionState.walletSigningSessionId,
    relayerKeyId: args.thresholdKeyMaterial.relayerKeyId,
    nearAccountId: args.nearAccountId,
    nearNetworkId,
    signerPublicKey: args.thresholdKeyMaterial.publicKey,
    participantIds,
    runtimePolicyScope,
    operation,
  });
  if (!reservation.ok) return null;

  let signedShare = false;
  try {
    const clientSignatureShare = await signThresholdEd25519ClientPresignWasm({
      sessionId: args.thresholdSessionId,
      clientParticipantId: requireParticipantId({
        thresholdKeyMaterial: args.thresholdKeyMaterial,
        role: 'client',
      }),
      relayerParticipantId: requireParticipantId({
        thresholdKeyMaterial: args.thresholdKeyMaterial,
        role: 'relayer',
      }),
      xClientBaseB64u: args.xClientBaseB64u,
      groupPublicKey: args.thresholdKeyMaterial.publicKey,
      signingDigestB64u: args.signingDigestB64u,
      clientNonceHandleB64u: reservation.reservation.entry.nonceHandle,
      clientCommitments: reservation.reservation.entry.clientCommitments,
      relayerCommitments: reservation.reservation.entry.relayerCommitments,
      workerCtx: args.ctx,
    });
    signedShare = true;
    const request = {
      kind: 'threshold_ed25519_finalize_signature_only_v1' as const,
      operation: {
        kind: 'threshold_ed25519_signing_operation_v1' as const,
        operationId: args.operationId,
        operationFingerprint: args.operationFingerprint,
        purpose: args.purpose,
      },
      presignId: reservation.reservation.entry.presignId,
      relayerKeyId: args.thresholdKeyMaterial.relayerKeyId,
      nearAccountId: args.nearAccountId,
      nearNetworkId,
      expectedSignerPublicKey: args.thresholdKeyMaterial.publicKey,
      intent: args.intent,
      clientSignatureShareB64u: clientSignatureShare.clientSignatureShareB64u,
    };
    const response = await finalizeThresholdEd25519Presign({
      relayServerUrl: args.thresholdSessionState.relayerUrl,
      auth: authFromThresholdSessionState(args.thresholdSessionState),
      request: {
        ...request,
        requestIntegrityHash: await thresholdEd25519FinalizeRequestIntegrityHash(request),
      },
    });
    if (!response.ok) {
      throw new Error(response.message || response.code || 'threshold-ed25519 presign failed');
    }
    burnThresholdEd25519ReservedPresign({
      scopeKey: reservation.scopeKey,
      reservation: reservation.reservation,
      reason: 'used',
    });
    return signatureOnlyResultFromFinalizeResponse(response);
  } catch (error) {
    burnThresholdEd25519ReservedPresign({
      scopeKey: reservation.scopeKey,
      reservation: reservation.reservation,
      reason: signedShare ? 'send_attempted' : 'rejected',
    });
    throw error;
  }
}

export async function finalizeThresholdEd25519DelegatePresignResult(args: {
  ctx: SigningRuntimeDeps;
  thresholdSessionId: string;
  delegate: DelegatePayload;
  signingDigestB64u: string;
  presignResult: ThresholdEd25519SignatureOnlyPresignResult;
}): Promise<ThresholdEd25519SignatureOnlyPresignDelegateResult> {
  const signedDelegate = await finalizeThresholdEd25519DelegateFromSignatureWasm({
    sessionId: args.thresholdSessionId,
    delegate: args.delegate,
    signingDigestB64u: args.signingDigestB64u,
    signatureB64u: args.presignResult.signatureB64u,
    workerCtx: args.ctx,
  });
  return {
    ...args.presignResult,
    signedDelegate,
    hash: digestB64uToHex(args.signingDigestB64u),
  };
}

export async function tryFinalizeThresholdEd25519NearTransactionPresign(args: {
  ctx: SigningRuntimeDeps;
  thresholdSessionId: string;
  thresholdSessionState: ResolvedThresholdEd25519SessionState;
  thresholdKeyMaterial: ThresholdEd25519KeyMaterial;
  nearAccountId: string;
  xClientBaseB64u: string;
  operationId: SigningOperationId;
  operationFingerprint: SigningOperationFingerprint;
  txSigningRequests: readonly TransactionPayload[];
  transactionContext: TransactionContext | undefined;
}): Promise<ThresholdEd25519NearTransactionPresignResult | null> {
  const finalizeStartedAtMs = Date.now();
  if (args.txSigningRequests.length !== 1 || !args.transactionContext) return null;
  const presignFinalizeTransactions = args.txSigningRequests.map((transaction, index) =>
    parseThresholdEd25519NearTransaction(transaction, `txSigningRequests[${index}]`),
  );
  const nearNetworkId = normalizeNearNetworkId(args.ctx);
  const participantIds = args.thresholdKeyMaterial.participants.map(
    (participant) => participant.id,
  );
  const runtimePolicyScope = resolveRuntimePolicyScope(args.thresholdSessionState);
  if (!runtimePolicyScope) return null;

  const unsigned = await buildThresholdEd25519NearTxUnsignedBorshWasm({
    sessionId: args.thresholdSessionId,
    txSigningRequests: args.txSigningRequests,
    transactionContext: args.transactionContext,
    workerCtx: args.ctx,
  });
  if (unsigned.length !== 1) return null;
  const unsignedTx = unsigned[0];
  const finalizeOperationFingerprint = SigningSessionIds.signingOperationFingerprint(
    await thresholdEd25519NearTransactionOperationFingerprint({
      nearAccountId: args.nearAccountId,
      nearNetworkId,
      relayerKeyId: args.thresholdKeyMaterial.relayerKeyId,
      signerPublicKey: args.thresholdKeyMaterial.publicKey,
      transactions: presignFinalizeTransactions,
      unsignedTransactionBorshB64u: unsignedTx.unsignedTransactionBorshB64u,
      signingDigestB64u: unsignedTx.signingDigestB64u,
    }),
  );
  const operation: Ed25519PresignOperationIdentity = {
    kind: 'threshold_ed25519_presign_operation_identity_v1',
    operationId: args.operationId,
    operationFingerprint: finalizeOperationFingerprint,
    purpose: 'near_transaction',
  };
  const reservation = reserveThresholdEd25519ReadyPresignForScope({
    thresholdSessionId: args.thresholdSessionId,
    walletSigningSessionId: args.thresholdSessionState.walletSigningSessionId,
    relayerKeyId: args.thresholdKeyMaterial.relayerKeyId,
    nearAccountId: args.nearAccountId,
    nearNetworkId,
    signerPublicKey: args.thresholdKeyMaterial.publicKey,
    participantIds,
    runtimePolicyScope,
    operation,
  });
  if (!reservation.ok) {
    emitThresholdEd25519PresignMetric({
      metric: 'ed25519_presign_pool_miss',
      nearAccountId: args.nearAccountId,
      nearNetworkId,
      operationId: args.operationId,
      operationFingerprint: args.operationFingerprint,
    });
    scheduleThresholdEd25519ClientPresignPoolRefillInBackground({
      ctx: args.ctx,
      thresholdSessionId: args.thresholdSessionId,
      thresholdSessionState: args.thresholdSessionState,
      thresholdKeyMaterial: args.thresholdKeyMaterial,
      nearAccountId: args.nearAccountId,
      xClientBaseB64u: args.xClientBaseB64u,
      requestTag: 'foreground_presign_pool_refill',
    });
    return null;
  }
  emitThresholdEd25519PresignMetric({
    metric: 'ed25519_presign_pool_hit',
    nearAccountId: args.nearAccountId,
    nearNetworkId,
    operationId: args.operationId,
    operationFingerprint: args.operationFingerprint,
  });

  let signedShare = false;
  try {
    const clientSignatureShare = await signThresholdEd25519ClientPresignWasm({
      sessionId: args.thresholdSessionId,
      clientParticipantId: requireParticipantId({
        thresholdKeyMaterial: args.thresholdKeyMaterial,
        role: 'client',
      }),
      relayerParticipantId: requireParticipantId({
        thresholdKeyMaterial: args.thresholdKeyMaterial,
        role: 'relayer',
      }),
      xClientBaseB64u: args.xClientBaseB64u,
      groupPublicKey: args.thresholdKeyMaterial.publicKey,
      signingDigestB64u: unsignedTx.signingDigestB64u,
      clientNonceHandleB64u: reservation.reservation.entry.nonceHandle,
      clientCommitments: reservation.reservation.entry.clientCommitments,
      relayerCommitments: reservation.reservation.entry.relayerCommitments,
      workerCtx: args.ctx,
    });
    signedShare = true;
    const request = {
      kind: 'threshold_ed25519_finalize_and_dispatch_near_tx_v1' as const,
      operation: {
        kind: 'threshold_ed25519_signing_operation_v1' as const,
        operationId: args.operationId,
        operationFingerprint: finalizeOperationFingerprint,
        purpose: 'near_transaction' as const,
      },
      presignId: reservation.reservation.entry.presignId,
      relayerKeyId: args.thresholdKeyMaterial.relayerKeyId,
      nearAccountId: args.nearAccountId,
      nearNetworkId,
      expectedSignerPublicKey: args.thresholdKeyMaterial.publicKey,
      transactions: presignFinalizeTransactions,
      unsignedTransactionBorshB64u: unsignedTx.unsignedTransactionBorshB64u,
      signingDigestB64u: unsignedTx.signingDigestB64u,
      clientSignatureShareB64u: clientSignatureShare.clientSignatureShareB64u,
      dispatch: { kind: 'near_rpc_configured_default_v1' as const },
    };
    const response = await finalizeThresholdEd25519Presign({
      relayServerUrl: args.thresholdSessionState.relayerUrl,
      auth: authFromThresholdSessionState(args.thresholdSessionState),
      request: {
        ...request,
        requestIntegrityHash: await thresholdEd25519FinalizeRequestIntegrityHash(request),
      },
    });
    if (!response.ok) {
      throw new Error(response.message || response.code || 'threshold-ed25519 presign failed');
    }
    if (response.kind !== 'threshold_ed25519_dispatched_near_tx_result_v1') {
      throw new Error('threshold-ed25519 transaction presign returned non-dispatch result');
    }
    const decoded = await decodeThresholdEd25519SignedNearTxBorshWasm({
      sessionId: args.thresholdSessionId,
      signedTransactionBorshB64u: response.signedTransactionBorshB64u,
      workerCtx: args.ctx,
    });
    burnThresholdEd25519ReservedPresign({
      scopeKey: reservation.scopeKey,
      reservation: reservation.reservation,
      reason: 'used',
    });
    emitThresholdEd25519PresignMetric({
      metric: 'ed25519_one_rtt_finalize_ms',
      nearAccountId: args.nearAccountId,
      nearNetworkId,
      operationId: args.operationId,
      operationFingerprint: args.operationFingerprint,
      durationMs: Date.now() - finalizeStartedAtMs,
    });
    scheduleThresholdEd25519ClientPresignPoolRefillInBackground({
      ctx: args.ctx,
      thresholdSessionId: args.thresholdSessionId,
      thresholdSessionState: args.thresholdSessionState,
      thresholdKeyMaterial: args.thresholdKeyMaterial,
      nearAccountId: args.nearAccountId,
      xClientBaseB64u: args.xClientBaseB64u,
      requestTag: 'background_presign_pool_refill',
    });
    const transactionHash = response.transactionHash || decoded.transactionHash;
    const signedTransaction = Object.assign(decoded.signedTransaction, {
      serverDispatch: {
        transactionHash,
        rpcResult: response.rpcResult,
      },
    });
    return {
      kind: 'threshold_ed25519_near_transaction_presign_result_v1',
      transactionHash,
      rpcResult: response.rpcResult,
      okResponse: {
        type: WorkerResponseType.SignTransactionsWithActionsSuccess,
        payload: {
          free: () => undefined,
          success: true,
          transactionHashes: [transactionHash],
          signedTransactions: [signedTransaction],
          logs: ['NEAR transaction signed and dispatched with threshold Ed25519 presign'],
          error: undefined,
        },
      },
    };
  } catch (error) {
    burnThresholdEd25519ReservedPresign({
      scopeKey: reservation.scopeKey,
      reservation: reservation.reservation,
      reason: signedShare ? 'send_attempted' : 'rejected',
    });
    throw error;
  }
}

function signatureOnlyResultFromFinalizeResponse(
  response: Extract<ThresholdEd25519FinalizeAndDispatchResponseWire, { ok: true }>,
): ThresholdEd25519SignatureOnlyPresignResult {
  if (response.kind !== 'threshold_ed25519_signature_only_result_v1') {
    throw new Error('threshold-ed25519 presign returned non-signature result');
  }
  return {
    kind: 'threshold_ed25519_signature_only_presign_result_v1',
    operationId: response.operationId,
    signatureB64u: response.signatureB64u,
    signerPublicKey: response.signerPublicKey,
    remainingSigningUses: response.remainingSigningUses,
    budgetState: response.budgetState,
  };
}
