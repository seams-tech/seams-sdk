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
  buildThresholdEd25519DelegateSigningPayloadWasm,
  buildThresholdEd25519NearTxUnsignedBorshWasm,
  burnThresholdEd25519ClientPresignWasm,
  createThresholdEd25519ClientPresignWasm,
  decodeThresholdEd25519SignedNearTxBorshWasm,
  finalizeThresholdEd25519NearTxFromSignatureWasm,
  finalizeThresholdEd25519DelegateFromSignatureWasm,
  signThresholdEd25519ClientPresignWasm,
} from '@/core/signingEngine/chains/near/nearSignerWasm';
import { createThresholdEd25519RoleSeparatedNormalSigningClientShareWasm } from '@/core/signingEngine/threshold/crypto/hssClientSignerWasm';
import type { TransactionContext } from '@/core/types/rpc';
import { ActionType, fromActionArgsWasm, type ActionArgsWasm } from '@/core/types/actions';
import type { NearSigningRuntimeDeps } from '@/core/signingEngine/interfaces/runtime';
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
import {
  buildRouterAbEd25519DelegateActionPrepareRequestV2,
  buildRouterAbEd25519NearTransactionPrepareRequestV2,
  buildRouterAbEd25519Nep413PrepareRequestV2,
  buildRouterAbEd25519NormalSigningFinalizeRequestV2,
  finalizeRouterAbNormalSigningV2,
  prepareRouterAbNormalSigningV2,
  routerAbCanonicalWireBytesToB64u,
  routerAbNormalSigningActionFingerprint,
  type RouterAbNormalSigningPrepareRequestV2BuildResult,
  type RouterAbNormalSigningScopeV1Wire,
} from '@/core/rpcClients/relayer/routerAbNormalSigning';
import {
  requireRouterAbNormalSigningPrepareMatchesRequest,
  requireRouterAbNormalSigningResponseMatchesRequest,
} from '@/core/rpcClients/relayer/routerAbNormalSigningValidation';
import type {
  SigningOperationFingerprint,
  SigningOperationId,
} from '@/core/signingEngine/session/operationState/types';
import { SigningSessionIds } from '@/core/signingEngine/session/operationState/types';
import { routerAbWalletSessionCredentialFromResolvedThresholdSessionState } from './routerAbWalletSessionCredential';
import type { ResolvedThresholdEd25519SessionState } from './thresholdSessionAuth';
import { emitThresholdEd25519PresignMetric } from './ed25519PresignMetrics';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import { base58Decode } from '@shared/utils/base58';
import {
  parseThresholdEd25519NearTransaction,
  thresholdEd25519FinalizeRequestIntegrityHash,
  thresholdEd25519NearTransactionOperationFingerprint,
  type ThresholdEd25519NearAction,
} from '@shared/threshold/ed25519OperationFingerprint';

const ROUTER_AB_NORMAL_SIGNING_REQUEST_TTL_MS = 120_000;

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

export type RouterAbEd25519NearTransactionNormalSigningResult = {
  kind: 'router_ab_ed25519_near_transaction_normal_signing_result_v1';
  okResponse: WorkerSuccessResponse<typeof WorkerRequestType.SignTransactionsWithActions>;
  transactionHash: string;
};

export type RouterAbEd25519SignatureOnlyNormalSigningResult = {
  kind: 'router_ab_ed25519_signature_only_normal_signing_result_v1';
  operationId: string;
  signatureB64u: string;
  signerPublicKey: string;
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

function normalizeNearNetworkId(ctx: NearSigningRuntimeDeps): 'testnet' | 'mainnet' {
  return resolveNearNetwork(ctx.chains || PASSKEY_MANAGER_DEFAULT_CONFIGS.network.chains);
}

function createRouterAbNormalSigningRequestId(operationId: SigningOperationId): string {
  const cryptoApi = globalThis.crypto;
  if (cryptoApi && typeof cryptoApi.randomUUID === 'function') {
    return `router-ab-normal-signing/${operationId}/${cryptoApi.randomUUID()}`;
  }
  if (cryptoApi && typeof cryptoApi.getRandomValues === 'function') {
    const bytes = new Uint8Array(16);
    cryptoApi.getRandomValues(bytes);
    return `router-ab-normal-signing/${operationId}/${base64UrlEncode(bytes)}`;
  }
  throw new Error('secure randomness is unavailable for Router A/B normal-signing request id');
}

function routerAbNormalSigningExpiresAtMs(): number {
  return Date.now() + ROUTER_AB_NORMAL_SIGNING_REQUEST_TTL_MS;
}

function buildRouterAbNormalSigningScope(args: {
  thresholdSessionId: string;
  thresholdSessionState: ResolvedThresholdEd25519SessionState;
  nearAccountId: string;
  operationId: SigningOperationId;
}): RouterAbNormalSigningScopeV1Wire | null {
  const routerAbState = args.thresholdSessionState.routerAbNormalSigning;
  if (!routerAbState) return null;
  return {
    request_id: createRouterAbNormalSigningRequestId(args.operationId),
    account_id: args.nearAccountId,
    session_id: args.thresholdSessionId,
    signing_worker_id: routerAbState.signingWorkerId,
  };
}

function routerAbDelegateActionsForWasm(
  actions: readonly ThresholdEd25519NearAction[],
): ActionArgsWasm[] {
  return actions.map((action): ActionArgsWasm => {
    switch (action.action_type) {
      case 'CreateAccount':
        return { action_type: ActionType.CreateAccount };
      case 'DeployContract':
        return { action_type: ActionType.DeployContract, code: [...action.code] };
      case 'FunctionCall':
        return {
          action_type: ActionType.FunctionCall,
          method_name: action.method_name,
          args: action.args,
          gas: action.gas,
          deposit: action.deposit,
        };
      case 'Transfer':
        return { action_type: ActionType.Transfer, deposit: action.deposit };
      case 'Stake':
        return {
          action_type: ActionType.Stake,
          stake: action.stake,
          public_key: action.public_key,
        };
      case 'AddKey':
        return {
          action_type: ActionType.AddKey,
          public_key: action.public_key,
          access_key: action.access_key,
        };
      case 'DeleteKey':
        return { action_type: ActionType.DeleteKey, public_key: action.public_key };
      case 'DeleteAccount':
        return {
          action_type: ActionType.DeleteAccount,
          beneficiary_id: action.beneficiary_id,
        };
      case 'SignedDelegate': {
        const delegateActions = routerAbDelegateActionsForWasm(action.delegate_action.actions).map(
          fromActionArgsWasm,
        );
        return {
          action_type: ActionType.SignedDelegate,
          delegate_action: {
            senderId: action.delegate_action.senderId,
            receiverId: action.delegate_action.receiverId,
            actions: delegateActions,
            nonce: action.delegate_action.nonce,
            maxBlockHeight: action.delegate_action.maxBlockHeight,
            publicKey: {
              keyType: action.delegate_action.publicKey.keyType,
              keyData: [...action.delegate_action.publicKey.keyData],
            },
          },
          signature: {
            keyType: action.signature.keyType,
            signatureData: [...action.signature.signatureData],
          },
        };
      }
      case 'DeployGlobalContract':
        return {
          action_type: ActionType.DeployGlobalContract,
          code: [...action.code],
          deploy_mode: action.deploy_mode,
        };
      case 'UseGlobalContract':
        return 'account_id' in action
          ? { action_type: ActionType.UseGlobalContract, account_id: action.account_id }
          : { action_type: ActionType.UseGlobalContract, code_hash: action.code_hash };
    }
  });
}

function nearEd25519PublicKeyToB64u(publicKey: string): string {
  const normalized = String(publicKey || '').trim();
  const base58 = normalized.startsWith('ed25519:') ? normalized.slice('ed25519:'.length) : '';
  if (!base58) throw new Error('Router A/B normal signing requires ed25519 public key');
  const bytes = base58Decode(base58);
  if (bytes.length !== 32) {
    throw new Error(
      `Router A/B normal signing public key must decode to 32 bytes, got ${bytes.length}`,
    );
  }
  return base64UrlEncode(bytes);
}

export async function refillThresholdEd25519ClientPresignPool(args: {
  ctx: NearSigningRuntimeDeps;
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
  ctx: NearSigningRuntimeDeps;
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
  ctx: NearSigningRuntimeDeps;
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
  ctx: NearSigningRuntimeDeps;
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
  ctx: NearSigningRuntimeDeps,
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
  ctx: NearSigningRuntimeDeps;
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
  ctx: NearSigningRuntimeDeps;
  thresholdSessionId: string;
  delegate: DelegatePayload;
  signingDigestB64u: string;
  presignResult: ThresholdEd25519SignatureOnlyPresignResult;
}): Promise<ThresholdEd25519SignatureOnlyPresignDelegateResult> {
  const finalized = await finalizeThresholdEd25519DelegateSignatureResult({
    ctx: args.ctx,
    thresholdSessionId: args.thresholdSessionId,
    delegate: args.delegate,
    signingDigestB64u: args.signingDigestB64u,
    signatureB64u: args.presignResult.signatureB64u,
  });
  return {
    ...args.presignResult,
    ...finalized,
  };
}

export async function finalizeThresholdEd25519DelegateSignatureResult(args: {
  ctx: NearSigningRuntimeDeps;
  thresholdSessionId: string;
  delegate: DelegatePayload;
  signingDigestB64u: string;
  signatureB64u: string;
}): Promise<{ signedDelegate: WasmSignedDelegate; hash: string }> {
  const signedDelegate = await finalizeThresholdEd25519DelegateFromSignatureWasm({
    sessionId: args.thresholdSessionId,
    delegate: args.delegate,
    signingDigestB64u: args.signingDigestB64u,
    signatureB64u: args.signatureB64u,
    workerCtx: args.ctx,
  });
  return {
    signedDelegate,
    hash: digestB64uToHex(args.signingDigestB64u),
  };
}

async function tryFinalizeRouterAbEd25519NormalSigningSignature(args: {
  ctx: NearSigningRuntimeDeps;
  thresholdSessionState: ResolvedThresholdEd25519SessionState;
  thresholdKeyMaterial: ThresholdEd25519KeyMaterial;
  xClientBaseB64u: string;
  signingDigestB64u: string;
  signingPayloadLabel: string;
  prepare: RouterAbNormalSigningPrepareRequestV2BuildResult;
}): Promise<{
  signatureB64u: string;
  signerPublicKey: string;
} | null> {
  const signingPayload = base64UrlDecode(args.signingDigestB64u);
  if (signingPayload.length !== 32) {
    throw new Error(`Router A/B normal-signing ${args.signingPayloadLabel} must be 32 bytes`);
  }

  const prepareResponse = await prepareRouterAbNormalSigningV2({
    relayServerUrl: args.thresholdSessionState.relayerUrl,
    credential: routerAbWalletSessionCredentialFromResolvedThresholdSessionState(
      args.thresholdSessionState,
    ),
    request: args.prepare.request,
  });
  requireRouterAbNormalSigningPrepareMatchesRequest({
    request: args.prepare.request,
    signingPayloadDigest: args.prepare.admissionMaterial.signingPayloadDigest,
    response: prepareResponse,
  });

  const clientShare = await createThresholdEd25519RoleSeparatedNormalSigningClientShareWasm({
    xClientBaseB64u: args.xClientBaseB64u,
    groupPublicKeyB64u: nearEd25519PublicKeyToB64u(args.thresholdKeyMaterial.publicKey),
    serverVerifyingShareB64u: prepareResponse.server_verifying_share_b64u,
    serverCommitments: {
      hidingB64u: prepareResponse.server_commitments.hiding,
      bindingB64u: prepareResponse.server_commitments.binding,
    },
    signingPayloadB64u: args.signingDigestB64u,
    workerCtx: args.ctx,
  });

  const signingResponse = await finalizeRouterAbNormalSigningV2({
    relayServerUrl: args.thresholdSessionState.relayerUrl,
    credential: routerAbWalletSessionCredentialFromResolvedThresholdSessionState(
      args.thresholdSessionState,
    ),
    request: buildRouterAbEd25519NormalSigningFinalizeRequestV2({
      scope: args.prepare.request.scope,
      expiresAtMs: args.prepare.request.expires_at_ms,
      prepareResponse,
      admissionMaterial: args.prepare.admissionMaterial,
      groupPublicKey: args.thresholdKeyMaterial.publicKey,
      clientCommitments: {
        hiding: clientShare.clientCommitments.hidingB64u,
        binding: clientShare.clientCommitments.bindingB64u,
      },
      clientVerifyingShareB64u: clientShare.clientVerifyingShareB64u,
      clientSignatureShareB64u: clientShare.clientSignatureShareB64u,
    }),
  });
  requireRouterAbNormalSigningResponseMatchesRequest({
    request: args.prepare.request,
    signingPayloadDigest: args.prepare.admissionMaterial.signingPayloadDigest,
    response: signingResponse,
  });

  return {
    signatureB64u: routerAbCanonicalWireBytesToB64u(
      signingResponse.signature,
      'Router A/B normal-signing signature',
    ),
    signerPublicKey: args.thresholdKeyMaterial.publicKey,
  };
}

export async function tryFinalizeRouterAbEd25519SignatureOnlyNormalSigning(args: {
  ctx: NearSigningRuntimeDeps;
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
}): Promise<RouterAbEd25519SignatureOnlyNormalSigningResult | null> {
  const scope = buildRouterAbNormalSigningScope({
    thresholdSessionId: args.thresholdSessionId,
    thresholdSessionState: args.thresholdSessionState,
    nearAccountId: args.nearAccountId,
    operationId: args.operationId,
  });
  if (!scope) return null;
  const nearNetworkId = normalizeNearNetworkId(args.ctx);
  const expiresAtMs = routerAbNormalSigningExpiresAtMs();
  const prepare =
    args.intent.kind === 'nep413_message_v1'
      ? await buildRouterAbEd25519Nep413PrepareRequestV2({
          scope,
          expiresAtMs,
          operationId: args.operationId,
          operationFingerprint: args.operationFingerprint,
          nearAccountId: args.nearAccountId,
          nearNetworkId,
          message: args.intent.message,
          recipient: args.intent.recipient,
          nonce: args.intent.nonce,
          ...(args.intent.state ? { callbackUrl: args.intent.state } : {}),
          expectedSigningDigestB64u: args.signingDigestB64u,
        })
      : await buildRouterAbEd25519DelegateActionPrepareRequestV2({
          scope,
          expiresAtMs,
          operationId: args.operationId,
          operationFingerprint: args.operationFingerprint,
          nearAccountId: args.nearAccountId,
          nearNetworkId,
          delegate: {
            senderId: args.intent.delegate.senderId,
            receiverId: args.intent.delegate.receiverId,
            publicKey: args.intent.delegate.publicKey,
            nonce: args.intent.delegate.nonce,
            maxBlockHeight: args.intent.delegate.maxBlockHeight,
            actionFingerprint: await routerAbNormalSigningActionFingerprint(
              args.intent.delegate.actions,
            ),
            canonicalDelegateBorshB64u: (
              await buildThresholdEd25519DelegateSigningPayloadWasm({
                sessionId: args.thresholdSessionId,
                delegate: {
                  senderId: args.intent.delegate.senderId,
                  receiverId: args.intent.delegate.receiverId,
                  actions: routerAbDelegateActionsForWasm(args.intent.delegate.actions),
                  nonce: args.intent.delegate.nonce,
                  maxBlockHeight: args.intent.delegate.maxBlockHeight,
                  publicKey: args.intent.delegate.publicKey,
                },
                workerCtx: args.ctx,
              })
            ).canonicalDelegateBorshB64u,
          },
          expectedSigningDigestB64u: args.signingDigestB64u,
        });
  const finalized = await tryFinalizeRouterAbEd25519NormalSigningSignature({
    ctx: args.ctx,
    thresholdSessionState: args.thresholdSessionState,
    thresholdKeyMaterial: args.thresholdKeyMaterial,
    xClientBaseB64u: args.xClientBaseB64u,
    signingDigestB64u: args.signingDigestB64u,
    signingPayloadLabel: 'signature-only payload digest',
    prepare,
  });
  if (!finalized) return null;
  return {
    kind: 'router_ab_ed25519_signature_only_normal_signing_result_v1',
    operationId: args.operationId,
    ...finalized,
  };
}

export async function tryFinalizeRouterAbEd25519NearTransactionNormalSigning(args: {
  ctx: NearSigningRuntimeDeps;
  thresholdSessionId: string;
  thresholdSessionState: ResolvedThresholdEd25519SessionState;
  thresholdKeyMaterial: ThresholdEd25519KeyMaterial;
  nearAccountId: string;
  xClientBaseB64u: string;
  operationId: SigningOperationId;
  operationFingerprint: SigningOperationFingerprint;
  txSigningRequests: readonly TransactionPayload[];
  transactionContext: TransactionContext | undefined;
}): Promise<RouterAbEd25519NearTransactionNormalSigningResult | null> {
  const routerAbState = args.thresholdSessionState.routerAbNormalSigning;
  if (!routerAbState) return null;
  if (args.txSigningRequests.length !== 1 || !args.transactionContext) return null;

  const unsigned = await buildThresholdEd25519NearTxUnsignedBorshWasm({
    sessionId: args.thresholdSessionId,
    txSigningRequests: args.txSigningRequests,
    transactionContext: args.transactionContext,
    workerCtx: args.ctx,
  });
  if (unsigned.length !== 1) return null;
  const unsignedTx = unsigned[0];
  const signingPayload = base64UrlDecode(unsignedTx.signingDigestB64u);
  if (signingPayload.length !== 32) {
    throw new Error('Router A/B normal-signing NEAR payload digest must be 32 bytes');
  }

  const nearNetworkId = normalizeNearNetworkId(args.ctx);
  const parsedTransactions = args.txSigningRequests.map((transaction, index) =>
    parseThresholdEd25519NearTransaction(transaction, `txSigningRequests[${index}]`),
  );
  const operationFingerprint = SigningSessionIds.signingOperationFingerprint(
    await thresholdEd25519NearTransactionOperationFingerprint({
      nearAccountId: args.nearAccountId,
      nearNetworkId,
      relayerKeyId: args.thresholdKeyMaterial.relayerKeyId,
      signerPublicKey: args.thresholdKeyMaterial.publicKey,
      transactions: parsedTransactions,
      unsignedTransactionBorshB64u: unsignedTx.unsignedTransactionBorshB64u,
      signingDigestB64u: unsignedTx.signingDigestB64u,
    }),
  );
  const scope = buildRouterAbNormalSigningScope({
    thresholdSessionId: args.thresholdSessionId,
    thresholdSessionState: args.thresholdSessionState,
    nearAccountId: args.nearAccountId,
    operationId: args.operationId,
  });
  if (!scope) return null;
  const prepare = await buildRouterAbEd25519NearTransactionPrepareRequestV2({
    scope,
    expiresAtMs: routerAbNormalSigningExpiresAtMs(),
    operationId: args.operationId,
    operationFingerprint,
    nearAccountId: args.nearAccountId,
    nearNetworkId,
    transactions: await Promise.all(
      parsedTransactions.map(async (transaction) => ({
        receiverId: transaction.receiverId,
        actionFingerprint: await routerAbNormalSigningActionFingerprint(transaction.actions),
      })),
    ),
    unsignedTransactionBorshB64u: unsignedTx.unsignedTransactionBorshB64u,
    expectedSigningDigestB64u: unsignedTx.signingDigestB64u,
  });
  const signatureResult = await tryFinalizeRouterAbEd25519NormalSigningSignature({
    ctx: args.ctx,
    thresholdSessionState: args.thresholdSessionState,
    thresholdKeyMaterial: args.thresholdKeyMaterial,
    xClientBaseB64u: args.xClientBaseB64u,
    signingDigestB64u: unsignedTx.signingDigestB64u,
    signingPayloadLabel: 'NEAR payload digest',
    prepare,
  });
  if (!signatureResult) return null;
  const finalized = await finalizeThresholdEd25519NearTxFromSignatureWasm({
    sessionId: args.thresholdSessionId,
    unsignedTransactionBorshB64u: unsignedTx.unsignedTransactionBorshB64u,
    signingDigestB64u: unsignedTx.signingDigestB64u,
    signatureB64u: signatureResult.signatureB64u,
    expectedNearAccountId: args.nearAccountId,
    expectedSignerPublicKey: args.thresholdKeyMaterial.publicKey,
    workerCtx: args.ctx,
  });
  const decoded = await decodeThresholdEd25519SignedNearTxBorshWasm({
    sessionId: args.thresholdSessionId,
    signedTransactionBorshB64u: finalized.signedTransactionBorshB64u,
    workerCtx: args.ctx,
  });
  const transactionHash = finalized.transactionHash || decoded.transactionHash;
  return {
    kind: 'router_ab_ed25519_near_transaction_normal_signing_result_v1',
    transactionHash,
    okResponse: {
      type: WorkerResponseType.SignTransactionsWithActionsSuccess,
      payload: {
        free: () => undefined,
        success: true,
        transactionHashes: [transactionHash],
        signedTransactions: [decoded.signedTransaction],
        logs: ['NEAR transaction signed through Router A/B normal signing'],
        error: undefined,
      },
    },
  };
}

export async function tryFinalizeThresholdEd25519NearTransactionPresign(args: {
  ctx: NearSigningRuntimeDeps;
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
