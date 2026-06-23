import { resolveNearNetwork } from '@/core/config/chains';
import { PASSKEY_MANAGER_DEFAULT_CONFIGS } from '@/core/config/defaultConfigs';
import type { ThresholdEd25519KeyMaterial } from '@/core/accountData/near/nearAccountData.types';
import {
  WorkerRequestType,
  WorkerResponseType,
  type DelegatePayload,
  type TransactionPayload,
  type ThresholdEd25519ClientPresignWorkerOffer,
  type WasmSignedDelegate,
  type WorkerSuccessResponse,
} from '@/core/types/signer-worker';
import {
  buildThresholdEd25519DelegateSigningPayloadWasm,
  buildThresholdEd25519NearTxUnsignedBorshWasm,
  burnThresholdEd25519ClientPresignWasm,
  createThresholdEd25519ClientPresignFromMaterialHandleWasm,
  createThresholdEd25519RoleSeparatedNormalSigningClientShareFromMaterialHandleNearSignerWasm,
  decodeThresholdEd25519SignedNearTxBorshWasm,
  finalizeThresholdEd25519NearTxFromSignatureWasm,
  finalizeThresholdEd25519DelegateFromSignatureWasm,
  signThresholdEd25519ClientPresignFromMaterialHandleWasm,
} from '@/core/signingEngine/chains/near/nearSignerWasm';
import {
  ed25519RuntimeMaterialBindingDigest,
  ed25519RuntimeMaterialClientVerifierB64u,
  ed25519RuntimeMaterialHandle,
  type RouterAbEd25519RuntimeValidatedMaterial,
} from '@/core/signingEngine/threshold/ed25519/workerMaterialHandle';
import type { TransactionContext } from '@/core/types/rpc';
import { ActionType, fromActionArgsWasm, type ActionArgsWasm } from '@/core/types/actions';
import type { NearSigningRuntimeDeps } from '@/core/signingEngine/interfaces/runtime';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import type { SigningSessionCoordinator } from '@/core/signingEngine/session/SigningSessionCoordinator';
import type {
  BudgetFinalizationSpend,
  SigningBudgetFinalizationResult,
  SigningSessionBudgetStatusAuth,
  SigningSessionPreparedBudgetIdentity,
} from '@/core/signingEngine/session/budget/budget';
import { isSigningSessionBudgetReservation } from '@/core/signingEngine/session/budget/budget';
import {
  createSigningSessionBudgetFinalizer,
  type SigningSessionBudgetFinalizer,
} from '@/core/signingEngine/session/budget/budgetFinalizer';
import {
  applyRouterAbEd25519PresignPoolRefillResult,
  burnThresholdEd25519ReservedPresign,
  createRouterAbEd25519PresignScopeKey,
  type Ed25519PresignOperationIdentity,
  type Ed25519PresignPoolRefillScheduleResult,
  getRouterAbEd25519ClientPresignPoolStatus,
  reserveRouterAbEd25519ReadyPresignForScope,
  resolveRouterAbEd25519PresignPoolPolicy,
  scheduleRouterAbEd25519ClientPresignPoolRefill,
  type RouterAbEd25519PresignPoolRefillResult,
  type RouterAbEd25519PresignPoolRefillPayload,
  type RouterAbEd25519PresignScopedReservationResult,
} from '@/core/signingEngine/threshold/ed25519/presignPool';
import {
  buildRouterAbEd25519DelegateActionPrepareRequestV2,
  buildRouterAbEd25519NearTransactionPrepareRequestV2,
  buildRouterAbEd25519Nep413PrepareRequestV2,
  buildRouterAbEd25519PresignPoolPrepareRequestV2,
  buildRouterAbEd25519PresignPoolHitFinalizeRequestV2,
  buildRouterAbEd25519NormalSigningFinalizeRequestV2,
  finalizeRouterAbNormalSigningV2,
  finalizeRouterAbNormalSigningPresignPoolHitV2,
  prepareRouterAbNormalSigningV2,
  prepareRouterAbNormalSigningPresignPoolV2,
  routerAbCanonicalWireBytesToB64u,
  routerAbNormalSigningActionFingerprint,
  type RouterAbNormalSigningPrepareRequestV2BuildResult,
  type RouterAbNormalSigningScopeV1Wire,
} from '@/core/rpcClients/relayer/routerAbNormalSigning';
import { requireRouterAbNormalSigningResponseMatchesRequest } from '@/core/rpcClients/relayer/routerAbNormalSigningValidation';
import type {
  SigningOperationFingerprint,
  SigningOperationId,
} from '@/core/signingEngine/session/operationState/types';
import {
  SigningOperationIntent,
  SigningSessionIds,
} from '@/core/signingEngine/session/operationState/types';
import {
  requireRouterAbEd25519NormalSigningReadyState,
  type RouterAbEd25519NormalSigningReadyState,
} from './routerAbWalletSessionCredential';
import type { ResolvedRouterAbEd25519WalletSessionState } from './routerAbEd25519WalletSessionState';
import { emitThresholdEd25519PresignMetric } from './ed25519PresignMetrics';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import {
  parseThresholdEd25519NearTransaction,
  thresholdEd25519NearTransactionOperationFingerprint,
  type ThresholdEd25519NearAction,
} from '@shared/threshold/ed25519OperationFingerprint';
import { parseEd25519RelayerKeyId } from '@/core/signingEngine/session/keyMaterialBrands';

const ROUTER_AB_NORMAL_SIGNING_REQUEST_TTL_MS = 120_000;

export type RouterAbEd25519SignatureOnlyPurpose = 'nep413_message' | 'delegate_action';

export type RouterAbEd25519SignatureOnlyIntentWire =
  | {
      kind: 'nep413_message_v1';
      message: string;
      recipient: string;
      nonce: string;
      state?: string;
    }
  | {
      kind: 'near_delegate_action_v1';
      delegate: {
        senderId: string;
        receiverId: string;
        actions: readonly ThresholdEd25519NearAction[];
        nonce: string;
        maxBlockHeight: string;
        publicKey: string;
      };
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

export type RouterAbEd25519PresignRefillRunResult = {
  kind: 'router_ab_ed25519_presign_refill_run_result_v1';
  schedule: Ed25519PresignPoolRefillScheduleResult;
  payload: RouterAbEd25519PresignPoolRefillPayload;
};

type RouterAbEd25519NormalSigningFinalized = {
  signatureB64u: string;
  signerPublicKey: string;
};

type RouterAbEd25519PresignPoolSigningInput = {
  ctx: NearSigningRuntimeDeps;
  thresholdSessionId: string;
  walletSessionState: ResolvedRouterAbEd25519WalletSessionState;
  thresholdKeyMaterial: ThresholdEd25519KeyMaterial;
  nearAccountId: string;
  nearNetworkId: 'testnet' | 'mainnet';
  signingMaterial: RouterAbEd25519RuntimeValidatedMaterial;
  operation: Ed25519PresignOperationIdentity;
  signingDigestB64u: string;
  prepare: RouterAbNormalSigningPrepareRequestV2BuildResult;
  routerAbReadyState: RouterAbEd25519NormalSigningReadyState;
};

type RouterAbEd25519PresignPoolReservation = Extract<
  RouterAbEd25519PresignScopedReservationResult,
  { ok: true }
>;

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

function routerAbNormalSigningExpiresAtMs(args: {
  walletSessionExpiresAtMs: number;
  requestedTtlMs: number;
}): number {
  const walletSessionExpiresAtMs = Math.floor(Number(args.walletSessionExpiresAtMs));
  const requestedTtlMs = Math.floor(Number(args.requestedTtlMs));
  if (!Number.isFinite(walletSessionExpiresAtMs) || walletSessionExpiresAtMs <= Date.now()) {
    throw new Error('[SigningEngine][near] Router A/B Ed25519 Wallet Session is expired');
  }
  if (!Number.isFinite(requestedTtlMs) || requestedTtlMs <= 0) {
    throw new Error('[SigningEngine][near] Router A/B Ed25519 request TTL is invalid');
  }
  return Math.min(walletSessionExpiresAtMs, Date.now() + requestedTtlMs);
}

function buildRouterAbNormalSigningScope(args: {
  thresholdSessionId: string;
  walletSessionState: ResolvedRouterAbEd25519WalletSessionState;
  nearAccountId: string;
  operationId: SigningOperationId;
}): RouterAbNormalSigningScopeV1Wire | null {
  const routerAbState = args.walletSessionState.routerAbNormalSigning;
  if (!routerAbState) return null;
  const walletId = String(args.walletSessionState.signingLane.accountId || '').trim();
  if (!walletId) {
    throw new Error('[SigningEngine][near] Router A/B Ed25519 signing scope is missing wallet id');
  }
  return {
    request_id: createRouterAbNormalSigningRequestId(args.operationId),
    account_id: walletId,
    session_id: args.thresholdSessionId,
    signing_worker_id: routerAbState.signingWorkerId,
  };
}

function buildRouterAbPresignPoolRefillScope(args: {
  thresholdSessionId: string;
  walletSessionState: ResolvedRouterAbEd25519WalletSessionState;
  nearAccountId: string;
}): RouterAbNormalSigningScopeV1Wire | null {
  const routerAbState = args.walletSessionState.routerAbNormalSigning;
  if (!routerAbState) return null;
  const walletId = String(args.walletSessionState.signingLane.accountId || '').trim();
  if (!walletId) {
    throw new Error('[SigningEngine][near] Router A/B Ed25519 presign scope is missing wallet id');
  }
  return {
    request_id: createRouterAbNormalSigningRequestId(
      SigningSessionIds.signingOperation('presign-pool-refill'),
    ),
    account_id: walletId,
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

export async function refillRouterAbEd25519ClientPresignPool(args: {
  ctx: NearSigningRuntimeDeps;
  thresholdSessionId: string;
  walletSessionState: ResolvedRouterAbEd25519WalletSessionState;
  thresholdKeyMaterial: ThresholdEd25519KeyMaterial;
  nearAccountId: string;
  signingMaterial: RouterAbEd25519RuntimeValidatedMaterial;
  requestTag: 'background_presign_pool_refill' | 'foreground_presign_pool_refill';
}): Promise<RouterAbEd25519PresignRefillRunResult | null> {
  const scope = buildRouterAbPresignPoolRefillScope({
    thresholdSessionId: args.thresholdSessionId,
    walletSessionState: args.walletSessionState,
    nearAccountId: args.nearAccountId,
  });
  if (!scope) return null;
  const routerAbReadyState = requireRouterAbEd25519NormalSigningReadyState({
    state: args.walletSessionState,
    thresholdSessionId: args.thresholdSessionId,
    nearAccountId: args.nearAccountId,
    thresholdKeyMaterial: args.thresholdKeyMaterial,
  });
  const runtimePolicyScope = routerAbReadyState.runtimePolicyScope;
  const nearNetworkId = normalizeNearNetworkId(args.ctx);
  const participantIds = args.thresholdKeyMaterial.participants.map(
    (participant) => participant.id,
  );
  const relayerKeyId = parseEd25519RelayerKeyId(args.thresholdKeyMaterial.relayerKeyId);
  const policy = resolveRouterAbEd25519PresignPoolPolicy(undefined);
  const firstOffer = await createRouterAbEd25519PresignOffer(args);
  const scopeKey = createRouterAbEd25519PresignScopeKey({
    thresholdSessionId: args.thresholdSessionId,
    signingGrantId: args.walletSessionState.signingGrantId,
    relayerKeyId,
    nearAccountId: args.nearAccountId,
    nearNetworkId,
    signerPublicKey: args.thresholdKeyMaterial.publicKey,
    participantIds,
    runtimePolicyScope,
    materialBindingDigest: ed25519RuntimeMaterialBindingDigest(args.signingMaterial),
  });
  const status = getRouterAbEd25519ClientPresignPoolStatus({
    kind: 'get_router_ab_ed25519_presign_pool_status_v1',
    scopeKey,
  });
  const offerCount = Math.min(policy.maxAcceptedRefillCount, policy.targetDepth);
  const offers = [
    firstOffer,
    ...(await createRouterAbEd25519PresignOffers({
      ...args,
      count: Math.max(0, offerCount - 1),
    })),
  ];
  const payload: RouterAbEd25519PresignPoolRefillPayload = {
    kind: 'router_ab_ed25519_presign_pool_refill_v1',
    relayUrl: args.walletSessionState.relayerUrl,
    thresholdSessionId: args.thresholdSessionId,
    signingGrantId: args.walletSessionState.signingGrantId,
    relayerKeyId,
    nearAccountId: args.nearAccountId,
    nearNetworkId,
    signerPublicKey: args.thresholdKeyMaterial.publicKey,
    participantIds,
    runtimePolicyScope,
    materialBindingDigest: ed25519RuntimeMaterialBindingDigest(args.signingMaterial),
    policy,
    requestTag: args.requestTag,
    generation: status.generation || 1,
    clientPresigns: offers,
  };
  const schedule = scheduleRouterAbEd25519ClientPresignPoolRefill(payload);
  if (!schedule.scheduled) {
    await burnRouterAbEd25519PresignOffers(args.ctx, args.thresholdSessionId, offers);
    return { kind: 'router_ab_ed25519_presign_refill_run_result_v1', schedule, payload };
  }
  emitThresholdEd25519PresignMetric({
    metric: 'ed25519_presign_refill_in_flight',
    nearAccountId: args.nearAccountId,
    nearNetworkId,
    depth: schedule.depth,
    targetDepth: schedule.targetDepth,
    generation: schedule.generation,
  });

  let refillResult: RouterAbEd25519PresignPoolRefillResult;
  try {
    const request = buildRouterAbEd25519PresignPoolPrepareRequestV2({
      scope,
      expiresAtMs: routerAbNormalSigningExpiresAtMs({
        walletSessionExpiresAtMs: args.walletSessionState.signingWalletSession.expiresAtMs,
        requestedTtlMs: policy.ttlMs,
      }),
      generation: payload.generation,
      clientOffers: offers.map((offer) => ({
        clientPresignId: offer.clientPresignId,
        clientNonceHandle: offer.nonceHandle,
        clientCommitments: {
          hiding: offer.clientCommitments.hiding,
          binding: offer.clientCommitments.binding,
        },
        clientVerifyingShareB64u: offer.clientVerifyingShareB64u,
      })),
    });
    const response = await prepareRouterAbNormalSigningPresignPoolV2({
      relayServerUrl: args.walletSessionState.relayerUrl,
      credential: routerAbReadyState.credential,
      request,
    });
    refillResult = {
      ok: true,
      generation: response.generation,
      scope: response.scope,
      accepted: response.accepted.map((entry) => ({
        clientPresignId: entry.client_presign_id,
        generation: entry.generation,
        poolEntryBindingDigest: entry.pool_entry_binding_digest,
        signingWorkerId: entry.signing_worker.server_id,
        serverRound1Handle: entry.server_round1_handle,
        serverCommitments: {
          hiding: entry.server_commitments.hiding,
          binding: entry.server_commitments.binding,
        },
        serverVerifyingShareB64u: entry.server_verifying_share_b64u,
        expiresAtMs: entry.expires_at_ms,
      })),
      rejectedClientPresignIds: response.rejected_client_presign_ids,
    };
  } catch (error) {
    refillResult = {
      ok: false,
      generation: payload.generation,
      code: 'router_ab_presign_pool_refill_failed',
      message: error instanceof Error ? error.message : String(error || 'unknown error'),
    };
    applyRouterAbEd25519PresignPoolRefillResult({ payload, result: refillResult });
    await burnRouterAbEd25519PresignOffers(args.ctx, args.thresholdSessionId, offers);
    throw error;
  }

  applyRouterAbEd25519PresignPoolRefillResult({ payload, result: refillResult });
  const acceptedClientIds = new Set(
    refillResult.ok ? refillResult.accepted.map((accepted) => accepted.clientPresignId) : [],
  );
  await burnRouterAbEd25519PresignOffers(
    args.ctx,
    args.thresholdSessionId,
    offers.filter((offer) => !acceptedClientIds.has(offer.clientPresignId)),
  );
  return { kind: 'router_ab_ed25519_presign_refill_run_result_v1', schedule, payload };
}

function scheduleRouterAbEd25519ClientPresignPoolRefillInBackground(args: {
  ctx: NearSigningRuntimeDeps;
  thresholdSessionId: string;
  walletSessionState: ResolvedRouterAbEd25519WalletSessionState;
  thresholdKeyMaterial: ThresholdEd25519KeyMaterial;
  nearAccountId: string;
  signingMaterial: RouterAbEd25519RuntimeValidatedMaterial;
  requestTag: 'background_presign_pool_refill' | 'foreground_presign_pool_refill';
}): void {
  void refillRouterAbEd25519ClientPresignPool(args).catch((error: unknown) => {
    console.warn('[SigningEngine][near] Router A/B Ed25519 presign refill failed', {
      error: error instanceof Error ? error.message : String(error || 'unknown error'),
    });
  });
}

function reserveRouterAbEd25519PresignForNormalSigning(
  args: RouterAbEd25519PresignPoolSigningInput,
): RouterAbEd25519PresignScopedReservationResult {
  return reserveRouterAbEd25519ReadyPresignForScope({
    thresholdSessionId: args.thresholdSessionId,
    signingGrantId: args.walletSessionState.signingGrantId,
    relayerKeyId: parseEd25519RelayerKeyId(args.thresholdKeyMaterial.relayerKeyId),
    nearAccountId: args.nearAccountId,
    nearNetworkId: args.nearNetworkId,
    signerPublicKey: args.thresholdKeyMaterial.publicKey,
    participantIds: args.thresholdKeyMaterial.participants.map((participant) => participant.id),
    runtimePolicyScope: args.routerAbReadyState.runtimePolicyScope,
    materialBindingDigest: ed25519RuntimeMaterialBindingDigest(args.signingMaterial),
    operation: args.operation,
  });
}

async function signReservedRouterAbEd25519Presign(args: {
  input: RouterAbEd25519PresignPoolSigningInput;
  reservation: RouterAbEd25519PresignPoolReservation;
}): Promise<RouterAbEd25519NormalSigningFinalized> {
  const { input, reservation } = args;
  let signedShare = false;
  try {
    const entry = reservation.reservation.entry;
    const clientSignatureShare = await signThresholdEd25519ClientPresignFromMaterialHandleWasm({
      sessionId: input.thresholdSessionId,
      clientParticipantId: requireParticipantId({
        thresholdKeyMaterial: input.thresholdKeyMaterial,
        role: 'client',
      }),
      relayerParticipantId: requireParticipantId({
        thresholdKeyMaterial: input.thresholdKeyMaterial,
        role: 'relayer',
      }),
      materialHandle: ed25519RuntimeMaterialHandle(input.signingMaterial),
      expectedMaterialBinding: input.signingMaterial.materialBinding,
      expectedSessionBinding: input.signingMaterial.sessionBinding,
      groupPublicKey: input.thresholdKeyMaterial.publicKey,
      signingDigestB64u: input.signingDigestB64u,
      clientNonceHandleB64u: entry.nonceHandle,
      clientCommitments: entry.clientCommitments,
      relayerCommitments: entry.relayerCommitments,
      workerCtx: input.ctx,
    });
    signedShare = true;
    const signingResponse = await finalizeRouterAbNormalSigningPresignPoolHitV2({
      relayServerUrl: input.walletSessionState.relayerUrl,
      credential: input.routerAbReadyState.credential,
      request: buildRouterAbEd25519PresignPoolHitFinalizeRequestV2({
        prepare: input.prepare,
        clientPresignId: entry.clientPresignId,
        clientNonceHandle: entry.nonceHandle,
        generation: entry.routerAbPoolEntry.generation,
        serverRound1Handle: entry.presignId,
        poolEntryBindingDigest: entry.routerAbPoolEntry.poolEntryBindingDigest,
        clientCommitments: entry.clientCommitments,
        serverCommitments: entry.relayerCommitments,
        clientVerifyingShareB64u: entry.clientVerifyingShareB64u,
        serverVerifyingShareB64u: entry.relayerVerifyingShareB64u,
        clientSignatureShareB64u: clientSignatureShare.clientSignatureShareB64u,
      }),
    });
    requireRouterAbNormalSigningResponseMatchesRequest({
      request: input.prepare.request,
      signingPayloadDigest: input.prepare.admissionMaterial.signingPayloadDigest,
      response: signingResponse,
    });
    burnThresholdEd25519ReservedPresign({
      scopeKey: reservation.scopeKey,
      reservation: reservation.reservation,
      reason: 'used',
    });
    scheduleRouterAbEd25519ClientPresignPoolRefillInBackground({
      ctx: input.ctx,
      thresholdSessionId: input.thresholdSessionId,
      walletSessionState: input.walletSessionState,
      thresholdKeyMaterial: input.thresholdKeyMaterial,
      nearAccountId: input.nearAccountId,
      signingMaterial: input.signingMaterial,
      requestTag: 'background_presign_pool_refill',
    });
    return {
      signatureB64u: routerAbCanonicalWireBytesToB64u(
        signingResponse.signature,
        'Router A/B normal-signing signature',
      ),
      signerPublicKey: input.thresholdKeyMaterial.publicKey,
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

async function trySignRouterAbEd25519WithPresignPool(
  args: RouterAbEd25519PresignPoolSigningInput,
): Promise<RouterAbEd25519NormalSigningFinalized | null> {
  const reservation = reserveRouterAbEd25519PresignForNormalSigning(args);
  if (!reservation.ok) return null;
  emitThresholdEd25519PresignMetric({
    metric: 'ed25519_presign_pool_hit',
    nearAccountId: args.nearAccountId,
    nearNetworkId: args.nearNetworkId,
    operationId: args.operation.operationId,
    operationFingerprint: args.operation.operationFingerprint,
  });
  return signReservedRouterAbEd25519Presign({ input: args, reservation });
}

async function createRouterAbEd25519PresignOffers(args: {
  ctx: NearSigningRuntimeDeps;
  thresholdSessionId: string;
  thresholdKeyMaterial: ThresholdEd25519KeyMaterial;
  signingMaterial: RouterAbEd25519RuntimeValidatedMaterial;
  count: number;
}): Promise<ThresholdEd25519ClientPresignWorkerOffer[]> {
  const offers: ThresholdEd25519ClientPresignWorkerOffer[] = [];
  for (let index = 0; index < args.count; index += 1) {
    offers.push(await createRouterAbEd25519PresignOffer(args));
  }
  return offers;
}

async function createRouterAbEd25519PresignOffer(args: {
  ctx: NearSigningRuntimeDeps;
  thresholdSessionId: string;
  thresholdKeyMaterial: ThresholdEd25519KeyMaterial;
  signingMaterial: RouterAbEd25519RuntimeValidatedMaterial;
}): Promise<ThresholdEd25519ClientPresignWorkerOffer> {
  const created = await createThresholdEd25519ClientPresignFromMaterialHandleWasm({
    sessionId: args.thresholdSessionId,
    clientParticipantId: requireParticipantId({
      thresholdKeyMaterial: args.thresholdKeyMaterial,
      role: 'client',
    }),
    relayerParticipantId: requireParticipantId({
      thresholdKeyMaterial: args.thresholdKeyMaterial,
      role: 'relayer',
    }),
    materialHandle: ed25519RuntimeMaterialHandle(args.signingMaterial),
    expectedMaterialBinding: args.signingMaterial.materialBinding,
    expectedSessionBinding: args.signingMaterial.sessionBinding,
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

async function burnRouterAbEd25519PresignOffers(
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
  thresholdSessionId: string;
  walletSessionState: ResolvedRouterAbEd25519WalletSessionState;
  thresholdKeyMaterial: ThresholdEd25519KeyMaterial;
  nearAccountId: string;
  nearNetworkId: 'testnet' | 'mainnet';
  signingMaterial: RouterAbEd25519RuntimeValidatedMaterial;
  operation: Ed25519PresignOperationIdentity;
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

  const routerAbReadyState = requireRouterAbEd25519NormalSigningReadyState({
    state: args.walletSessionState,
    thresholdSessionId: args.thresholdSessionId,
    nearAccountId: args.nearAccountId,
    thresholdKeyMaterial: args.thresholdKeyMaterial,
  });
  if (
    ed25519RuntimeMaterialClientVerifierB64u(args.signingMaterial) !==
    routerAbReadyState.signingMaterial.clientVerifierB64u
  ) {
    throw new Error('Router A/B Ed25519 signing material binding mismatch');
  }
  const prepareResponse = await prepareRouterAbNormalSigningV2({
    relayServerUrl: args.walletSessionState.relayerUrl,
    credential: routerAbReadyState.credential,
    request: args.prepare.request,
  });
  const clientShare =
    await createThresholdEd25519RoleSeparatedNormalSigningClientShareFromMaterialHandleNearSignerWasm(
      {
        sessionId: args.thresholdSessionId,
        materialHandle: ed25519RuntimeMaterialHandle(args.signingMaterial),
        expectedMaterialBinding: args.signingMaterial.materialBinding,
        expectedSessionBinding: args.signingMaterial.sessionBinding,
        groupPublicKey: args.thresholdKeyMaterial.publicKey,
        serverVerifyingShareB64u: prepareResponse.server_verifying_share_b64u,
        serverCommitments: prepareResponse.server_commitments,
        signingDigestB64u: args.signingDigestB64u,
        workerCtx: args.ctx,
      },
    );
  if (clientShare.clientVerifyingShareB64u !== ed25519RuntimeMaterialClientVerifierB64u(args.signingMaterial)) {
    throw new Error('Router A/B Ed25519 role-separated client verifier mismatch');
  }
  const signingResponse = await finalizeRouterAbNormalSigningV2({
    relayServerUrl: args.walletSessionState.relayerUrl,
    credential: routerAbReadyState.credential,
    request: buildRouterAbEd25519NormalSigningFinalizeRequestV2({
      scope: args.prepare.request.scope,
      expiresAtMs: args.prepare.request.expires_at_ms,
      prepareResponse,
      admissionMaterial: args.prepare.admissionMaterial,
      clientCommitments: clientShare.clientCommitments,
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
  signingSessionCoordinator: SigningSessionCoordinator;
  walletSessionState: ResolvedRouterAbEd25519WalletSessionState;
  thresholdKeyMaterial: ThresholdEd25519KeyMaterial;
  nearAccountId: string;
  signingMaterial: RouterAbEd25519RuntimeValidatedMaterial;
  operationId: SigningOperationId;
  operationFingerprint: SigningOperationFingerprint;
  purpose: RouterAbEd25519SignatureOnlyPurpose;
  signingDigestB64u: string;
  intent: RouterAbEd25519SignatureOnlyIntentWire;
}): Promise<RouterAbEd25519SignatureOnlyNormalSigningResult | null> {
  const scope = buildRouterAbNormalSigningScope({
    thresholdSessionId: args.thresholdSessionId,
    walletSessionState: args.walletSessionState,
    nearAccountId: args.nearAccountId,
    operationId: args.operationId,
  });
  if (!scope) return null;
  const nearNetworkId = normalizeNearNetworkId(args.ctx);
  const expiresAtMs = routerAbNormalSigningExpiresAtMs({
    walletSessionExpiresAtMs: args.walletSessionState.signingWalletSession.expiresAtMs,
    requestedTtlMs: ROUTER_AB_NORMAL_SIGNING_REQUEST_TTL_MS,
  });
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
  const budgetFinalizer = await prepareRouterAbEd25519SignatureOnlyBudgetFinalizer({
    signingSessionCoordinator: args.signingSessionCoordinator,
    walletSessionState: args.walletSessionState,
    thresholdSessionId: args.thresholdSessionId,
    thresholdKeyMaterial: args.thresholdKeyMaterial,
    nearAccountId: args.nearAccountId,
    operationId: args.operationId,
    operationFingerprint: args.operationFingerprint,
  });
  const reservation = await budgetFinalizer.reserve();
  if (reservation && !isSigningSessionBudgetReservation(reservation)) {
    throw new Error('[SigningEngine][near] signature-only budget reservation identity mismatch');
  }

  let finalized: RouterAbEd25519NormalSigningFinalized | null;
  try {
    finalized = await tryFinalizeRouterAbEd25519NormalSigningSignature({
      ctx: args.ctx,
      thresholdSessionId: args.thresholdSessionId,
      walletSessionState: args.walletSessionState,
      thresholdKeyMaterial: args.thresholdKeyMaterial,
      nearAccountId: args.nearAccountId,
      nearNetworkId,
      signingMaterial: args.signingMaterial,
      operation: {
        kind: 'router_ab_ed25519_presign_operation_identity_v1',
        operationId: args.operationId,
        operationFingerprint: args.operationFingerprint,
        purpose: args.purpose,
      },
      signingDigestB64u: args.signingDigestB64u,
      signingPayloadLabel: 'signature-only payload digest',
      prepare,
    });
  } catch (error) {
    budgetFinalizer.recordZeroSpend(error);
    throw error;
  }
  if (!finalized) {
    budgetFinalizer.recordZeroSpend(
      new Error('[SigningEngine][near] signature-only Router A/B normal signing unavailable'),
    );
    return null;
  }
  requireSignatureOnlyBudgetFinalizationResult(await budgetFinalizer.recordSuccess());
  return {
    kind: 'router_ab_ed25519_signature_only_normal_signing_result_v1',
    operationId: args.operationId,
    ...finalized,
  };
}

function requireSignatureOnlyBudgetFinalizationResult(
  result: SigningBudgetFinalizationResult | null,
): void {
  if (!result || result.kind === 'finalized' || result.kind === 'already_finalized') return;
  switch (result.kind) {
    case 'projection_mismatch':
      throw new Error(
        `[SigningEngine][near] signature-only budget finalization projection mismatch: expected ${result.expectedProjectionVersion}, got ${result.actualProjectionVersion}`,
      );
    case 'missing_reservation':
      throw new Error('[SigningEngine][near] signature-only budget finalization missing reservation');
    case 'reservation_identity_mismatch':
      throw new Error(
        '[SigningEngine][near] signature-only budget finalization reservation identity mismatch',
      );
    case 'budget_status_unavailable':
      throw new Error(
        `[SigningEngine][near] signature-only budget finalization status unavailable: ${result.status}`,
      );
    default:
      assertNever(result satisfies never);
  }
}

function assertNever(value: never): never {
  throw new Error(`Unexpected signature-only budget finalization result: ${String(value)}`);
}

async function prepareRouterAbEd25519SignatureOnlyBudgetFinalizer(args: {
  signingSessionCoordinator: SigningSessionCoordinator;
  walletSessionState: ResolvedRouterAbEd25519WalletSessionState;
  thresholdSessionId: string;
  thresholdKeyMaterial: ThresholdEd25519KeyMaterial;
  nearAccountId: string;
  operationId: SigningOperationId;
  operationFingerprint: SigningOperationFingerprint;
}): Promise<SigningSessionBudgetFinalizer> {
  const routerAbReadyState = requireRouterAbEd25519NormalSigningReadyState({
    state: args.walletSessionState,
    thresholdSessionId: args.thresholdSessionId,
    nearAccountId: args.nearAccountId,
    thresholdKeyMaterial: args.thresholdKeyMaterial,
  });
  const trustedStatusAuth = budgetStatusAuthFromRouterAbReadyState(routerAbReadyState);
  const budgetIdentity = await args.signingSessionCoordinator.prepareBudgetIdentity({
    lane: args.walletSessionState.signingLane,
    trustedStatusAuth,
    operationUsesNeeded: 1,
  });
  return createRouterAbEd25519SignatureOnlyBudgetFinalizer({
    signingSessionCoordinator: args.signingSessionCoordinator,
    budgetIdentity,
    finalization: {
      kind: 'externally_consumed_success',
      spend: {
        operationId: args.operationId,
        operationFingerprint: args.operationFingerprint,
        walletId: args.walletSessionState.signingLane.accountId,
        signingGrantId: args.walletSessionState.signingLane.signingGrantId,
        lane: args.walletSessionState.signingLane,
        thresholdSessionIds: [args.walletSessionState.signingLane.thresholdSessionId],
        backingMaterialSessionIds: [],
        uses: 1,
        reason: SigningOperationIntent.TransactionSign,
      },
      trustedStatusAuth,
      alreadyConsumedThresholdSessionIds: [args.walletSessionState.signingLane.thresholdSessionId],
    },
    nearAccountId: args.nearAccountId,
    signingGrantId: args.walletSessionState.signingGrantId,
    thresholdSessionId: args.thresholdSessionId,
  });
}

function budgetStatusAuthFromRouterAbReadyState(
  state: RouterAbEd25519NormalSigningReadyState,
): SigningSessionBudgetStatusAuth {
  const thresholdSessionId = String(state.thresholdSessionId || '').trim();
  const relayerUrl = String(state.relayerUrl || '').trim();
  const walletSessionJwt = String(state.credential.walletSessionJwt || '').trim();
  if (!thresholdSessionId || !relayerUrl || !walletSessionJwt) {
    throw new Error('[SigningEngine][near] signature-only budget auth is incomplete');
  }
  return {
    thresholdSessionId,
    relayerUrl,
    walletSessionJwt,
  };
}

function createRouterAbEd25519SignatureOnlyBudgetFinalizer(args: {
  signingSessionCoordinator: SigningSessionCoordinator;
  budgetIdentity: SigningSessionPreparedBudgetIdentity;
  finalization: BudgetFinalizationSpend;
  nearAccountId: string;
  signingGrantId: string;
  thresholdSessionId: string;
}): SigningSessionBudgetFinalizer {
  return createSigningSessionBudgetFinalizer({
    budgetMode: 'with_budget',
    signingSessionBudget: args.signingSessionCoordinator,
    budgetIdentity: args.budgetIdentity,
    finalization: args.finalization,
    onRecordSuccessError: (error) => {
      console.warn('[SigningEngine][near] failed to update signature-only signing grant budget', {
        nearAccountId: args.nearAccountId,
        signingGrantId: args.signingGrantId,
        thresholdSessionId: args.thresholdSessionId,
        error: error instanceof Error ? error.message : String(error || 'unknown error'),
      });
    },
    onRecordZeroSpendError: (error) => {
      console.warn('[SigningEngine][near] failed to record signature-only zero spend', {
        nearAccountId: args.nearAccountId,
        thresholdSessionId: args.thresholdSessionId,
        error: error instanceof Error ? error.message : String(error || 'unknown error'),
      });
    },
  });
}

export async function tryFinalizeRouterAbEd25519NearTransactionNormalSigning(args: {
  ctx: NearSigningRuntimeDeps;
  thresholdSessionId: string;
  walletSessionState: ResolvedRouterAbEd25519WalletSessionState;
  thresholdKeyMaterial: ThresholdEd25519KeyMaterial;
  nearAccountId: string;
  signingMaterial: RouterAbEd25519RuntimeValidatedMaterial;
  operationId: SigningOperationId;
  operationFingerprint: SigningOperationFingerprint;
  txSigningRequest: TransactionPayload;
  transactionContext: TransactionContext | undefined;
}): Promise<RouterAbEd25519NearTransactionNormalSigningResult | null> {
  const routerAbState = args.walletSessionState.routerAbNormalSigning;
  if (!routerAbState) {
    throw new Error(
      '[SigningEngine][near] Router A/B Ed25519 normal-signing state is missing',
    );
  }
  if (!args.transactionContext) {
    throw new Error(
      '[SigningEngine][near] Router A/B Ed25519 transaction signing is missing transaction context from confirmation',
    );
  }

  const unsigned = await buildThresholdEd25519NearTxUnsignedBorshWasm({
    sessionId: args.thresholdSessionId,
    txSigningRequest: args.txSigningRequest,
    transactionContext: args.transactionContext,
    workerCtx: args.ctx,
  });
  const signingPayload = base64UrlDecode(unsigned.signingDigestB64u);
  if (signingPayload.length !== 32) {
    throw new Error('Router A/B normal-signing NEAR payload digest must be 32 bytes');
  }

  const nearNetworkId = normalizeNearNetworkId(args.ctx);
  const parsedTransaction = parseThresholdEd25519NearTransaction(
    args.txSigningRequest,
    'txSigningRequest',
  );
  const operationFingerprint = SigningSessionIds.signingOperationFingerprint(
    await thresholdEd25519NearTransactionOperationFingerprint({
      nearAccountId: args.nearAccountId,
      nearNetworkId,
      relayerKeyId: args.thresholdKeyMaterial.relayerKeyId,
      signerPublicKey: args.thresholdKeyMaterial.publicKey,
      transactions: [parsedTransaction],
      unsignedTransactionBorshB64u: unsigned.unsignedTransactionBorshB64u,
      signingDigestB64u: unsigned.signingDigestB64u,
    }),
  );
  const scope = buildRouterAbNormalSigningScope({
    thresholdSessionId: args.thresholdSessionId,
    walletSessionState: args.walletSessionState,
    nearAccountId: args.nearAccountId,
    operationId: args.operationId,
  });
  if (!scope) {
    throw new Error('[SigningEngine][near] Router A/B Ed25519 signing scope is missing');
  }
  const prepare = await buildRouterAbEd25519NearTransactionPrepareRequestV2({
    scope,
    expiresAtMs: routerAbNormalSigningExpiresAtMs({
      walletSessionExpiresAtMs: args.walletSessionState.signingWalletSession.expiresAtMs,
      requestedTtlMs: ROUTER_AB_NORMAL_SIGNING_REQUEST_TTL_MS,
    }),
    operationId: args.operationId,
    operationFingerprint,
    nearAccountId: args.nearAccountId,
    nearNetworkId,
    transactions: [
      {
        receiverId: parsedTransaction.receiverId,
        actionFingerprint: await routerAbNormalSigningActionFingerprint(parsedTransaction.actions),
      },
    ],
    unsignedTransactionBorshB64u: unsigned.unsignedTransactionBorshB64u,
    expectedSigningDigestB64u: unsigned.signingDigestB64u,
  });
  const signatureResult = await tryFinalizeRouterAbEd25519NormalSigningSignature({
    ctx: args.ctx,
    thresholdSessionId: args.thresholdSessionId,
    walletSessionState: args.walletSessionState,
    thresholdKeyMaterial: args.thresholdKeyMaterial,
    nearAccountId: args.nearAccountId,
    nearNetworkId,
    signingMaterial: args.signingMaterial,
    operation: {
      kind: 'router_ab_ed25519_presign_operation_identity_v1',
      operationId: args.operationId,
      operationFingerprint,
      purpose: 'near_transaction',
    },
    signingDigestB64u: unsigned.signingDigestB64u,
    signingPayloadLabel: 'NEAR payload digest',
    prepare,
  });
  if (!signatureResult) return null;
  const finalized = await finalizeThresholdEd25519NearTxFromSignatureWasm({
    sessionId: args.thresholdSessionId,
    unsignedTransactionBorshB64u: unsigned.unsignedTransactionBorshB64u,
    signingDigestB64u: unsigned.signingDigestB64u,
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
