import type { UnifiedIndexedDBManager } from '@/core/indexedDB';
import { buildNearAccountRefs } from '@/core/accountData/near/accountRefs';
import { normalizeIndexedDbAccountModel } from '@/core/indexedDB/normalization';
import {
  resolveProfileAccountContextFromCandidates,
  selectAccountSigner,
} from '@/core/indexedDB/profileAccountProjection';
import { toAccountId } from '@/core/types/accountIds';
import type { ConfirmationConfig } from '@/core/types/signer-worker';
import { chainFamilyFromNetwork } from '@/core/config/chains';
import type { ChainAccountRecord } from '@/core/indexedDB/passkeyClientDB.types';
import type { TatchiChainConfig, TatchiConfigsReadonly } from '@/core/types/tatchi';
import {
  createEmailOtpWalletAuthAdapter,
  createPasskeyWalletAuthAdapter,
  createWalletAuthModeResolver,
  resolveAccountAuthMetadataForSignerSource,
  type AccountAuthMetadata,
  type WalletAuthPlan,
} from '@/core/signingEngine/auth';
import {
  fromManagedNonceReservationSnapshot,
  type NonceLaneStatus,
  type EvmNonceManager,
  type ReserveNonceInput,
} from '@/core/rpcClients/evm/nonceManager';
import type { EvmSigningRequest } from '../chainAdaptors/evm/types';
import type { EvmSignedResult } from '../chainAdaptors/evm/evmAdapter';
import type { TempoSigningRequest } from '../chainAdaptors/tempo/types';
import type { TempoSignedResult } from '../chainAdaptors/tempo/tempoAdapter';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../interfaces/signing';
import { resolveThresholdEcdsaCommitQueueKey } from './thresholdLifecycle/thresholdEcdsaCommitQueue';
import type {
  ThresholdEcdsaSessionRecord,
  ThresholdEd25519SessionRecord,
} from './thresholdLifecycle/thresholdSessionStore';
import type { SigningSessionSealedStoreRecord } from './session/signingSessionSealedStore';
import { emitNonceLifecycleMetric } from './evmNonceLifecycleMetrics';
import {
  deriveSmartAccountDeploymentTargetFromSigningRequest,
  ensureSmartAccountDeployed,
} from '../orchestration/ensureSmartAccountDeployed';
import { reportSmartAccountDeploymentObservation } from '../orchestration/reportSmartAccountDeploymentObservation';
import type {
  TouchConfirmContextPort,
  TouchConfirmSigningPort,
  TouchConfirmSecureConfirmationPort,
  WarmSessionMaterialClearer,
  WarmSessionStatusResult,
  WarmSessionStatusReader,
} from '../touchConfirm';
import type { SignerWorkerManagerContext } from '../workerManager';
import {
  deploySmartAccountForChain,
  resolveSmartAccountDeploymentMaxAttempts,
  resolveSmartAccountDeploymentMode,
} from '../orchestration/smartAccountDeployment';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { assertThresholdSigningSessionReady } from '../orchestration/shared/thresholdSigningSessionPlanner';
import type { ThresholdEcdsaSessionBootstrapResult } from '../orchestration/thresholdActivation';
import { clearThresholdEcdsaClientPresignaturesForLane } from '../orchestration/walletOrigin/thresholdEcdsaCoordinator';
import { createWarmSessionManager } from '../session/WarmSessionManager';
import type { BootstrapEcdsaSessionArgs } from './thresholdLifecycle/thresholdSessionActivation';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import { isThresholdSessionAuthUnavailableError } from '../threshold/session/sessionPolicy';
import type { EmailOtpAuthLane } from '../emailOtp/authLane';
import {
  createSigningFlowEvent,
  SigningEventPhase,
  type CreateSigningFlowEventInput,
  type SigningFlowEvent,
} from '@/core/types/sdkSentEvents';

type EvmFamilySenderSignatureAlgorithm =
  | EvmSigningRequest['senderSignatureAlgorithm']
  | TempoSigningRequest['senderSignatureAlgorithm'];

export type EvmFamilySigningDeps = {
  indexedDB: UnifiedIndexedDBManager;
  tatchiPasskeyConfigs: TatchiConfigsReadonly;
  evmNonceManager: EvmNonceManager;
  getSignerWorkerContext: () => SignerWorkerManagerContext;
  withThresholdEcdsaCommitQueue: <T>(args: {
    queueKey: string;
    nearAccountId: string;
    enabled: boolean;
    shouldAbort?: () => boolean;
    maxQueueLength?: number;
    queueTimeoutMs?: number;
    task: () => Promise<T>;
  }) => Promise<T>;
  getThresholdEcdsaKeyRefForSigning: (args: {
    nearAccountId: string;
    chain: 'tempo' | 'evm';
  }) => ThresholdEcdsaSecp256k1KeyRef;
  getThresholdEcdsaSessionRecordForSigning: (args: {
    nearAccountId: string;
    chain: 'tempo' | 'evm';
  }) => ThresholdEcdsaSessionRecord;
  requestEmailOtpChallengeForSigning?: (args: {
    nearAccountId: string;
    chain: 'tempo' | 'evm';
    operation?: 'transaction_sign' | 'export_key';
    authLane?: EmailOtpAuthLane;
  }) => Promise<{ challengeId: string; emailHint?: string; appSessionJwt?: string }>;
  resolveEmailOtpSigningSessionAuthLane?: (args: {
    thresholdSessionId: string;
    curve: 'ecdsa';
    chain: 'tempo' | 'evm';
  }) => EmailOtpAuthLane | null;
  loginWithEmailOtpEcdsaCapabilityForSigning?: (args: {
    nearAccountId: string;
    chain: 'tempo' | 'evm';
    challengeId: string;
    otpCode: string;
    record: ThresholdEcdsaSessionRecord;
    operation?: 'transaction_sign' | 'export_key';
    appSessionJwt?: string;
    authLane?: EmailOtpAuthLane;
  }) => Promise<ThresholdEcdsaSecp256k1KeyRef>;
  rehydrateEmailOtpEcdsaSigningSessionFromSealedRecord?: (args: {
    sealedRecord: SigningSessionSealedStoreRecord;
    ecdsaRecord: ThresholdEcdsaSessionRecord;
    ed25519Record?: ThresholdEd25519SessionRecord | null;
  }) => Promise<{
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    remainingUses: number;
    expiresAtMs: number;
  } | null>;
  getEmailOtpWarmSessionStatus?: (sessionId: string) => Promise<WarmSessionStatusResult>;
  markThresholdEcdsaEmailOtpSessionConsumedForAccount?: (args: {
    nearAccountId: string;
    chain: 'tempo' | 'evm';
  }) => void;
  clearThresholdEcdsaSessionRecordForLane: (args: {
    nearAccountId: string;
    chain: 'tempo' | 'evm';
  }) => void;
  provisionThresholdEcdsaSession: (
    args: BootstrapEcdsaSessionArgs,
  ) => Promise<ThresholdEcdsaSessionBootstrapResult>;
  touchConfirm: TouchConfirmContextPort &
    TouchConfirmSigningPort &
    TouchConfirmSecureConfirmationPort &
    WarmSessionStatusReader &
    Partial<WarmSessionMaterialClearer>;
};

type EvmFamilyLifecycleEvent = Omit<CreateSigningFlowEventInput, 'flowId' | 'accountId'> & {
  flowId?: string;
  accountId?: string;
};

type EvmFamilyLifecycleEventCallback = (event: SigningFlowEvent) => void;

type EvmFamilyLifecycleArgsBase = {
  nearAccountId: string;
  signedResult: TempoSignedResult | EvmSignedResult;
  onEvent?: EvmFamilyLifecycleEventCallback;
};

type SignEvmFamilyArgs = {
  nearAccountId: string;
  request: TempoSigningRequest | EvmSigningRequest;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
  shouldAbort?: () => boolean;
  onEvent?: EvmFamilyLifecycleEventCallback;
};

type SignEvmFamilyAttemptOptions = {
  forceFreshEmailOtpAuth?: boolean;
  retryingFreshEmailOtpAuth?: boolean;
};

export type EvmFamilyBroadcastAcceptedArgs = EvmFamilyLifecycleArgsBase & {
  txHash?: `0x${string}`;
};

export type EvmFamilyBroadcastRejectedArgs = EvmFamilyLifecycleArgsBase & {
  error?: unknown;
};

export type EvmFamilyFinalizedArgs = EvmFamilyLifecycleArgsBase & {
  txHash?: `0x${string}`;
  receiptStatus?: 'success' | 'reverted';
};

export type EvmFamilyDroppedOrReplacedArgs = EvmFamilyLifecycleArgsBase & {
  reason: 'dropped' | 'replaced';
  txHash?: `0x${string}`;
};

export type EvmFamilyReconcileLaneArgs = EvmFamilyLifecycleArgsBase;

export type EvmFamilyNonceLaneStatus = {
  chainNextNonce: string;
  unresolvedInFlightNonces: string[];
  blocked: boolean;
  blockedNonce?: string;
};

type EvmFamilySigningCancelledError = Error & { code: 'cancelled' };
type EvmFamilySigningNonceConflictError = Error & {
  code: 'nonce_conflict_retryable';
  retryable: true;
  details: {
    chain: 'tempo' | 'evm';
    reason:
      | 'nonce_too_low'
      | 'nonce_too_high'
      | 'already_known'
      | 'replacement_underpriced'
      | 'nonce_conflict';
    networkKey: string;
    chainId: number;
  };
};
type EvmFamilySigningNonceLaneBlockedError = Error & {
  code: 'nonce_lane_blocked';
  retryable: true;
  details: {
    chain: 'tempo' | 'evm';
    networkKey: string;
    chainId: number;
    blockedNonce: string;
    ageMs?: number;
  };
};
type ManagedNonceReservation = ReserveNonceInput & { nonce: bigint };

type Secp256k1EngineCtor = new (opts: unknown) => unknown;
type WebAuthnP256EngineCtor = new (workerCtx: unknown) => unknown;
type SignEvmWithTouchConfirmFn = (args: unknown) => Promise<EvmSignedResult>;
type SignTempoWithTouchConfirmFn = (args: unknown) => Promise<TempoSignedResult>;
type ThresholdEcdsaPresignRefillEvent = {
  trigger: 'commit_start' | 'post_sign_success';
  result: {
    scheduled: boolean;
    reason?: string;
    [key: string]: unknown;
  };
};
type ThresholdEcdsaCommitQueueArgs = {
  nearAccountId: string;
  thresholdSessionId: string;
  shouldAbort?: () => boolean;
  task: () => Promise<unknown>;
};
let secp256k1EngineCtorPromise: Promise<Secp256k1EngineCtor> | null = null;
let webAuthnP256EngineCtorPromise: Promise<WebAuthnP256EngineCtor> | null = null;
let signEvmWithTouchConfirmPromise: Promise<SignEvmWithTouchConfirmFn> | null = null;
let signTempoWithTouchConfirmPromise: Promise<SignTempoWithTouchConfirmFn> | null = null;

async function loadSecp256k1EngineCtor(): Promise<Secp256k1EngineCtor> {
  if (!secp256k1EngineCtorPromise) {
    secp256k1EngineCtorPromise = import('../signers/algorithms/secp256k1').then(
      (mod) => mod.Secp256k1Engine as Secp256k1EngineCtor,
    );
  }
  return await secp256k1EngineCtorPromise;
}

async function loadWebAuthnP256EngineCtor(): Promise<WebAuthnP256EngineCtor> {
  if (!webAuthnP256EngineCtorPromise) {
    webAuthnP256EngineCtorPromise = import('../signers/algorithms/webauthnP256').then(
      (mod) => mod.WebAuthnP256Engine as WebAuthnP256EngineCtor,
    );
  }
  return await webAuthnP256EngineCtorPromise;
}

async function loadSignEvmWithTouchConfirm(): Promise<SignEvmWithTouchConfirmFn> {
  if (!signEvmWithTouchConfirmPromise) {
    signEvmWithTouchConfirmPromise = import('../orchestration/evm/evmSigningFlow').then(
      (mod) => mod.signEvmWithTouchConfirm as SignEvmWithTouchConfirmFn,
    );
  }
  return await signEvmWithTouchConfirmPromise;
}

async function loadSignTempoWithTouchConfirm(): Promise<SignTempoWithTouchConfirmFn> {
  if (!signTempoWithTouchConfirmPromise) {
    signTempoWithTouchConfirmPromise = import('../orchestration/tempo/tempoSigningFlow').then(
      (mod) => mod.signTempoWithTouchConfirm as SignTempoWithTouchConfirmFn,
    );
  }
  return await signTempoWithTouchConfirmPromise;
}

function createEvmFamilySigningCancelledError(): EvmFamilySigningCancelledError {
  const err = new Error('Request cancelled') as EvmFamilySigningCancelledError;
  err.code = 'cancelled';
  return err;
}

function throwIfEvmFamilySigningCancelled(shouldAbort?: () => boolean): void {
  if (typeof shouldAbort === 'function' && shouldAbort()) {
    throw createEvmFamilySigningCancelledError();
  }
}

function normalizeToken(value: unknown): string {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[\s-]+/g, '_');
}

function extractErrorCode(error: unknown): string {
  if (!error || typeof error !== 'object' || !('code' in error)) return '';
  return normalizeToken((error as { code?: unknown }).code);
}

function extractErrorMessage(error: unknown): string {
  if (!error) return '';
  if (typeof error === 'string') return error.trim();
  if (error instanceof Error) return String(error.message || '').trim();
  if (typeof error === 'object' && 'message' in error) {
    return String((error as { message?: unknown }).message || '').trim();
  }
  return String(error).trim();
}

function isFreshEmailOtpReauthRequiredError(error: unknown): boolean {
  if (extractErrorCode(error) === 'fresh_email_otp_required') return true;
  const message = extractErrorMessage(error).toLowerCase();
  return (
    message.includes('requires fresh email otp verification') ||
    message.includes('fresh email otp verification is required')
  );
}

function inferNonceConflictReason(args: {
  code: string;
  message: string;
}): EvmFamilySigningNonceConflictError['details']['reason'] | null {
  const haystack = `${args.code} ${args.message}`.toLowerCase();
  if (!haystack.trim()) return null;

  if (haystack.includes('nonce_too_low') || haystack.includes('nonce too low')) {
    return 'nonce_too_low';
  }
  if (haystack.includes('nonce_too_high') || haystack.includes('nonce too high')) {
    return 'nonce_too_high';
  }
  if (haystack.includes('already_known') || haystack.includes('already known')) {
    return 'already_known';
  }
  if (
    haystack.includes('replacement_transaction_underpriced') ||
    haystack.includes('replacement transaction underpriced')
  ) {
    return 'replacement_underpriced';
  }
  if (
    haystack.includes('nonce_conflict') ||
    (haystack.includes('nonce') && haystack.includes('conflict')) ||
    haystack.includes('invalid nonce') ||
    haystack.includes('nonce has already been used')
  ) {
    return 'nonce_conflict';
  }
  return null;
}

function createEvmFamilySigningNonceConflictError(args: {
  chain: 'tempo' | 'evm';
  networkKey: string;
  chainId: number;
  reason: EvmFamilySigningNonceConflictError['details']['reason'];
  cause?: unknown;
}): EvmFamilySigningNonceConflictError {
  const chainLabel = args.chain === 'tempo' ? 'Tempo' : 'EVM';
  const err = new Error(
    `[SigningEngine] ${chainLabel} nonce conflict (${args.reason}) on ${args.networkKey}. Refresh nonce context and retry.`,
  ) as EvmFamilySigningNonceConflictError;
  err.code = 'nonce_conflict_retryable';
  err.retryable = true;
  err.details = {
    chain: args.chain,
    reason: args.reason,
    networkKey: args.networkKey,
    chainId: args.chainId,
  };
  if (args.cause !== undefined) {
    try {
      (err as Error & { cause?: unknown }).cause = args.cause;
    } catch {}
  }
  return err;
}

function createEvmFamilySigningNonceLaneBlockedError(args: {
  chain: 'tempo' | 'evm';
  networkKey: string;
  chainId: number;
  blockedNonce: string;
  ageMs?: number;
  cause?: unknown;
}): EvmFamilySigningNonceLaneBlockedError {
  const chainLabel = args.chain === 'tempo' ? 'Tempo' : 'EVM';
  const err = new Error(
    `[SigningEngine] ${chainLabel} nonce lane blocked on ${args.networkKey} (nonce=${args.blockedNonce}). Reconcile lane and retry.`,
  ) as EvmFamilySigningNonceLaneBlockedError;
  err.code = 'nonce_lane_blocked';
  err.retryable = true;
  err.details = {
    chain: args.chain,
    networkKey: args.networkKey,
    chainId: args.chainId,
    blockedNonce: args.blockedNonce,
    ...(typeof args.ageMs === 'number' ? { ageMs: args.ageMs } : {}),
  };
  if (args.cause !== undefined) {
    try {
      (err as Error & { cause?: unknown }).cause = args.cause;
    } catch {}
  }
  return err;
}

function mapToRetryableNonceConflictError(args: {
  error: unknown;
  chain: 'tempo' | 'evm';
  networkKey: string;
  chainId: number;
}): unknown {
  if (!args.error || typeof args.error !== 'object') return args.error;
  const existingCode = extractErrorCode(args.error);
  if (existingCode === 'nonce_conflict_retryable') return args.error;
  const reason = inferNonceConflictReason({
    code: existingCode,
    message: extractErrorMessage(args.error),
  });
  if (!reason) return args.error;
  return createEvmFamilySigningNonceConflictError({
    chain: args.chain,
    networkKey: args.networkKey,
    chainId: args.chainId,
    reason,
    cause: args.error,
  });
}

function mapToRetryableNonceLaneBlockedError(args: {
  error: unknown;
  chain: 'tempo' | 'evm';
  networkKey: string;
  chainId: number;
}): unknown {
  if (!args.error || typeof args.error !== 'object') return args.error;
  const existingCode = extractErrorCode(args.error);
  if (existingCode === 'nonce_lane_blocked') {
    const details =
      typeof (args.error as { details?: unknown }).details === 'object'
        ? (args.error as { details?: Record<string, unknown> }).details || {}
        : {};
    const blockedNonceRaw = String(details?.blockedNonce || '').trim();
    const ageRaw = Number(details?.ageMs);
    return createEvmFamilySigningNonceLaneBlockedError({
      chain: args.chain,
      networkKey: args.networkKey,
      chainId: args.chainId,
      blockedNonce: blockedNonceRaw || 'unknown',
      ...(Number.isFinite(ageRaw) ? { ageMs: ageRaw } : {}),
      cause: args.error,
    });
  }

  const message = extractErrorMessage(args.error).toLowerCase();
  if (
    message.includes('nonce lane blocked') ||
    (message.includes('nonce') && message.includes('blocked'))
  ) {
    return createEvmFamilySigningNonceLaneBlockedError({
      chain: args.chain,
      networkKey: args.networkKey,
      chainId: args.chainId,
      blockedNonce: 'unknown',
      cause: args.error,
    });
  }
  return args.error;
}

function mapToRetryableNonceStateError(args: {
  error: unknown;
  chain: 'tempo' | 'evm';
  networkKey: string;
  chainId: number;
}): unknown {
  const mappedConflict = mapToRetryableNonceConflictError(args);
  return mapToRetryableNonceLaneBlockedError({
    ...args,
    error: mappedConflict,
  });
}

function toManagedNonceReservationFromSignedResult(args: {
  signedResult: TempoSignedResult | EvmSignedResult;
  nearAccountId: string;
}): (ReserveNonceInput & { nonce: bigint }) | null {
  const snapshot = (args.signedResult as { managedNonce?: unknown }).managedNonce;
  if (!snapshot || typeof snapshot !== 'object') return null;
  try {
    const parsed = fromManagedNonceReservationSnapshot(
      snapshot as Parameters<typeof fromManagedNonceReservationSnapshot>[0],
    );
    return {
      ...parsed,
      ...(String(parsed.nearAccountId || '').trim() ? {} : { nearAccountId: args.nearAccountId }),
    };
  } catch {
    return null;
  }
}

function toNonceLifecycleMetricBase(
  reservation: ManagedNonceReservation,
): Omit<Parameters<typeof emitNonceLifecycleMetric>[0], 'metric'> {
  const base = {
    chain: reservation.chain,
    networkKey: reservation.networkKey,
    chainId: reservation.chainId,
    sender: reservation.sender,
    nonce: reservation.nonce.toString(),
    ...(reservation.nearAccountId ? { nearAccountId: reservation.nearAccountId } : {}),
  };
  return reservation.nonceKey != null
    ? { ...base, nonceKey: reservation.nonceKey.toString() }
    : base;
}

function emitEvmFamilyBroadcastEvent(
  onEvent: EvmFamilyLifecycleEventCallback | undefined,
  event: EvmFamilyLifecycleEvent,
): void {
  try {
    onEvent?.(
      createSigningFlowEvent({
        ...event,
        flowId: event.flowId ?? createEvmFamilySigningFlowId(event),
      }),
    );
  } catch {}
}

function createEvmFamilySigningFlowId(event: EvmFamilyLifecycleEvent): string {
  const data = event.data || {};
  const chain = String(data.chain || 'evm_family');
  const networkKey = String(data.networkKey || 'unknown_network');
  const nonce = String(data.nonce || '');
  return ['signing', chain, networkKey, nonce || String(event.phase)].join(':');
}

function emitEvmFamilySigningEvent(
  onEvent: EvmFamilyLifecycleEventCallback | undefined,
  event: EvmFamilyLifecycleEvent,
): void {
  emitEvmFamilyBroadcastEvent(onEvent, event);
}

function isNonceConflictRetryableError(
  error: unknown,
): error is EvmFamilySigningNonceConflictError {
  if (!error || typeof error !== 'object') return false;
  return extractErrorCode(error) === 'nonce_conflict_retryable';
}

function isNonceLaneBlockedRetryableError(
  error: unknown,
): error is EvmFamilySigningNonceLaneBlockedError {
  if (!error || typeof error !== 'object') return false;
  return extractErrorCode(error) === 'nonce_lane_blocked';
}

function tryGetThresholdEcdsaKeyRefForSigning(args: {
  deps: EvmFamilySigningDeps;
  nearAccountId: string;
  chain: 'tempo' | 'evm';
}): ThresholdEcdsaSecp256k1KeyRef | undefined {
  try {
    return args.deps.getThresholdEcdsaKeyRefForSigning({
      nearAccountId: args.nearAccountId,
      chain: args.chain,
    });
  } catch {
    return undefined;
  }
}

async function resolveEvmFamilyTransactionAccountAuth(args: {
  deps: EvmFamilySigningDeps;
  nearAccountId: string;
  senderSignatureAlgorithm: EvmFamilySenderSignatureAlgorithm;
  record?: ThresholdEcdsaSessionRecord;
  keyRef?: ThresholdEcdsaSecp256k1KeyRef;
}): Promise<AccountAuthMetadata> {
  if (args.senderSignatureAlgorithm === 'webauthnP256') {
    return resolveAccountAuthMetadataForSignerSource();
  }
  if (isEmailOtpThresholdEcdsaSigningContext(args)) {
    return resolveAccountAuthMetadataForSignerSource({
      source: SIGNER_AUTH_METHODS.emailOtp,
    });
  }

  const accountId = toAccountId(args.nearAccountId);
  const context = await resolveProfileAccountContextFromCandidates(
    args.deps.indexedDB.clientDB,
    buildNearAccountRefs(accountId),
  ).catch(() => null);
  if (context?.profileId) {
    const [profile, activeSigners, lastProfileState] = await Promise.all([
      args.deps.indexedDB.clientDB.getProfile(context.profileId).catch(() => null),
      args.deps.indexedDB.clientDB
        .listAccountSigners({
          chainIdKey: context.accountRef.chainIdKey,
          accountAddress: context.accountRef.accountAddress,
          status: 'active',
        })
        .catch(() => []),
      args.deps.indexedDB.clientDB.getLastProfileState().catch(() => null),
    ]);
    if (profile && activeSigners.length) {
      const activeSignerSlot =
        lastProfileState?.profileId === context.profileId
          ? Number(lastProfileState.activeSignerSlot)
          : undefined;
      const selectedSigner = selectAccountSigner({
        profile,
        activeSigners,
        ...(typeof activeSignerSlot === 'number' &&
        Number.isSafeInteger(activeSignerSlot) &&
        activeSignerSlot >= 1
          ? { signerSlot: activeSignerSlot }
          : {}),
      });
      if (selectedSigner?.signerAuthMethod === SIGNER_AUTH_METHODS.emailOtp) {
        return resolveAccountAuthMetadataForSignerSource({
          source: SIGNER_AUTH_METHODS.emailOtp,
        });
      }
      if (selectedSigner?.signerAuthMethod === SIGNER_AUTH_METHODS.passkey) {
        return resolveAccountAuthMetadataForSignerSource({
          source: SIGNER_AUTH_METHODS.passkey,
        });
      }
    }
  }

  return resolveAccountAuthMetadataForSignerSource({
    source: args.record?.source,
  });
}

function isEmailOtpThresholdEcdsaSigningContext(args: {
  record?: ThresholdEcdsaSessionRecord;
  keyRef?: ThresholdEcdsaSecp256k1KeyRef;
}): boolean {
  if (args.record?.source === SIGNER_AUTH_METHODS.emailOtp) return true;
  if (args.record?.emailOtpAuthContext?.authMethod === SIGNER_AUTH_METHODS.emailOtp) return true;
  if (args.record?.clientAdditiveShareHandle?.kind === 'email_otp_worker_session') return true;
  return (
    args.keyRef?.backendBinding?.clientAdditiveShareHandle?.kind === 'email_otp_worker_session'
  );
}

function createEvmFamilyWarmSessionManager(
  deps: EvmFamilySigningDeps,
  onEvent?: EvmFamilyLifecycleEventCallback,
) {
  return createWarmSessionManager({
    touchConfirm: deps.touchConfirm,
    clearThresholdEcdsaSigningArtifactsForLane: ({ nearAccountId, chain }) => {
      const record = deps.getThresholdEcdsaSessionRecordForSigning({
        nearAccountId: String(nearAccountId),
        chain,
      });
      clearThresholdEcdsaClientPresignaturesForLane({
        relayerUrl: record.relayerUrl,
        ecdsaThresholdKeyId: record.ecdsaThresholdKeyId,
        participantIds: record.participantIds,
      });
    },
    clearThresholdEcdsaSessionRecordForLane: deps.clearThresholdEcdsaSessionRecordForLane,
    markThresholdEcdsaEmailOtpSessionConsumedForAccount:
      deps.markThresholdEcdsaEmailOtpSessionConsumedForAccount,
    getThresholdEcdsaSessionRecordForSigning: deps.getThresholdEcdsaSessionRecordForSigning,
    getThresholdEcdsaKeyRefForSigning: deps.getThresholdEcdsaKeyRefForSigning,
    provisionThresholdEcdsaSession: deps.provisionThresholdEcdsaSession,
    rehydrateEmailOtpEcdsaSigningSessionFromSealedRecord:
      deps.rehydrateEmailOtpEcdsaSigningSessionFromSealedRecord,
    getEmailOtpWarmSessionStatus: deps.getEmailOtpWarmSessionStatus,
    onSealedRestore: (event) => {
      const chain = event.chain;
      if (event.status === 'started') {
        emitEvmFamilySigningEvent(onEvent, {
          phase: SigningEventPhase.STEP_05_CONFIRMATION_DISPLAYED,
          status: 'waiting_for_user',
          accountId: String(event.accountId),
          message: 'Restoring signing session...',
          interaction: { kind: 'transaction_confirmation', overlay: 'show' },
          data: {
            chain,
            thresholdSessionId: event.thresholdSessionId,
            ...(event.walletSigningSessionId
              ? { walletSigningSessionId: event.walletSigningSessionId }
              : {}),
          },
        });
        return;
      }
      if (event.status === 'restored') {
        emitEvmFamilySigningEvent(onEvent, {
          phase: SigningEventPhase.STEP_06_AUTH_WARM_SESSION_CLAIMED,
          status: 'succeeded',
          accountId: String(event.accountId),
          message: 'Signing session restored',
          interaction: { kind: 'none', overlay: 'none' },
          data: {
            chain,
            thresholdSessionId: event.thresholdSessionId,
            ...(event.walletSigningSessionId
              ? { walletSigningSessionId: event.walletSigningSessionId }
              : {}),
          },
        });
      }
    },
  });
}

async function resolveEvmFamilyTransactionWalletAuth(args: {
  deps: EvmFamilySigningDeps;
  nearAccountId: string;
  chain: 'tempo' | 'evm';
  senderSignatureAlgorithm: EvmFamilySenderSignatureAlgorithm;
  record?: ThresholdEcdsaSessionRecord;
  keyRef?: ThresholdEcdsaSecp256k1KeyRef;
  forceFreshAuth?: boolean;
  onEvent?: EvmFamilyLifecycleEventCallback;
}): Promise<{
  walletAuthPlan: WalletAuthPlan;
  emailOtpSigning?: {
    challengeId: string;
    emailHint?: string;
    appSessionJwt?: string;
    resend?: () => Promise<{ challengeId: string; emailHint?: string; appSessionJwt?: string }>;
    complete: (otpCode: string, challengeId?: string) => Promise<ThresholdEcdsaSecp256k1KeyRef>;
  };
}> {
  const appSessionJwtByChallengeId = new Map<string, string>();
  const warmSessionManager = createEvmFamilyWarmSessionManager(args.deps, args.onEvent);
  const resolver = createWalletAuthModeResolver({
    passkey: createPasskeyWalletAuthAdapter({
      challenge: async () => ({}),
      complete: async () => ({
        method: 'passkey',
        webauthnAuthentication: {},
      }),
    }),
    emailOtp: createEmailOtpWalletAuthAdapter({
      challenge: async () => {
        if (typeof args.deps.requestEmailOtpChallengeForSigning !== 'function') {
          throw new Error('[SigningEngine] Email OTP per-operation signing is not configured');
        }
        emitEvmFamilySigningEvent(args.onEvent, {
          phase: SigningEventPhase.STEP_06_AUTH_EMAIL_OTP_CHALLENGE_STARTED,
          status: 'running',
          accountId: args.nearAccountId,
          interaction: { kind: 'none', overlay: 'none' },
        });
        const authLane = args.record
          ? args.deps.resolveEmailOtpSigningSessionAuthLane?.({
              thresholdSessionId: args.record.thresholdSessionId,
              curve: 'ecdsa',
              chain: args.chain,
            }) || undefined
          : undefined;
        const challenge = await args.deps.requestEmailOtpChallengeForSigning({
          nearAccountId: args.nearAccountId,
          chain: args.chain,
          ...(authLane ? { authLane } : {}),
        });
        const challengeId = String(challenge.challengeId || '').trim();
        if (!challengeId) {
          throw new Error(
            '[SigningEngine] Email OTP challenge response did not include challengeId',
          );
        }
        const appSessionJwt = String(challenge.appSessionJwt || '').trim();
        if (appSessionJwt) {
          appSessionJwtByChallengeId.set(challengeId, appSessionJwt);
        }
        emitEvmFamilySigningEvent(args.onEvent, {
          phase: SigningEventPhase.STEP_06_AUTH_EMAIL_OTP_INPUT_REQUIRED,
          status: 'waiting_for_user',
          accountId: args.nearAccountId,
          interaction: { kind: 'otp_input', overlay: 'show' },
          ...(challenge.emailHint ? { data: { emailHint: challenge.emailHint } } : {}),
        });
        return {
          challengeId,
          email: String(challenge.emailHint || '').trim(),
        };
      },
      complete: async ({ challengeId, code }) => {
        if (
          typeof args.deps.loginWithEmailOtpEcdsaCapabilityForSigning !== 'function' ||
          !args.record
        ) {
          throw new Error('[SigningEngine] Email OTP per-operation signing is not configured');
        }
        const authLane =
          args.deps.resolveEmailOtpSigningSessionAuthLane?.({
            thresholdSessionId: args.record.thresholdSessionId,
            curve: 'ecdsa',
            chain: args.chain,
          }) || undefined;
        const refreshed = await args.deps.loginWithEmailOtpEcdsaCapabilityForSigning({
          nearAccountId: args.nearAccountId,
          chain: args.chain,
          challengeId,
          otpCode: code,
          record: args.record,
          operation: 'transaction_sign',
          ...(appSessionJwtByChallengeId.get(challengeId)
            ? { appSessionJwt: appSessionJwtByChallengeId.get(challengeId)! }
            : {}),
          ...(authLane ? { authLane } : {}),
        });
        return {
          method: 'email_otp',
          emailOtpAuthentication: refreshed,
        };
      },
    }),
    warmSession: {
      resolveWarmSessionPlan: async (input) => {
        if (args.forceFreshAuth) return null;
        const record = args.record;
        if (args.senderSignatureAlgorithm !== 'secp256k1' || !record) {
          return null;
        }
        if (record.emailOtpAuthContext?.retention === 'single_use') {
          return null;
        }
        const expiresAtMs = Math.floor(Number(record.expiresAtMs) || 0);
        const remainingUses = Math.floor(Number(record.remainingUses) || 0);
        if (expiresAtMs <= 0 || remainingUses <= 0) return null;
        if (isEmailOtpThresholdEcdsaSigningContext({ record, keyRef: args.keyRef })) {
          const emailOtpWorkerSessionId =
            record.clientAdditiveShareHandle?.kind === 'email_otp_worker_session'
              ? String(record.clientAdditiveShareHandle.sessionId || '').trim()
              : String(record.thresholdSessionId || '').trim();
          const readEmailOtpStatus = async () => {
            if (
              emailOtpWorkerSessionId &&
              typeof args.deps.getEmailOtpWarmSessionStatus === 'function'
            ) {
              return await args.deps
                .getEmailOtpWarmSessionStatus(emailOtpWorkerSessionId)
                .catch(() => null);
            }
            return await args.deps.touchConfirm
              .getWarmSessionStatus({ sessionId: record.thresholdSessionId })
              .catch(() => null);
          };
          let status = await readEmailOtpStatus();
          if (!status?.ok || status.remainingUses <= 0 || status.expiresAtMs <= Date.now()) {
            await warmSessionManager.getWarmSession(args.nearAccountId).catch(() => null);
            status = await readEmailOtpStatus();
          }
          if (!status?.ok || status.remainingUses <= 0 || status.expiresAtMs <= Date.now()) {
            return null;
          }
          return {
            kind: 'warmSession',
            method: input.accountAuth.primaryAuthMethod,
            accountId: input.accountId,
            intent: input.intent,
            ...(input.curve ? { curve: input.curve } : {}),
            ...(record.runtimePolicyScope
              ? {
                  signingRootId: signingRootScopeFromRuntimePolicyScope(record.runtimePolicyScope)
                    .signingRootId,
                }
              : {}),
            sessionId: record.thresholdSessionId,
            retention: record.emailOtpAuthContext?.retention || 'session',
            expiresAtMs: status.expiresAtMs,
            remainingUses: status.remainingUses,
          };
        }
        return {
          kind: 'warmSession',
          method: input.accountAuth.primaryAuthMethod,
          accountId: input.accountId,
          intent: input.intent,
          ...(input.curve ? { curve: input.curve } : {}),
          ...(record.runtimePolicyScope
            ? {
                signingRootId: signingRootScopeFromRuntimePolicyScope(record.runtimePolicyScope)
                  .signingRootId,
              }
            : {}),
          sessionId: record.thresholdSessionId,
          retention: record.emailOtpAuthContext?.retention || 'session',
          expiresAtMs,
          remainingUses,
        };
      },
    },
  });
  const walletAuthPlan = await resolver.resolveWalletAuthPlan({
    accountId: args.nearAccountId,
    accountAuth: await resolveEvmFamilyTransactionAccountAuth({
      deps: args.deps,
      nearAccountId: args.nearAccountId,
      senderSignatureAlgorithm: args.senderSignatureAlgorithm,
      ...(args.record ? { record: args.record } : {}),
      ...(args.keyRef ? { keyRef: args.keyRef } : {}),
    }),
    intent: 'transaction_sign',
    curve: args.senderSignatureAlgorithm === 'secp256k1' ? 'ecdsa' : undefined,
  });
  if (walletAuthPlan.kind !== 'emailOtpReauth') return { walletAuthPlan };

  const challenge = await walletAuthPlan.challenge();
  let activeChallenge = challenge;
  return {
    walletAuthPlan,
    emailOtpSigning: {
      challengeId: activeChallenge.challengeId,
      ...(activeChallenge.email ? { emailHint: activeChallenge.email } : {}),
      ...(appSessionJwtByChallengeId.get(activeChallenge.challengeId)
        ? { appSessionJwt: appSessionJwtByChallengeId.get(activeChallenge.challengeId)! }
        : {}),
      resend: async () => {
        activeChallenge = await walletAuthPlan.challenge();
        return {
          challengeId: activeChallenge.challengeId,
          ...(activeChallenge.email ? { emailHint: activeChallenge.email } : {}),
          ...(appSessionJwtByChallengeId.get(activeChallenge.challengeId)
            ? { appSessionJwt: appSessionJwtByChallengeId.get(activeChallenge.challengeId)! }
            : {}),
        };
      },
      complete: async (otpCode: string, challengeId?: string) => {
        const resolvedChallengeId = String(challengeId || activeChallenge.challengeId).trim();
        const proof = await walletAuthPlan.complete({
          challengeId: resolvedChallengeId,
          code: otpCode,
        });
        return proof.emailOtpAuthentication as ThresholdEcdsaSecp256k1KeyRef;
      },
    },
  };
}

function resolveManagedRuntimeScopeBootstrap(
  configs: TatchiConfigsReadonly,
): { environmentId: string; publishableKey: string } | undefined {
  const registration = configs.registration;
  if (registration.mode !== 'managed') return undefined;
  const environmentId = String(registration.environmentId || '').trim();
  const publishableKey = String(registration.publishableKey || '').trim();
  if (!environmentId || !publishableKey) return undefined;
  return { environmentId, publishableKey };
}

export async function ensureEvmFamilyThresholdEcdsaKeyRefReady(args: {
  deps: EvmFamilySigningDeps;
  nearAccountId: string;
  chain: 'tempo' | 'evm';
  keyRef: ThresholdEcdsaSecp256k1KeyRef | undefined;
  shouldAbort?: () => boolean;
  onEvent?: EvmFamilyLifecycleEventCallback;
}): Promise<ThresholdEcdsaSecp256k1KeyRef> {
  throwIfEvmFamilySigningCancelled(args.shouldAbort);

  const warmSessionManager = createEvmFamilyWarmSessionManager(args.deps, args.onEvent);
  const resolvedKeyRef =
    args.keyRef ||
    tryGetThresholdEcdsaKeyRefForSigning({
      deps: args.deps,
      nearAccountId: args.nearAccountId,
      chain: args.chain,
    });

  const readyCapability = await warmSessionManager.ensureEcdsaCapabilityReady({
    nearAccountId: args.nearAccountId,
    chain: args.chain,
    keyRef: resolvedKeyRef,
    runtimeScopeBootstrap: resolveManagedRuntimeScopeBootstrap(args.deps.tatchiPasskeyConfigs),
    usesNeeded: 1,
    beforeReconnect: async () => {
      try {
        emitEvmFamilySigningEvent(args.onEvent, {
          phase: SigningEventPhase.STEP_09_THRESHOLD_SESSION_RECONNECT_STARTED,
          status: 'running',
          accountId: args.nearAccountId,
          interaction: { kind: 'none', overlay: 'none' },
          data: { chain: args.chain },
        });
      } catch {}
    },
    assertNotCancelled: () => {
      throwIfEvmFamilySigningCancelled(args.shouldAbort);
    },
  });

  emitEvmFamilySigningEvent(args.onEvent, {
    phase: SigningEventPhase.STEP_09_THRESHOLD_SESSION_RECONNECT_SUCCEEDED,
    status: 'succeeded',
    accountId: args.nearAccountId,
    interaction: { kind: 'none', overlay: 'none' },
    data: { chain: args.chain },
  });

  return readyCapability.keyRef;
}

function toOptionalEvmAddress(value: unknown): `0x${string}` | undefined {
  const normalized = String(value || '')
    .trim()
    .toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(normalized)) return undefined;
  return normalized as `0x${string}`;
}

function readOptionalChainId(chain: TatchiChainConfig): number | undefined {
  if (!('chainId' in chain)) return undefined;
  return typeof chain.chainId === 'number' ? chain.chainId : undefined;
}

function isEvmFamilyNetwork(chain: TatchiChainConfig): boolean {
  return String(chainFamilyFromNetwork(chain.network)) === 'evm';
}

function isTempoFamilyNetwork(chain: TatchiChainConfig): boolean {
  return String(chainFamilyFromNetwork(chain.network)) === 'tempo';
}

function resolveNonceNetworkKey(args: {
  configs: TatchiConfigsReadonly;
  request: EvmSigningRequest | TempoSigningRequest;
}): string {
  const resolved = tryResolveNonceNetworkKey(args);
  if (resolved) return resolved;
  const chainId = args.request.tx.chainId;
  throw new Error(
    `[SigningEngine] unable to resolve nonce network for ${args.request.chain} chainId=${String(chainId)} from configured chains`,
  );
}

function resolveNonceNetworkKeyForError(args: {
  configs: TatchiConfigsReadonly;
  request: EvmSigningRequest | TempoSigningRequest;
}): string {
  return (
    tryResolveNonceNetworkKey(args) || `${args.request.chain}:${String(args.request.tx.chainId)}`
  );
}

function tryResolveNonceNetworkKey(args: {
  configs: TatchiConfigsReadonly;
  request: EvmSigningRequest | TempoSigningRequest;
}): string | null {
  const chainId = args.request.tx.chainId;
  const matchesByChainId = args.configs.network.chains.filter((chain) => {
    const configured = readOptionalChainId(chain);
    return typeof configured === 'number' && configured === chainId;
  });
  if (!matchesByChainId.length) return null;

  if (args.request.chain === 'tempo') {
    const tempoMatches = matchesByChainId.filter((chain) => isTempoFamilyNetwork(chain));
    if (tempoMatches.length === 1) return tempoMatches[0]!.network;
    if (tempoMatches.length > 1) {
      const candidates = tempoMatches.map((chain) => chain.network).join(', ');
      throw new Error(
        `[SigningEngine] ambiguous nonce network for tempo chainId=${String(args.request.tx.chainId)} across [${candidates}]`,
      );
    }
    return null;
  }

  const evmMatches = matchesByChainId.filter((chain) => isEvmFamilyNetwork(chain));
  if (evmMatches.length === 1) return evmMatches[0]!.network;
  if (evmMatches.length > 1) {
    const candidates = evmMatches.map((chain) => chain.network).join(', ');
    throw new Error(
      `[SigningEngine] ambiguous nonce network for evm chainId=${String(args.request.tx.chainId)} across [${candidates}]`,
    );
  }

  const tempoMatches = matchesByChainId.filter((chain) => isTempoFamilyNetwork(chain));
  if (tempoMatches.length === 1) return tempoMatches[0]!.network;
  if (tempoMatches.length > 1) {
    const candidates = tempoMatches.map((chain) => chain.network).join(', ');
    throw new Error(
      `[SigningEngine] ambiguous nonce network for evm->tempo chainId=${String(args.request.tx.chainId)} across [${candidates}]`,
    );
  }
  return null;
}

function pickPreferredSmartAccountRow(args: {
  rows: ChainAccountRecord[];
  accountModelCandidates: readonly string[];
}): ChainAccountRecord | null {
  const modelSet = new Set(args.accountModelCandidates.map(normalizeIndexedDbAccountModel));
  const filtered = args.rows.filter((row) =>
    modelSet.has(normalizeIndexedDbAccountModel(row.accountModel)),
  );
  const source = filtered.length ? filtered : args.rows;
  if (!source.length) return null;
  return source.find((row) => !!row.isPrimary) || source[0] || null;
}

async function resolveManagedNonceSender(args: {
  deps: EvmFamilySigningDeps;
  nearAccountId: string;
  request: EvmSigningRequest | TempoSigningRequest;
}): Promise<`0x${string}`> {
  const nearAccountId = toAccountId(args.nearAccountId);
  const context = await resolveProfileAccountContextFromCandidates(
    args.deps.indexedDB.clientDB,
    buildNearAccountRefs(nearAccountId),
  );
  if (!context?.profileId) {
    throw new Error(
      `[SigningEngine] unable to resolve profile mapping for managed ${args.request.chain.toUpperCase()} nonce (${String(nearAccountId)})`,
    );
  }

  const target = deriveSmartAccountDeploymentTargetFromSigningRequest(args.request);
  for (const chainId of target.chainIdCandidates) {
    const chainIdKey = `${target.chain}:${String(chainId)}`;
    const rows = await args.deps.indexedDB.clientDB
      .listChainAccountsByProfileAndChain(context.profileId, chainIdKey)
      .catch(() => []);
    if (!rows.length) continue;
    const selected = pickPreferredSmartAccountRow({
      rows,
      accountModelCandidates: target.accountModelCandidates,
    });
    const sender = toOptionalEvmAddress(selected?.accountAddress);
    if (sender) return sender;
  }

  if (typeof args.deps.indexedDB.clientDB.listChainAccountsByProfile === 'function') {
    const allProfileRows = await args.deps.indexedDB.clientDB
      .listChainAccountsByProfile(context.profileId)
      .catch(() => []);
    if (allProfileRows.length) {
      const counterpartModels = target.chain === 'evm' ? ['tempo-native'] : ['erc4337'];
      const selected = pickPreferredSmartAccountRow({
        rows: allProfileRows,
        accountModelCandidates: [...target.accountModelCandidates, ...counterpartModels],
      });
      const sender = toOptionalEvmAddress(selected?.accountAddress);
      if (sender) return sender;
    }
  }

  const contextMappedSender = toOptionalEvmAddress(context.accountRef.accountAddress);
  if (contextMappedSender) return contextMappedSender;

  throw new Error(
    `[SigningEngine] unable to resolve managed ${args.request.chain.toUpperCase()} nonce sender (no usable sender row for ${context.profileId})`,
  );
}

async function resolveManagedEvmNonceReservationInput(args: {
  deps: EvmFamilySigningDeps;
  nearAccountId: string;
  request: EvmSigningRequest;
}): Promise<ReserveNonceInput> {
  const sender = await resolveManagedNonceSender(args);
  return {
    chain: 'evm',
    networkKey: resolveNonceNetworkKey({
      configs: args.deps.tatchiPasskeyConfigs,
      request: args.request,
    }),
    chainId: args.request.tx.chainId,
    sender,
    nearAccountId: args.nearAccountId,
  };
}

async function reserveManagedNonceForRequest(args: {
  deps: EvmFamilySigningDeps;
  request: EvmSigningRequest;
  reservationInput: ReserveNonceInput;
}): Promise<{ request: EvmSigningRequest; reservation: ManagedNonceReservation }> {
  const reservationInput = args.reservationInput;
  let nonce: bigint;
  try {
    nonce = await args.deps.evmNonceManager.reserveNextNonce(reservationInput);
  } catch (error: unknown) {
    throw mapToRetryableNonceStateError({
      error,
      chain: 'evm',
      networkKey: reservationInput.networkKey,
      chainId: reservationInput.chainId,
    });
  }
  return {
    request: {
      ...args.request,
      tx: {
        ...args.request.tx,
        nonce,
      },
    },
    reservation: {
      ...reservationInput,
      nonce,
    },
  };
}

async function reserveManagedNonceForTempoRequest(args: {
  deps: EvmFamilySigningDeps;
  nearAccountId: string;
  request: TempoSigningRequest;
}): Promise<{ request: TempoSigningRequest; reservation: ManagedNonceReservation }> {
  const sender = await resolveManagedNonceSender(args);
  const reservationInput: ReserveNonceInput = {
    chain: 'tempo',
    networkKey: resolveNonceNetworkKey({
      configs: args.deps.tatchiPasskeyConfigs,
      request: args.request,
    }),
    chainId: args.request.tx.chainId,
    sender,
    nonceKey: args.request.tx.nonceKey,
    nearAccountId: args.nearAccountId,
  };
  let nonce: bigint;
  try {
    nonce = await args.deps.evmNonceManager.reserveNextNonce(reservationInput);
  } catch (error: unknown) {
    throw mapToRetryableNonceStateError({
      error,
      chain: 'tempo',
      networkKey: reservationInput.networkKey,
      chainId: reservationInput.chainId,
    });
  }
  return {
    request: {
      ...args.request,
      tx: {
        ...args.request.tx,
        nonce,
      },
    },
    reservation: {
      ...reservationInput,
      nonce,
    },
  };
}

function formatNonceLaneStatus(status: NonceLaneStatus): EvmFamilyNonceLaneStatus {
  return {
    chainNextNonce: status.chainNextNonce.toString(),
    unresolvedInFlightNonces: status.unresolvedInFlightNonces.map((value) => value.toString()),
    blocked: status.blocked,
    ...(status.blockedNonce != null ? { blockedNonce: status.blockedNonce.toString() } : {}),
  };
}

export async function reportEvmFamilyBroadcastAccepted(
  deps: EvmFamilySigningDeps,
  args: EvmFamilyBroadcastAcceptedArgs,
): Promise<void> {
  const reservation = toManagedNonceReservationFromSignedResult({
    signedResult: args.signedResult,
    nearAccountId: args.nearAccountId,
  });
  if (!reservation) return;

  emitEvmFamilyBroadcastEvent(args.onEvent, {
    phase: SigningEventPhase.STEP_12_BROADCAST_ACCEPTED,
    status: 'running',
    message: 'Marking managed nonce lane as in-flight',
    data: {
      chain: reservation.chain,
      networkKey: reservation.networkKey,
      chainId: reservation.chainId.toString(),
      nonce: reservation.nonce.toString(),
    },
  });
  const txHash =
    args.txHash ||
    (args.signedResult.chain === 'evm'
      ? (args.signedResult.txHashHex as `0x${string}`)
      : undefined);
  await deps.evmNonceManager.markBroadcastAccepted({
    ...reservation,
    ...(txHash ? { txHash } : {}),
  });
  emitNonceLifecycleMetric({
    metric: 'broadcast_accepted',
    ...toNonceLifecycleMetricBase(reservation),
    ...(txHash ? { txHash } : {}),
  });
  emitEvmFamilyBroadcastEvent(args.onEvent, {
    phase: SigningEventPhase.STEP_12_BROADCAST_ACCEPTED,
    status: 'succeeded',
    message: 'Managed nonce lane marked in-flight',
    data: {
      chain: reservation.chain,
      networkKey: reservation.networkKey,
      chainId: reservation.chainId.toString(),
      nonce: reservation.nonce.toString(),
      ...(txHash ? { txHash } : {}),
    },
  });
}

export async function reportEvmFamilyBroadcastRejected(
  deps: EvmFamilySigningDeps,
  args: EvmFamilyBroadcastRejectedArgs,
): Promise<void> {
  const reservation = toManagedNonceReservationFromSignedResult({
    signedResult: args.signedResult,
    nearAccountId: args.nearAccountId,
  });
  if (!reservation) return;
  emitEvmFamilyBroadcastEvent(args.onEvent, {
    phase: SigningEventPhase.STEP_12_BROADCAST_REJECTED,
    status: 'running',
    message: 'Marking managed nonce reservation rejected',
    data: {
      chain: reservation.chain,
      networkKey: reservation.networkKey,
      chainId: reservation.chainId.toString(),
      nonce: reservation.nonce.toString(),
    },
  });
  deps.evmNonceManager.markBroadcastRejected(reservation);
  const mappedError = mapToRetryableNonceStateError({
    error: args.error,
    chain: reservation.chain,
    networkKey: reservation.networkKey,
    chainId: reservation.chainId,
  });
  emitNonceLifecycleMetric({
    metric: 'broadcast_rejected',
    ...toNonceLifecycleMetricBase(reservation),
    errorCode: extractErrorCode(mappedError) || extractErrorCode(args.error),
  });
  emitEvmFamilyBroadcastEvent(args.onEvent, {
    phase: SigningEventPhase.STEP_12_BROADCAST_REJECTED,
    status: 'failed',
    message: 'Managed nonce reservation marked rejected',
    data: {
      chain: reservation.chain,
      networkKey: reservation.networkKey,
      chainId: reservation.chainId.toString(),
      nonce: reservation.nonce.toString(),
    },
  });
  if (
    !isNonceConflictRetryableError(mappedError) &&
    !isNonceLaneBlockedRetryableError(mappedError)
  ) {
    return;
  }

  emitEvmFamilyBroadcastEvent(args.onEvent, {
    phase: SigningEventPhase.STEP_13_NONCE_RECONCILE_STARTED,
    status: 'running',
    message: 'Reconciling managed nonce lane after broadcast error',
    data: {
      chain: reservation.chain,
      networkKey: reservation.networkKey,
      chainId: reservation.chainId.toString(),
      nonce: reservation.nonce.toString(),
      errorCode: extractErrorCode(mappedError),
    },
  });
  const laneStatus = await deps.evmNonceManager.reconcileLane(reservation).catch(() => null);
  emitEvmFamilyBroadcastEvent(args.onEvent, {
    phase: SigningEventPhase.STEP_13_NONCE_RECONCILE_SUCCEEDED,
    status: 'succeeded',
    message: 'Managed nonce lane reconciled',
    data: {
      chain: reservation.chain,
      networkKey: reservation.networkKey,
      chainId: reservation.chainId.toString(),
      ...(laneStatus ? { laneStatus: formatNonceLaneStatus(laneStatus) } : {}),
    },
  });
  emitNonceLifecycleMetric({
    metric: 'reconciled',
    ...toNonceLifecycleMetricBase(reservation),
    errorCode: extractErrorCode(mappedError) || undefined,
  });
  throw mappedError;
}

export async function reportEvmFamilyFinalized(
  deps: EvmFamilySigningDeps,
  args: EvmFamilyFinalizedArgs,
): Promise<void> {
  void args.receiptStatus;
  const reservation = toManagedNonceReservationFromSignedResult({
    signedResult: args.signedResult,
    nearAccountId: args.nearAccountId,
  });
  if (!reservation) return;
  const txHash =
    args.txHash ||
    (args.signedResult.chain === 'evm'
      ? (args.signedResult.txHashHex as `0x${string}`)
      : undefined);
  await deps.evmNonceManager.markFinalized({
    ...reservation,
    ...(txHash ? { txHash } : {}),
  });
  emitNonceLifecycleMetric({
    metric: 'finalized',
    ...toNonceLifecycleMetricBase(reservation),
    ...(txHash ? { txHash } : {}),
  });
}

export async function reportEvmFamilyDroppedOrReplaced(
  deps: EvmFamilySigningDeps,
  args: EvmFamilyDroppedOrReplacedArgs,
): Promise<void> {
  const reservation = toManagedNonceReservationFromSignedResult({
    signedResult: args.signedResult,
    nearAccountId: args.nearAccountId,
  });
  if (!reservation) return;
  emitEvmFamilyBroadcastEvent(args.onEvent, {
    phase:
      args.reason === 'replaced'
        ? SigningEventPhase.STEP_13_TRANSACTION_REPLACED
        : SigningEventPhase.STEP_13_TRANSACTION_DROPPED,
    status: 'running',
    message:
      args.reason === 'replaced'
        ? 'Marking managed nonce lane replaced'
        : 'Marking managed nonce lane dropped',
    data: {
      chain: reservation.chain,
      networkKey: reservation.networkKey,
      chainId: reservation.chainId.toString(),
      nonce: reservation.nonce.toString(),
      reason: args.reason,
      ...(args.txHash ? { txHash: args.txHash } : {}),
    },
  });
  await deps.evmNonceManager.markDroppedOrReplaced({
    ...reservation,
    reason: args.reason,
    ...(args.txHash ? { txHash: args.txHash } : {}),
  });
  emitNonceLifecycleMetric({
    metric: args.reason === 'replaced' ? 'replaced' : 'dropped',
    ...toNonceLifecycleMetricBase(reservation),
    ...(args.txHash ? { txHash: args.txHash } : {}),
  });
  emitEvmFamilyBroadcastEvent(args.onEvent, {
    phase:
      args.reason === 'replaced'
        ? SigningEventPhase.STEP_13_TRANSACTION_REPLACED
        : SigningEventPhase.STEP_13_TRANSACTION_DROPPED,
    status: args.reason === 'replaced' ? 'succeeded' : 'failed',
    message:
      args.reason === 'replaced'
        ? 'Managed nonce lane marked replaced'
        : 'Managed nonce lane marked dropped',
    data: {
      chain: reservation.chain,
      networkKey: reservation.networkKey,
      chainId: reservation.chainId.toString(),
      nonce: reservation.nonce.toString(),
      reason: args.reason,
      ...(args.txHash ? { txHash: args.txHash } : {}),
    },
  });
}

export async function reconcileEvmFamilyNonceLane(
  deps: EvmFamilySigningDeps,
  args: EvmFamilyReconcileLaneArgs,
): Promise<EvmFamilyNonceLaneStatus> {
  const reservation = toManagedNonceReservationFromSignedResult({
    signedResult: args.signedResult,
    nearAccountId: args.nearAccountId,
  });
  if (!reservation) {
    return {
      chainNextNonce: '0',
      unresolvedInFlightNonces: [],
      blocked: false,
    };
  }
  emitEvmFamilyBroadcastEvent(args.onEvent, {
    phase: SigningEventPhase.STEP_13_NONCE_RECONCILE_STARTED,
    status: 'running',
    message: 'Reconciling managed nonce lane',
    data: {
      chain: reservation.chain,
      networkKey: reservation.networkKey,
      chainId: reservation.chainId.toString(),
    },
  });
  const laneStatus = await deps.evmNonceManager.reconcileLane(reservation);
  const formatted = formatNonceLaneStatus(laneStatus);
  emitNonceLifecycleMetric({
    metric: 'reconciled',
    ...toNonceLifecycleMetricBase(reservation),
    ...(formatted.blockedNonce ? { blockedNonce: formatted.blockedNonce } : {}),
  });
  emitEvmFamilyBroadcastEvent(args.onEvent, {
    phase: SigningEventPhase.STEP_13_NONCE_RECONCILE_SUCCEEDED,
    status: 'succeeded',
    message: 'Managed nonce lane reconciled',
    data: {
      chain: reservation.chain,
      networkKey: reservation.networkKey,
      chainId: reservation.chainId.toString(),
      laneStatus: formatted,
    },
  });
  if (laneStatus.blocked) {
    emitNonceLifecycleMetric({
      metric: 'lane_blocked',
      ...toNonceLifecycleMetricBase(reservation),
      blockedNonce: String(formatted.blockedNonce || 'unknown'),
    });
    throw createEvmFamilySigningNonceLaneBlockedError({
      chain: reservation.chain,
      networkKey: reservation.networkKey,
      chainId: reservation.chainId,
      blockedNonce: String(formatted.blockedNonce || 'unknown'),
    });
  }
  return formatted;
}

async function ensureSmartAccountDeploymentReady(args: {
  deps: EvmFamilySigningDeps;
  nearAccountId: string;
  request: TempoSigningRequest | EvmSigningRequest;
  thresholdEcdsaKeyRef?: ThresholdEcdsaSecp256k1KeyRef;
  onEvent?: EvmFamilyLifecycleEventCallback;
}): Promise<void> {
  const target = deriveSmartAccountDeploymentTargetFromSigningRequest(args.request);
  const deploymentMode = resolveSmartAccountDeploymentMode(args.deps.tatchiPasskeyConfigs);
  const deploymentEventData = {
    chain: target.chain,
    chainIdCandidates: target.chainIdCandidates,
    accountModelCandidates: target.accountModelCandidates,
    deploymentMode,
  };
  emitEvmFamilySigningEvent(args.onEvent, {
    phase: SigningEventPhase.STEP_04_ACCOUNT_READINESS_STARTED,
    status: 'running',
    accountId: args.nearAccountId,
    interaction: { kind: 'none', overlay: 'none' },
    data: deploymentEventData,
  });
  try {
    const deployment = await ensureSmartAccountDeployed({
      clientDB: args.deps.indexedDB.clientDB,
      nearAccountId: toAccountId(args.nearAccountId),
      chain: target.chain,
      chainIdCandidates: target.chainIdCandidates,
      accountModelCandidates: target.accountModelCandidates,
      maxDeployAttempts: resolveSmartAccountDeploymentMaxAttempts(args.deps.tatchiPasskeyConfigs),
      ...(deploymentMode === 'enforce'
        ? {
            deploy: (input) => {
              const relayerUrl = String(args.thresholdEcdsaKeyRef?.relayerUrl || '').trim();
              const thresholdSessionJwt = String(
                args.thresholdEcdsaKeyRef?.thresholdSessionJwt || '',
              ).trim();
              if (!relayerUrl || !thresholdSessionJwt) {
                return Promise.resolve({
                  ok: false,
                  code: 'missing_transport',
                  message:
                    'Missing threshold-session transport for canonical smart-account deployment',
                });
              }
              return deploySmartAccountForChain(args.deps.tatchiPasskeyConfigs, input, {
                relayerUrl,
                thresholdSessionJwt,
              });
            },
            ...(args.thresholdEcdsaKeyRef?.relayerUrl &&
            args.thresholdEcdsaKeyRef?.thresholdSessionJwt
              ? {
                  reportDeployed: async (
                    input: Parameters<
                      NonNullable<
                        Parameters<typeof ensureSmartAccountDeployed>[0]['reportDeployed']
                      >
                    >[0],
                  ) => {
                    await reportSmartAccountDeploymentObservation({
                      ...input,
                      relayerUrl: args.thresholdEcdsaKeyRef!.relayerUrl,
                      thresholdSessionJwt: args.thresholdEcdsaKeyRef!.thresholdSessionJwt!,
                    });
                  },
                }
              : {}),
            enforce: true,
          }
        : { enforce: false }),
    });
    const deploymentReady =
      deployment.status === 'deployed' || deployment.status === 'already_deployed';
    emitEvmFamilySigningEvent(args.onEvent, {
      phase: deploymentReady
        ? SigningEventPhase.STEP_04_ACCOUNT_READINESS_SUCCEEDED
        : SigningEventPhase.STEP_04_ACCOUNT_READINESS_SKIPPED,
      status: deploymentReady ? 'succeeded' : 'skipped',
      accountId: args.nearAccountId,
      interaction: { kind: 'none', overlay: 'none' },
      data: {
        ...deploymentEventData,
        deploymentStatus: deployment.status,
        attempts: deployment.attempts,
        ...(typeof deployment.chainId === 'number' ? { chainId: deployment.chainId } : {}),
        ...(deployment.accountAddress ? { accountAddress: deployment.accountAddress } : {}),
        ...(deployment.deploymentTxHash ? { deploymentTxHash: deployment.deploymentTxHash } : {}),
        ...(deployment.failureCode ? { failureCode: deployment.failureCode } : {}),
        ...(deployment.failureMessage ? { failureMessage: deployment.failureMessage } : {}),
      },
    });
  } catch (error: unknown) {
    const details =
      String((error as { message?: unknown })?.message || error || '').trim() ||
      'deployment failed';
    emitEvmFamilySigningEvent(args.onEvent, {
      phase: SigningEventPhase.FAILED,
      status: 'failed',
      accountId: args.nearAccountId,
      interaction: { kind: 'none', overlay: 'hide' },
      data: deploymentEventData,
      error: { message: details },
    });
    throw new Error(
      `[SigningEngine] smart-account deployment must succeed before first ${target.chain.toUpperCase()} send: ${details}`,
    );
  }
}

export async function signEvmFamily(
  deps: EvmFamilySigningDeps,
  args: SignEvmFamilyArgs,
): Promise<TempoSignedResult | EvmSignedResult> {
  return await signEvmFamilyAttempt(deps, args, {});
}

async function signEvmFamilyAttempt(
  deps: EvmFamilySigningDeps,
  args: SignEvmFamilyArgs,
  attempt: SignEvmFamilyAttemptOptions,
): Promise<TempoSignedResult | EvmSignedResult> {
  throwIfEvmFamilySigningCancelled(args.shouldAbort);

  if (args.request.chain !== 'tempo' && args.request.chain !== 'evm') {
    throw new Error('[SigningEngine] invalid request: chain must be tempo or evm');
  }

  let thresholdEcdsaKeyRef: ThresholdEcdsaSecp256k1KeyRef | undefined;
  let thresholdEcdsaRecord: ThresholdEcdsaSessionRecord | undefined;
  if (args.request.senderSignatureAlgorithm === 'secp256k1') {
    try {
      thresholdEcdsaRecord = deps.getThresholdEcdsaSessionRecordForSigning({
        nearAccountId: args.nearAccountId,
        chain: args.request.chain,
      });
    } catch {
      thresholdEcdsaRecord = undefined;
    }
    thresholdEcdsaKeyRef =
      tryGetThresholdEcdsaKeyRefForSigning({
        deps,
        nearAccountId: args.nearAccountId,
        chain: args.request.chain,
      }) || undefined;
  }

  throwIfEvmFamilySigningCancelled(args.shouldAbort);

  const [Secp256k1Engine, WebAuthnP256Engine] = await Promise.all([
    loadSecp256k1EngineCtor(),
    loadWebAuthnP256EngineCtor(),
  ]);

  const signerWorkerCtx = deps.getSignerWorkerContext();
  const ctx = deps.touchConfirm.getContext();
  const { walletAuthPlan, emailOtpSigning } = await resolveEvmFamilyTransactionWalletAuth({
    deps,
    nearAccountId: args.nearAccountId,
    chain: args.request.chain,
    senderSignatureAlgorithm: args.request.senderSignatureAlgorithm,
    ...(thresholdEcdsaRecord ? { record: thresholdEcdsaRecord } : {}),
    ...(thresholdEcdsaKeyRef ? { keyRef: thresholdEcdsaKeyRef } : {}),
    forceFreshAuth: attempt.forceFreshEmailOtpAuth === true,
    onEvent: args.onEvent,
  });
  const warmSessionManager = createEvmFamilyWarmSessionManager(deps, args.onEvent);
  const flowArgs = {
    ctx,
    touchConfirm: deps.touchConfirm,
    workerCtx: signerWorkerCtx,
    nearAccountId: args.nearAccountId,
    onEvent: args.onEvent,
    engines: {
      secp256k1: new Secp256k1Engine({
        getRpId: () => ctx.touchIdPrompt.getRpId(),
        workerCtx: signerWorkerCtx,
        shouldAbort: args.shouldAbort,
        thresholdEcdsaPresignPoolPolicy:
          deps.tatchiPasskeyConfigs.signing.thresholdEcdsa.presignPool,
        onThresholdEcdsaPresignRefillScheduled: ({
          trigger,
          result,
        }: ThresholdEcdsaPresignRefillEvent) => {
          try {
            emitEvmFamilySigningEvent(args.onEvent, {
              phase: SigningEventPhase.STEP_08_PRESIGN_REFILL_SCHEDULED,
              status: 'running',
              accountId: args.nearAccountId,
              message: result.scheduled
                ? `Scheduled threshold presign refill (${trigger})`
                : `Skipped threshold presign refill (${trigger}): ${result.reason}`,
              interaction: { kind: 'none', overlay: 'none' },
              data: { trigger, ...result },
            });
          } catch {}
        },
        enqueueThresholdEcdsaCommit: async (queueArgs: ThresholdEcdsaCommitQueueArgs) => {
          const thresholdSessionId = String(queueArgs.thresholdSessionId || '').trim();
          const queueKey = resolveThresholdEcdsaCommitQueueKey({
            chain: args.request.chain,
            thresholdSessionId,
          });
          try {
            emitEvmFamilySigningEvent(args.onEvent, {
              phase: SigningEventPhase.STEP_10_COMMIT_QUEUED,
              status: 'running',
              accountId: args.nearAccountId,
              interaction: { kind: 'none', overlay: 'none' },
              data: { queueKey, chain: args.request.chain },
            });
          } catch {}
          return await deps.withThresholdEcdsaCommitQueue({
            queueKey,
            nearAccountId: queueArgs.nearAccountId,
            enabled: true,
            shouldAbort: queueArgs.shouldAbort,
            task: async () => {
              throwIfEvmFamilySigningCancelled(queueArgs.shouldAbort);
              await assertThresholdSigningSessionReady({
                warmSessionManager,
                nearAccountId: String(queueArgs.nearAccountId),
                chain: args.request.chain,
                sessionId: thresholdSessionId,
                usesNeeded: 1,
              });
              try {
                emitEvmFamilySigningEvent(args.onEvent, {
                  phase: SigningEventPhase.STEP_10_COMMIT_STARTED,
                  status: 'running',
                  accountId: args.nearAccountId,
                  interaction: { kind: 'none', overlay: 'none' },
                  data: { queueKey, chain: args.request.chain },
                });
              } catch {}
              await ensureSmartAccountDeploymentReady({
                deps,
                nearAccountId: args.nearAccountId,
                request: args.request,
                onEvent: args.onEvent,
                ...(thresholdEcdsaKeyRef ? { thresholdEcdsaKeyRef } : {}),
              });
              throwIfEvmFamilySigningCancelled(queueArgs.shouldAbort);
              return await queueArgs.task();
            },
          });
        },
      }),
      webauthnP256: new WebAuthnP256Engine(signerWorkerCtx),
    },
    ...(thresholdEcdsaKeyRef ? { keyRefsByAlgorithm: { secp256k1: thresholdEcdsaKeyRef } } : {}),
    ...(emailOtpSigning ? { emailOtpSigning } : {}),
    walletAuthPlan,
    confirmationConfigOverride: args.confirmationConfigOverride,
    ...(args.request.senderSignatureAlgorithm === 'secp256k1'
      ? {
          ensureThresholdEcdsaKeyRefReady: async () => {
            const readyKeyRef = await ensureEvmFamilyThresholdEcdsaKeyRefReady({
              deps,
              nearAccountId: args.nearAccountId,
              chain: args.request.chain,
              keyRef: thresholdEcdsaKeyRef,
              shouldAbort: args.shouldAbort,
              onEvent: args.onEvent,
            });
            thresholdEcdsaKeyRef = readyKeyRef;
            return readyKeyRef;
          },
        }
      : {}),
  };

  if (args.request.senderSignatureAlgorithm === 'secp256k1') {
    if (!emailOtpSigning) {
      await warmSessionManager.assertEcdsaOperationAllowed({
        nearAccountId: args.nearAccountId,
        chain: args.request.chain,
        operationLabel: `${args.request.chain} signing`,
        thresholdSessionId: thresholdEcdsaKeyRef?.thresholdSessionId,
      });
    }
  }

  const retryWithFreshEmailOtpAuth = async (
    error: unknown,
  ): Promise<TempoSignedResult | EvmSignedResult | null> => {
    if (attempt.retryingFreshEmailOtpAuth || emailOtpSigning) return null;
    if (args.request.senderSignatureAlgorithm !== 'secp256k1') return null;
    if (
      !isThresholdSessionAuthUnavailableError(error) &&
      !isFreshEmailOtpReauthRequiredError(error)
    ) {
      return null;
    }
    const accountAuth = await resolveEvmFamilyTransactionAccountAuth({
      deps,
      nearAccountId: args.nearAccountId,
      senderSignatureAlgorithm: args.request.senderSignatureAlgorithm,
      ...(thresholdEcdsaRecord ? { record: thresholdEcdsaRecord } : {}),
      ...(thresholdEcdsaKeyRef ? { keyRef: thresholdEcdsaKeyRef } : {}),
    });
    if (accountAuth.primaryAuthMethod !== SIGNER_AUTH_METHODS.emailOtp) return null;
    emitEvmFamilySigningEvent(args.onEvent, {
      phase: SigningEventPhase.STEP_06_AUTH_EMAIL_OTP_CHALLENGE_STARTED,
      status: 'running',
      accountId: args.nearAccountId,
      message: 'Signing session expired; requesting Email OTP reauthorization',
      interaction: { kind: 'none', overlay: 'none' },
      data: { chain: args.request.chain, reason: 'threshold_session_expired' },
    });
    return await signEvmFamilyAttempt(deps, args, {
      forceFreshEmailOtpAuth: true,
      retryingFreshEmailOtpAuth: true,
    });
  };

  if (args.request.chain === 'evm') {
    const signEvmWithTouchConfirm = await loadSignEvmWithTouchConfirm();
    const request = args.request;
    const reservationInputPromise = resolveManagedEvmNonceReservationInput({
      deps,
      nearAccountId: args.nearAccountId,
      request,
    });
    // Warm nonce state as soon as sender/network are known; keep non-fatal and non-blocking.
    void reservationInputPromise
      .then((reservationInput) => deps.evmNonceManager.reconcileLane(reservationInput))
      .catch(() => null);
    try {
      const result = await signEvmWithTouchConfirm({
        ...flowArgs,
        request,
        prepareRequestWithManagedNonce: async () =>
          await reserveManagedNonceForRequest({
            deps,
            request,
            reservationInput: await reservationInputPromise,
          }),
        releaseNonceReservation: (reservation: ManagedNonceReservation) => {
          deps.evmNonceManager.markBroadcastRejected(reservation);
        },
      } as unknown);
      await warmSessionManager.applyEcdsaPostSignPolicy({
        nearAccountId: args.nearAccountId,
        chain: 'evm',
        thresholdSessionId: thresholdEcdsaKeyRef?.thresholdSessionId,
      });
      return result;
    } catch (error: unknown) {
      const retried = await retryWithFreshEmailOtpAuth(error);
      if (retried) return retried;
      throw mapToRetryableNonceStateError({
        error,
        chain: 'evm',
        networkKey: resolveNonceNetworkKeyForError({
          configs: deps.tatchiPasskeyConfigs,
          request,
        }),
        chainId: request.tx.chainId,
      });
    }
  }

  const signTempoWithTouchConfirm = await loadSignTempoWithTouchConfirm();
  const request = args.request;
  try {
    const result = await signTempoWithTouchConfirm({
      ...flowArgs,
      request,
      prepareRequestWithManagedNonce: async () =>
        await reserveManagedNonceForTempoRequest({
          deps,
          nearAccountId: args.nearAccountId,
          request,
        }),
      releaseNonceReservation: (reservation: ManagedNonceReservation) => {
        deps.evmNonceManager.markBroadcastRejected(reservation);
      },
    } as unknown);
    await warmSessionManager.applyEcdsaPostSignPolicy({
      nearAccountId: args.nearAccountId,
      chain: 'tempo',
      thresholdSessionId: thresholdEcdsaKeyRef?.thresholdSessionId,
    });
    return result;
  } catch (error: unknown) {
    const retried = await retryWithFreshEmailOtpAuth(error);
    if (retried) return retried;
    throw mapToRetryableNonceStateError({
      error,
      chain: 'tempo',
      networkKey: resolveNonceNetworkKeyForError({
        configs: deps.tatchiPasskeyConfigs,
        request,
      }),
      chainId: request.tx.chainId,
    });
  }
}
