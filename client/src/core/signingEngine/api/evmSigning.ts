import type { UnifiedIndexedDBManager } from '@/core/indexedDB';
import { buildNearAccountRefs } from '@/core/accountData/near/accountRefs';
import { normalizeIndexedDbAccountModel } from '@/core/indexedDB/normalization';
import { resolveProfileAccountContextFromCandidates } from '@/core/indexedDB/profileAccountProjection';
import { toAccountId } from '@/core/types/accountIds';
import type { ConfirmationConfig } from '@/core/types/signer-worker';
import { chainFamilyFromNetwork } from '@/core/config/chains';
import type { ChainAccountRecord } from '@/core/indexedDB/passkeyClientDB.types';
import type { TatchiChainConfig, TatchiConfigsReadonly } from '@/core/types/tatchi';
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
  ThresholdPrfFirstCachePeekPort,
} from '../touchConfirm';
import type { SignerWorkerManagerContext } from '../workerManager';
import {
  deploySmartAccountForChain,
  resolveSmartAccountDeploymentMaxAttempts,
  resolveSmartAccountDeploymentMode,
} from '../orchestration/smartAccountDeployment';
import {
  assertThresholdSigningSessionReady,
  isThresholdSigningSessionReady,
} from '../orchestration/shared/thresholdSigningSessionPlanner';
import type { ThresholdEcdsaSessionBootstrapResult } from '../orchestration/thresholdActivation';

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
  bootstrapThresholdEcdsaSession: (args: {
    nearAccountId: string;
    chain: 'tempo' | 'evm';
  }) => Promise<ThresholdEcdsaSessionBootstrapResult>;
  touchConfirm: TouchConfirmContextPort &
    TouchConfirmSigningPort &
    TouchConfirmSecureConfirmationPort &
    ThresholdPrfFirstCachePeekPort;
};

type EvmFamilyLifecycleEvent = {
  step: number;
  phase: string;
  status: 'progress' | 'success' | 'error';
  message?: string;
  data?: unknown;
};

type EvmFamilyLifecycleEventCallback = (event: EvmFamilyLifecycleEvent) => void;

type EvmFamilyLifecycleArgsBase = {
  nearAccountId: string;
  signedResult: TempoSignedResult | EvmSignedResult;
  onEvent?: EvmFamilyLifecycleEventCallback;
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
        ? ((args.error as { details?: Record<string, unknown> }).details || {})
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
    onEvent?.(event);
  } catch {}
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
}): ThresholdEcdsaSecp256k1KeyRef | null {
  try {
    return args.deps.getThresholdEcdsaKeyRefForSigning({
      nearAccountId: args.nearAccountId,
      chain: args.chain,
    });
  } catch {
    return null;
  }
}

async function ensureThresholdEcdsaKeyRefReady(args: {
  deps: EvmFamilySigningDeps;
  nearAccountId: string;
  chain: 'tempo' | 'evm';
  keyRef: ThresholdEcdsaSecp256k1KeyRef | undefined;
  shouldAbort?: () => boolean;
  onEvent?: (event: {
    step: number;
    phase: string;
    status: 'progress' | 'success' | 'error';
    message?: string;
    data?: unknown;
  }) => void;
}): Promise<ThresholdEcdsaSecp256k1KeyRef> {
  throwIfEvmFamilySigningCancelled(args.shouldAbort);

  let resolvedKeyRef =
    args.keyRef ||
    tryGetThresholdEcdsaKeyRefForSigning({
      deps: args.deps,
      nearAccountId: args.nearAccountId,
      chain: args.chain,
    });

  const isReady = await (async (): Promise<boolean> => {
    const sessionId = String(resolvedKeyRef?.thresholdSessionId || '').trim();
    if (!resolvedKeyRef || !sessionId) return false;
    return await isThresholdSigningSessionReady({
      touchConfirm: args.deps.touchConfirm,
      sessionId,
      usesNeeded: 1,
    });
  })();

  if (!isReady) {
    try {
      args.onEvent?.({
        step: 3,
        phase: 'threshold-session-reconnect',
        status: 'progress',
        message:
          args.chain === 'tempo'
            ? 'Threshold signer not ready, reconnecting Tempo signer'
            : 'Threshold signer not ready, reconnecting EVM signer',
      });
    } catch {}

    throwIfEvmFamilySigningCancelled(args.shouldAbort);
    await args.deps.bootstrapThresholdEcdsaSession({
      nearAccountId: args.nearAccountId,
      chain: args.chain,
    });
    throwIfEvmFamilySigningCancelled(args.shouldAbort);

    resolvedKeyRef = args.deps.getThresholdEcdsaKeyRefForSigning({
      nearAccountId: args.nearAccountId,
      chain: args.chain,
    });
  }
  if (!resolvedKeyRef) {
    throw new Error('[SigningEngine] threshold ECDSA keyRef is unavailable after reconnect');
  }

  await assertThresholdSigningSessionReady({
    touchConfirm: args.deps.touchConfirm,
    sessionId: resolvedKeyRef.thresholdSessionId,
    usesNeeded: 1,
  });

  return resolvedKeyRef;
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
  return tryResolveNonceNetworkKey(args) || `${args.request.chain}:${String(args.request.tx.chainId)}`;
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
    step: 7,
    phase: 'nonce-broadcast-accepted',
    status: 'progress',
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
    step: 7,
    phase: 'nonce-broadcast-accepted',
    status: 'success',
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
    step: 7,
    phase: 'nonce-broadcast-rejected',
    status: 'progress',
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
    step: 7,
    phase: 'nonce-broadcast-rejected',
    status: 'success',
    message: 'Managed nonce reservation marked rejected',
    data: {
      chain: reservation.chain,
      networkKey: reservation.networkKey,
      chainId: reservation.chainId.toString(),
      nonce: reservation.nonce.toString(),
    },
  });
  if (!isNonceConflictRetryableError(mappedError) && !isNonceLaneBlockedRetryableError(mappedError)) {
    return;
  }

  emitEvmFamilyBroadcastEvent(args.onEvent, {
    step: 7,
    phase: 'nonce-reconcile',
    status: 'progress',
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
    step: 7,
    phase: 'nonce-reconcile',
    status: 'success',
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
  emitEvmFamilyBroadcastEvent(args.onEvent, {
    step: 7,
    phase: 'nonce-finalized',
    status: 'progress',
    message: 'Finalizing managed nonce lane',
    data: {
      chain: reservation.chain,
      networkKey: reservation.networkKey,
      chainId: reservation.chainId.toString(),
      nonce: reservation.nonce.toString(),
      ...(txHash ? { txHash } : {}),
    },
  });
  await deps.evmNonceManager.markFinalized({
    ...reservation,
    ...(txHash ? { txHash } : {}),
  });
  emitNonceLifecycleMetric({
    metric: 'finalized',
    ...toNonceLifecycleMetricBase(reservation),
    ...(txHash ? { txHash } : {}),
  });
  emitEvmFamilyBroadcastEvent(args.onEvent, {
    step: 7,
    phase: 'nonce-finalized',
    status: 'success',
    message: 'Managed nonce lane finalized',
    data: {
      chain: reservation.chain,
      networkKey: reservation.networkKey,
      chainId: reservation.chainId.toString(),
      nonce: reservation.nonce.toString(),
      ...(txHash ? { txHash } : {}),
    },
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
    step: 7,
    phase: 'nonce-dropped-or-replaced',
    status: 'progress',
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
    step: 7,
    phase: 'nonce-dropped-or-replaced',
    status: 'success',
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
    step: 7,
    phase: 'nonce-reconcile',
    status: 'progress',
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
    step: 7,
    phase: 'nonce-reconcile',
    status: 'success',
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
}): Promise<void> {
  const target = deriveSmartAccountDeploymentTargetFromSigningRequest(args.request);
  const deploymentMode = resolveSmartAccountDeploymentMode(args.deps.tatchiPasskeyConfigs);
  try {
    await ensureSmartAccountDeployed({
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
            ...(args.thresholdEcdsaKeyRef?.relayerUrl && args.thresholdEcdsaKeyRef?.thresholdSessionJwt
              ? {
                  reportDeployed: async (input: Parameters<
                    NonNullable<Parameters<typeof ensureSmartAccountDeployed>[0]['reportDeployed']>
                  >[0]) => {
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
  } catch (error: unknown) {
    const details =
      String((error as { message?: unknown })?.message || error || '').trim() ||
      'deployment failed';
    throw new Error(
      `[SigningEngine] smart-account deployment must succeed before first ${target.chain.toUpperCase()} send: ${details}`,
    );
  }
}

export async function signEvmFamily(
  deps: EvmFamilySigningDeps,
  args: {
    nearAccountId: string;
    request: TempoSigningRequest | EvmSigningRequest;
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
    shouldAbort?: () => boolean;
    onEvent?: (event: {
      step: number;
      phase: string;
      status: 'progress' | 'success' | 'error';
      message?: string;
      data?: unknown;
    }) => void;
  },
): Promise<TempoSignedResult | EvmSignedResult> {
  throwIfEvmFamilySigningCancelled(args.shouldAbort);

  if (args.request.chain !== 'tempo' && args.request.chain !== 'evm') {
    throw new Error('[SigningEngine] invalid request: chain must be tempo or evm');
  }

  let thresholdEcdsaKeyRef: ThresholdEcdsaSecp256k1KeyRef | undefined;
  if (args.request.senderSignatureAlgorithm === 'secp256k1') {
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
            args.onEvent?.({
              step: 4,
              phase: 'presign-refill-scheduled',
              status: 'progress',
              message: result.scheduled
                ? `Scheduled threshold presign refill (${trigger})`
                : `Skipped threshold presign refill (${trigger}): ${result.reason}`,
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
            args.onEvent?.({
              step: 4,
              phase: 'commit-queued',
              status: 'progress',
              message: 'Queued for threshold signing commit',
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
                touchConfirm: deps.touchConfirm,
                sessionId: thresholdSessionId,
                usesNeeded: 1,
              });
              try {
                args.onEvent?.({
                  step: 4,
                  phase: 'commit-started',
                  status: 'progress',
                  message: 'Starting threshold signing commit',
                  data: { queueKey, chain: args.request.chain },
                });
              } catch {}
              await ensureSmartAccountDeploymentReady({
                deps,
                nearAccountId: args.nearAccountId,
                request: args.request,
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
    confirmationConfigOverride: args.confirmationConfigOverride,
    ...(args.request.senderSignatureAlgorithm === 'secp256k1'
      ? {
          ensureThresholdEcdsaKeyRefReady: async () => {
            const readyKeyRef = await ensureThresholdEcdsaKeyRefReady({
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
      .then(reservationInput => deps.evmNonceManager.reconcileLane(reservationInput))
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
      return result;
    } catch (error: unknown) {
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
    return result;
  } catch (error: unknown) {
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
