import type {
  ClearThresholdEd25519PresignPoolPayload,
  ClearThresholdEd25519PresignPoolResult,
  GetThresholdEd25519PresignPoolStatusPayload,
  GetThresholdEd25519PresignPoolStatusResult,
  PrepareThresholdEd25519PresignPoolPayload,
  PrepareThresholdEd25519PresignPoolResult,
  ThresholdEd25519ClientPresignWorkerOffer,
  ThresholdEd25519PresignCommitmentsWire,
  ThresholdEd25519PresignPoolAcceptedPair,
  ThresholdEd25519PresignPoolPolicy,
  ThresholdEd25519PresignPoolPolicyConfig,
} from '@/core/types/signer-worker';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { normalizeRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import type {
  Brand,
  SigningOperationFingerprint,
  SigningOperationId,
} from '../../session/operationState/types';
import type { ThresholdRuntimePolicyScope } from '../sessionPolicy';

export type Ed25519ClientPresignNonceHandle = Brand<
  string,
  'Ed25519ClientPresignNonceHandle'
>;
export type Ed25519ClientPresignId = Brand<string, 'Ed25519ClientPresignId'>;
export type Ed25519ServerPresignId = Brand<string, 'Ed25519ServerPresignId'>;
export type Ed25519PresignScopeKey = Brand<string, 'Ed25519PresignScopeKey'>;

export type Ed25519PresignOperationIdentity = {
  kind: 'threshold_ed25519_presign_operation_identity_v1';
  operationId: SigningOperationId;
  operationFingerprint: SigningOperationFingerprint;
  purpose: 'near_transaction' | 'nep413_message' | 'delegate_action';
};

export type Ed25519PresignRefillState =
  | {
      state: 'idle';
      startedAtMs?: never;
      requestTag?: never;
      previousFailureCount?: never;
      failedAtMs?: never;
      failureCount?: never;
      backoffUntilMs?: never;
      code?: never;
      message?: never;
    }
  | {
      state: 'in_flight';
      startedAtMs: number;
      requestTag: 'background_presign_pool_refill' | 'foreground_presign_pool_refill';
      previousFailureCount: number;
      failedAtMs?: never;
      failureCount?: never;
      backoffUntilMs?: never;
      code?: never;
      message?: never;
    }
  | {
      state: 'failed';
      failedAtMs: number;
      failureCount: number;
      backoffUntilMs: number;
      code: string;
      message: string;
      startedAtMs?: never;
      requestTag?: never;
      previousFailureCount?: never;
    };

export type Ed25519OfferedClientPresignEntry = {
  state: 'offered';
  clientPresignId: Ed25519ClientPresignId;
  nonceHandle: Ed25519ClientPresignNonceHandle;
  clientVerifyingShareB64u: string;
  clientCommitments: ThresholdEd25519PresignCommitmentsWire;
  createdAtMs: number;
  presignId?: never;
  relayerCommitments?: never;
  relayerVerifyingShareB64u?: never;
  nearNetworkId?: never;
  signerPublicKey?: never;
  participantIds?: never;
  runtimePolicyScope?: never;
  expiresAtMs?: never;
  burnedAtMs?: never;
  reason?: never;
};

export type Ed25519ReadyClientPresignEntry = {
  state: 'ready';
  presignId: Ed25519ServerPresignId;
  clientPresignId: Ed25519ClientPresignId;
  nonceHandle: Ed25519ClientPresignNonceHandle;
  clientVerifyingShareB64u: string;
  clientCommitments: ThresholdEd25519PresignCommitmentsWire;
  relayerCommitments: ThresholdEd25519PresignCommitmentsWire;
  relayerVerifyingShareB64u: string;
  nearNetworkId: string;
  signerPublicKey: string;
  participantIds: readonly number[];
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  expiresAtMs: number;
  createdAtMs?: never;
  burnedAtMs?: never;
  reason?: never;
};

export type Ed25519BurnedClientPresignEntry = {
  state: 'burned';
  presignId: Ed25519ServerPresignId;
  clientPresignId: Ed25519ClientPresignId;
  reason: 'used' | 'expired' | 'rejected' | 'stale_generation' | 'send_attempted';
  burnedAtMs: number;
  nonceHandle?: never;
  clientVerifyingShareB64u?: never;
  clientCommitments?: never;
  relayerCommitments?: never;
  relayerVerifyingShareB64u?: never;
  nearNetworkId?: never;
  signerPublicKey?: never;
  participantIds?: never;
  runtimePolicyScope?: never;
  expiresAtMs?: never;
  createdAtMs?: never;
};

export type Ed25519ClientPresignEntry =
  | Ed25519OfferedClientPresignEntry
  | Ed25519ReadyClientPresignEntry
  | Ed25519BurnedClientPresignEntry;

export type Ed25519ClientPresignPoolState =
  | {
      state: 'disabled';
      reason: 'no_threshold_session' | 'unsupported_signer' | 'worker_unavailable';
      scopeKey?: never;
      generation?: never;
      targetDepth?: never;
      lowWatermark?: never;
      entries?: never;
      refill?: never;
    }
  | {
      state: 'ready';
      scopeKey: Ed25519PresignScopeKey;
      generation: number;
      targetDepth: number;
      lowWatermark: number;
      entries: readonly Ed25519ClientPresignEntry[];
      refill: Ed25519PresignRefillState;
      reason?: never;
    };

export type Ed25519ClientPresignReservation = {
  state: 'reserved_for_finalize';
  entry: Ed25519ReadyClientPresignEntry;
  operation: Ed25519PresignOperationIdentity;
  reservedAtMs: number;
};

export type Ed25519PresignPoolRefillScheduleResult = {
  scheduled: boolean;
  reason:
    | 'scheduled'
    | 'depth_above_trigger'
    | 'depth_at_or_above_target'
    | 'in_flight_for_scope'
    | 'backoff_active'
    | 'stale_generation'
    | 'invalid_args';
  depth: number;
  targetDepth: number;
  generation: number;
};

export type Ed25519PresignReservationResult =
  | { ok: true; reservation: Ed25519ClientPresignReservation }
  | { ok: false; code: 'pool_not_ready' | 'pool_empty'; message: string };

export type Ed25519PresignScopedReservationResult =
  | {
      ok: true;
      scopeKey: Ed25519PresignScopeKey;
      reservation: Ed25519ClientPresignReservation;
    }
  | Extract<Ed25519PresignReservationResult, { ok: false }>;

export type Ed25519PresignSigningPathSelection =
  | {
      kind: 'pool_hit_one_rtt';
      operation: Ed25519PresignOperationIdentity;
      reservation: Ed25519ClientPresignReservation;
      miss?: never;
      refill?: never;
    }
  | {
      kind: 'pool_miss_two_rtt';
      operation: Ed25519PresignOperationIdentity;
      miss: Extract<Ed25519PresignReservationResult, { ok: false }>;
      refill: Ed25519PresignPoolRefillScheduleResult;
      reservation?: never;
    };

export const DEFAULT_ED25519_PRESIGN_POOL_POLICY: ThresholdEd25519PresignPoolPolicy = {
  targetDepth: 2,
  lowWatermark: 1,
  maxAcceptedRefillCount: 8,
  ttlMs: 120_000,
};

export function resolveThresholdEd25519PresignPoolPolicy(
  input: ThresholdEd25519PresignPoolPolicyConfig | undefined,
): ThresholdEd25519PresignPoolPolicy {
  const targetDepth = normalizeIntInRange(
    input?.targetDepth,
    DEFAULT_ED25519_PRESIGN_POOL_POLICY.targetDepth,
    1,
    64,
  );
  return {
    targetDepth,
    lowWatermark: normalizeIntInRange(
      input?.lowWatermark,
      DEFAULT_ED25519_PRESIGN_POOL_POLICY.lowWatermark,
      0,
      targetDepth,
    ),
    maxAcceptedRefillCount: normalizeIntInRange(
      input?.maxAcceptedRefillCount,
      DEFAULT_ED25519_PRESIGN_POOL_POLICY.maxAcceptedRefillCount,
      1,
      8,
    ),
    ttlMs: normalizeIntInRange(input?.ttlMs, DEFAULT_ED25519_PRESIGN_POOL_POLICY.ttlMs, 1, 300_000),
  };
}

const poolByScopeKey = new Map<string, Ed25519ClientPresignPoolState & { state: 'ready' }>();

function normalizeIntInRange(value: unknown, fallback: number, min: number, max: number): number {
  const n = Math.floor(Number(value));
  if (!Number.isFinite(n)) return fallback;
  if (n < min) return min;
  if (n > max) return max;
  return n;
}

function normalizeNonEmptyString<T extends string>(value: unknown, label: string): T {
  const text = String(value || '').trim();
  if (!text) throw new Error(`${label} is required`);
  return text as T;
}

function normalizeCommitments(
  value: ThresholdEd25519PresignCommitmentsWire,
): ThresholdEd25519PresignCommitmentsWire {
  return {
    hiding: normalizeNonEmptyString(value.hiding, 'commitments.hiding'),
    binding: normalizeNonEmptyString(value.binding, 'commitments.binding'),
  };
}

function scopeKeyPart(value: unknown, label: string): string {
  return `${label}=${encodeURIComponent(normalizeNonEmptyString<string>(value, label))}`;
}

function countReadyEntries(entries: readonly Ed25519ClientPresignEntry[], nowMs: number): number {
  return entries.filter((entry) => entry.state === 'ready' && entry.expiresAtMs > nowMs).length;
}

function countOfferedEntries(entries: readonly Ed25519ClientPresignEntry[]): number {
  return entries.filter((entry) => entry.state === 'offered').length;
}

function countBurnedEntries(entries: readonly Ed25519ClientPresignEntry[]): number {
  return entries.filter((entry) => entry.state === 'burned').length;
}

function pruneExpiredReadyEntries(
  entries: readonly Ed25519ClientPresignEntry[],
  nowMs: number,
): Ed25519ClientPresignEntry[] {
  return entries.map((entry): Ed25519ClientPresignEntry => {
    if (entry.state !== 'ready' || entry.expiresAtMs > nowMs) return entry;
    return {
      state: 'burned',
      presignId: entry.presignId,
      clientPresignId: entry.clientPresignId,
      reason: 'expired',
      burnedAtMs: nowMs,
    };
  });
}

function nextExpiry(entries: readonly Ed25519ClientPresignEntry[], nowMs: number): number | null {
  const expiries = entries
    .filter((entry): entry is Ed25519ReadyClientPresignEntry => entry.state === 'ready')
    .map((entry) => entry.expiresAtMs)
    .filter((expiresAtMs) => expiresAtMs > nowMs)
    .sort((a, b) => a - b);
  return expiries[0] ?? null;
}

function refillBackoffMs(code: string, failureCount: number): number {
  if (code === 'capacity_exceeded' || code === 'rate_limited') return 10_000;
  if (code === 'wrong_scope') return failureCount >= 2 ? 30_000 : 0;
  if (failureCount < 3) return 0;
  return Math.min(60_000, 5_000 * 2 ** Math.min(4, failureCount - 3));
}

function getOrCreateReadyPool(args: {
  scopeKey: Ed25519PresignScopeKey;
  policy: ThresholdEd25519PresignPoolPolicy;
}): Ed25519ClientPresignPoolState & { state: 'ready' } {
  const key = args.scopeKey;
  const existing = poolByScopeKey.get(key);
  if (existing) {
    return {
      ...existing,
      targetDepth: args.policy.targetDepth,
      lowWatermark: args.policy.lowWatermark,
    };
  }
  const created: Ed25519ClientPresignPoolState & { state: 'ready' } = {
    state: 'ready',
    scopeKey: args.scopeKey,
    generation: 1,
    targetDepth: args.policy.targetDepth,
    lowWatermark: args.policy.lowWatermark,
    entries: [],
    refill: { state: 'idle' },
  };
  poolByScopeKey.set(key, created);
  return created;
}

function saveReadyPool(pool: Ed25519ClientPresignPoolState & { state: 'ready' }): void {
  poolByScopeKey.set(pool.scopeKey, pool);
}

export function createThresholdEd25519PresignScopeKey(input: {
  thresholdSessionId: string;
  walletSigningSessionId: string;
  relayerKeyId: string;
  nearAccountId: string;
  nearNetworkId: string;
  signerPublicKey: string;
  participantIds: readonly number[];
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  clientVerifyingShareB64u: string;
}): Ed25519PresignScopeKey {
  const participantIds = normalizeThresholdEd25519ParticipantIds([...input.participantIds]);
  if (!participantIds || participantIds.length < 2) {
    throw new Error('participantIds must contain at least two signer ids');
  }
  const runtimePolicyScope = normalizeRuntimePolicyScope(input.runtimePolicyScope);
  if (!runtimePolicyScope) throw new Error('runtimePolicyScope is required');
  return [
    scopeKeyPart(input.thresholdSessionId, 'thresholdSessionId'),
    scopeKeyPart(input.walletSigningSessionId, 'walletSigningSessionId'),
    scopeKeyPart(input.relayerKeyId, 'relayerKeyId'),
    scopeKeyPart(input.nearAccountId, 'nearAccountId'),
    scopeKeyPart(input.nearNetworkId, 'nearNetworkId'),
    scopeKeyPart(input.signerPublicKey, 'signerPublicKey'),
    `participantIds=${participantIds.join(',')}`,
    scopeKeyPart(runtimePolicyScope.orgId, 'orgId'),
    scopeKeyPart(runtimePolicyScope.projectId, 'projectId'),
    scopeKeyPart(runtimePolicyScope.envId, 'envId'),
    scopeKeyPart(runtimePolicyScope.signingRootVersion, 'signingRootVersion'),
    scopeKeyPart(input.clientVerifyingShareB64u, 'clientVerifyingShareB64u'),
  ].join('|') as Ed25519PresignScopeKey;
}

export function clearAllThresholdEd25519ClientPresigns(): void {
  poolByScopeKey.clear();
}

export function clearThresholdEd25519ClientPresignPool(
  payload: ClearThresholdEd25519PresignPoolPayload,
): ClearThresholdEd25519PresignPoolResult {
  const scopeKey = normalizeNonEmptyString<Ed25519PresignScopeKey>(payload.scopeKey, 'scopeKey');
  const existing = poolByScopeKey.get(scopeKey);
  const previousGeneration = existing?.generation ?? Math.max(0, Number(payload.generation) || 0);
  const nextGeneration = previousGeneration + 1;
  const clearedEntries = existing?.entries.length ?? 0;
  poolByScopeKey.set(scopeKey, {
    state: 'ready',
    scopeKey,
    generation: nextGeneration,
    targetDepth: existing?.targetDepth ?? DEFAULT_ED25519_PRESIGN_POOL_POLICY.targetDepth,
    lowWatermark: existing?.lowWatermark ?? DEFAULT_ED25519_PRESIGN_POOL_POLICY.lowWatermark,
    entries: [],
    refill: { state: 'idle' },
  });
  return {
    ok: true,
    kind: 'clear_threshold_ed25519_presign_pool_result_v1',
    scopeKey,
    previousGeneration,
    nextGeneration,
    clearedEntries,
  };
}

export function getThresholdEd25519ClientPresignPoolStatus(
  payload: GetThresholdEd25519PresignPoolStatusPayload,
  nowMs = Date.now(),
): GetThresholdEd25519PresignPoolStatusResult {
  const scopeKey = normalizeNonEmptyString<Ed25519PresignScopeKey>(payload.scopeKey, 'scopeKey');
  const pool = poolByScopeKey.get(scopeKey);
  if (!pool) {
    return {
      kind: 'get_threshold_ed25519_presign_pool_status_result_v1',
      scopeKey,
      generation: 0,
      offeredCount: 0,
      readyCount: 0,
      burnedCount: 0,
      refillInFlight: false,
      nextExpiryAtMs: null,
    };
  }
  const entries = pruneExpiredReadyEntries(pool.entries, nowMs);
  if (entries !== pool.entries) saveReadyPool({ ...pool, entries });
  return {
    kind: 'get_threshold_ed25519_presign_pool_status_result_v1',
    scopeKey,
    generation: pool.generation,
    offeredCount: countOfferedEntries(entries),
    readyCount: countReadyEntries(entries, nowMs),
    burnedCount: countBurnedEntries(entries),
    refillInFlight: pool.refill.state === 'in_flight',
    nextExpiryAtMs: nextExpiry(entries, nowMs),
  };
}

export function scheduleThresholdEd25519ClientPresignPoolRefill(
  payload: PrepareThresholdEd25519PresignPoolPayload,
  nowMs = Date.now(),
): Ed25519PresignPoolRefillScheduleResult {
  try {
    const policy = resolveThresholdEd25519PresignPoolPolicy(payload.policy);
    const scopeKey = normalizeNonEmptyString<Ed25519PresignScopeKey>(
      createThresholdEd25519PresignScopeKey({
        thresholdSessionId: payload.thresholdSessionId,
        walletSigningSessionId: payload.walletSigningSessionId,
        relayerKeyId: payload.relayerKeyId,
        nearAccountId: payload.nearAccountId,
        nearNetworkId: payload.nearNetworkId,
        signerPublicKey: payload.signerPublicKey,
        participantIds: payload.participantIds,
        runtimePolicyScope: payload.runtimePolicyScope,
        clientVerifyingShareB64u: payload.clientPresigns[0]?.clientVerifyingShareB64u,
      }),
      'scopeKey',
    );
    const pool = getOrCreateReadyPool({ scopeKey, policy });
    const entries = pruneExpiredReadyEntries(pool.entries, nowMs);
    const depth = countReadyEntries(entries, nowMs);
    if (payload.generation !== pool.generation) {
      return {
        scheduled: false,
        reason: 'stale_generation',
        depth,
        targetDepth: policy.targetDepth,
        generation: pool.generation,
      };
    }
    if (pool.refill.state === 'in_flight') {
      return {
        scheduled: false,
        reason: 'in_flight_for_scope',
        depth,
        targetDepth: policy.targetDepth,
        generation: pool.generation,
      };
    }
    if (pool.refill.state === 'failed' && pool.refill.backoffUntilMs > nowMs) {
      return {
        scheduled: false,
        reason: 'backoff_active',
        depth,
        targetDepth: policy.targetDepth,
        generation: pool.generation,
      };
    }
    if (depth > policy.lowWatermark) {
      return {
        scheduled: false,
        reason: 'depth_above_trigger',
        depth,
        targetDepth: policy.targetDepth,
        generation: pool.generation,
      };
    }
    if (depth >= policy.targetDepth) {
      return {
        scheduled: false,
        reason: 'depth_at_or_above_target',
        depth,
        targetDepth: policy.targetDepth,
        generation: pool.generation,
      };
    }
    const acceptedOfferCount = Math.max(0, policy.targetDepth - depth);
    const offered = payload.clientPresigns
      .slice(0, Math.min(policy.maxAcceptedRefillCount, acceptedOfferCount))
      .map((offer) => offeredEntryFromWorkerOffer(offer, nowMs));
    saveReadyPool({
      ...pool,
      entries: [...entries, ...offered],
      refill: {
        state: 'in_flight',
        startedAtMs: nowMs,
        requestTag: payload.requestTag,
        previousFailureCount: pool.refill.state === 'failed' ? pool.refill.failureCount : 0,
      },
    });
    return {
      scheduled: true,
      reason: 'scheduled',
      depth,
      targetDepth: policy.targetDepth,
      generation: pool.generation,
    };
  } catch {
    return {
      scheduled: false,
      reason: 'invalid_args',
      depth: 0,
      targetDepth: 0,
      generation: 0,
    };
  }
}

function offeredEntryFromWorkerOffer(
  offer: ThresholdEd25519ClientPresignWorkerOffer,
  nowMs: number,
): Ed25519OfferedClientPresignEntry {
  return {
    state: 'offered',
    clientPresignId: normalizeNonEmptyString<Ed25519ClientPresignId>(
      offer.clientPresignId,
      'clientPresignId',
    ),
    nonceHandle: normalizeNonEmptyString<Ed25519ClientPresignNonceHandle>(
      offer.nonceHandle,
      'nonceHandle',
    ),
    clientVerifyingShareB64u: normalizeNonEmptyString(
      offer.clientVerifyingShareB64u,
      'clientVerifyingShareB64u',
    ),
    clientCommitments: normalizeCommitments(offer.clientCommitments),
    createdAtMs: nowMs,
  };
}

export function applyThresholdEd25519PresignRefillResult(input: {
  payload: PrepareThresholdEd25519PresignPoolPayload;
  result: PrepareThresholdEd25519PresignPoolResult;
  nowMs?: number;
}): PrepareThresholdEd25519PresignPoolResult {
  const nowMs = input.nowMs ?? Date.now();
  const scopeKey = createThresholdEd25519PresignScopeKey({
    thresholdSessionId: input.payload.thresholdSessionId,
    walletSigningSessionId: input.payload.walletSigningSessionId,
    relayerKeyId: input.payload.relayerKeyId,
    nearAccountId: input.payload.nearAccountId,
    nearNetworkId: input.payload.nearNetworkId,
    signerPublicKey: input.payload.signerPublicKey,
    participantIds: input.payload.participantIds,
    runtimePolicyScope: input.payload.runtimePolicyScope,
    clientVerifyingShareB64u: input.payload.clientPresigns[0]?.clientVerifyingShareB64u,
  });
  const pool = poolByScopeKey.get(scopeKey);
  if (!pool || input.payload.generation !== pool.generation) {
    return input.result;
  }
  if (!input.result.ok) {
    const failureCount = pool.refill.state === 'in_flight' ? pool.refill.previousFailureCount + 1 : 1;
    const backoffUntilMs = nowMs + refillBackoffMs(input.result.code, failureCount);
    saveReadyPool({
      ...pool,
      entries: pool.entries.map((entry): Ed25519ClientPresignEntry => {
        if (entry.state !== 'offered') return entry;
        return {
          state: 'burned',
          clientPresignId: entry.clientPresignId,
          presignId: normalizeNonEmptyString<Ed25519ServerPresignId>(
            `rejected:${entry.clientPresignId}`,
            'presignId',
          ),
          reason: 'rejected',
          burnedAtMs: nowMs,
        };
      }),
      refill: {
        state: 'failed',
        failedAtMs: nowMs,
        failureCount,
        backoffUntilMs,
        code: input.result.code,
        message: input.result.message,
      },
    });
    return input.result;
  }
  const acceptedByClientId = new Map<string, ThresholdEd25519PresignPoolAcceptedPair>();
  for (const accepted of input.result.accepted) {
    acceptedByClientId.set(accepted.clientPresignId, accepted);
  }
  const rejected = new Set(input.result.rejectedClientPresignIds);
  const nextEntries = pool.entries.map((entry): Ed25519ClientPresignEntry => {
    if (entry.state !== 'offered') return entry;
    const accepted = acceptedByClientId.get(entry.clientPresignId);
    if (accepted) {
      return {
        state: 'ready',
        presignId: normalizeNonEmptyString<Ed25519ServerPresignId>(
          accepted.presignId,
          'presignId',
        ),
        clientPresignId: entry.clientPresignId,
        nonceHandle: entry.nonceHandle,
        clientVerifyingShareB64u: entry.clientVerifyingShareB64u,
        clientCommitments: entry.clientCommitments,
        relayerCommitments: normalizeCommitments(accepted.relayerCommitments),
        relayerVerifyingShareB64u: normalizeNonEmptyString(
          accepted.relayerVerifyingShareB64u,
          'relayerVerifyingShareB64u',
        ),
        nearNetworkId: input.payload.nearNetworkId,
        signerPublicKey: input.payload.signerPublicKey,
        participantIds: [...input.payload.participantIds],
        runtimePolicyScope: input.payload.runtimePolicyScope,
        expiresAtMs: accepted.expiresAtMs,
      };
    }
    if (rejected.has(entry.clientPresignId)) {
      return {
        state: 'burned',
        clientPresignId: entry.clientPresignId,
        presignId: normalizeNonEmptyString<Ed25519ServerPresignId>(
          `rejected:${entry.clientPresignId}`,
          'presignId',
        ),
        reason: 'rejected',
        burnedAtMs: nowMs,
      };
    }
    return {
      state: 'burned',
      clientPresignId: entry.clientPresignId,
      presignId: normalizeNonEmptyString<Ed25519ServerPresignId>(
        `stale:${entry.clientPresignId}`,
        'presignId',
      ),
      reason: 'stale_generation',
      burnedAtMs: nowMs,
    };
  });
  saveReadyPool({
    ...pool,
    entries: nextEntries,
    refill: { state: 'idle' },
  });
  return input.result;
}

export function reserveThresholdEd25519ReadyPresign(input: {
  scopeKey: Ed25519PresignScopeKey;
  operation: Ed25519PresignOperationIdentity;
  nowMs?: number;
}): Ed25519PresignReservationResult {
  const nowMs = input.nowMs ?? Date.now();
  const pool = poolByScopeKey.get(input.scopeKey);
  if (!pool) {
    return { ok: false, code: 'pool_not_ready', message: 'threshold-ed25519 pool is not ready' };
  }
  const entries = pruneExpiredReadyEntries(pool.entries, nowMs);
  const readyIndex = entries.findIndex(
    (entry) => entry.state === 'ready' && entry.expiresAtMs > nowMs,
  );
  if (readyIndex < 0) {
    saveReadyPool({ ...pool, entries });
    return { ok: false, code: 'pool_empty', message: 'threshold-ed25519 pool is empty' };
  }
  const entry = entries[readyIndex] as Ed25519ReadyClientPresignEntry;
  const nextEntries = entries.filter((_entry, index) => index !== readyIndex);
  saveReadyPool({ ...pool, entries: nextEntries });
  return {
    ok: true,
    reservation: {
      state: 'reserved_for_finalize',
      entry,
      operation: input.operation,
      reservedAtMs: nowMs,
    },
  };
}

export function reserveThresholdEd25519ReadyPresignForScope(input: {
  thresholdSessionId: string;
  walletSigningSessionId: string;
  relayerKeyId: string;
  nearAccountId: string;
  nearNetworkId: string;
  signerPublicKey: string;
  participantIds: readonly number[];
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  operation: Ed25519PresignOperationIdentity;
  nowMs?: number;
}): Ed25519PresignScopedReservationResult {
  const participantIds = normalizeThresholdEd25519ParticipantIds([...input.participantIds]);
  if (!participantIds || participantIds.length < 2) {
    return {
      ok: false,
      code: 'pool_not_ready',
      message: 'threshold-ed25519 pool scope has invalid participant ids',
    };
  }
  let runtimePolicyScope: ThresholdRuntimePolicyScope;
  try {
    runtimePolicyScope = normalizeRuntimePolicyScope(input.runtimePolicyScope);
  } catch {
    return {
      ok: false,
      code: 'pool_not_ready',
      message: 'threshold-ed25519 pool scope has invalid runtime policy',
    };
  }
  const prefix = [
    scopeKeyPart(input.thresholdSessionId, 'thresholdSessionId'),
    scopeKeyPart(input.walletSigningSessionId, 'walletSigningSessionId'),
    scopeKeyPart(input.relayerKeyId, 'relayerKeyId'),
    scopeKeyPart(input.nearAccountId, 'nearAccountId'),
    scopeKeyPart(input.nearNetworkId, 'nearNetworkId'),
    scopeKeyPart(input.signerPublicKey, 'signerPublicKey'),
    `participantIds=${participantIds.join(',')}`,
    scopeKeyPart(runtimePolicyScope.orgId, 'orgId'),
    scopeKeyPart(runtimePolicyScope.projectId, 'projectId'),
    scopeKeyPart(runtimePolicyScope.envId, 'envId'),
    scopeKeyPart(runtimePolicyScope.signingRootVersion, 'signingRootVersion'),
  ].join('|');

  for (const pool of poolByScopeKey.values()) {
    if (!String(pool.scopeKey).startsWith(`${prefix}|clientVerifyingShareB64u=`)) continue;
    const reserved = reserveThresholdEd25519ReadyPresign({
      scopeKey: pool.scopeKey,
      operation: input.operation,
      nowMs: input.nowMs,
    });
    if (reserved.ok) {
      return {
        ok: true,
        scopeKey: pool.scopeKey,
        reservation: reserved.reservation,
      };
    }
  }
  return { ok: false, code: 'pool_empty', message: 'threshold-ed25519 pool is empty' };
}

export function selectThresholdEd25519PresignSigningPath(input: {
  scopeKey: Ed25519PresignScopeKey;
  operation: Ed25519PresignOperationIdentity;
  refillPayload: PrepareThresholdEd25519PresignPoolPayload;
  nowMs?: number;
}): Ed25519PresignSigningPathSelection {
  const nowMs = input.nowMs ?? Date.now();
  const reservation = reserveThresholdEd25519ReadyPresign({
    scopeKey: input.scopeKey,
    operation: input.operation,
    nowMs,
  });
  if (reservation.ok) {
    return {
      kind: 'pool_hit_one_rtt',
      operation: input.operation,
      reservation: reservation.reservation,
    };
  }
  return {
    kind: 'pool_miss_two_rtt',
    operation: input.operation,
    miss: reservation,
    refill: scheduleThresholdEd25519ClientPresignPoolRefill(input.refillPayload, nowMs),
  };
}

export function burnThresholdEd25519ReservedPresign(input: {
  scopeKey: Ed25519PresignScopeKey;
  reservation: Ed25519ClientPresignReservation;
  reason: Ed25519BurnedClientPresignEntry['reason'];
  nowMs?: number;
}): void {
  const nowMs = input.nowMs ?? Date.now();
  const pool = poolByScopeKey.get(input.scopeKey);
  if (!pool) return;
  saveReadyPool({
    ...pool,
    entries: [
      ...pool.entries,
      {
        state: 'burned',
        presignId: input.reservation.entry.presignId,
        clientPresignId: input.reservation.entry.clientPresignId,
        reason: input.reason,
        burnedAtMs: nowMs,
      },
    ],
  });
}

export type PrepareThresholdEd25519PresignPoolWorkerContract = {
  payload: PrepareThresholdEd25519PresignPoolPayload;
  result: PrepareThresholdEd25519PresignPoolResult;
};

export type GetThresholdEd25519PresignPoolStatusWorkerContract = {
  payload: GetThresholdEd25519PresignPoolStatusPayload;
  result: GetThresholdEd25519PresignPoolStatusResult;
};

export type ClearThresholdEd25519PresignPoolWorkerContract = {
  payload: ClearThresholdEd25519PresignPoolPayload;
  result: ClearThresholdEd25519PresignPoolResult;
};
