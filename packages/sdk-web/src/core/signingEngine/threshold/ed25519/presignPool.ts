import type {
  ClearRouterAbEd25519PresignPoolPayload,
  ClearRouterAbEd25519PresignPoolResult,
  GetRouterAbEd25519PresignPoolStatusPayload,
  GetRouterAbEd25519PresignPoolStatusResult,
  ThresholdEd25519ClientPresignWorkerOffer,
  ThresholdEd25519PresignCommitmentsWire,
  RouterAbEd25519PresignPoolPolicy,
  RouterAbEd25519PresignPoolPolicyConfig,
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
  kind: 'router_ab_ed25519_presign_operation_identity_v1';
  operationId: SigningOperationId;
  operationFingerprint: SigningOperationFingerprint;
  purpose: 'near_transaction' | 'nep413_message' | 'delegate_action';
};

export type RouterAbEd25519PresignPoolRefillPayload = {
  kind: 'router_ab_ed25519_presign_pool_refill_v1';
  relayUrl: string;
  thresholdSessionId: string;
  walletSigningSessionId: string;
  relayerKeyId: string;
  nearAccountId: string;
  nearNetworkId: string;
  signerPublicKey: string;
  participantIds: readonly number[];
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  policy: RouterAbEd25519PresignPoolPolicy;
  requestTag: 'background_presign_pool_refill' | 'foreground_presign_pool_refill';
  generation: number;
  clientPresigns: readonly ThresholdEd25519ClientPresignWorkerOffer[];
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

export type RouterAbEd25519ReadyPoolEntryMetadata = {
  kind: 'router_ab_ed25519_presign_pool_entry_v2';
  scope: {
    request_id: string;
    account_id: string;
    session_id: string;
    signing_worker_id: string;
  };
  generation: number;
  poolEntryBindingDigest: { bytes: readonly number[] };
};

type Ed25519ReadyClientPresignEntryBase = {
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

export type Ed25519ReadyClientPresignEntry = Ed25519ReadyClientPresignEntryBase & {
  source: 'router_ab_ed25519_presign_pool_v2';
  routerAbPoolEntry: RouterAbEd25519ReadyPoolEntryMetadata;
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

export type RouterAbEd25519ReadyClientPresignEntry = Ed25519ReadyClientPresignEntry;

export type RouterAbEd25519ClientPresignReservation = Omit<
  Ed25519ClientPresignReservation,
  'entry'
> & {
  entry: RouterAbEd25519ReadyClientPresignEntry;
};

export type RouterAbEd25519PresignScopedReservationResult =
  | {
      ok: true;
      scopeKey: Ed25519PresignScopeKey;
      reservation: RouterAbEd25519ClientPresignReservation;
    }
  | Extract<Ed25519PresignReservationResult, { ok: false }>;

export type RouterAbEd25519PresignPoolAcceptedEntry = {
  clientPresignId: string;
  generation: number;
  poolEntryBindingDigest: { bytes: readonly number[] };
  signingWorkerId: string;
  serverRound1Handle: string;
  serverCommitments: ThresholdEd25519PresignCommitmentsWire;
  serverVerifyingShareB64u: string;
  expiresAtMs: number;
};

export type RouterAbEd25519PresignPoolRefillResult =
  | {
      ok: true;
      generation: number;
      scope: RouterAbEd25519ReadyPoolEntryMetadata['scope'];
      accepted: readonly RouterAbEd25519PresignPoolAcceptedEntry[];
      rejectedClientPresignIds: readonly string[];
    }
  | {
      ok: false;
      generation: number;
      code: string;
      message: string;
      scope?: never;
      accepted?: never;
      rejectedClientPresignIds?: never;
    };

export const DEFAULT_ED25519_PRESIGN_POOL_POLICY: RouterAbEd25519PresignPoolPolicy = {
  targetDepth: 2,
  lowWatermark: 1,
  maxAcceptedRefillCount: 8,
  ttlMs: 120_000,
};

export function resolveRouterAbEd25519PresignPoolPolicy(
  input: RouterAbEd25519PresignPoolPolicyConfig | undefined,
): RouterAbEd25519PresignPoolPolicy {
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

function normalizeDigest32(
  value: { bytes: readonly number[] },
  label: string,
): { bytes: readonly number[] } {
  const bytes = Array.isArray(value.bytes) ? value.bytes.map((entry) => Number(entry)) : [];
  if (bytes.length !== 32 || !bytes.every((entry) => Number.isInteger(entry) && entry >= 0 && entry <= 255)) {
    throw new Error(`${label}.bytes must contain 32 bytes`);
  }
  return { bytes };
}

function normalizeRouterAbScope(
  value: RouterAbEd25519ReadyPoolEntryMetadata['scope'],
): RouterAbEd25519ReadyPoolEntryMetadata['scope'] {
  return {
    request_id: normalizeNonEmptyString(value.request_id, 'routerAb.scope.request_id'),
    account_id: normalizeNonEmptyString(value.account_id, 'routerAb.scope.account_id'),
    session_id: normalizeNonEmptyString(value.session_id, 'routerAb.scope.session_id'),
    signing_worker_id: normalizeNonEmptyString(
      value.signing_worker_id,
      'routerAb.scope.signing_worker_id',
    ),
  };
}

function scopeKeyPart(value: unknown, label: string): string {
  return `${label}=${encodeURIComponent(normalizeNonEmptyString<string>(value, label))}`;
}

function countReadyEntries(entries: readonly Ed25519ClientPresignEntry[], nowMs: number): number {
  return entries.filter((entry) => entry.state === 'ready' && entry.expiresAtMs > nowMs).length;
}

function countRouterAbReadyEntries(
  entries: readonly Ed25519ClientPresignEntry[],
  nowMs: number,
): number {
  return entries.filter(
    (entry) =>
      entry.state === 'ready' &&
      entry.source === 'router_ab_ed25519_presign_pool_v2' &&
      entry.expiresAtMs > nowMs,
  ).length;
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
  policy: RouterAbEd25519PresignPoolPolicy;
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

export function createRouterAbEd25519PresignScopeKey(input: {
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

export function clearAllRouterAbEd25519ClientPresigns(): void {
  poolByScopeKey.clear();
}

export function clearRouterAbEd25519ClientPresignPool(
  payload: ClearRouterAbEd25519PresignPoolPayload,
): ClearRouterAbEd25519PresignPoolResult {
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
    kind: 'clear_router_ab_ed25519_presign_pool_result_v1',
    scopeKey,
    previousGeneration,
    nextGeneration,
    clearedEntries,
  };
}

export function getRouterAbEd25519ClientPresignPoolStatus(
  payload: GetRouterAbEd25519PresignPoolStatusPayload,
  nowMs = Date.now(),
): GetRouterAbEd25519PresignPoolStatusResult {
  const scopeKey = normalizeNonEmptyString<Ed25519PresignScopeKey>(payload.scopeKey, 'scopeKey');
  const pool = poolByScopeKey.get(scopeKey);
  if (!pool) {
    return {
      kind: 'get_router_ab_ed25519_presign_pool_status_result_v1',
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
    kind: 'get_router_ab_ed25519_presign_pool_status_result_v1',
    scopeKey,
    generation: pool.generation,
    offeredCount: countOfferedEntries(entries),
    readyCount: countReadyEntries(entries, nowMs),
    burnedCount: countBurnedEntries(entries),
    refillInFlight: pool.refill.state === 'in_flight',
    nextExpiryAtMs: nextExpiry(entries, nowMs),
  };
}

export function scheduleRouterAbEd25519ClientPresignPoolRefill(
  payload: RouterAbEd25519PresignPoolRefillPayload,
  nowMs = Date.now(),
): Ed25519PresignPoolRefillScheduleResult {
  try {
    const policy = resolveRouterAbEd25519PresignPoolPolicy(payload.policy);
    const scopeKey = normalizeNonEmptyString<Ed25519PresignScopeKey>(
      createRouterAbEd25519PresignScopeKey({
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
    const depth = countRouterAbReadyEntries(entries, nowMs);
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

export function applyRouterAbEd25519PresignPoolRefillResult(input: {
  payload: RouterAbEd25519PresignPoolRefillPayload;
  result: RouterAbEd25519PresignPoolRefillResult;
  nowMs?: number;
}): RouterAbEd25519PresignPoolRefillResult {
  const nowMs = input.nowMs ?? Date.now();
  const scopeKey = createRouterAbEd25519PresignScopeKey({
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

  const scope = normalizeRouterAbScope(input.result.scope);
  const acceptedByClientId = new Map<string, RouterAbEd25519PresignPoolAcceptedEntry>();
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
        source: 'router_ab_ed25519_presign_pool_v2',
        presignId: normalizeNonEmptyString<Ed25519ServerPresignId>(
          accepted.serverRound1Handle,
          'serverRound1Handle',
        ),
        clientPresignId: entry.clientPresignId,
        nonceHandle: entry.nonceHandle,
        clientVerifyingShareB64u: entry.clientVerifyingShareB64u,
        clientCommitments: entry.clientCommitments,
        relayerCommitments: normalizeCommitments(accepted.serverCommitments),
        relayerVerifyingShareB64u: normalizeNonEmptyString(
          accepted.serverVerifyingShareB64u,
          'serverVerifyingShareB64u',
        ),
        nearNetworkId: input.payload.nearNetworkId,
        signerPublicKey: input.payload.signerPublicKey,
        participantIds: [...input.payload.participantIds],
        runtimePolicyScope: input.payload.runtimePolicyScope,
        expiresAtMs: accepted.expiresAtMs,
        routerAbPoolEntry: {
          kind: 'router_ab_ed25519_presign_pool_entry_v2',
          scope,
          generation: accepted.generation,
          poolEntryBindingDigest: normalizeDigest32(
            accepted.poolEntryBindingDigest,
            'poolEntryBindingDigest',
          ),
        },
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

export function reserveRouterAbEd25519ReadyPresignForScope(input: {
  thresholdSessionId: string;
  walletSigningSessionId: string;
  relayerKeyId: string;
  nearAccountId: string;
  nearNetworkId: string;
  signerPublicKey: string;
  participantIds: readonly number[];
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  clientVerifyingShareB64u: string;
  operation: Ed25519PresignOperationIdentity;
  nowMs?: number;
}): RouterAbEd25519PresignScopedReservationResult {
  const nowMs = input.nowMs ?? Date.now();
  const participantIds = normalizeThresholdEd25519ParticipantIds([...input.participantIds]);
  if (!participantIds || participantIds.length < 2) {
    return {
      ok: false,
      code: 'pool_not_ready',
      message: 'Router A/B Ed25519 pool scope has invalid participant ids',
    };
  }
  let runtimePolicyScope: ThresholdRuntimePolicyScope;
  try {
    runtimePolicyScope = normalizeRuntimePolicyScope(input.runtimePolicyScope);
  } catch {
    return {
      ok: false,
      code: 'pool_not_ready',
      message: 'Router A/B Ed25519 pool scope has invalid runtime policy',
    };
  }
  let scopeKey: Ed25519PresignScopeKey;
  try {
    scopeKey = createRouterAbEd25519PresignScopeKey({
      thresholdSessionId: input.thresholdSessionId,
      walletSigningSessionId: input.walletSigningSessionId,
      relayerKeyId: input.relayerKeyId,
      nearAccountId: input.nearAccountId,
      nearNetworkId: input.nearNetworkId,
      signerPublicKey: input.signerPublicKey,
      participantIds,
      runtimePolicyScope,
      clientVerifyingShareB64u: input.clientVerifyingShareB64u,
    });
  } catch {
    return {
      ok: false,
      code: 'pool_not_ready',
      message: 'Router A/B Ed25519 pool scope has invalid client verifying share',
    };
  }

  const pool = poolByScopeKey.get(scopeKey);
  if (!pool) return { ok: false, code: 'pool_empty', message: 'Router A/B Ed25519 pool is empty' };
  const entries = pruneExpiredReadyEntries(pool.entries, nowMs);
  const readyIndex = entries.findIndex(
    (entry) =>
      entry.state === 'ready' &&
      entry.source === 'router_ab_ed25519_presign_pool_v2' &&
      entry.expiresAtMs > nowMs,
  );
  if (readyIndex < 0) {
    if (entries !== pool.entries) saveReadyPool({ ...pool, entries });
    return { ok: false, code: 'pool_empty', message: 'Router A/B Ed25519 pool is empty' };
  }
  const entry = entries[readyIndex] as RouterAbEd25519ReadyClientPresignEntry;
  const nextEntries = entries.filter((_entry, index) => index !== readyIndex);
  saveReadyPool({ ...pool, entries: nextEntries });
  return {
    ok: true,
    scopeKey,
    reservation: {
      state: 'reserved_for_finalize',
      entry,
      operation: input.operation,
      reservedAtMs: nowMs,
    },
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
