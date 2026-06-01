import type { NonceLaneStatus } from '@/core/rpcClients/evm/nonceBackend';
import type { NearClient } from '@/core/rpcClients/near/NearClient';
import type { TransactionContext } from '@/core/types/rpc';
import type { AccessKeyView, BlockResult } from '@near-js/types';
import { errorMessage } from '@shared/utils/errors';
import { isObject, isString } from '@shared/utils/validation';
import type {
  SigningOperationFingerprint,
  SigningOperationId,
} from '../session/operationState/types';
export type { NonceLeaseRef } from '../interfaces/nonceLease';
export {
  EvmNonceOutcomeReason,
  NearNonceOutcomeKind,
  NearNonceReconcileReason,
  NonceCoordinatorDegradationReason,
  NonceCoordinatorFallback,
  NonceCoordinatorTraceEventName,
  NonceDurableLeaseState,
  NonceLeaseReleaseReason,
  NonceLeaseState,
} from './nonceTypes';
export type {
  EvmNonceLane,
  NearNonceLane,
  NonceCoordinator,
  NonceCoordinatorAlert,
  NonceCoordinatorAggregateMetrics,
  NonceCoordinatorDegradation,
  NonceCoordinatorDeps,
  NonceCoordinatorDiagnostics,
  NonceCoordinatorDiagnosticsOptions,
  NonceCoordinatorOutcomeMetrics,
  NonceCoordinatorSameOriginLockPort,
  NonceCoordinatorTraceEvent,
  NonceLane,
  NonceLaneCoordinationRecord,
  NonceLaneCoordinationStore,
  NonceLease,
  NonceOperationContext,
} from './nonceTypes';
import {
  EvmNonceOutcomeReason,
  NonceCoordinatorDegradationReason,
  NonceCoordinatorFallback,
  NonceCoordinatorTraceEventName,
  NonceDurableLeaseState,
  NonceLeaseState,
  type EvmNonceLane,
  type NearNonceLane,
  type NonceCoordinator,
  type NonceCoordinatorAggregateMetrics,
  type NonceCoordinatorAlert,
  type NonceCoordinatorDegradation,
  type NonceCoordinatorDeps,
  type NonceCoordinatorDiagnostics,
  type NonceCoordinatorDiagnosticsOptions,
  type NonceCoordinatorSameOriginLockPort,
  type NonceCoordinatorTraceEvent,
  type NonceLane,
  type NonceLaneCoordinationRecord,
  type NonceLease,
  type NonceOperationContext,
} from './nonceTypes';
import {
  isActiveCoordinationLeaseRecord,
  isActiveEvmLeaseState,
  isActiveNearLeaseState,
  isInFlightNonceLeaseState,
  reduceNonceLeaseState,
  type NonceLeaseTransition,
} from './nonceLeaseState';
export { reduceNonceLeaseState } from './nonceLeaseState';
import {
  assertEvmLease,
  assertOperationMatches,
  createNonceBatchId,
  createNonceLeaseId,
  createRuntimeId,
  evmLaneToReserveNonceInput,
  evmManagedReservationToLane,
  evmNonceLeaseToManagedReservation,
  evmReserveNonceInputToLane,
  legacyNonceLaneKeys,
  nonceLaneFromCoordinationRecord,
  nonceLaneKey,
  nonceLaneNetworkKey,
  nonceLaneSubjectId,
  nonceLeaseToRef,
} from './nonceLaneKeys';
export {
  evmManagedReservationToLane,
  evmNonceLeaseToManagedReservation,
  evmReserveNonceInputToLane,
  nonceLeaseToRef,
} from './nonceLaneKeys';
import {
  createEvmNonceLaneBlockedError,
  createEvmNonceLaneState,
  readBlockedEvmInFlight,
  type EvmInFlightNonceRecord,
  type EvmNonceLaneState,
} from './evmNonceLane';
import {
  computeLastReservedNonce,
  createNearNonceLaneState,
  isMissingNearAccessKeyError,
  pruneReservedNearNonces,
} from './nearNonceLane';
import {
  appendOutcomeMetricEvent,
  createEmptyLeaseStateCounts,
  readOutcomeMetrics,
  type NonceOutcomeMetricEvent,
} from './nonceDiagnostics';
import {
  maxBigint,
  minBigint,
  normalizeBigint,
  normalizePositiveInteger,
  normalizeRequiredString,
} from './nonceUtils';

const DEFAULT_NONCE_LEASE_TTL_MS = 120_000;
const DEFAULT_SIGNED_NONCE_LEASE_TTL_MS = 30_000;
const DEFAULT_EVM_REFRESH_TTL_MS = 5_000;
const DEFAULT_EVM_STALE_INFLIGHT_THRESHOLD_MS = 45_000;
const DEFAULT_DROPPED_REPLACED_ALERT_THRESHOLD = 3;
const DEFAULT_DROPPED_REPLACED_ALERT_WINDOW_MS = 5 * 60_000;
const DEFAULT_DURABLE_LOCK_TTL_MS = 5_000;
const DEFAULT_DURABLE_LOCK_WAIT_TIMEOUT_MS = 3_000;
const NEAR_NONCE_FRESHNESS_THRESHOLD_MS = 5_000;
const NEAR_BLOCK_FRESHNESS_THRESHOLD_MS = 20_000;
const NEAR_PREFETCH_DEBOUNCE_MS = 400;

type DroppedReplacedAlertWindow = {
  count: number;
  firstSeenAtMs: number;
  lastSeenAtMs: number;
};

export function createNonceCoordinator(deps: NonceCoordinatorDeps): NonceCoordinator {
  const leases = new Map<string, NonceLease>();
  const evmStates = new Map<string, EvmNonceLaneState>();
  const evmAccountLaneKeys = new Map<string, Set<string>>();
  const droppedReplacedAlerts = new Map<string, DroppedReplacedAlertWindow>();
  const outcomeMetricEvents: NonceOutcomeMetricEvent[] = [];
  const laneLocks = new Map<string, Promise<void>>();
  const now = deps.now || Date.now;
  const leaseTtlMs = normalizePositiveInteger(deps.leaseTtlMs, DEFAULT_NONCE_LEASE_TTL_MS);
  const signedLeaseTtlMs = normalizePositiveInteger(
    deps.signedLeaseTtlMs,
    DEFAULT_SIGNED_NONCE_LEASE_TTL_MS,
  );
  const evmRefreshTtlMs = normalizePositiveInteger(
    deps.evmRefreshTtlMs,
    DEFAULT_EVM_REFRESH_TTL_MS,
  );
  const evmStaleInFlightThresholdMs = normalizePositiveInteger(
    deps.evmStaleInFlightThresholdMs,
    DEFAULT_EVM_STALE_INFLIGHT_THRESHOLD_MS,
  );
  const droppedReplacedAlertThreshold = normalizePositiveInteger(
    deps.droppedReplacedAlertThreshold,
    DEFAULT_DROPPED_REPLACED_ALERT_THRESHOLD,
  );
  const droppedReplacedAlertWindowMs = normalizePositiveInteger(
    deps.droppedReplacedAlertWindowMs,
    DEFAULT_DROPPED_REPLACED_ALERT_WINDOW_MS,
  );
  const sameOriginLock =
    deps.sameOriginLock === undefined ? createDefaultSameOriginLock() : deps.sameOriginLock;
  const nonceLaneCoordinationStore = deps.nonceLaneCoordinationStore ?? null;
  const shouldWarnOnMissingCoordinationStore = deps.nonceLaneCoordinationStore !== undefined;
  const runtimeId = createRuntimeId();
  const observedCoordinationDegradations = new Map<string, NonceCoordinatorDegradation>();

  const emit = (event: NonceCoordinatorTraceEvent): void => {
    appendOutcomeMetricEvent(outcomeMetricEvents, event);
    try {
      deps.onTrace?.(event);
    } catch {}
  };

  const emitCoordinationDegradedOnce = (
    reason: NonceCoordinatorDegradation['reason'],
    input?: {
      lane?: NonceLane;
      fallback?: NonceCoordinatorDegradation['fallback'];
      accountId?: string;
      networkKey?: string;
      laneFamily?: NonceLane['family'];
    },
  ): void => {
    const lane = input?.lane;
    const fallback = input?.fallback || NonceCoordinatorFallback.InRuntimeLock;
    const networkKey = lane ? nonceLaneNetworkKey(lane) : String(input?.networkKey || '').trim();
    const accountId = lane ? nonceLaneSubjectId(lane) : String(input?.accountId || '').trim();
    const laneFamily = lane?.family || input?.laneFamily;
    const key = [reason, laneFamily || '', networkKey, accountId, fallback].join('|');
    if (observedCoordinationDegradations.has(key)) return;
    const degradation: NonceCoordinatorDegradation = {
      reason,
      ...(laneFamily ? { laneFamily } : {}),
      ...(networkKey ? { networkKey } : {}),
      ...(accountId ? { accountId } : {}),
      fallback,
    };
    observedCoordinationDegradations.set(key, degradation);
    emit({
      event: NonceCoordinatorTraceEventName.CoordinationDegraded,
      ...(lane ? { lane } : {}),
      degradation,
    });
    console.warn('[NonceCoordinator] nonce coordination degraded', degradation);
  };

  const readLease = (input: {
    leaseId: string;
    operationId: SigningOperationId | string;
    operationFingerprint: SigningOperationFingerprint | string;
  }): NonceLease => {
    const leaseId = normalizeRequiredString(input.leaseId, 'leaseId');
    const lease = leases.get(leaseId);
    if (!lease) {
      throw new Error('[NonceCoordinator] nonce lease not found');
    }
    assertOperationMatches(lease, input.operationId, input.operationFingerprint);
    return lease;
  };

  const transitionLease = (args: {
    lease: NonceLease;
    transition: Parameters<typeof reduceNonceLeaseState>[1];
    event: NonceCoordinatorTraceEvent['event'];
    reason?: string;
    txHash?: string;
    expiresAtMs?: number;
  }): void => {
    const previousState = args.lease.state;
    const nextState = reduceNonceLeaseState(previousState, args.transition);
    args.lease.state = nextState;
    const expiresAtMs = args.expiresAtMs;
    if (typeof expiresAtMs === 'number' && Number.isSafeInteger(expiresAtMs)) {
      args.lease.expiresAtMs = expiresAtMs;
    }
    emit({
      event: args.event,
      lease: args.lease,
      previousState,
      nextState,
      ...(args.reason ? { reason: args.reason } : {}),
      ...(args.txHash ? { txHash: args.txHash } : {}),
    });
  };

  const preflightLeaseTransition = (
    lease: NonceLease,
    transition: Parameters<typeof reduceNonceLeaseState>[1],
  ): void => {
    reduceNonceLeaseState(lease.state, transition);
  };

  const getOrCreateEvmState = (laneKey: string): EvmNonceLaneState => {
    const existing = evmStates.get(laneKey);
    if (existing) return existing;
    const created = createEvmNonceLaneState();
    evmStates.set(laneKey, created);
    return created;
  };

  const indexEvmLaneByAccount = (lane: EvmNonceLane, laneKey: string): void => {
    const accountId = String(lane.subjectId || '').trim();
    if (!accountId) return;
    const keys = evmAccountLaneKeys.get(accountId);
    if (!keys) {
      evmAccountLaneKeys.set(accountId, new Set<string>([laneKey]));
      return;
    }
    keys.add(laneKey);
  };

  const readCoordinationLaneRecords = async (
    laneKey: string,
    lane?: NonceLane,
  ): Promise<NonceLaneCoordinationRecord[]> => {
    if (!nonceLaneCoordinationStore) {
      if (shouldWarnOnMissingCoordinationStore) {
        emitCoordinationDegradedOnce(NonceCoordinatorDegradationReason.IndexedDBUnavailable, {
          lane,
        });
      }
      return [];
    }
    try {
      await nonceLaneCoordinationStore.pruneExpired(now());
    } catch {
      emitCoordinationDegradedOnce(NonceCoordinatorDegradationReason.DurableStoreError, {
        lane,
      });
    }
    try {
      const records = await nonceLaneCoordinationStore.readLane(laneKey);
      if (!lane) return records;
      const seenLeaseIds = new Set(records.map((record) => record.leaseId));
      for (const legacyLaneKey of legacyNonceLaneKeys(lane)) {
        if (legacyLaneKey === laneKey) continue;
        for (const legacyRecord of await nonceLaneCoordinationStore.readLane(legacyLaneKey)) {
          if (seenLeaseIds.has(legacyRecord.leaseId)) continue;
          records.push(legacyRecord);
          seenLeaseIds.add(legacyRecord.leaseId);
        }
      }
      return records;
    } catch {
      emitCoordinationDegradedOnce(NonceCoordinatorDegradationReason.DurableStoreError, {
        lane,
      });
      return [];
    }
  };

  const readActiveEvmLeaseNonces = async (
    laneKey: string,
    input?: { chainNextNonce?: bigint; excludeLeaseId?: string; lane?: EvmNonceLane },
  ): Promise<Set<string>> => {
    const active = new Set<string>();
    for (const lease of leases.values()) {
      if (input?.excludeLeaseId && lease.leaseId === input.excludeLeaseId) continue;
      if (lease.lane.family !== 'evm') continue;
      if (nonceLaneKey(lease.lane) !== laneKey) continue;
      if (!isActiveEvmLeaseState(lease.state)) continue;
      const nonce = normalizeBigint(lease.nonce, 'nonce');
      if (input?.chainNextNonce != null && nonce < input.chainNextNonce) continue;
      active.add(nonce.toString());
    }
    for (const record of await readCoordinationLaneRecords(laneKey, input?.lane)) {
      if (record.family !== 'evm') continue;
      if (input?.excludeLeaseId && record.leaseId === input.excludeLeaseId) continue;
      if (!isActiveCoordinationLeaseRecord(record, now())) continue;
      const nonce = normalizeBigint(record.nonce, 'nonce');
      if (input?.chainNextNonce != null && nonce < input.chainNextNonce) continue;
      active.add(nonce.toString());
    }
    return active;
  };

  const readActiveNearLeaseNonces = async (
    laneKey: string,
    input?: { chainNextNonce?: bigint; excludeLeaseId?: string; lane?: NearNonceLane },
  ): Promise<Set<string>> => {
    const active = new Set<string>();
    for (const lease of leases.values()) {
      if (input?.excludeLeaseId && lease.leaseId === input.excludeLeaseId) continue;
      if (lease.lane.family !== 'near') continue;
      if (nonceLaneKey(lease.lane) !== laneKey) continue;
      if (!isActiveNearLeaseState(lease.state)) continue;
      const nonce = normalizeBigint(lease.nonce, 'nonce');
      if (input?.chainNextNonce != null && nonce < input.chainNextNonce) continue;
      active.add(nonce.toString());
    }
    for (const record of await readCoordinationLaneRecords(laneKey, input?.lane)) {
      if (record.family !== 'near') continue;
      if (input?.excludeLeaseId && record.leaseId === input.excludeLeaseId) continue;
      if (!isActiveCoordinationLeaseRecord(record, now())) continue;
      const nonce = normalizeBigint(record.nonce, 'nonce');
      if (input?.chainNextNonce != null && nonce < input.chainNextNonce) continue;
      active.add(nonce.toString());
    }
    return active;
  };

  const persistCoordinationLease = async (
    lease: NonceLease,
    state: NonceLaneCoordinationRecord['state'],
    expiresAtMs = lease.expiresAtMs,
  ): Promise<void> => {
    if (!nonceLaneCoordinationStore) {
      if (shouldWarnOnMissingCoordinationStore) {
        emitCoordinationDegradedOnce(NonceCoordinatorDegradationReason.IndexedDBUnavailable, {
          lane: lease.lane,
        });
      }
      return;
    }
    const laneKey = nonceLaneKey(lease.lane);
    const baseRecord = {
      v: 1,
      laneKey,
      leaseId: lease.leaseId,
      networkKey: nonceLaneNetworkKey(lease.lane),
      nonce: String(lease.nonce),
      state,
      operationId: String(lease.operationId),
      operationFingerprint: String(lease.operationFingerprint),
      reservedAtMs: lease.reservedAtMs,
      expiresAtMs,
      updatedAtMs: now(),
      ...(nonceLaneSubjectId(lease.lane) ? { accountId: nonceLaneSubjectId(lease.lane) } : {}),
      runtimeId,
      ...(lease.batchId ? { batchId: lease.batchId } : {}),
      ...(Number.isSafeInteger(lease.txIndex) ? { txIndex: lease.txIndex } : {}),
    } as const;
    const record: NonceLaneCoordinationRecord =
      lease.lane.family === 'evm'
        ? {
            ...baseRecord,
            family: 'evm',
            chainTarget: lease.lane.chainTarget,
            sender: lease.lane.sender,
            ...(lease.lane.nonceKey != null ? { nonceKey: lease.lane.nonceKey.toString() } : {}),
          }
        : {
            ...baseRecord,
            family: 'near',
            accountId: lease.lane.accountId,
            publicKey: lease.lane.publicKey,
          };
    try {
      await nonceLaneCoordinationStore.upsert(record);
    } catch {
      emitCoordinationDegradedOnce(NonceCoordinatorDegradationReason.DurableStoreError, {
        lane: lease.lane,
      });
    }
  };

  const removeCoordinationLease = async (lease: NonceLease): Promise<void> => {
    if (!nonceLaneCoordinationStore) return;
    try {
      await nonceLaneCoordinationStore.remove({
        laneKey: nonceLaneKey(lease.lane),
        leaseId: lease.leaseId,
      });
    } catch {
      emitCoordinationDegradedOnce(NonceCoordinatorDegradationReason.DurableStoreError, {
        lane: lease.lane,
      });
    }
  };

  const refreshEvmLaneFromChainLocked = async (
    lane: EvmNonceLane,
    state: EvmNonceLaneState,
  ): Promise<bigint> => {
    if (state.inflightRefresh) {
      return await state.inflightRefresh;
    }
    const laneKey = nonceLaneKey(lane);
    const refreshTask = (async (): Promise<bigint> => {
      const chainNextNonceRaw = await deps.evmNonceBackend.fetchChainNonce(
        evmLaneToReserveNonceInput(lane),
      );
      const chainNextNonce = chainNextNonceRaw >= 0n ? chainNextNonceRaw : 0n;
      const activeLeaseNonces = await readActiveEvmLeaseNonces(laneKey, {
        chainNextNonce,
        lane,
      });

      let highestActiveLease = 0n;
      for (const nonce of activeLeaseNonces) {
        const value = BigInt(nonce);
        if (value > highestActiveLease) highestActiveLease = value;
      }

      let highestInFlight = 0n;
      const prunedInFlight = new Map<string, EvmInFlightNonceRecord>();
      for (const [key, record] of state.inFlight.entries()) {
        if (record.nonce < chainNextNonce) continue;
        prunedInFlight.set(key, record);
        if (record.nonce > highestInFlight) highestInFlight = record.nonce;
      }
      state.inFlight = prunedInFlight;

      const hasOutstandingLocalNonce = activeLeaseNonces.size > 0 || prunedInFlight.size > 0;
      const nextFromCurrent = hasOutstandingLocalNonce ? state.nextCandidate || 0n : 0n;
      const nextFromActiveLease = highestActiveLease > 0n ? highestActiveLease + 1n : 0n;
      const nextFromInFlight = highestInFlight > 0n ? highestInFlight + 1n : 0n;
      state.nextCandidate = maxBigint(
        0n,
        chainNextNonce,
        nextFromCurrent,
        nextFromActiveLease,
        nextFromInFlight,
      );
      state.chainNonce = chainNextNonce;
      state.lastRefreshMs = now();
      return chainNextNonce;
    })();

    state.inflightRefresh = refreshTask;
    try {
      return await refreshTask;
    } finally {
      if (state.inflightRefresh === refreshTask) {
        state.inflightRefresh = null;
      }
    }
  };

  const shouldRefreshEvmLane = async (
    laneKey: string,
    state: EvmNonceLaneState,
    lane: EvmNonceLane,
  ): Promise<boolean> => {
    if (state.nextCandidate == null) return true;
    if (state.lastRefreshMs == null) return true;
    if (state.inFlight.size > 0) return true;
    if ((await readActiveEvmLeaseNonces(laneKey, { lane })).size > 0) return false;
    return now() - state.lastRefreshMs >= evmRefreshTtlMs;
  };

  const reserveEvmNonceLeaseUnlocked = async (input: {
    lane: EvmNonceLane;
    operation: NonceOperationContext;
  }): Promise<NonceLease> => {
    await expireDueLeases({ accountId: nonceLaneSubjectId(input.lane) });
    const laneKey = nonceLaneKey(input.lane);
    const state = getOrCreateEvmState(laneKey);
    indexEvmLaneByAccount(input.lane, laneKey);
    if (await shouldRefreshEvmLane(laneKey, state, input.lane)) {
      await refreshEvmLaneFromChainLocked(input.lane, state);
    }
    const blocked = readBlockedEvmInFlight({
      state,
      nowMs: now(),
      staleInFlightThresholdMs: evmStaleInFlightThresholdMs,
    });
    if (blocked) {
      throw createEvmNonceLaneBlockedError({
        lane: input.lane,
        blockedNonce: blocked.blockedNonce,
        ageMs: blocked.ageMs,
      });
    }

    // Start from the chain-visible nonce and skip only active coordinator-owned
    // leases/in-flight records. Released or expired holes must be reusable; this
    // is the bug class that previously left Tempo/Arc polling transactions that
    // could never enter the pending pool.
    let candidate = state.chainNonce ?? state.nextCandidate ?? 0n;
    const activeLeaseNonces = await readActiveEvmLeaseNonces(laneKey, { lane: input.lane });
    while (
      activeLeaseNonces.has(candidate.toString()) ||
      state.inFlight.has(candidate.toString())
    ) {
      candidate += 1n;
    }
    state.nextCandidate = candidate + 1n;
    const reservedAtMs = now();
    const lease: NonceLease = {
      leaseId: createNonceLeaseId({
        operationId: input.operation.operationId,
        chain: input.lane.chainTarget.kind,
        nonce: candidate,
      }),
      lane: input.lane,
      operationId: input.operation.operationId,
      operationFingerprint: input.operation.operationFingerprint,
      nonce: candidate,
      state: NonceLeaseState.Reserved,
      reservedAtMs,
      expiresAtMs: reservedAtMs + leaseTtlMs,
    };
    leases.set(lease.leaseId, lease);
    await persistCoordinationLease(lease, NonceDurableLeaseState.Reserved);
    emit({ event: NonceCoordinatorTraceEventName.LeaseReserved, lease });
    return { ...lease };
  };

  const releaseEvmNonceReservation = async (
    lease: NonceLease & { lane: EvmNonceLane },
  ): Promise<void> => {
    const laneKey = nonceLaneKey(lease.lane);
    const state = evmStates.get(laneKey);
    await removeCoordinationLease(lease);
    if (!state) return;
    const nonce = normalizeBigint(lease.nonce, 'nonce');
    state.inFlight.delete(nonce.toString());
    const hasOtherActiveLease =
      (
        await readActiveEvmLeaseNonces(laneKey, {
          excludeLeaseId: lease.leaseId,
          lane: lease.lane,
        })
      ).size > 0;
    if (!hasOtherActiveLease && state.inFlight.size === 0) {
      state.lastRefreshMs = null;
    }
  };

  const markEvmBroadcastAccepted = async (
    lease: NonceLease & { lane: EvmNonceLane },
    txHash?: string,
  ): Promise<void> => {
    const laneKey = nonceLaneKey(lease.lane);
    const state = getOrCreateEvmState(laneKey);
    const nonce = normalizeBigint(lease.nonce, 'nonce');
    const atMs = now();
    state.inFlight.set(nonce.toString(), {
      nonce,
      ...(txHash ? { txHash: txHash as `0x${string}` } : {}),
      status: 'accepted',
      acceptedAtMs: atMs,
      updatedAtMs: atMs,
    });
    const minNext = nonce + 1n;
    if (state.nextCandidate == null || state.nextCandidate < minNext) {
      state.nextCandidate = minNext;
    }
    await persistCoordinationLease(
      lease,
      NonceDurableLeaseState.BroadcastAccepted,
      atMs + evmStaleInFlightThresholdMs,
    );
  };

  const markEvmFinalized = async (lease: NonceLease & { lane: EvmNonceLane }): Promise<void> => {
    const laneKey = nonceLaneKey(lease.lane);
    const state = getOrCreateEvmState(laneKey);
    const nonce = normalizeBigint(lease.nonce, 'nonce');
    state.inFlight.delete(nonce.toString());
    const minNext = nonce + 1n;
    state.chainNonce = state.chainNonce == null ? minNext : maxBigint(state.chainNonce, minNext);
    if (state.nextCandidate == null || state.nextCandidate < minNext) {
      state.nextCandidate = minNext;
    }
    state.lastRefreshMs = now();
    await removeCoordinationLease(lease);
  };

  const markEvmDroppedOrReplaced = async (
    lease: NonceLease & { lane: EvmNonceLane },
    input: { reason: EvmNonceOutcomeReason; txHash?: string },
  ): Promise<void> => {
    const laneKey = nonceLaneKey(lease.lane);
    const state = getOrCreateEvmState(laneKey);
    const nonce = normalizeBigint(lease.nonce, 'nonce');
    if (input.reason === EvmNonceOutcomeReason.Dropped) {
      state.inFlight.delete(nonce.toString());
      if (state.chainNonce == null || state.chainNonce <= nonce) {
        state.nextCandidate =
          state.nextCandidate == null ? nonce : minBigint(state.nextCandidate, nonce);
      }
    } else {
      const previous = state.inFlight.get(nonce.toString());
      state.inFlight.set(nonce.toString(), {
        nonce,
        ...(input.txHash
          ? { txHash: input.txHash as `0x${string}` }
          : previous?.txHash
            ? { txHash: previous.txHash }
            : {}),
        status: 'replaced',
        acceptedAtMs: previous?.acceptedAtMs ?? now(),
        updatedAtMs: now(),
      });
    }
    state.lastRefreshMs = null;
    await removeCoordinationLease(lease);
  };

  const reconcileEvmLaneLocked = async (lane: EvmNonceLane): Promise<NonceLaneStatus> => {
    const laneKey = nonceLaneKey(lane);
    const state = getOrCreateEvmState(laneKey);
    indexEvmLaneByAccount(lane, laneKey);
    const chainNextNonce = await refreshEvmLaneFromChainLocked(lane, state);
    const unresolvedInFlightNonces = Array.from(state.inFlight.values())
      .map((entry) => entry.nonce)
      .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    const blockedState = readBlockedEvmInFlight({
      state,
      nowMs: now(),
      staleInFlightThresholdMs: evmStaleInFlightThresholdMs,
    });
    return {
      chainNextNonce,
      unresolvedInFlightNonces,
      blocked: !!blockedState,
      ...(blockedState ? { blockedNonce: blockedState.blockedNonce } : {}),
    };
  };

  const recordDroppedReplacedAlert = (args: {
    lane: EvmNonceLane;
    reason: EvmNonceOutcomeReason;
  }): void => {
    const atMs = now();
    const key = [nonceLaneKey(args.lane), args.reason].join('|');
    const existing = droppedReplacedAlerts.get(key);
    const windowState =
      existing && atMs - existing.firstSeenAtMs <= droppedReplacedAlertWindowMs
        ? {
            count: existing.count + 1,
            firstSeenAtMs: existing.firstSeenAtMs,
            lastSeenAtMs: atMs,
          }
        : {
            count: 1,
            firstSeenAtMs: atMs,
            lastSeenAtMs: atMs,
          };
    droppedReplacedAlerts.set(key, windowState);
    if (windowState.count < droppedReplacedAlertThreshold) return;

    const alert: NonceCoordinatorAlert = {
      kind: 'repeated_dropped_or_replaced',
      severity: 'warning',
      lane: args.lane,
      reason: args.reason,
      count: windowState.count,
      windowMs: droppedReplacedAlertWindowMs,
      firstSeenAtMs: windowState.firstSeenAtMs,
      lastSeenAtMs: windowState.lastSeenAtMs,
    };
    emit({ event: NonceCoordinatorTraceEventName.LaneAlert, lane: args.lane, alert });
    console.warn('[NonceCoordinator] repeated EVM-family dropped/replaced nonce outcomes', {
      chainTarget: args.lane.chainTarget,
      networkKey: nonceLaneNetworkKey(args.lane),
      chainId: args.lane.chainTarget.chainId,
      sender: args.lane.sender,
      nonceKey: args.lane.nonceKey?.toString(),
      subjectId: args.lane.subjectId,
      reason: args.reason,
      count: windowState.count,
      windowMs: droppedReplacedAlertWindowMs,
    });
  };

  const nearState = createNearNonceLaneState();

  const clearNearRefreshTimer = (): void => {
    if (!nearState.refreshTimer) return;
    clearTimeout(nearState.refreshTimer);
    nearState.refreshTimer = null;
  };

  const clearNearPrefetchTimer = (): void => {
    if (!nearState.prefetchTimer) return;
    clearTimeout(nearState.prefetchTimer);
    nearState.prefetchTimer = null;
  };

  const clearNearTransactionContext = (): void => {
    nearState.transactionContext = null;
    nearState.lastNonceUpdate = null;
    nearState.lastBlockHeightUpdate = null;
    nearState.inflightFetch = null;
    nearState.reservedNonces.clear();
    nearState.lastReservedNonce = null;
    clearNearRefreshTimer();
    clearNearPrefetchTimer();
  };

  const clearNearAccessKeyState = (): void => {
    nearState.accountId = null;
    nearState.publicKey = null;
    clearNearTransactionContext();
  };

  const requireNearClient = (nearClient?: NearClient): NearClient => {
    const resolved = nearClient || deps.nearClient;
    if (!resolved) {
      throw new Error('[NonceCoordinator] NEAR client is not configured');
    }
    return resolved;
  };

  const initializeNearAccessKey = (input: { accountId: string; publicKey: string }): void => {
    const accountId = normalizeRequiredString(input.accountId, 'accountId');
    const publicKey = normalizeRequiredString(input.publicKey, 'publicKey');
    // Idempotence here is load-bearing: repeated setup for the same NEAR
    // access key must not clear reservations while concurrent signing requests
    // are queued behind the coordinator lane lock.
    if (nearState.accountId === accountId && nearState.publicKey === publicKey) {
      return;
    }
    nearState.accountId = accountId;
    nearState.publicKey = publicKey;
    clearNearTransactionContext();
  };

  const reserveNearNonces = async (lane: NearNonceLane, countInput: number): Promise<string[]> => {
    if (!nearState.transactionContext) {
      throw new Error('NEAR transaction context not available - call fetchNearContext() first');
    }
    const count = Math.max(0, Math.floor(Number(countInput || 0)));
    if (count <= 0) return [];

    const laneKey = nonceLaneKey(lane);
    const activeDurableNonces = await readActiveNearLeaseNonces(laneKey, { lane });
    let highestDurable = 0n;
    for (const nonce of activeDurableNonces) {
      const value = BigInt(nonce);
      if (value > highestDurable) highestDurable = value;
    }
    const start = maxBigint(
      nearState.lastReservedNonce ? BigInt(nearState.lastReservedNonce) + 1n : 0n,
      BigInt(nearState.transactionContext.nextNonce),
      highestDurable > 0n ? highestDurable + 1n : 0n,
    );
    const planned: string[] = [];
    let candidateValue = start;
    for (let index = 0; index < count; index += 1) {
      while (
        nearState.reservedNonces.has(candidateValue.toString()) ||
        activeDurableNonces.has(candidateValue.toString())
      ) {
        candidateValue += 1n;
      }
      const candidate = candidateValue.toString();
      planned.push(candidate);
      candidateValue += 1n;
    }
    for (const nonce of planned) {
      nearState.reservedNonces.add(nonce);
    }
    nearState.lastReservedNonce = planned[planned.length - 1] || nearState.lastReservedNonce;
    return planned;
  };

  const releaseNearNonce = (nonce: string): void => {
    if (!nearState.reservedNonces.delete(String(nonce))) return;
    nearState.lastReservedNonce = computeLastReservedNonce(nearState.reservedNonces);
  };

  const releaseAllNearNonces = (): void => {
    nearState.reservedNonces.clear();
    nearState.lastReservedNonce = null;
  };

  const fetchNearFreshData = async (
    nearClient: NearClient,
    force = false,
  ): Promise<TransactionContext> => {
    if (!nearState.accountId || !nearState.publicKey) {
      throw new Error('[NonceCoordinator] NEAR access key is not initialized');
    }
    if (nearState.inflightFetch && !force) {
      return nearState.inflightFetch;
    }

    const capturedAccountId = nearState.accountId;
    const capturedPublicKey = nearState.publicKey;
    const requestId = ++nearState.inflightId;
    const fetchPromise = (async () => {
      try {
        const nowMs = now();
        const isNonceStale =
          force ||
          !nearState.lastNonceUpdate ||
          nowMs - nearState.lastNonceUpdate >= NEAR_NONCE_FRESHNESS_THRESHOLD_MS;
        const isBlockStale =
          force ||
          !nearState.lastBlockHeightUpdate ||
          nowMs - nearState.lastBlockHeightUpdate >= NEAR_BLOCK_FRESHNESS_THRESHOLD_MS;

        let accessKeyInfo = nearState.transactionContext?.accessKeyInfo;
        let txBlockHeight = nearState.transactionContext?.txBlockHeight;
        let txBlockHash = nearState.transactionContext?.txBlockHash;
        const fetchAccessKey = isNonceStale || !accessKeyInfo;
        const fetchBlock = isBlockStale || !txBlockHeight || !txBlockHash;

        let maybeAccessKey: unknown = accessKeyInfo ?? null;
        let maybeBlock: unknown = null;
        let accessKeyError: unknown = null;
        let blockError: unknown = null;
        const tasks: Promise<void>[] = [];

        if (fetchAccessKey) {
          tasks.push(
            (async () => {
              try {
                maybeAccessKey = await nearClient.viewAccessKey(
                  capturedAccountId,
                  capturedPublicKey,
                );
              } catch (error: unknown) {
                const message = errorMessage(error);
                if (isMissingNearAccessKeyError(message)) {
                  maybeAccessKey = null;
                  return;
                }
                accessKeyError = error;
              }
            })(),
          );
        }

        if (fetchBlock) {
          tasks.push(
            (async () => {
              try {
                maybeBlock = await nearClient.viewBlock({ finality: 'final' });
              } catch (error: unknown) {
                blockError = error;
              }
            })(),
          );
        }

        if (tasks.length > 0) {
          await Promise.all(tasks);
        }
        if (accessKeyError) throw accessKeyError;
        if (blockError) throw blockError;

        if (fetchAccessKey) {
          accessKeyInfo = isAccessKeyViewLike(maybeAccessKey)
            ? normalizeAccessKeyView(maybeAccessKey)
            : nearState.transactionContext?.accessKeyInfo || makePlaceholderAccessKey();
        }
        if (fetchBlock) {
          if (!isBlockResultLike(maybeBlock)) {
            throw new Error('[NonceCoordinator] failed to fetch NEAR block info');
          }
          txBlockHeight = String(maybeBlock.header.height);
          txBlockHash = maybeBlock.header.hash;
        }

        const nextCandidate = maxBigint(
          accessKeyInfo?.nonce !== undefined ? BigInt(accessKeyInfo.nonce) + 1n : 0n,
          nearState.transactionContext?.nextNonce
            ? BigInt(nearState.transactionContext.nextNonce)
            : 0n,
          nearState.lastReservedNonce ? BigInt(nearState.lastReservedNonce) + 1n : 0n,
          1n,
        );
        const transactionContext: TransactionContext = {
          nearPublicKeyStr: capturedPublicKey,
          accessKeyInfo: accessKeyInfo!,
          nextNonce: nextCandidate.toString(),
          txBlockHeight: txBlockHeight!,
          txBlockHash: txBlockHash!,
        };

        if (
          capturedAccountId === nearState.accountId &&
          capturedPublicKey === nearState.publicKey &&
          requestId === nearState.inflightId
        ) {
          nearState.transactionContext = transactionContext;
          const commitMs = now();
          if (fetchAccessKey) nearState.lastNonceUpdate = commitMs;
          if (fetchBlock) nearState.lastBlockHeightUpdate = commitMs;
        }
        return transactionContext;
      } finally {
        if (requestId === nearState.inflightId) {
          nearState.inflightFetch = null;
        }
      }
    })();

    nearState.inflightFetch = fetchPromise;
    return fetchPromise;
  };

  const fetchNearContextForLane = async (input: {
    lane: NearNonceLane;
    nearClient?: NearClient;
    force?: boolean;
  }): Promise<TransactionContext> => {
    initializeNearAccessKey({
      accountId: input.lane.accountId,
      publicKey: input.lane.publicKey,
    });
    return {
      ...(await fetchNearFreshData(requireNearClient(input.nearClient), input.force === true)),
    };
  };

  const updateNearNonceFromBlockchain = async (
    nearClient: NearClient,
    actualNonce: string,
  ): Promise<void> => {
    if (!nearState.accountId || !nearState.publicKey) {
      throw new Error('[NonceCoordinator] NEAR access key is not initialized');
    }
    try {
      const accessKeyInfoRaw = await nearClient.viewAccessKey(
        nearState.accountId,
        nearState.publicKey,
      );
      if (!isAccessKeyViewLike(accessKeyInfoRaw)) {
        throw new Error(`Access key not found or invalid for account ${nearState.accountId}`);
      }
      const accessKeyInfo = normalizeAccessKeyView(accessKeyInfoRaw);
      const chainNonce = BigInt(accessKeyInfo.nonce);
      const actual = BigInt(actualNonce);
      const candidateNext = maxBigint(
        chainNonce + 1n,
        actual + 1n,
        nearState.transactionContext?.nextNonce
          ? BigInt(nearState.transactionContext.nextNonce)
          : 0n,
        nearState.lastReservedNonce ? BigInt(nearState.lastReservedNonce) + 1n : 0n,
      );

      if (nearState.transactionContext) {
        nearState.transactionContext = {
          ...nearState.transactionContext,
          accessKeyInfo,
          nextNonce: candidateNext.toString(),
        };
      } else {
        nearState.transactionContext = {
          nearPublicKeyStr: nearState.publicKey,
          accessKeyInfo,
          nextNonce: candidateNext.toString(),
          txBlockHeight: '0',
          txBlockHash: '',
        };
      }
      nearState.lastNonceUpdate = now();
      releaseNearNonce(actualNonce);
      if (nearState.reservedNonces.size > 0) {
        const pruned = pruneReservedNearNonces(chainNonce, nearState.reservedNonces);
        nearState.reservedNonces = pruned.set;
        nearState.lastReservedNonce = pruned.lastReserved;
      }
    } catch (error: unknown) {
      const message = errorMessage(error);
      if (isMissingNearAccessKeyError(message)) {
        const actual = BigInt(actualNonce);
        const candidateNext = maxBigint(
          actual + 1n,
          nearState.transactionContext?.nextNonce
            ? BigInt(nearState.transactionContext.nextNonce)
            : 0n,
          nearState.lastReservedNonce ? BigInt(nearState.lastReservedNonce) + 1n : 0n,
        );
        nearState.transactionContext = {
          ...(nearState.transactionContext || {
            nearPublicKeyStr: nearState.publicKey,
            accessKeyInfo: makePlaceholderAccessKey(),
            txBlockHeight: '0',
            txBlockHash: '',
          }),
          nextNonce: candidateNext.toString(),
        };
        nearState.lastNonceUpdate = now();
      }
    }
  };

  const releaseBackendReservation = async (lease: NonceLease): Promise<void> => {
    if (lease.lane.family === 'evm') {
      await releaseEvmNonceReservation(lease as NonceLease & { lane: EvmNonceLane });
      return;
    }
    releaseNearNonce(String(lease.nonce));
    await removeCoordinationLease(lease);
  };

  const reconcileAfterSignedLeaseExpiry = async (lease: NonceLease): Promise<void> => {
    await releaseBackendReservation(lease);
    if (lease.lane.family !== 'evm') return;
    await reconcileEvmLaneLocked(lease.lane);
    emit({ event: NonceCoordinatorTraceEventName.LaneReconciled, lane: lease.lane });
  };

  const withLocalLaneLock = async <T>(laneKey: string, fn: () => Promise<T>): Promise<T> => {
    const previous = laneLocks.get(laneKey) ?? Promise.resolve();
    let releaseCurrent!: () => void;
    const current = new Promise<void>((resolve) => {
      releaseCurrent = resolve;
    });
    const next = previous.catch(() => undefined).then(() => current);
    laneLocks.set(laneKey, next);
    await previous.catch(() => undefined);
    try {
      return await fn();
    } finally {
      releaseCurrent();
      if (laneLocks.get(laneKey) === next) {
        laneLocks.delete(laneKey);
      }
    }
  };

  const withLaneLock = async <T>(lane: NonceLane, fn: () => Promise<T>): Promise<T> => {
    const laneKey = nonceLaneKey(lane);
    const runLocal = async () => await withLocalLaneLock(laneKey, fn);
    const lockKey = `nonce-coordinator:${laneKey}`;
    if (sameOriginLock) {
      return await sameOriginLock.withLock(lockKey, runLocal);
    }
    if (nonceLaneCoordinationStore?.withLock) {
      let taskError: unknown = null;
      const runLockedTask = async (): Promise<T> => {
        try {
          return await runLocal();
        } catch (error: unknown) {
          taskError = error;
          throw error;
        }
      };
      try {
        return await nonceLaneCoordinationStore.withLock(
          {
            lockKey,
            ownerId: runtimeId,
            ttlMs: DEFAULT_DURABLE_LOCK_TTL_MS,
            waitTimeoutMs: DEFAULT_DURABLE_LOCK_WAIT_TIMEOUT_MS,
          },
          runLockedTask,
        );
      } catch (error: unknown) {
        if (taskError === error) {
          throw error;
        }
        const code = isObject(error) ? String((error as { code?: unknown }).code || '') : '';
        emitCoordinationDegradedOnce(
          code === NonceCoordinatorDegradationReason.DurableLockTimeout
            ? NonceCoordinatorDegradationReason.DurableLockTimeout
            : NonceCoordinatorDegradationReason.DurableStoreError,
          { lane, fallback: NonceCoordinatorFallback.None },
        );
        throw error;
      }
    }
    if (shouldWarnOnMissingCoordinationStore) {
      emitCoordinationDegradedOnce(NonceCoordinatorDegradationReason.WebLocksUnavailable, {
        lane,
      });
    }
    return await runLocal();
  };

  const expireDueLeases = async (input?: { accountId?: string }): Promise<NonceLease[]> => {
    const nowMs = now();
    const accountId = input?.accountId ? String(input.accountId).trim() : '';
    const expired: NonceLease[] = [];
    for (const lease of Array.from(leases.values())) {
      if (accountId && nonceLaneSubjectId(lease.lane) !== accountId) continue;
      if (lease.expiresAtMs > nowMs) continue;
      if (lease.state !== NonceLeaseState.Reserved && lease.state !== NonceLeaseState.Signed) {
        continue;
      }
      if (lease.state === NonceLeaseState.Signed) {
        await reconcileAfterSignedLeaseExpiry(lease);
      } else {
        await releaseBackendReservation(lease);
      }
      transitionLease({
        lease,
        transition: 'expire',
        event: NonceCoordinatorTraceEventName.LeaseExpired,
        reason:
          lease.state === NonceLeaseState.Signed ? 'signed_lease_ttl_elapsed' : 'lease_ttl_elapsed',
      });
      expired.push({ ...lease });
    }
    return expired;
  };

  const recoverDurableLeases = async (input?: { accountId?: string }): Promise<void> => {
    if (!nonceLaneCoordinationStore) {
      if (shouldWarnOnMissingCoordinationStore) {
        emitCoordinationDegradedOnce(NonceCoordinatorDegradationReason.IndexedDBUnavailable);
      }
      return;
    }
    let records: NonceLaneCoordinationRecord[] = [];
    try {
      records = await nonceLaneCoordinationStore.readAll(input);
    } catch {
      emitCoordinationDegradedOnce(NonceCoordinatorDegradationReason.DurableStoreError);
      return;
    }

    for (let record of records) {
      const lane = nonceLaneFromCoordinationRecord(record);
      if (!lane) {
        await nonceLaneCoordinationStore.remove({
          laneKey: record.laneKey,
          leaseId: record.leaseId,
        });
        emitCoordinationDegradedOnce(NonceCoordinatorDegradationReason.MalformedDurableRecord, {
          accountId: record.accountId,
          networkKey: record.networkKey,
          laneFamily: record.family,
          fallback: NonceCoordinatorFallback.None,
        });
        continue;
      }
      await withLaneLock(lane, async () => {
        const canonicalLaneKey = nonceLaneKey(lane);
        if (record.laneKey !== canonicalLaneKey) {
          const migratedRecord = { ...record, laneKey: canonicalLaneKey, updatedAtMs: now() };
          await nonceLaneCoordinationStore.upsert(migratedRecord);
          await nonceLaneCoordinationStore.remove({
            laneKey: record.laneKey,
            leaseId: record.leaseId,
          });
          record = migratedRecord;
        }
        const recordNonce = normalizeBigint(record.nonce, 'nonce');
        const isExpired = record.expiresAtMs <= now();
        if (isExpired && record.state !== NonceDurableLeaseState.BroadcastAccepted) {
          await nonceLaneCoordinationStore.remove({
            laneKey: record.laneKey,
            leaseId: record.leaseId,
          });
          if (record.family === 'evm') {
            await reconcileEvmLaneLocked(lane as EvmNonceLane).catch(() => null);
          }
          emit({
            event: NonceCoordinatorTraceEventName.LaneReconciled,
            lane,
            reason: 'startup_recovery_expired_lease',
          });
          return;
        }

        if (record.family === 'evm') {
          const evmLane = lane as EvmNonceLane;
          const state = getOrCreateEvmState(record.laneKey);
          if (record.state === NonceDurableLeaseState.BroadcastAccepted) {
            state.inFlight.set(record.nonce, {
              nonce: recordNonce,
              status: 'accepted',
              acceptedAtMs: record.reservedAtMs,
              updatedAtMs: record.updatedAtMs,
            });
          }
          const status = await reconcileEvmLaneLocked(evmLane).catch(() => null);
          if (status && status.chainNextNonce > recordNonce) {
            await nonceLaneCoordinationStore.remove({
              laneKey: record.laneKey,
              leaseId: record.leaseId,
            });
          }
          emit({
            event: NonceCoordinatorTraceEventName.LaneReconciled,
            lane: evmLane,
            reason: 'startup_recovery',
          });
          return;
        }

        if (record.family === 'near' && deps.nearClient) {
          try {
            const accessKey = await deps.nearClient.viewAccessKey(
              record.accountId || '',
              record.publicKey || '',
            );
            if (isAccessKeyViewLike(accessKey) && BigInt(accessKey.nonce) >= recordNonce) {
              await nonceLaneCoordinationStore.remove({
                laneKey: record.laneKey,
                leaseId: record.leaseId,
              });
            }
          } catch {}
        }
      });
    }
  };

  const reserveNearNonceBatchUnlocked = async (input: {
    lane: NearNonceLane;
    operation: NonceOperationContext;
    count: number;
  }): Promise<NonceLease[]> => {
    await expireDueLeases({ accountId: input.operation.accountId });
    const count = Math.max(1, Math.floor(Number(input.count || 1)));
    const nonces = await reserveNearNonces(input.lane, count);
    if (nonces.length !== count) {
      throw new Error('[NonceCoordinator] NEAR nonce reservation returned an incomplete batch');
    }
    const reservedAtMs = now();
    const batchId = createNonceBatchId({
      operationId: input.operation.operationId,
      chain: 'near',
      firstNonce: nonces[0],
      count,
    });
    const batchLeases = nonces.map(
      (nonce, txIndex): NonceLease => ({
        leaseId: createNonceLeaseId({
          operationId: input.operation.operationId,
          chain: 'near',
          nonce,
        }),
        lane: input.lane,
        operationId: input.operation.operationId,
        operationFingerprint: input.operation.operationFingerprint,
        nonce,
        state: NonceLeaseState.Reserved,
        reservedAtMs,
        expiresAtMs: reservedAtMs + leaseTtlMs,
        batchId,
        txIndex,
      }),
    );
    for (const lease of batchLeases) {
      leases.set(lease.leaseId, lease);
      await persistCoordinationLease(lease, NonceDurableLeaseState.Reserved);
      emit({ event: NonceCoordinatorTraceEventName.LeaseReserved, lease });
    }
    return batchLeases.map((lease) => ({ ...lease }));
  };

  const readDiagnostics = (
    input?: NonceCoordinatorDiagnosticsOptions,
  ): NonceCoordinatorDiagnostics => {
    const accountId = input?.accountId ? String(input.accountId).trim() : '';
    const atMs = now();
    const leasesByState = createEmptyLeaseStateCounts();
    const lanes = new Map<
      string,
      {
        lane: NonceLane;
        leaseCount: number;
        states: Partial<Record<NonceLeaseState, number>>;
      }
    >();
    const staleInFlightLaneKeys = new Set<string>();
    let leaseCount = 0;
    let oldestLeaseAgeMs = 0;
    let oldestInFlightLeaseAgeMs = 0;
    let staleInFlightLeaseCount = 0;

    for (const lease of leases.values()) {
      if (accountId && nonceLaneSubjectId(lease.lane) !== accountId) continue;
      leaseCount += 1;
      leasesByState[lease.state] += 1;
      const laneKey = nonceLaneKey(lease.lane);
      const leaseAgeMs = Math.max(0, atMs - lease.reservedAtMs);
      oldestLeaseAgeMs = Math.max(oldestLeaseAgeMs, leaseAgeMs);
      if (isInFlightNonceLeaseState(lease.state)) {
        oldestInFlightLeaseAgeMs = Math.max(oldestInFlightLeaseAgeMs, leaseAgeMs);
        if (lease.expiresAtMs <= atMs) {
          staleInFlightLeaseCount += 1;
          staleInFlightLaneKeys.add(laneKey);
        }
      }
      const existing =
        lanes.get(laneKey) ||
        ({
          lane: lease.lane,
          leaseCount: 0,
          states: {},
        } satisfies {
          lane: NonceLane;
          leaseCount: number;
          states: Partial<Record<NonceLeaseState, number>>;
        });
      existing.leaseCount += 1;
      existing.states[lease.state] = (existing.states[lease.state] || 0) + 1;
      lanes.set(laneKey, existing);
    }

    const metrics: NonceCoordinatorAggregateMetrics = {
      atMs,
      ...(accountId ? { accountId } : {}),
      leaseCount,
      laneCount: lanes.size,
      oldestLeaseAgeMs,
      oldestInFlightLeaseAgeMs,
      staleInFlightLeaseCount,
      staleInFlightLaneCount: staleInFlightLaneKeys.size,
      reservedLeaseCount: leasesByState[NonceLeaseState.Reserved],
      signedLeaseCount: leasesByState[NonceLeaseState.Signed],
      broadcastAcceptedLeaseCount: leasesByState[NonceLeaseState.BroadcastAccepted],
      droppedLeaseCount: leasesByState[NonceLeaseState.Dropped],
      replacedLeaseCount: leasesByState[NonceLeaseState.Replaced],
      reconciledLeaseCount: leasesByState[NonceLeaseState.Reconciled],
      releasedLeaseCount: leasesByState[NonceLeaseState.Released],
      outcomes: readOutcomeMetrics(outcomeMetricEvents, accountId),
    };

    const diagnostics = {
      leaseCount,
      leasesByState,
      laneCount: lanes.size,
      metrics,
      coordinationWarnings: Array.from(observedCoordinationDegradations.values()).filter(
        (degradation) =>
          !accountId || !degradation.accountId || degradation.accountId === accountId,
      ),
      lanes: Array.from(lanes.values()).map((entry) => ({
        family: entry.lane.family,
        ...(nonceLaneSubjectId(entry.lane) ? { accountId: nonceLaneSubjectId(entry.lane) } : {}),
        networkKey: nonceLaneNetworkKey(entry.lane),
        ...(entry.lane.family === 'evm'
          ? { chain: entry.lane.chainTarget.kind, chainId: entry.lane.chainTarget.chainId }
          : {}),
        leaseCount: entry.leaseCount,
        states: { ...entry.states },
      })),
      near: {
        ...(nearState.accountId ? { activeAccountId: nearState.accountId } : {}),
        ...(nearState.publicKey ? { activePublicKey: nearState.publicKey } : {}),
        hasContext: !!nearState.transactionContext,
        reservedNonceCount: nearState.reservedNonces.size,
        ...(nearState.lastReservedNonce ? { lastReservedNonce: nearState.lastReservedNonce } : {}),
      },
    };

    if (input?.emitMetrics) {
      emit({
        event: NonceCoordinatorTraceEventName.Metrics,
        metrics,
        ...(accountId ? { accountId } : {}),
      });
    }

    return diagnostics;
  };

  return {
    async reserve(input) {
      if (input.lane.family === 'near') {
        const nearLane = input.lane;
        return await withLaneLock(nearLane, async () => {
          return (
            await reserveNearNonceBatchUnlocked({
              lane: nearLane,
              operation: input.operation,
              count: 1,
            })
          )[0];
        });
      }
      const evmLane = input.lane;
      return await withLaneLock(evmLane, async () => {
        return await reserveEvmNonceLeaseUnlocked({
          lane: evmLane,
          operation: input.operation,
        });
      });
    },

    async reserveBatch(input) {
      return await withLaneLock(input.lane, async () => {
        return await reserveNearNonceBatchUnlocked(input);
      });
    },

    async reserveNearContext(input) {
      return await withLaneLock(input.lane, async () => {
        await expireDueLeases({ accountId: input.operation.accountId });
        initializeNearAccessKey({
          accountId: input.lane.accountId,
          publicKey: input.lane.publicKey,
        });
        const context = {
          ...(input.fetchContext
            ? await input.fetchContext()
            : await fetchNearContextForLane({
                lane: input.lane,
                nearClient: input.nearClient,
                force: input.force,
              })),
        };
        nearState.transactionContext = context;
        nearState.lastNonceUpdate = now();
        nearState.lastBlockHeightUpdate = now();
        const leases = await reserveNearNonceBatchUnlocked({
          lane: input.lane,
          operation: input.operation,
          count: input.count,
        });
        if (leases[0]) {
          context.nextNonce = String(leases[0].nonce);
        }
        return { context, leases };
      });
    },

    initializeNearAccessKey,

    getActiveNearPublicKey() {
      return String(nearState.publicKey || '').trim() || null;
    },

    async fetchNearContext(input) {
      return await withLaneLock(input.lane, async () => fetchNearContextForLane(input));
    },

    async prefetchNearContext(input) {
      if (input?.accountId || input?.publicKey) {
        if (!input.accountId || !input.publicKey) {
          throw new Error('[NonceCoordinator] NEAR prefetch requires both accountId and publicKey');
        }
        initializeNearAccessKey({
          accountId: input.accountId,
          publicKey: input.publicKey,
        });
      }
      if (!nearState.accountId || !nearState.publicKey) return;
      clearNearPrefetchTimer();
      const nearClient = requireNearClient(input?.nearClient);
      nearState.prefetchTimer = setTimeout(() => {
        nearState.prefetchTimer = null;
        if (nearState.inflightFetch) return;
        const nowMs = now();
        const blockStale =
          !nearState.lastBlockHeightUpdate ||
          nowMs - nearState.lastBlockHeightUpdate >= NEAR_BLOCK_FRESHNESS_THRESHOLD_MS;
        const missingContext = !nearState.transactionContext;
        if (!blockStale && !missingContext) return;
        void fetchNearFreshData(nearClient).catch(() => undefined);
      }, NEAR_PREFETCH_DEBOUNCE_MS);
    },

    clearNearAccessKey() {
      clearNearAccessKeyState();
      for (const [leaseId, lease] of leases.entries()) {
        if (lease.lane.family === 'near') {
          leases.delete(leaseId);
        }
      }
    },

    async markSigned(input) {
      const lease = readLease(input);
      return await withLaneLock(lease.lane, async () => {
        const lockedLease = readLease(input);
        const expiresAtMs = now() + signedLeaseTtlMs;
        transitionLease({
          lease: lockedLease,
          transition: 'mark_signed',
          event: NonceCoordinatorTraceEventName.LeaseSigned,
          expiresAtMs,
          ...(input.signedTxHash ? { txHash: input.signedTxHash } : {}),
        });
        await persistCoordinationLease(lockedLease, NonceDurableLeaseState.Signed, expiresAtMs);
      });
    },

    async markBroadcastAccepted(input) {
      const lease = readLease(input);
      return await withLaneLock(lease.lane, async () => {
        const lockedLease = readLease(input);
        preflightLeaseTransition(lockedLease, 'broadcast_accepted');
        if (lockedLease.lane.family === 'evm') {
          await markEvmBroadcastAccepted(
            lockedLease as NonceLease & { lane: EvmNonceLane },
            input.txHash ? String(input.txHash) : undefined,
          );
        } else {
          await persistCoordinationLease(lockedLease, NonceDurableLeaseState.BroadcastAccepted);
        }
        transitionLease({
          lease: lockedLease,
          transition: 'broadcast_accepted',
          event: NonceCoordinatorTraceEventName.LeaseBroadcastAccepted,
          ...(input.txHash ? { txHash: String(input.txHash) } : {}),
        });
      });
    },

    async markBroadcastRejected(input) {
      const lease = readLease(input);
      return await withLaneLock(lease.lane, async () => {
        const lockedLease = readLease(input);
        preflightLeaseTransition(lockedLease, 'broadcast_rejected');
        await releaseBackendReservation(lockedLease);
        transitionLease({
          lease: lockedLease,
          transition: 'broadcast_rejected',
          event: NonceCoordinatorTraceEventName.LeaseBroadcastRejected,
          reason: input.error instanceof Error ? input.error.message : String(input.error || ''),
        });
      });
    },

    async markFinalized(input) {
      const lease = readLease(input);
      return await withLaneLock(lease.lane, async () => {
        const lockedLease = readLease(input);
        preflightLeaseTransition(lockedLease, 'finalize');
        if (lockedLease.lane.family === 'evm') {
          await markEvmFinalized(lockedLease as NonceLease & { lane: EvmNonceLane });
        } else {
          if (deps.nearClient) {
            await updateNearNonceFromBlockchain(deps.nearClient, String(lockedLease.nonce));
          } else {
            await releaseBackendReservation(lockedLease);
          }
          await removeCoordinationLease(lockedLease);
        }
        transitionLease({
          lease: lockedLease,
          transition: 'finalize',
          event: NonceCoordinatorTraceEventName.LeaseFinalized,
          ...(input.txHash ? { txHash: String(input.txHash) } : {}),
        });
      });
    },

    async markDroppedOrReplaced(input) {
      const lease = readLease(input);
      assertEvmLease(lease);
      return await withLaneLock(lease.lane, async () => {
        const lockedLease = readLease(input);
        assertEvmLease(lockedLease);
        preflightLeaseTransition(
          lockedLease,
          input.reason === EvmNonceOutcomeReason.Replaced ? 'replace' : 'drop',
        );
        await markEvmDroppedOrReplaced(lockedLease, {
          reason: input.reason,
          ...(input.txHash ? { txHash: String(input.txHash) } : {}),
        });
        transitionLease({
          lease: lockedLease,
          transition: input.reason === EvmNonceOutcomeReason.Replaced ? 'replace' : 'drop',
          event:
            input.reason === EvmNonceOutcomeReason.Replaced
              ? NonceCoordinatorTraceEventName.LeaseReplaced
              : NonceCoordinatorTraceEventName.LeaseDropped,
          reason: input.reason,
          ...(input.txHash ? { txHash: String(input.txHash) } : {}),
        });
        recordDroppedReplacedAlert({
          lane: lockedLease.lane,
          reason: input.reason,
        });
      });
    },

    async release(input) {
      const lease = readLease(input);
      return await withLaneLock(lease.lane, async () => {
        const lockedLease = readLease(input);
        preflightLeaseTransition(lockedLease, 'release');
        await releaseBackendReservation(lockedLease);
        transitionLease({
          lease: lockedLease,
          transition: 'release',
          event: NonceCoordinatorTraceEventName.LeaseReleased,
          reason: input.reason,
        });
      });
    },

    async expireLeases(input) {
      return await expireDueLeases(input);
    },

    async recoverDurableLeases(input) {
      await recoverDurableLeases(input);
    },

    async reconcile(input) {
      if (input.lane.family !== 'evm') {
        throw new Error('[NonceCoordinator] NEAR nonce reconciliation is not wired yet');
      }
      const evmLane = input.lane;
      return await withLaneLock(evmLane, async () => {
        const status = await reconcileEvmLaneLocked(evmLane);
        emit({ event: NonceCoordinatorTraceEventName.LaneReconciled, lane: evmLane });
        return status;
      });
    },

    clearForAccount(accountId) {
      const normalizedAccountId = String(accountId || '').trim();
      if (!normalizedAccountId) return;
      void nonceLaneCoordinationStore
        ?.clearForAccount(normalizedAccountId)
        .catch(() =>
          emitCoordinationDegradedOnce(NonceCoordinatorDegradationReason.DurableStoreError),
        );
      const evmLaneKeys = evmAccountLaneKeys.get(normalizedAccountId);
      if (evmLaneKeys) {
        for (const key of evmLaneKeys) {
          evmStates.delete(key);
        }
        evmAccountLaneKeys.delete(normalizedAccountId);
      }
      if (nearState.accountId === normalizedAccountId) {
        clearNearAccessKeyState();
      }
      for (const [leaseId, lease] of leases.entries()) {
        if (nonceLaneSubjectId(lease.lane) === normalizedAccountId) {
          leases.delete(leaseId);
        }
      }
      emit({
        event: NonceCoordinatorTraceEventName.LanesCleared,
        accountId: normalizedAccountId,
        reason: 'clear_for_account',
      });
    },

    clearAll() {
      evmStates.clear();
      evmAccountLaneKeys.clear();
      droppedReplacedAlerts.clear();
      void nonceLaneCoordinationStore
        ?.clearAll()
        .catch(() =>
          emitCoordinationDegradedOnce(NonceCoordinatorDegradationReason.DurableStoreError),
        );
      clearNearAccessKeyState();
      leases.clear();
      laneLocks.clear();
      emit({ event: NonceCoordinatorTraceEventName.LanesCleared, reason: 'clear_all' });
    },

    getDiagnostics(input) {
      return readDiagnostics(input);
    },
  };
}

function isAccessKeyViewLike(value: unknown): value is AccessKeyView {
  if (!isObject(value)) return false;
  try {
    normalizeBigint((value as { nonce?: unknown }).nonce, 'near access-key nonce');
    return true;
  } catch {
    return false;
  }
}

function normalizeAccessKeyView(value: AccessKeyView): AccessKeyView {
  const permission = (value as { permission?: unknown }).permission;
  return {
    ...value,
    nonce: normalizeBigint((value as { nonce?: unknown }).nonce, 'near access-key nonce'),
    permission:
      permission === 'FullAccess' || isObject(permission)
        ? (permission as AccessKeyView['permission'])
        : 'FullAccess',
    block_hash: String((value as { block_hash?: unknown }).block_hash || ''),
    block_height: Number((value as { block_height?: unknown }).block_height || 0),
  };
}

function isBlockResultLike(value: unknown): value is BlockResult {
  if (!isObject(value)) return false;
  const header = (value as { header?: unknown }).header;
  if (!isObject(header)) return false;
  const height = (header as { height?: unknown }).height;
  const hash = (header as { hash?: unknown }).hash;
  return (typeof height === 'number' || typeof height === 'bigint') && isString(hash);
}

function makePlaceholderAccessKey(): AccessKeyView {
  return {
    nonce: 0n,
    permission: 'FullAccess',
    block_hash: '',
    block_height: 0,
  };
}

function createDefaultSameOriginLock(): NonceCoordinatorSameOriginLockPort | null {
  const maybeNavigator = globalThis as {
    navigator?: {
      locks?: {
        request<T>(
          name: string,
          options: { mode: 'exclusive' },
          callback: () => Promise<T>,
        ): Promise<T>;
      };
    };
  };
  const locks = maybeNavigator.navigator?.locks;
  if (typeof locks?.request !== 'function') return null;
  return {
    async withLock<T>(key: string, task: () => Promise<T>): Promise<T> {
      return await locks.request(key, { mode: 'exclusive' }, task);
    },
  };
}
