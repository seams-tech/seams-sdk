import type { NonceLaneStatus } from '@/core/rpcClients/evm/nonceBackend';
import type { NearClient } from '@/core/rpcClients/near/NearClient';
import type { TransactionContext } from '@/core/types/rpc';
import { isObject } from '@shared/utils/validation';
import type {
  SigningOperationFingerprint,
  SigningOperationId,
} from '../session/operationState/types';
import { SigningSessionIds } from '../session/operationState/types';
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
  ParsedNonceLaneCoordinationRecord,
  PreparedNonceOperationContext,
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
  type NonceCoordinatorDegradation,
  type NonceCoordinatorDeps,
  type NonceCoordinatorDiagnostics,
  type NonceCoordinatorDiagnosticsOptions,
  type NonceCoordinatorSameOriginLockPort,
  type NonceCoordinatorTraceEvent,
  type NonceLane,
  type NonceLaneCoordinationStore,
  type EvmNonceLease,
  type NearNonceLease,
  type ParsedNonceLaneCoordinationRecord,
  type NonceLease,
  type PreparedNonceOperationContext,
} from './nonceTypes';
import {
  isActiveCoordinationLeaseRecord,
  isActiveEvmLeaseState,
  isActiveNearLeaseState,
  reduceNonceLeaseState,
  type NonceLeaseTransition,
} from './nonceLeaseState';
export { reduceNonceLeaseState, tryReduceNonceLeaseState } from './nonceLeaseState';
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
export {
  classifyNearExecutionReadiness,
  type NearExecutionReadiness,
} from './nearNonceLane';
import {
  createEvmNonceLaneBlockedError,
  getOrCreateEvmNonceLaneState,
  indexEvmNonceLaneBySubject,
  markEvmBroadcastAcceptedState,
  markEvmDroppedOrReplacedState,
  markEvmFinalizedState,
  reconcileEvmLaneState,
  readBlockedEvmInFlight,
  refreshEvmLaneFromChainLocked as refreshEvmLaneFromChainState,
  releaseEvmNonceReservationState,
  shouldRefreshEvmLane as shouldRefreshEvmLaneState,
  type EvmNonceLaneState,
} from './evmNonceLane';
import {
  clearNearAccessKeyState as clearNearAccessKeyLaneState,
  clearNearPrefetchTimer,
  commitNearTransactionContextForState,
  createNearNonceLaneState,
  fetchNearFreshDataForState,
  hasNearInflightFetch,
  initializeNearAccessKeyState,
  isAccessKeyViewLike,
  markNearBroadcastAcceptedState,
  readNearActiveAccountId,
  readNearActivePublicKey,
  readNearAccessKeySubject,
  reconcileNearLaneState,
  refreshNearNonceAfterBroadcastRejectedState,
  releaseAllNearNoncesFromState,
  releaseNearNonceFromState,
  reserveNearNoncesFromState,
  shouldPrefetchNearContext,
  updateNearNonceFromBlockchainState,
} from './nearNonceLane';
import {
  appendOutcomeMetricEvent,
  createNonceCoordinatorDiagnostics,
  recordCoordinationDegradationOnce,
  recordDroppedReplacedAlertWindow,
  type DroppedReplacedAlertWindow,
  type NonceOutcomeMetricEvent,
} from './nonceDiagnostics';
import {
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
    const degradationEvent = recordCoordinationDegradationOnce({
      observed: observedCoordinationDegradations,
      reason,
      ...input,
    });
    if (!degradationEvent) return;
    emit({
      event: NonceCoordinatorTraceEventName.CoordinationDegraded,
      ...degradationEvent,
    });
    console.warn('[NonceCoordinator] nonce coordination degraded', degradationEvent.degradation);
  };

  type NonceLeaseOperationInput = {
    leaseId: string;
    operationId: SigningOperationId;
    operationFingerprint: SigningOperationFingerprint;
  };

  const normalizeLeaseOperationInput = (input: {
    leaseId: string;
    operationId: SigningOperationId | string;
    operationFingerprint: SigningOperationFingerprint | string;
  }): NonceLeaseOperationInput => ({
    leaseId: normalizeRequiredString(input.leaseId, 'leaseId'),
    operationId: SigningSessionIds.signingOperation(input.operationId),
    operationFingerprint: SigningSessionIds.signingOperationFingerprint(input.operationFingerprint),
  });

  const readLease = (input: NonceLeaseOperationInput): NonceLease => {
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
    return getOrCreateEvmNonceLaneState(evmStates, laneKey);
  };

  const indexEvmLaneByAccount = (lane: EvmNonceLane, laneKey: string): void => {
    indexEvmNonceLaneBySubject({ accountLaneKeys: evmAccountLaneKeys, lane, laneKey });
  };

  const readCoordinationLaneRecords = async (
    laneKey: string,
    lane?: NonceLane,
  ): Promise<ParsedNonceLaneCoordinationRecord[]> => {
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
      return await nonceLaneCoordinationStore.readLane(laneKey);
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
      if (!isEvmNonceLease(lease)) continue;
      if (nonceLaneKey(lease.lane) !== laneKey) continue;
      if (!isActiveEvmLeaseState(lease.state)) continue;
      const nonce = lease.nonce;
      if (input?.chainNextNonce != null && nonce < input.chainNextNonce) continue;
      active.add(nonce.toString());
    }
    for (const parsed of await readCoordinationLaneRecords(laneKey, input?.lane)) {
      if (parsed.record.family !== 'evm') continue;
      if (input?.excludeLeaseId && parsed.record.leaseId === input.excludeLeaseId) continue;
      if (!isActiveCoordinationLeaseRecord(parsed.record, now())) continue;
      if (input?.chainNextNonce != null && parsed.nonce < input.chainNextNonce) continue;
      active.add(parsed.nonce.toString());
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
      if (!isNearNonceLease(lease)) continue;
      if (nonceLaneKey(lease.lane) !== laneKey) continue;
      if (!isActiveNearLeaseState(lease.state)) continue;
      const nonce = BigInt(lease.nonce);
      if (input?.chainNextNonce != null && nonce < input.chainNextNonce) continue;
      active.add(nonce.toString());
    }
    for (const parsed of await readCoordinationLaneRecords(laneKey, input?.lane)) {
      if (parsed.record.family !== 'near') continue;
      if (input?.excludeLeaseId && parsed.record.leaseId === input.excludeLeaseId) continue;
      if (!isActiveCoordinationLeaseRecord(parsed.record, now())) continue;
      if (input?.chainNextNonce != null && parsed.nonce < input.chainNextNonce) continue;
      active.add(parsed.nonce.toString());
    }
    return active;
  };

  const persistCoordinationLease = async (
    lease: NonceLease,
    state: ParsedNonceLaneCoordinationRecord['record']['state'],
    expiresAtMs = lease.expiresAtMs,
  ): Promise<void> => {
    const coordinationStore = nonceLaneCoordinationStore;
    if (!coordinationStore) {
      if (shouldWarnOnMissingCoordinationStore) {
        emitCoordinationDegradedOnce(NonceCoordinatorDegradationReason.IndexedDBUnavailable, {
          lane: lease.lane,
        });
      }
      return;
    }
    if (isEvmNonceLease(lease)) {
      await persistCoordinationRecord(
        coordinationStore,
        buildEvmCoordinationRecord({
          lease,
          state,
          expiresAtMs,
          updatedAtMs: now(),
          runtimeId,
        }),
        lease.lane,
      );
    } else if (isNearNonceLease(lease)) {
      await persistCoordinationRecord(
        coordinationStore,
        buildNearCoordinationRecord({
          lease,
          state,
          expiresAtMs,
          updatedAtMs: now(),
          runtimeId,
        }),
        lease.lane,
      );
    } else {
      assertNever(lease);
    }
  };

  const persistCoordinationRecord = async (
    coordinationStore: NonceLaneCoordinationStore,
    record: ParsedNonceLaneCoordinationRecord['record'],
    lane: NonceLane,
  ): Promise<void> => {
    try {
      await coordinationStore.upsert(record);
    } catch {
      emitCoordinationDegradedOnce(NonceCoordinatorDegradationReason.DurableStoreError, {
        lane,
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
    const laneKey = nonceLaneKey(lane);
    return await refreshEvmLaneFromChainState({
      lane,
      state,
      nowMs: now(),
      fetchChainNonce: async (targetLane) =>
        await deps.evmNonceBackend.fetchChainNonce(evmLaneToReserveNonceInput(targetLane)),
      readActiveLeaseNonces: async (input) => await readActiveEvmLeaseNonces(laneKey, input),
    });
  };

  const shouldRefreshEvmLaneLocked = async (
    laneKey: string,
    state: EvmNonceLaneState,
    lane: EvmNonceLane,
  ): Promise<boolean> => {
    return await shouldRefreshEvmLaneState({
      state,
      lane,
      nowMs: now(),
      refreshTtlMs: evmRefreshTtlMs,
      readActiveLeaseNonces: async (input) => await readActiveEvmLeaseNonces(laneKey, input),
    });
  };

  const reserveEvmNonceLeaseUnlocked = async (input: {
    lane: EvmNonceLane;
    operation: PreparedNonceOperationContext;
  }): Promise<NonceLease> => {
    await expireDueLeasesForLockedLane(input.lane);
    const laneKey = nonceLaneKey(input.lane);
    const state = getOrCreateEvmState(laneKey);
    indexEvmLaneByAccount(input.lane, laneKey);
    if (await shouldRefreshEvmLaneLocked(laneKey, state, input.lane)) {
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

  const releaseEvmNonceReservation = async (lease: EvmNonceLease): Promise<void> => {
    const laneKey = nonceLaneKey(lease.lane);
    await releaseEvmNonceReservationState({
      lease,
      state: evmStates.get(laneKey),
      removeCoordinationLease,
      readActiveLeaseNonces: async (input) => await readActiveEvmLeaseNonces(laneKey, input),
    });
  };

  const markEvmBroadcastAccepted = async (
    lease: EvmNonceLease,
    txHash?: string,
  ): Promise<void> => {
    const laneKey = nonceLaneKey(lease.lane);
    const state = getOrCreateEvmState(laneKey);
    await markEvmBroadcastAcceptedState({
      lease,
      state,
      ...(txHash ? { txHash } : {}),
      nowMs: now(),
      staleInFlightThresholdMs: evmStaleInFlightThresholdMs,
      persistCoordinationLease,
    });
  };

  const markEvmFinalized = async (lease: EvmNonceLease): Promise<void> => {
    const laneKey = nonceLaneKey(lease.lane);
    const state = getOrCreateEvmState(laneKey);
    await markEvmFinalizedState({
      lease,
      state,
      nowMs: now(),
      removeCoordinationLease,
    });
  };

  const markEvmDroppedOrReplaced = async (
    lease: EvmNonceLease,
    input: { reason: EvmNonceOutcomeReason; txHash?: string },
  ): Promise<void> => {
    const laneKey = nonceLaneKey(lease.lane);
    const state = getOrCreateEvmState(laneKey);
    await markEvmDroppedOrReplacedState({
      lease,
      state,
      outcome: input,
      nowMs: now(),
      removeCoordinationLease,
    });
  };

  const reconcileEvmLaneLocked = async (lane: EvmNonceLane): Promise<NonceLaneStatus> => {
    const laneKey = nonceLaneKey(lane);
    const state = getOrCreateEvmState(laneKey);
    indexEvmLaneByAccount(lane, laneKey);
    return await reconcileEvmLaneState({
      lane,
      state,
      nowMs: now(),
      staleInFlightThresholdMs: evmStaleInFlightThresholdMs,
      refreshFromChain: refreshEvmLaneFromChainLocked,
    });
  };

  const recordDroppedReplacedAlert = (args: {
    lane: EvmNonceLane;
    reason: EvmNonceOutcomeReason;
  }): void => {
    const result = recordDroppedReplacedAlertWindow({
      alerts: droppedReplacedAlerts,
      lane: args.lane,
      reason: args.reason,
      nowMs: now(),
      threshold: droppedReplacedAlertThreshold,
      windowMs: droppedReplacedAlertWindowMs,
    });
    if (!result) return;
    emit({ event: NonceCoordinatorTraceEventName.LaneAlert, lane: args.lane, alert: result.alert });
    console.warn(
      '[NonceCoordinator] repeated EVM-family dropped/replaced nonce outcomes',
      result.warning,
    );
  };

  const nearState = createNearNonceLaneState();

  const clearNearAccessKeyState = (): void => {
    clearNearAccessKeyLaneState(nearState);
  };

  const requireNearClient = (nearClient?: NearClient): NearClient => {
    const resolved = nearClient || deps.nearClient;
    if (!resolved) {
      throw new Error('[NonceCoordinator] NEAR client is not configured');
    }
    return resolved;
  };

  const initializeNearAccessKey = (input: {
    walletId: string;
    nearAccountId: string;
    publicKey: string;
  }): void => {
    initializeNearAccessKeyState({ state: nearState, ...input });
  };

  const reserveNearNonces = async (lane: NearNonceLane, countInput: number): Promise<string[]> => {
    return await reserveNearNoncesFromState({
      state: nearState,
      lane,
      countInput,
      readActiveLeaseNonces: readActiveNearLeaseNonces,
    });
  };

  const releaseNearNonce = (nonce: string): void => {
    releaseNearNonceFromState(nearState, nonce);
  };

  const releaseAllNearNonces = (): void => {
    releaseAllNearNoncesFromState(nearState);
  };

  const fetchNearFreshData = async (
    nearClient: NearClient,
    force = false,
  ): Promise<TransactionContext> => {
    return await fetchNearFreshDataForState({
      state: nearState,
      nearClient,
      force,
      now,
      nonceFreshnessThresholdMs: NEAR_NONCE_FRESHNESS_THRESHOLD_MS,
      blockFreshnessThresholdMs: NEAR_BLOCK_FRESHNESS_THRESHOLD_MS,
    });
  };

  const fetchNearContextForLane = async (input: {
    lane: NearNonceLane;
    nearClient?: NearClient;
    force?: boolean;
  }): Promise<TransactionContext> => {
    initializeNearAccessKey({
      walletId: input.lane.walletId,
      nearAccountId: input.lane.nearAccountId,
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
    await updateNearNonceFromBlockchainState({
      state: nearState,
      nearClient,
      actualNonce,
      now,
    });
  };

  const refreshNearNonceAfterBroadcastRejected = async (nearClient: NearClient): Promise<void> => {
    await refreshNearNonceAfterBroadcastRejectedState({
      state: nearState,
      nearClient,
      now,
    });
  };

  const reconcileNearLaneLocked = async (lane: NearNonceLane): Promise<NonceLaneStatus> => {
    const laneKey = nonceLaneKey(lane);
    return await reconcileNearLaneState({
      lane,
      state: nearState,
      nearClient: requireNearClient(),
      now,
      activeLeases: Array.from(leases.values()).filter(
        (lease): lease is NearNonceLease =>
          lease.lane.family === 'near' &&
          nonceLaneKey(lease.lane) === laneKey &&
          lease.state === NonceLeaseState.BroadcastAccepted,
      ),
      removeCoordinationLease,
      transitionLease: ({ lease, transition, reason, txHash }) => {
        transitionLease({
          lease,
          transition,
          event:
            transition === 'finalize'
              ? NonceCoordinatorTraceEventName.LeaseFinalized
              : NonceCoordinatorTraceEventName.LeaseDropped,
          reason,
          ...(txHash ? { txHash } : {}),
        });
      },
    });
  };

  const releaseBackendReservation = async (lease: NonceLease): Promise<void> => {
    if (isEvmNonceLease(lease)) {
      await releaseEvmNonceReservation(lease);
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

  const expireLeaseLocked = async (lease: NonceLease, nowMs: number): Promise<NonceLease | null> => {
    if (lease.expiresAtMs > nowMs) return null;
    if (lease.state !== NonceLeaseState.Reserved && lease.state !== NonceLeaseState.Signed) {
      return null;
    }
    const expiringFromState = lease.state;
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
        expiringFromState === NonceLeaseState.Signed
          ? 'signed_lease_ttl_elapsed'
          : 'lease_ttl_elapsed',
    });
    return { ...lease };
  };

  const expireDueLeasesForLockedLane = async (lane: NonceLane): Promise<NonceLease[]> => {
    const nowMs = now();
    const laneKey = nonceLaneKey(lane);
    const expired: NonceLease[] = [];
    for (const lease of Array.from(leases.values())) {
      if (nonceLaneKey(lease.lane) !== laneKey) continue;
      const expiredLease = await expireLeaseLocked(lease, nowMs);
      if (expiredLease) expired.push(expiredLease);
    }
    return expired;
  };

  const expireDueLeasesForWallet = async (input?: { walletId?: string }): Promise<NonceLease[]> => {
    const walletId = input?.walletId ? String(input.walletId).trim() : '';
    const laneByKey = new Map<string, NonceLane>();
    for (const lease of Array.from(leases.values())) {
      if (walletId && nonceLaneSubjectId(lease.lane) !== walletId) continue;
      laneByKey.set(nonceLaneKey(lease.lane), lease.lane);
    }
    const expired: NonceLease[] = [];
    for (const lane of laneByKey.values()) {
      expired.push(...(await withLaneLock(lane, async () => expireDueLeasesForLockedLane(lane))));
    }
    return expired;
  };

  const recoverDurableLeases = async (input?: { walletId?: string }): Promise<void> => {
    if (!nonceLaneCoordinationStore) {
      if (shouldWarnOnMissingCoordinationStore) {
        emitCoordinationDegradedOnce(NonceCoordinatorDegradationReason.IndexedDBUnavailable);
      }
      return;
    }
    let readResults: Awaited<ReturnType<NonceLaneCoordinationStore['readAllForRecovery']>> = [];
    try {
      readResults = await nonceLaneCoordinationStore.readAllForRecovery(input);
    } catch {
      emitCoordinationDegradedOnce(NonceCoordinatorDegradationReason.DurableStoreError);
      return;
    }

    for (const readResult of readResults) {
      if (!readResult.ok) {
        if (readResult.leaseId) {
          await nonceLaneCoordinationStore.remove({
            laneKey: readResult.laneKey,
            leaseId: readResult.leaseId,
          });
        }
        emitCoordinationDegradedOnce(readResult.degradation.reason, {
          accountId: readResult.degradation.accountId,
          networkKey: readResult.degradation.networkKey,
          laneFamily: readResult.degradation.laneFamily,
          fallback: readResult.degradation.fallback,
        });
        continue;
      }
      const { record, lane, canonicalLaneKey, nonce: recordNonce } = readResult.parsed;
      await withLaneLock(lane, async () => {
        if (record.laneKey !== canonicalLaneKey) {
          await nonceLaneCoordinationStore.remove({
            laneKey: record.laneKey,
            leaseId: record.leaseId,
          });
          emitCoordinationDegradedOnce(NonceCoordinatorDegradationReason.MalformedDurableRecord, {
            accountId: nonceLaneSubjectId(lane),
            networkKey: record.networkKey,
            laneFamily: record.family,
            fallback: NonceCoordinatorFallback.None,
          });
          return;
        }
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
            state.inFlight.set(record.nonce.toString(), {
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
              record.nearAccountId,
              record.publicKey,
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
    operation: PreparedNonceOperationContext;
    count: number;
  }): Promise<NonceLease[]> => {
    await expireDueLeasesForLockedLane(input.lane);
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
    const diagnostics = createNonceCoordinatorDiagnostics({
      options: input,
      leases: leases.values(),
      nearState,
      observedCoordinationDegradations: observedCoordinationDegradations.values(),
      outcomeMetricEvents,
      nowMs: now(),
    });

    if (input?.emitMetrics) {
      emit({
        event: NonceCoordinatorTraceEventName.Metrics,
        metrics: diagnostics.metrics,
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
        initializeNearAccessKey({
          walletId: input.lane.walletId,
          nearAccountId: input.lane.nearAccountId,
          publicKey: input.lane.publicKey,
        });
        const context = {
          ...(input.fetchContext
            ? await input.fetchContext()
            : await fetchNearContextForLane({
                lane: input.lane,
                nearClient: input.nearClient,
                force: input.force === false ? false : true,
              })),
        };
        commitNearTransactionContextForState({
          state: nearState,
          walletId: input.lane.walletId,
          nearAccountId: input.lane.nearAccountId,
          publicKey: input.lane.publicKey,
          transactionContext: context,
          nowMs: now(),
        });
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
      return readNearActivePublicKey(nearState);
    },

    async fetchNearContext(input) {
      return await withLaneLock(input.lane, async () => fetchNearContextForLane(input));
    },

    async prefetchNearContext(input) {
      if (input?.kind === 'access_key_subject') {
        initializeNearAccessKey({
          walletId: input.walletId,
          nearAccountId: input.nearAccountId,
          publicKey: input.publicKey,
        });
      }
      if (!readNearAccessKeySubject(nearState)) return;
      clearNearPrefetchTimer(nearState);
      const nearClient = requireNearClient(input?.nearClient);
      nearState.prefetchTimer = setTimeout(() => {
        nearState.prefetchTimer = null;
        if (hasNearInflightFetch(nearState)) return;
        if (
          !shouldPrefetchNearContext({
            state: nearState,
            nowMs: now(),
            blockFreshnessThresholdMs: NEAR_BLOCK_FRESHNESS_THRESHOLD_MS,
          })
        ) {
          return;
        }
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
      const operationInput = normalizeLeaseOperationInput(input);
      const lease = readLease(operationInput);
      return await withLaneLock(lease.lane, async () => {
        const lockedLease = readLease(operationInput);
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
      const operationInput = normalizeLeaseOperationInput(input);
      const lease = readLease(operationInput);
      return await withLaneLock(lease.lane, async () => {
        const lockedLease = readLease(operationInput);
        preflightLeaseTransition(lockedLease, 'broadcast_accepted');
        if (isEvmNonceLease(lockedLease)) {
          await markEvmBroadcastAccepted(
            lockedLease,
            input.txHash ? String(input.txHash) : undefined,
          );
        } else if (isNearNonceLease(lockedLease)) {
          if (!input.txHash) {
            throw new Error('[NonceCoordinator] NEAR broadcast acceptance requires txHash');
          }
          await markNearBroadcastAcceptedState({
            lease: lockedLease,
            state: nearState,
            txHash: String(input.txHash),
            nowMs: now(),
            persistCoordinationLease,
          });
        } else {
          assertNever(lockedLease);
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
      const operationInput = normalizeLeaseOperationInput(input);
      const lease = readLease(operationInput);
      return await withLaneLock(lease.lane, async () => {
        const lockedLease = readLease(operationInput);
        preflightLeaseTransition(lockedLease, 'broadcast_rejected');
        await releaseBackendReservation(lockedLease);
        if (isNearNonceLease(lockedLease) && deps.nearClient) {
          try {
            await refreshNearNonceAfterBroadcastRejected(deps.nearClient);
          } catch {
            // Rejection handling must always release the lease; the next reservation can refresh again.
          }
        }
        transitionLease({
          lease: lockedLease,
          transition: 'broadcast_rejected',
          event: NonceCoordinatorTraceEventName.LeaseBroadcastRejected,
          reason: input.error instanceof Error ? input.error.message : String(input.error || ''),
        });
      });
    },

    async markFinalized(input) {
      const operationInput = normalizeLeaseOperationInput(input);
      const lease = readLease(operationInput);
      return await withLaneLock(lease.lane, async () => {
        const lockedLease = readLease(operationInput);
        preflightLeaseTransition(lockedLease, 'finalize');
        if (isEvmNonceLease(lockedLease)) {
          await markEvmFinalized(lockedLease);
        } else if (isNearNonceLease(lockedLease)) {
          if (deps.nearClient) {
            await updateNearNonceFromBlockchain(deps.nearClient, String(lockedLease.nonce));
          } else {
            await releaseBackendReservation(lockedLease);
          }
          await removeCoordinationLease(lockedLease);
        } else {
          assertNever(lockedLease);
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
      const operationInput = normalizeLeaseOperationInput(input);
      const lease = readLease(operationInput);
      assertEvmLease(lease);
      return await withLaneLock(lease.lane, async () => {
        const lockedLease = readLease(operationInput);
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
      const operationInput = normalizeLeaseOperationInput(input);
      const lease = readLease(operationInput);
      return await withLaneLock(lease.lane, async () => {
        const lockedLease = readLease(operationInput);
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
      return await expireDueLeasesForWallet(input);
    },

    async recoverDurableLeases(input) {
      await recoverDurableLeases(input);
    },

    async reconcile(input) {
      return await withLaneLock(input.lane, async () => {
        const status =
          input.lane.family === 'evm'
            ? await reconcileEvmLaneLocked(input.lane)
            : await reconcileNearLaneLocked(input.lane);
        emit({ event: NonceCoordinatorTraceEventName.LaneReconciled, lane: input.lane });
        return status;
      });
    },

    clearForWallet(walletId) {
      const normalizedWalletId = String(walletId || '').trim();
      if (!normalizedWalletId) return;
      void nonceLaneCoordinationStore
        ?.clearForWallet(normalizedWalletId)
        .catch(() =>
          emitCoordinationDegradedOnce(NonceCoordinatorDegradationReason.DurableStoreError),
        );
      const evmLaneKeys = evmAccountLaneKeys.get(normalizedWalletId);
      if (evmLaneKeys) {
        for (const key of evmLaneKeys) {
          evmStates.delete(key);
        }
        evmAccountLaneKeys.delete(normalizedWalletId);
      }
      if (readNearAccessKeySubject(nearState)?.walletId === normalizedWalletId) {
        clearNearAccessKeyState();
      }
      for (const [leaseId, lease] of leases.entries()) {
        if (nonceLaneSubjectId(lease.lane) === normalizedWalletId) {
          leases.delete(leaseId);
        }
      }
      emit({
        event: NonceCoordinatorTraceEventName.LanesCleared,
        accountId: normalizedWalletId,
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

type BuildCoordinationRecordArgs<TLease extends EvmNonceLease | NearNonceLease> = {
  lease: TLease;
  state: ParsedNonceLaneCoordinationRecord['record']['state'];
  expiresAtMs: number;
  updatedAtMs: number;
  runtimeId: string;
};

function isEvmNonceLease(lease: NonceLease): lease is EvmNonceLease {
  return lease.lane.family === 'evm';
}

function isNearNonceLease(lease: NonceLease): lease is NearNonceLease {
  return lease.lane.family === 'near';
}

function assertNever(value: never): never {
  throw new Error(`Unexpected nonce lease variant: ${String(value)}`);
}

function buildEvmCoordinationRecord(
  args: BuildCoordinationRecordArgs<EvmNonceLease>,
): Extract<ParsedNonceLaneCoordinationRecord['record'], { family: 'evm' }> {
  const lease = args.lease;
  const record: Extract<ParsedNonceLaneCoordinationRecord['record'], { family: 'evm' }> = {
    v: 1,
    laneKey: nonceLaneKey(lease.lane),
    leaseId: lease.leaseId,
    networkKey: nonceLaneNetworkKey(lease.lane),
    nonce: lease.nonce,
    state: args.state,
    operationId: String(lease.operationId),
    operationFingerprint: String(lease.operationFingerprint),
    reservedAtMs: lease.reservedAtMs,
    expiresAtMs: args.expiresAtMs,
    updatedAtMs: args.updatedAtMs,
    runtimeId: args.runtimeId,
    family: 'evm',
    chainTarget: lease.lane.chainTarget,
    accountId: lease.lane.subjectId,
    sender: lease.lane.sender,
  };
  if (lease.lane.nonceKey != null) {
    record.nonceKey = lease.lane.nonceKey;
  }
  addLeaseRecordMetadata(record, lease);
  return record;
}

function buildNearCoordinationRecord(
  args: BuildCoordinationRecordArgs<NearNonceLease>,
): Extract<ParsedNonceLaneCoordinationRecord['record'], { family: 'near' }> {
  const lease = args.lease;
  const record: Extract<ParsedNonceLaneCoordinationRecord['record'], { family: 'near' }> = {
    v: 1,
    laneKey: nonceLaneKey(lease.lane),
    leaseId: lease.leaseId,
    networkKey: nonceLaneNetworkKey(lease.lane),
    nonce: BigInt(lease.nonce),
    state: args.state,
    operationId: String(lease.operationId),
    operationFingerprint: String(lease.operationFingerprint),
    reservedAtMs: lease.reservedAtMs,
    expiresAtMs: args.expiresAtMs,
    updatedAtMs: args.updatedAtMs,
    runtimeId: args.runtimeId,
    family: 'near',
    walletId: lease.lane.walletId,
    nearAccountId: lease.lane.nearAccountId,
    publicKey: lease.lane.publicKey,
  };
  addLeaseRecordMetadata(record, lease);
  return record;
}

function addLeaseRecordMetadata(
  record: ParsedNonceLaneCoordinationRecord['record'],
  lease: EvmNonceLease | NearNonceLease,
): void {
  if (lease.batchId) {
    record.batchId = lease.batchId;
  }
  if (Number.isSafeInteger(lease.txIndex)) {
    record.txIndex = lease.txIndex;
  }
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
