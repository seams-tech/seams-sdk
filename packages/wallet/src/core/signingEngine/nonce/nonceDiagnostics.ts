import {
  EvmNonceOutcomeReason,
  NONCE_LEASE_STATES,
  NonceCoordinatorFallback,
  NonceCoordinatorTraceEventName,
  NonceLeaseState,
  type EvmNonceLane,
  type NonceCoordinatorAlert,
  type NonceCoordinatorAggregateMetrics,
  type NonceCoordinatorDegradation,
  type NonceCoordinatorDiagnostics,
  type NonceCoordinatorDiagnosticsOptions,
  type NonceCoordinatorOutcomeMetrics,
  type NonceCoordinatorTraceEvent,
  type NonceLane,
  type NonceLease,
} from './nonceTypes';
import {
  nonceLaneKey,
  nonceLaneNetworkKey,
  nonceLaneSubjectId,
} from './nonceLaneKeys';
import { isInFlightNonceLeaseState } from './nonceLeaseState';
import { normalizeMetricReason } from './nonceUtils';
import {
  hasNearTransactionContext,
  readNearActiveAccountId,
  readNearActivePublicKey,
  type NearNonceLaneState,
} from './nearNonceLane';

export type NonceOutcomeMetricKind =
  | 'dropped'
  | 'replaced'
  | 'reconciled'
  | 'released'
  | 'expired'
  | 'broadcast_rejected';

export type NonceOutcomeMetricEvent = {
  accountId?: string;
  kind: NonceOutcomeMetricKind;
  reason: string;
};

export type DroppedReplacedAlertWindow = {
  count: number;
  firstSeenAtMs: number;
  lastSeenAtMs: number;
};

export function recordCoordinationDegradationOnce(input: {
  observed: Map<string, NonceCoordinatorDegradation>;
  reason: NonceCoordinatorDegradation['reason'];
  lane?: NonceLane;
  fallback?: NonceCoordinatorDegradation['fallback'];
  accountId?: string;
  networkKey?: string;
  laneFamily?: NonceLane['family'];
}): { lane?: NonceLane; degradation: NonceCoordinatorDegradation } | null {
  const lane = input.lane;
  const fallback = input.fallback || NonceCoordinatorFallback.InRuntimeLock;
  const networkKey = lane ? nonceLaneNetworkKey(lane) : String(input.networkKey || '').trim();
  const accountId = lane ? nonceLaneSubjectId(lane) : String(input.accountId || '').trim();
  const laneFamily = lane?.family || input.laneFamily;
  const key = [input.reason, laneFamily || '', networkKey, accountId, fallback].join('|');
  if (input.observed.has(key)) return null;
  const degradation: NonceCoordinatorDegradation = {
    reason: input.reason,
    ...(laneFamily ? { laneFamily } : {}),
    ...(networkKey ? { networkKey } : {}),
    ...(accountId ? { accountId } : {}),
    fallback,
  };
  input.observed.set(key, degradation);
  return {
    ...(lane ? { lane } : {}),
    degradation,
  };
}

export function recordDroppedReplacedAlertWindow(input: {
  alerts: Map<string, DroppedReplacedAlertWindow>;
  lane: EvmNonceLane;
  reason: EvmNonceOutcomeReason;
  nowMs: number;
  threshold: number;
  windowMs: number;
}): { alert: NonceCoordinatorAlert; warning: Record<string, unknown> } | null {
  const key = [nonceLaneKey(input.lane), input.reason].join('|');
  const existing = input.alerts.get(key);
  const windowState =
    existing && input.nowMs - existing.firstSeenAtMs <= input.windowMs
      ? {
          count: existing.count + 1,
          firstSeenAtMs: existing.firstSeenAtMs,
          lastSeenAtMs: input.nowMs,
        }
      : {
          count: 1,
          firstSeenAtMs: input.nowMs,
          lastSeenAtMs: input.nowMs,
        };
  input.alerts.set(key, windowState);
  if (windowState.count < input.threshold) return null;

  const alert: NonceCoordinatorAlert = {
    kind: 'repeated_dropped_or_replaced',
    severity: 'warning',
    lane: input.lane,
    reason: input.reason,
    count: windowState.count,
    windowMs: input.windowMs,
    firstSeenAtMs: windowState.firstSeenAtMs,
    lastSeenAtMs: windowState.lastSeenAtMs,
  };
  return {
    alert,
    warning: {
      chainTarget: input.lane.chainTarget,
      networkKey: nonceLaneNetworkKey(input.lane),
      chainId: input.lane.chainTarget.chainId,
      sender: input.lane.sender,
      nonceKey: input.lane.nonceKey?.toString(),
      subjectId: input.lane.subjectId,
      reason: input.reason,
      count: windowState.count,
      windowMs: input.windowMs,
    },
  };
}

export function createEmptyLeaseStateCounts(): Record<NonceLeaseState, number> {
  const counts = {} as Record<NonceLeaseState, number>;
  for (const state of NONCE_LEASE_STATES) {
    counts[state] = 0;
  }
  return counts;
}

export function appendOutcomeMetricEvent(
  sink: NonceOutcomeMetricEvent[],
  event: NonceCoordinatorTraceEvent,
): void {
  const accountId =
    (event.lease?.lane ? nonceLaneSubjectId(event.lease.lane) : '') ||
    (event.lane ? nonceLaneSubjectId(event.lane) : '') ||
    event.accountId;
  const push = (kind: NonceOutcomeMetricKind, reason: string): void => {
    sink.push({
      ...(accountId ? { accountId } : {}),
      kind,
      reason,
    });
  };
  if (event.event === NonceCoordinatorTraceEventName.LeaseDropped) {
    push(EvmNonceOutcomeReason.Dropped, EvmNonceOutcomeReason.Dropped);
    return;
  }
  if (event.event === NonceCoordinatorTraceEventName.LeaseReplaced) {
    push(EvmNonceOutcomeReason.Replaced, EvmNonceOutcomeReason.Replaced);
    return;
  }
  if (event.event === NonceCoordinatorTraceEventName.LaneReconciled) {
    push('reconciled', normalizeMetricReason(event.reason, 'manual'));
    return;
  }
  if (event.event === NonceCoordinatorTraceEventName.LeaseReleased) {
    push('released', normalizeMetricReason(event.reason, 'unspecified'));
    return;
  }
  if (event.event === NonceCoordinatorTraceEventName.LeaseExpired) {
    push('expired', normalizeMetricReason(event.reason, 'lease_ttl_elapsed'));
    return;
  }
  if (event.event === NonceCoordinatorTraceEventName.LeaseBroadcastRejected) {
    push(NonceLeaseState.BroadcastRejected, NonceLeaseState.BroadcastRejected);
  }
}

export function readOutcomeMetrics(
  events: readonly NonceOutcomeMetricEvent[],
  accountId: string,
): NonceCoordinatorOutcomeMetrics {
  const metrics: NonceCoordinatorOutcomeMetrics = {
    droppedCount: 0,
    replacedCount: 0,
    reconciledCount: 0,
    releasedCount: 0,
    expiredCount: 0,
    broadcastRejectedCount: 0,
    releaseReasons: {},
    reconcileReasons: {},
    expiryReasons: {},
  };

  for (const event of events) {
    if (accountId && event.accountId !== accountId) continue;
    if (event.kind === EvmNonceOutcomeReason.Dropped) {
      metrics.droppedCount += 1;
      continue;
    }
    if (event.kind === EvmNonceOutcomeReason.Replaced) {
      metrics.replacedCount += 1;
      continue;
    }
    if (event.kind === 'broadcast_rejected') {
      metrics.broadcastRejectedCount += 1;
      continue;
    }
    if (event.kind === 'reconciled') {
      metrics.reconciledCount += 1;
      metrics.reconcileReasons[event.reason] = (metrics.reconcileReasons[event.reason] || 0) + 1;
      continue;
    }
    if (event.kind === 'released') {
      metrics.releasedCount += 1;
      metrics.releaseReasons[event.reason] = (metrics.releaseReasons[event.reason] || 0) + 1;
      continue;
    }
    if (event.kind === 'expired') {
      metrics.expiredCount += 1;
      metrics.expiryReasons[event.reason] = (metrics.expiryReasons[event.reason] || 0) + 1;
    }
  }

  return metrics;
}

export function createNonceCoordinatorDiagnostics(input: {
  options?: NonceCoordinatorDiagnosticsOptions;
  leases: Iterable<NonceLease>;
  nearState: NearNonceLaneState;
  observedCoordinationDegradations: Iterable<NonceCoordinatorDegradation>;
  outcomeMetricEvents: readonly NonceOutcomeMetricEvent[];
  nowMs: number;
}): NonceCoordinatorDiagnostics {
  const accountId = input.options?.accountId ? String(input.options.accountId).trim() : '';
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

  for (const lease of input.leases) {
    if (accountId && nonceLaneSubjectId(lease.lane) !== accountId) continue;
    leaseCount += 1;
    leasesByState[lease.state] += 1;
    const laneKey = nonceLaneKey(lease.lane);
    const leaseAgeMs = Math.max(0, input.nowMs - lease.reservedAtMs);
    oldestLeaseAgeMs = Math.max(oldestLeaseAgeMs, leaseAgeMs);
    if (isInFlightNonceLeaseState(lease.state)) {
      oldestInFlightLeaseAgeMs = Math.max(oldestInFlightLeaseAgeMs, leaseAgeMs);
      if (lease.expiresAtMs <= input.nowMs) {
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
    atMs: input.nowMs,
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
    outcomes: readOutcomeMetrics(input.outcomeMetricEvents, accountId),
  };
  const nearActiveAccountId = readNearActiveAccountId(input.nearState);
  const nearActivePublicKey = readNearActivePublicKey(input.nearState);

  return {
    leaseCount,
    leasesByState,
    laneCount: lanes.size,
    metrics,
    coordinationWarnings: Array.from(input.observedCoordinationDegradations).filter(
      (degradation) =>
        !accountId || !degradation.accountId || degradation.accountId === accountId,
    ),
    lanes: Array.from(lanes.values()).map((entry) => ({
      family: entry.lane.family,
      accountId: nonceLaneSubjectId(entry.lane),
      networkKey: nonceLaneNetworkKey(entry.lane),
      ...(entry.lane.family === 'evm'
        ? { chain: entry.lane.chainTarget.kind, chainId: entry.lane.chainTarget.chainId }
        : {}),
      leaseCount: entry.leaseCount,
      states: { ...entry.states },
    })),
    near: {
      ...(nearActiveAccountId ? { activeAccountId: nearActiveAccountId } : {}),
      ...(nearActivePublicKey ? { activePublicKey: nearActivePublicKey } : {}),
      hasContext: hasNearTransactionContext(input.nearState),
      reservedNonceCount: input.nearState.reservedNonces.size,
      ...(input.nearState.lastReservedNonce
        ? { lastReservedNonce: input.nearState.lastReservedNonce }
        : {}),
    },
  };
}
