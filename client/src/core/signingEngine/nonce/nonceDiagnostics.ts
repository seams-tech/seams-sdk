import {
  EvmNonceOutcomeReason,
  NONCE_LEASE_STATES,
  NonceCoordinatorTraceEventName,
  NonceLeaseState,
  type NonceCoordinatorOutcomeMetrics,
  type NonceCoordinatorTraceEvent,
} from './nonceTypes';
import { nonceLaneSubjectId } from './nonceLaneKeys';
import { normalizeMetricReason } from './nonceUtils';

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
    nonceLaneSubjectId(event.lease?.lane) || nonceLaneSubjectId(event.lane) || event.accountId;
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
