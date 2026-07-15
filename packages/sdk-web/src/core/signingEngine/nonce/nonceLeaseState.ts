import {
  NonceDurableLeaseState,
  NonceLeaseState,
  type NonceLaneCoordinationRecord,
} from './nonceTypes';

export type NonceLeaseTransition =
  | 'release'
  | 'expire'
  | 'mark_signed'
  | 'broadcast_accepted'
  | 'broadcast_rejected'
  | 'finalize'
  | 'drop'
  | 'replace'
  | 'reconcile';

export type NonceLeaseTransitionResult =
  | {
      ok: true;
      state: NonceLeaseState;
    }
  | {
      ok: false;
      current: NonceLeaseState;
      transition: NonceLeaseTransition;
      reason: 'illegal_transition';
    };

export function reduceNonceLeaseState(
  current: NonceLeaseState,
  transition: NonceLeaseTransition,
): NonceLeaseState {
  const result = tryReduceNonceLeaseState(current, transition);
  if (result.ok) return result.state;
  throw createIllegalNonceTransitionError(result.current, result.transition);
}

export function tryReduceNonceLeaseState(
  current: NonceLeaseState,
  transition: NonceLeaseTransition,
): NonceLeaseTransitionResult {
  switch (transition) {
    case 'release':
      return reduceReleaseNonceLeaseState(current);
    case 'expire':
      return reduceExpireNonceLeaseState(current);
    case 'mark_signed':
      return reduceMarkSignedNonceLeaseState(current);
    case 'broadcast_accepted':
      return reduceBroadcastAcceptedNonceLeaseState(current);
    case 'broadcast_rejected':
      return reduceBroadcastRejectedNonceLeaseState(current);
    case 'finalize':
      return reduceFinalizeNonceLeaseState(current);
    case 'drop':
      return reduceDropNonceLeaseState(current);
    case 'replace':
      return reduceReplaceNonceLeaseState(current);
    case 'reconcile':
      return reduceReconcileNonceLeaseState(current);
    default:
      return assertNeverNonceLeaseTransition(transition);
  }
}

function reduceReleaseNonceLeaseState(current: NonceLeaseState): NonceLeaseTransitionResult {
  switch (current) {
    case NonceLeaseState.Released:
      return acceptedNonceTransition(current);
    case NonceLeaseState.Reserved:
      return acceptedNonceTransition(NonceLeaseState.Released);
    default:
      return rejectedNonceTransition(current, 'release');
  }
}

function reduceExpireNonceLeaseState(current: NonceLeaseState): NonceLeaseTransitionResult {
  switch (current) {
    case NonceLeaseState.Reserved:
      return acceptedNonceTransition(NonceLeaseState.Expired);
    case NonceLeaseState.Signed:
      return acceptedNonceTransition(NonceLeaseState.SignedLeaseExpired);
    case NonceLeaseState.Expired:
    case NonceLeaseState.SignedLeaseExpired:
      return acceptedNonceTransition(current);
    default:
      return rejectedNonceTransition(current, 'expire');
  }
}

function reduceMarkSignedNonceLeaseState(current: NonceLeaseState): NonceLeaseTransitionResult {
  switch (current) {
    case NonceLeaseState.Reserved:
    case NonceLeaseState.Signed:
      return acceptedNonceTransition(NonceLeaseState.Signed);
    default:
      return rejectedNonceTransition(current, 'mark_signed');
  }
}

function reduceBroadcastAcceptedNonceLeaseState(
  current: NonceLeaseState,
): NonceLeaseTransitionResult {
  switch (current) {
    case NonceLeaseState.Signed:
    case NonceLeaseState.BroadcastAccepted:
      return acceptedNonceTransition(NonceLeaseState.BroadcastAccepted);
    default:
      return rejectedNonceTransition(current, 'broadcast_accepted');
  }
}

function reduceBroadcastRejectedNonceLeaseState(
  current: NonceLeaseState,
): NonceLeaseTransitionResult {
  switch (current) {
    case NonceLeaseState.Signed:
    case NonceLeaseState.BroadcastRejected:
      return acceptedNonceTransition(NonceLeaseState.BroadcastRejected);
    default:
      return rejectedNonceTransition(current, 'broadcast_rejected');
  }
}

function reduceFinalizeNonceLeaseState(current: NonceLeaseState): NonceLeaseTransitionResult {
  switch (current) {
    case NonceLeaseState.BroadcastAccepted:
    case NonceLeaseState.Finalized:
      return acceptedNonceTransition(NonceLeaseState.Finalized);
    default:
      return rejectedNonceTransition(current, 'finalize');
  }
}

function reduceDropNonceLeaseState(current: NonceLeaseState): NonceLeaseTransitionResult {
  switch (current) {
    case NonceLeaseState.BroadcastAccepted:
    case NonceLeaseState.Dropped:
      return acceptedNonceTransition(NonceLeaseState.Dropped);
    default:
      return rejectedNonceTransition(current, 'drop');
  }
}

function reduceReplaceNonceLeaseState(current: NonceLeaseState): NonceLeaseTransitionResult {
  switch (current) {
    case NonceLeaseState.BroadcastAccepted:
    case NonceLeaseState.Replaced:
      return acceptedNonceTransition(NonceLeaseState.Replaced);
    default:
      return rejectedNonceTransition(current, 'replace');
  }
}

function reduceReconcileNonceLeaseState(current: NonceLeaseState): NonceLeaseTransitionResult {
  switch (current) {
    case NonceLeaseState.Released:
    case NonceLeaseState.Expired:
    case NonceLeaseState.SignedLeaseExpired:
    case NonceLeaseState.BroadcastRejected:
    case NonceLeaseState.Dropped:
    case NonceLeaseState.Replaced:
    case NonceLeaseState.Reconciled:
      return acceptedNonceTransition(NonceLeaseState.Reconciled);
    default:
      return rejectedNonceTransition(current, 'reconcile');
  }
}

function acceptedNonceTransition(state: NonceLeaseState): NonceLeaseTransitionResult {
  return {
    ok: true,
    state,
  };
}

function rejectedNonceTransition(
  current: NonceLeaseState,
  transition: NonceLeaseTransition,
): NonceLeaseTransitionResult {
  return {
    ok: false,
    current,
    transition,
    reason: 'illegal_transition',
  };
}

function assertNeverNonceLeaseTransition(value: never): never {
  throw new Error(`[NonceCoordinator] unhandled nonce lease transition: ${String(value)}`);
}

export function isInFlightNonceLeaseState(state: NonceLeaseState): boolean {
  return state === NonceLeaseState.Reserved || state === NonceLeaseState.Signed;
}

export function isActiveEvmLeaseState(state: NonceLeaseState): boolean {
  return (
    state === NonceLeaseState.Reserved ||
    state === NonceLeaseState.Signed ||
    state === NonceLeaseState.BroadcastAccepted
  );
}

export function isActiveNearLeaseState(state: NonceLeaseState): boolean {
  return (
    state === NonceLeaseState.Reserved ||
    state === NonceLeaseState.Signed ||
    state === NonceLeaseState.BroadcastAccepted
  );
}

export function isActiveCoordinationLeaseRecord(
  record: NonceLaneCoordinationRecord,
  nowMs: number,
): boolean {
  if (record.state === NonceDurableLeaseState.BroadcastAccepted) return true;
  return (
    (record.state === NonceDurableLeaseState.Reserved ||
      record.state === NonceDurableLeaseState.Signed) &&
    record.expiresAtMs > nowMs
  );
}

function createIllegalNonceTransitionError(current: NonceLeaseState, transition: string): Error {
  return new Error(
    `[NonceCoordinator] illegal nonce lease transition: ${current} -> ${transition}`,
  );
}
