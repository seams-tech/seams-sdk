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

export function reduceNonceLeaseState(
  current: NonceLeaseState,
  transition: NonceLeaseTransition,
): NonceLeaseState {
  if (transition === 'release') {
    if (current === NonceLeaseState.Released) return current;
    if (current === NonceLeaseState.Reserved) return NonceLeaseState.Released;
    throw createIllegalNonceTransitionError(current, transition);
  }

  if (transition === 'expire') {
    if (current === NonceLeaseState.Reserved) return NonceLeaseState.Expired;
    if (current === NonceLeaseState.Signed) return NonceLeaseState.SignedLeaseExpired;
    if (current === NonceLeaseState.Expired || current === NonceLeaseState.SignedLeaseExpired) {
      return current;
    }
    throw createIllegalNonceTransitionError(current, transition);
  }

  if (transition === 'mark_signed') {
    if (current === NonceLeaseState.Reserved || current === NonceLeaseState.Signed) {
      return NonceLeaseState.Signed;
    }
    throw createIllegalNonceTransitionError(current, transition);
  }

  if (transition === 'broadcast_accepted') {
    if (current === NonceLeaseState.Signed || current === NonceLeaseState.BroadcastAccepted) {
      return NonceLeaseState.BroadcastAccepted;
    }
    throw createIllegalNonceTransitionError(current, transition);
  }

  if (transition === 'broadcast_rejected') {
    if (current === NonceLeaseState.Signed || current === NonceLeaseState.BroadcastRejected) {
      return NonceLeaseState.BroadcastRejected;
    }
    throw createIllegalNonceTransitionError(current, transition);
  }

  if (transition === 'finalize') {
    if (current === NonceLeaseState.BroadcastAccepted || current === NonceLeaseState.Finalized) {
      return NonceLeaseState.Finalized;
    }
    throw createIllegalNonceTransitionError(current, transition);
  }

  if (transition === 'drop') {
    if (current === NonceLeaseState.BroadcastAccepted || current === NonceLeaseState.Dropped) {
      return NonceLeaseState.Dropped;
    }
    throw createIllegalNonceTransitionError(current, transition);
  }

  if (transition === 'replace') {
    if (current === NonceLeaseState.BroadcastAccepted || current === NonceLeaseState.Replaced) {
      return NonceLeaseState.Replaced;
    }
    throw createIllegalNonceTransitionError(current, transition);
  }

  if (transition === 'reconcile') {
    if (
      current === NonceLeaseState.Released ||
      current === NonceLeaseState.Expired ||
      current === NonceLeaseState.SignedLeaseExpired ||
      current === NonceLeaseState.BroadcastRejected ||
      current === NonceLeaseState.Dropped ||
      current === NonceLeaseState.Replaced ||
      current === NonceLeaseState.Reconciled
    ) {
      return NonceLeaseState.Reconciled;
    }
    throw createIllegalNonceTransitionError(current, transition);
  }

  throw createIllegalNonceTransitionError(current, transition);
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
  return (
    (record.state === NonceDurableLeaseState.Reserved ||
      record.state === NonceDurableLeaseState.Signed ||
      record.state === NonceDurableLeaseState.BroadcastAccepted) &&
    record.expiresAtMs > nowMs
  );
}

function createIllegalNonceTransitionError(current: NonceLeaseState, transition: string): Error {
  return new Error(
    `[NonceCoordinator] illegal nonce lease transition: ${current} -> ${transition}`,
  );
}
