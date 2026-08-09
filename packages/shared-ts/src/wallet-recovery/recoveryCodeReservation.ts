import type { RecoveryCodeLifecycleState } from './recoveryEnvelopes';

/**
 * Recovery-code reservation lifecycle.
 *
 * A code is held while a recovery runs and is consumed only once the complete
 * replacement-credential activation commits. That ordering is the point: a code
 * burned at the start of a recovery that then fails would leave the user one
 * code poorer with nothing recovered.
 *
 * Reservations expire so an abandoned recovery cannot strand a code forever.
 * Expiry is evaluated against the caller's clock at transition time rather than
 * swept in the background, so a stale hold never blocks a fresh attempt.
 */

export type RecoveryCodeReservationId = string & {
  readonly __recoveryCodeReservationIdBrand: 'RecoveryCodeReservationId';
};

export type RecoveryCodeTransitionResult =
  | { ok: true; lifecycle: RecoveryCodeLifecycleState }
  | { ok: false; code: RecoveryCodeTransitionRejection; message: string };

export type RecoveryCodeTransitionRejection =
  | 'already_consumed'
  | 'revoked'
  | 'already_reserved'
  | 'not_reserved'
  | 'reservation_expired'
  | 'reservation_mismatch';

export function parseRecoveryCodeReservationId(value: unknown): RecoveryCodeReservationId {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > 512 ||
    value.trim() !== value ||
    /[\s\u0000-\u001f\u007f]/.test(value)
  ) {
    throw new Error('recovery code reservation id must be a compact opaque identifier');
  }
  return value as RecoveryCodeReservationId;
}

function reject(
  code: RecoveryCodeTransitionRejection,
  message: string,
): RecoveryCodeTransitionResult {
  return { ok: false, code, message };
}

/**
 * Places a hold on an active code.
 *
 * A reservation that has already expired is treated as absent, so an abandoned
 * attempt does not block a later one. A live reservation held by a different
 * recovery is refused: two concurrent recoveries must not share one code.
 */
export function reserveRecoveryCode(args: {
  lifecycle: RecoveryCodeLifecycleState;
  reservationId: RecoveryCodeReservationId;
  nowMs: number;
  reservationTtlMs: number;
}): RecoveryCodeTransitionResult {
  const { lifecycle } = args;
  if (lifecycle.state === 'consumed') {
    return reject('already_consumed', 'recovery code has already been consumed');
  }
  if (lifecycle.state === 'revoked') {
    return reject('revoked', 'recovery code has been revoked');
  }
  if (args.reservationTtlMs <= 0) {
    return reject('reservation_expired', 'reservation ttl must be positive');
  }
  if (
    lifecycle.state === 'reserved' &&
    lifecycle.reservationExpiresAtMs > args.nowMs &&
    lifecycle.reservationId !== args.reservationId
  ) {
    return reject('already_reserved', 'recovery code is reserved by another recovery');
  }
  return {
    ok: true,
    lifecycle: {
      state: 'reserved',
      issuedAtMs: lifecycle.issuedAtMs,
      reservationId: args.reservationId,
      reservedAtMs: args.nowMs,
      reservationExpiresAtMs: args.nowMs + args.reservationTtlMs,
    },
  };
}

/**
 * Releases a hold after a failed pre-commit recovery, returning the code to the
 * active pool. Releasing a consumed code is refused: consumption is terminal
 * and a post-commit failure must not hand the code back.
 */
export function releaseRecoveryCodeReservation(args: {
  lifecycle: RecoveryCodeLifecycleState;
  reservationId: RecoveryCodeReservationId;
}): RecoveryCodeTransitionResult {
  const { lifecycle } = args;
  if (lifecycle.state === 'consumed') {
    return reject('already_consumed', 'a consumed recovery code cannot be released');
  }
  if (lifecycle.state === 'revoked') {
    return reject('revoked', 'recovery code has been revoked');
  }
  if (lifecycle.state !== 'reserved') {
    return reject('not_reserved', 'recovery code is not reserved');
  }
  if (lifecycle.reservationId !== args.reservationId) {
    return reject('reservation_mismatch', 'reservation id does not hold this recovery code');
  }
  return { ok: true, lifecycle: { state: 'active', issuedAtMs: lifecycle.issuedAtMs } };
}

/**
 * Consumes a reserved code once every required activation receipt has verified.
 *
 * The reservation must still be live and held by this exact recovery. An
 * expired hold cannot be consumed: the code may have been re-reserved by
 * another attempt in the meantime, and consuming it here would burn a code that
 * a different recovery is relying on.
 */
export function consumeReservedRecoveryCode(args: {
  lifecycle: RecoveryCodeLifecycleState;
  reservationId: RecoveryCodeReservationId;
  nowMs: number;
}): RecoveryCodeTransitionResult {
  const { lifecycle } = args;
  if (lifecycle.state === 'consumed') {
    return reject('already_consumed', 'recovery code has already been consumed');
  }
  if (lifecycle.state === 'revoked') {
    return reject('revoked', 'recovery code has been revoked');
  }
  if (lifecycle.state !== 'reserved') {
    return reject('not_reserved', 'recovery code must be reserved before it is consumed');
  }
  if (lifecycle.reservationId !== args.reservationId) {
    return reject('reservation_mismatch', 'reservation id does not hold this recovery code');
  }
  if (lifecycle.reservationExpiresAtMs <= args.nowMs) {
    return reject('reservation_expired', 'recovery code reservation expired before commit');
  }
  return {
    ok: true,
    lifecycle: {
      state: 'consumed',
      issuedAtMs: lifecycle.issuedAtMs,
      reservationId: args.reservationId,
      consumedAtMs: args.nowMs,
    },
  };
}

/** Revocation is terminal from every state except consumption. */
export function revokeRecoveryCode(args: {
  lifecycle: RecoveryCodeLifecycleState;
  nowMs: number;
}): RecoveryCodeTransitionResult {
  if (args.lifecycle.state === 'consumed') {
    return reject('already_consumed', 'a consumed recovery code cannot be revoked');
  }
  if (args.lifecycle.state === 'revoked') {
    return reject('revoked', 'recovery code has already been revoked');
  }
  return {
    ok: true,
    lifecycle: {
      state: 'revoked',
      issuedAtMs: args.lifecycle.issuedAtMs,
      revokedAtMs: args.nowMs,
    },
  };
}

/**
 * Whether a code can back a new recovery attempt right now. An expired
 * reservation counts as available, matching `reserveRecoveryCode`.
 */
export function isRecoveryCodeAvailable(
  lifecycle: RecoveryCodeLifecycleState,
  nowMs: number,
): boolean {
  if (lifecycle.state === 'active') return true;
  return lifecycle.state === 'reserved' && lifecycle.reservationExpiresAtMs <= nowMs;
}
