import type { RecoveryCodeReservationId } from './recoveryCodeReservation';

/**
 * Lifecycle of one recovery code.
 *
 * `reserved` is a transient hold taken while a recovery runs; consumption
 * commits only after the replacement credential activates. See
 * `recoveryCodeReservation.ts` for the transitions between these states.
 */
export type RecoveryCodeLifecycleState =
  | {
      state: 'active';
      issuedAtMs: number;
      reservationId?: never;
      reservedAtMs?: never;
      reservationExpiresAtMs?: never;
      consumedAtMs?: never;
      revokedAtMs?: never;
    }
  | {
      state: 'reserved';
      issuedAtMs: number;
      reservationId: RecoveryCodeReservationId;
      reservedAtMs: number;
      reservationExpiresAtMs: number;
      consumedAtMs?: never;
      revokedAtMs?: never;
    }
  | {
      state: 'consumed';
      issuedAtMs: number;
      reservationId: RecoveryCodeReservationId;
      consumedAtMs: number;
      reservedAtMs?: never;
      reservationExpiresAtMs?: never;
      revokedAtMs?: never;
    }
  | {
      state: 'revoked';
      issuedAtMs: number;
      revokedAtMs: number;
      reservationId?: never;
      reservedAtMs?: never;
      reservationExpiresAtMs?: never;
      consumedAtMs?: never;
    };
