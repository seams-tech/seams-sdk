import {
  consumeReservedRecoveryCode,
  releaseRecoveryCodeReservation,
  reserveRecoveryCode,
  type RecoveryCodeReservationId,
  type RecoveryCodeTransitionRejection,
} from './recoveryCodeReservation';
import type { RecoveryCodeLifecycleState } from './recoveryEnvelopes';

/**
 * One recovery attempt, with the code's lifecycle bound to its outcome.
 *
 * **A code is consumed only when the activation commits.** The three
 * transitions that enforce that already exist; what did not was anything
 * making the ordering structural. Spelling it out at each call site is a rule
 * that holds until someone adds an early return — and the failure is silent
 * and expensive: a code burned by a recovery that then failed leaves the user
 * one code poorer with nothing recovered.
 *
 * So the attempt owns the order. The caller supplies the work; this reserves
 * before it runs, consumes only if it reports a commit, and releases on every
 * other path including a throw.
 *
 * Nothing here persists. Each transition returns the next lifecycle for the
 * caller to write — this composes the decisions, it does not own the record.
 */

export type WalletRecoveryAttemptOutcome<T> =
  | {
      readonly kind: 'committed';
      readonly value: T;
      /** Consumed. Write this before reporting success. */
      readonly lifecycle: RecoveryCodeLifecycleState;
    }
  | {
      readonly kind: 'released';
      /** Back in the active pool: the attempt did not commit. */
      readonly lifecycle: RecoveryCodeLifecycleState;
      readonly reason: string;
    }
  | {
      readonly kind: 'refused';
      /** Unchanged: the code was never held by this attempt. */
      readonly lifecycle: RecoveryCodeLifecycleState;
      readonly code: RecoveryCodeTransitionRejection;
      readonly reason: string;
    };

/**
 * What the caller's activation work reports.
 *
 * `committed` is a claim that every required receipt verified — it is the
 * only thing that burns the code, so it must not be returned optimistically.
 */
export type WalletRecoveryActivationResult<T> =
  | { readonly kind: 'committed'; readonly value: T }
  | { readonly kind: 'not_committed'; readonly reason: string };

export async function runWalletRecoveryWithCode<T>(args: {
  readonly lifecycle: RecoveryCodeLifecycleState;
  readonly reservationId: RecoveryCodeReservationId;
  readonly nowMs: number;
  readonly reservationTtlMs: number;
  /** Reads the clock again at commit time: activation is not instantaneous. */
  readonly clockMs?: () => number;
  readonly activate: () => Promise<WalletRecoveryActivationResult<T>>;
}): Promise<WalletRecoveryAttemptOutcome<T>> {
  const reserved = reserveRecoveryCode({
    lifecycle: args.lifecycle,
    reservationId: args.reservationId,
    nowMs: args.nowMs,
    reservationTtlMs: args.reservationTtlMs,
  });
  if (!reserved.ok) {
    return {
      kind: 'refused',
      lifecycle: args.lifecycle,
      code: reserved.code,
      reason: reserved.message,
    };
  }

  const held = reserved.lifecycle;
  const clockMs = args.clockMs ?? (() => args.nowMs);

  let activation: WalletRecoveryActivationResult<T>;
  try {
    activation = await args.activate();
  } catch (error: unknown) {
    /* A throw is not a commit. Releasing here is what keeps a crashed recovery
       from costing a code — the one case a hand-written call site is most
       likely to miss. */
    return released(held, args.reservationId, errorReason(error));
  }

  if (activation.kind === 'not_committed') {
    return released(held, args.reservationId, activation.reason);
  }

  const consumed = consumeReservedRecoveryCode({
    lifecycle: held,
    reservationId: args.reservationId,
    nowMs: clockMs(),
  });
  if (!consumed.ok) {
    /* The activation committed but the hold no longer stands — an expired
       reservation another attempt may have taken. Reported rather than
       released: consumption is what a committed activation is owed, and
       handing the code back here would let it be spent twice. */
    return {
      kind: 'refused',
      lifecycle: held,
      code: consumed.code,
      reason: consumed.message,
    };
  }
  return { kind: 'committed', value: activation.value, lifecycle: consumed.lifecycle };
}

function released<T>(
  held: RecoveryCodeLifecycleState,
  reservationId: RecoveryCodeReservationId,
  reason: string,
): WalletRecoveryAttemptOutcome<T> {
  const release = releaseRecoveryCodeReservation({ lifecycle: held, reservationId });
  return {
    kind: 'released',
    // A release that cannot apply leaves the hold to expire on its own, which
    // is strictly safer than reporting the code as active when it is not.
    lifecycle: release.ok ? release.lifecycle : held,
    reason,
  };
}

function errorReason(error: unknown): string {
  return error instanceof Error ? error.message : 'recovery activation failed';
}
