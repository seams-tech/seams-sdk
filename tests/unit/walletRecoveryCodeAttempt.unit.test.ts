import { expect, test } from '@playwright/test';
import { runWalletRecoveryWithCode } from '../../packages/shared-ts/src/wallet-recovery/recoveryCodeAttempt';
import type { RecoveryCodeReservationId } from '../../packages/shared-ts/src/wallet-recovery/recoveryCodeReservation';
import type { RecoveryCodeLifecycleState } from '../../packages/shared-ts/src/wallet-recovery/recoveryEnvelopes';

/**
 * A recovery code is consumed only when the activation commits.
 *
 * The three transitions that enforce that already existed; what did not was
 * anything making the ordering structural. These own the property that
 * replaces the convention: a code burned by a recovery that then failed leaves
 * the user one code poorer with nothing recovered.
 */

const RESERVATION = 'reservation-1' as RecoveryCodeReservationId;
const NOW = 1_700_000_000_000;
const TTL = 60_000;

const ACTIVE: RecoveryCodeLifecycleState = { state: 'active', issuedAtMs: 1_000 };

test('a committed activation consumes the code', async () => {
  const outcome = await runWalletRecoveryWithCode({
    lifecycle: ACTIVE,
    reservationId: RESERVATION,
    nowMs: NOW,
    reservationTtlMs: TTL,
    activate: async () => ({ kind: 'committed', value: 'wallet-recovered' }),
  });

  expect(outcome.kind).toBe('committed');
  expect(outcome.kind === 'committed' && outcome.value).toBe('wallet-recovered');
  expect(outcome.lifecycle.state).toBe('consumed');
});

test('an activation that did not commit returns the code to the pool', async () => {
  const outcome = await runWalletRecoveryWithCode({
    lifecycle: ACTIVE,
    reservationId: RESERVATION,
    nowMs: NOW,
    reservationTtlMs: TTL,
    activate: async () => ({ kind: 'not_committed', reason: 'a signer never activated' }),
  });

  expect(outcome.kind).toBe('released');
  expect(outcome.lifecycle.state).toBe('active');
  expect(outcome.kind === 'released' && outcome.reason).toContain('never activated');
});

test('a throw is not a commit', async () => {
  /* The case a hand-written call site is most likely to miss: an exception
     between reserving and committing must not cost a code. */
  const outcome = await runWalletRecoveryWithCode({
    lifecycle: ACTIVE,
    reservationId: RESERVATION,
    nowMs: NOW,
    reservationTtlMs: TTL,
    activate: async () => {
      throw new Error('the Router went away');
    },
  });

  expect(outcome.kind).toBe('released');
  expect(outcome.lifecycle.state).toBe('active');
  expect(outcome.kind === 'released' && outcome.reason).toContain('Router went away');
});

test('the activation never runs when the code cannot be held', async () => {
  // Work must not start against a code this attempt does not own.
  let ran = false;
  const outcome = await runWalletRecoveryWithCode({
    lifecycle: {
      state: 'consumed',
      issuedAtMs: 1_000,
      reservationId: RESERVATION,
      consumedAtMs: 2_000,
    },
    reservationId: RESERVATION,
    nowMs: NOW,
    reservationTtlMs: TTL,
    activate: async () => {
      ran = true;
      return { kind: 'committed', value: 'never' };
    },
  });

  expect(ran).toBe(false);
  expect(outcome.kind).toBe('refused');
  expect(outcome.kind === 'refused' && outcome.code).toBe('already_consumed');
  // Untouched: the attempt never held it.
  expect(outcome.lifecycle).toEqual({
    state: 'consumed',
    issuedAtMs: 1_000,
    reservationId: RESERVATION,
    consumedAtMs: 2_000,
  });
});

test('a code another recovery holds is refused', async () => {
  const outcome = await runWalletRecoveryWithCode({
    lifecycle: {
      state: 'reserved',
      issuedAtMs: 1_000,
      reservationId: 'someone-else' as RecoveryCodeReservationId,
      reservedAtMs: NOW,
      reservationExpiresAtMs: NOW + TTL,
    },
    reservationId: RESERVATION,
    nowMs: NOW,
    reservationTtlMs: TTL,
    activate: async () => ({ kind: 'committed', value: 'never' }),
  });

  expect(outcome.kind).toBe('refused');
  expect(outcome.kind === 'refused' && outcome.code).toBe('already_reserved');
});

test('a commit whose hold expired is refused, not released', async () => {
  /* The activation committed, so the code is owed consumption — but the hold
     lapsed and another attempt may have taken it. Handing it back here would
     let one code be spent twice. */
  const outcome = await runWalletRecoveryWithCode({
    lifecycle: ACTIVE,
    reservationId: RESERVATION,
    nowMs: NOW,
    reservationTtlMs: TTL,
    clockMs: () => NOW + TTL + 1,
    activate: async () => ({ kind: 'committed', value: 'wallet-recovered' }),
  });

  expect(outcome.kind).toBe('refused');
  expect(outcome.kind === 'refused' && outcome.code).toBe('reservation_expired');
  expect(outcome.lifecycle.state).toBe('reserved');
});
