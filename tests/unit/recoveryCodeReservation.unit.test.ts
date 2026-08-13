import { expect, test } from '@playwright/test';
import {
  consumeReservedRecoveryCode,
  isRecoveryCodeAvailable,
  releaseRecoveryCodeReservation,
  reserveRecoveryCode,
  revokeRecoveryCode,
  type RecoveryCodeLifecycleState,
  type RecoveryCodeReservationId,
} from '@shared/wallet-recovery';

const RESERVATION = 'recovery-reservation-1' as RecoveryCodeReservationId;
const OTHER_RESERVATION = 'recovery-reservation-2' as RecoveryCodeReservationId;
const TTL_MS = 10_000;
const ISSUED_AT = 1_000;

const active: RecoveryCodeLifecycleState = { state: 'active', issuedAtMs: ISSUED_AT };

function reserved(nowMs: number, reservationId = RESERVATION): RecoveryCodeLifecycleState {
  const result = reserveRecoveryCode({
    lifecycle: active,
    reservationId,
    nowMs,
    reservationTtlMs: TTL_MS,
  });
  if (!result.ok) throw new Error(result.message);
  return result.lifecycle;
}

test('a reservation holds a code and consumption commits it', () => {
  const held = reserved(2_000);
  expect(held).toEqual({
    state: 'reserved',
    issuedAtMs: ISSUED_AT,
    reservationId: RESERVATION,
    reservedAtMs: 2_000,
    reservationExpiresAtMs: 12_000,
  });

  const consumed = consumeReservedRecoveryCode({
    lifecycle: held,
    reservationId: RESERVATION,
    nowMs: 3_000,
  });
  expect(consumed).toEqual({
    ok: true,
    lifecycle: {
      state: 'consumed',
      issuedAtMs: ISSUED_AT,
      reservationId: RESERVATION,
      consumedAtMs: 3_000,
    },
  });
});

test('a code cannot be consumed without first being reserved', () => {
  // Consumption must follow activation, so a code can never be burned by a
  // recovery that never held it.
  const direct = consumeReservedRecoveryCode({
    lifecycle: active,
    reservationId: RESERVATION,
    nowMs: 2_000,
  });
  expect(direct).toMatchObject({ ok: false, code: 'not_reserved' });
});

test('a failed pre-commit recovery releases the code back to active', () => {
  const held = reserved(2_000);
  const released = releaseRecoveryCodeReservation({
    lifecycle: held,
    reservationId: RESERVATION,
  });
  expect(released).toEqual({ ok: true, lifecycle: { state: 'active', issuedAtMs: ISSUED_AT } });

  // Released codes are usable again, so an abandoned attempt costs nothing.
  expect(
    reserveRecoveryCode({
      lifecycle: { state: 'active', issuedAtMs: ISSUED_AT },
      reservationId: OTHER_RESERVATION,
      nowMs: 4_000,
      reservationTtlMs: TTL_MS,
    }).ok,
  ).toBe(true);
});

test('only the holding reservation can release or consume a code', () => {
  const held = reserved(2_000);
  expect(
    releaseRecoveryCodeReservation({ lifecycle: held, reservationId: OTHER_RESERVATION }),
  ).toMatchObject({ ok: false, code: 'reservation_mismatch' });
  expect(
    consumeReservedRecoveryCode({
      lifecycle: held,
      reservationId: OTHER_RESERVATION,
      nowMs: 3_000,
    }),
  ).toMatchObject({ ok: false, code: 'reservation_mismatch' });
});

test('a live reservation blocks a competing recovery', () => {
  const held = reserved(2_000);
  expect(
    reserveRecoveryCode({
      lifecycle: held,
      reservationId: OTHER_RESERVATION,
      nowMs: 3_000,
      reservationTtlMs: TTL_MS,
    }),
  ).toMatchObject({ ok: false, code: 'already_reserved' });
});

test('an expired reservation frees the code for a new attempt', () => {
  const held = reserved(2_000);
  expect(isRecoveryCodeAvailable(held, 3_000)).toBe(false);
  expect(isRecoveryCodeAvailable(held, 12_000)).toBe(true);

  // An abandoned recovery must not strand a code permanently.
  const retaken = reserveRecoveryCode({
    lifecycle: held,
    reservationId: OTHER_RESERVATION,
    nowMs: 12_000,
    reservationTtlMs: TTL_MS,
  });
  expect(retaken.ok).toBe(true);
  if (!retaken.ok) return;
  expect(retaken.lifecycle).toMatchObject({
    state: 'reserved',
    reservationId: OTHER_RESERVATION,
  });
});

test('an expired reservation cannot be consumed', () => {
  const held = reserved(2_000);
  // The code may already have been re-reserved by another attempt, so
  // consuming here would burn a code a different recovery is relying on.
  expect(
    consumeReservedRecoveryCode({
      lifecycle: held,
      reservationId: RESERVATION,
      nowMs: 12_000,
    }),
  ).toMatchObject({ ok: false, code: 'reservation_expired' });
});

test('the same recovery may re-reserve its own code idempotently', () => {
  const held = reserved(2_000);
  const again = reserveRecoveryCode({
    lifecycle: held,
    reservationId: RESERVATION,
    nowMs: 5_000,
    reservationTtlMs: TTL_MS,
  });
  expect(again.ok).toBe(true);
  if (!again.ok) return;
  // Re-reserving extends the hold rather than failing a retried request.
  expect(again.lifecycle).toMatchObject({
    state: 'reserved',
    reservationId: RESERVATION,
    reservationExpiresAtMs: 15_000,
  });
});

test('consumption is terminal', () => {
  const consumed: RecoveryCodeLifecycleState = {
    state: 'consumed',
    issuedAtMs: ISSUED_AT,
    reservationId: RESERVATION,
    consumedAtMs: 3_000,
  };
  expect(
    reserveRecoveryCode({
      lifecycle: consumed,
      reservationId: RESERVATION,
      nowMs: 4_000,
      reservationTtlMs: TTL_MS,
    }),
  ).toMatchObject({ ok: false, code: 'already_consumed' });
  // A post-commit failure must not hand the code back.
  expect(
    releaseRecoveryCodeReservation({ lifecycle: consumed, reservationId: RESERVATION }),
  ).toMatchObject({ ok: false, code: 'already_consumed' });
  expect(revokeRecoveryCode({ lifecycle: consumed, nowMs: 4_000 })).toMatchObject({
    ok: false,
    code: 'already_consumed',
  });
});

test('revocation blocks reservation and consumption', () => {
  const revoked = revokeRecoveryCode({ lifecycle: reserved(2_000), nowMs: 3_000 });
  expect(revoked.ok).toBe(true);
  if (!revoked.ok) return;
  expect(revoked.lifecycle).toEqual({
    state: 'revoked',
    issuedAtMs: ISSUED_AT,
    revokedAtMs: 3_000,
  });

  expect(
    reserveRecoveryCode({
      lifecycle: revoked.lifecycle,
      reservationId: RESERVATION,
      nowMs: 4_000,
      reservationTtlMs: TTL_MS,
    }),
  ).toMatchObject({ ok: false, code: 'revoked' });
  expect(
    consumeReservedRecoveryCode({
      lifecycle: revoked.lifecycle,
      reservationId: RESERVATION,
      nowMs: 4_000,
    }),
  ).toMatchObject({ ok: false, code: 'revoked' });
  expect(isRecoveryCodeAvailable(revoked.lifecycle, 4_000)).toBe(false);
});

test('a non-positive reservation ttl is rejected', () => {
  expect(
    reserveRecoveryCode({
      lifecycle: active,
      reservationId: RESERVATION,
      nowMs: 2_000,
      reservationTtlMs: 0,
    }),
  ).toMatchObject({ ok: false, code: 'reservation_expired' });
});
