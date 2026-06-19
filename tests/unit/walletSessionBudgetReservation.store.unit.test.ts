import { expect, test } from '@playwright/test';
import { setTimeout as delay } from 'node:timers/promises';
import { createEd25519WalletSessionStore } from '../../packages/sdk-server-ts/src/core/ThresholdService/stores/WalletSessionStore';

const logger = {
  info() {},
  warn() {},
  error() {},
  debug() {},
} as const;

function createStore() {
  return createEd25519WalletSessionStore({
    config: { kind: 'in-memory' },
    logger,
    isNode: true,
  });
}

async function putWalletSession(input: { remainingUses: number }) {
  const store = createStore();
  const expiresAtMs = Date.now() + 60_000;
  await store.putSession(
    'wallet-session-1',
    {
      userId: 'user-1',
      rpId: 'rp.example',
      relayerKeyId: 'relayer-1',
      participantIds: [1, 2],
      expiresAtMs,
      walletBudgetBinding: {
        curve: 'ed25519',
        thresholdSessionId: 'threshold-session-1',
      },
    },
    { ttlMs: 60_000, remainingUses: input.remainingUses },
  );
  return { store, expiresAtMs };
}

test.describe('Wallet Session budget reservations', () => {
  test('reserve holds visible available budget and commit is idempotent', async () => {
    const { store, expiresAtMs } = await putWalletSession({ remainingUses: 1 });

    const reservation = await store.reserveUseCountOnce({
      walletSigningSessionId: 'wallet-session-1',
      curve: 'ed25519',
      thresholdSessionId: 'threshold-session-1',
      operationId: 'operation-1',
      requestDigest: 'digest-1',
      signatureUses: 1,
      expiresAtMs,
    });

    expect(reservation.ok).toBe(true);
    if (!reservation.ok) throw new Error(reservation.message);
    expect(reservation.availableUses).toBe(0);

    const duplicate = await store.reserveUseCountOnce({
      walletSigningSessionId: 'wallet-session-1',
      curve: 'ed25519',
      thresholdSessionId: 'threshold-session-1',
      operationId: 'operation-1',
      requestDigest: 'digest-1',
      signatureUses: 1,
      expiresAtMs,
    });
    expect(duplicate.ok).toBe(true);
    if (!duplicate.ok) throw new Error(duplicate.message);
    expect(duplicate.reservation.reservationId).toBe(reservation.reservation.reservationId);

    const inFlight = await store.reserveUseCountOnce({
      walletSigningSessionId: 'wallet-session-1',
      curve: 'ed25519',
      thresholdSessionId: 'threshold-session-1',
      operationId: 'operation-2',
      requestDigest: 'digest-2',
      signatureUses: 1,
      expiresAtMs,
    });
    expect(inFlight).toMatchObject({ ok: false, code: 'wallet_budget_in_flight' });

    const statusWhileReserved = await store.getSessionStatus('wallet-session-1');
    expect(statusWhileReserved).toMatchObject({
      committedRemainingUses: 1,
      reservedUses: 1,
      availableUses: 0,
      remainingUses: 0,
    });

    const committed = await store.commitReservedUseCountOnce({
      walletSigningSessionId: 'wallet-session-1',
      reservationId: reservation.reservation.reservationId,
      operationId: 'operation-1',
      requestDigest: 'digest-1',
    });
    expect(committed).toEqual({ ok: true, remainingUses: 0 });

    const duplicateCommit = await store.commitReservedUseCountOnce({
      walletSigningSessionId: 'wallet-session-1',
      reservationId: reservation.reservation.reservationId,
      operationId: 'operation-1',
      requestDigest: 'digest-1',
    });
    expect(duplicateCommit).toEqual({ ok: true, remainingUses: 0 });
  });

  test('release restores available budget for abandoned prepares', async () => {
    const { store, expiresAtMs } = await putWalletSession({ remainingUses: 1 });

    const reservation = await store.reserveUseCountOnce({
      walletSigningSessionId: 'wallet-session-1',
      curve: 'ed25519',
      thresholdSessionId: 'threshold-session-1',
      operationId: 'operation-1',
      requestDigest: 'digest-1',
      signatureUses: 1,
      expiresAtMs,
    });
    expect(reservation.ok).toBe(true);
    if (!reservation.ok) throw new Error(reservation.message);

    const release = await store.releaseReservedUseCount({
      walletSigningSessionId: 'wallet-session-1',
      reservationId: reservation.reservation.reservationId,
    });

    expect(release).toMatchObject({
      ok: true,
      released: true,
      remainingUses: 1,
      reservedUses: 0,
      availableUses: 1,
    });
    expect(await store.getSessionStatus('wallet-session-1')).toMatchObject({
      remainingUses: 1,
      availableUses: 1,
    });
  });

  test('reserve rejects exhausted budget', async () => {
    const { store, expiresAtMs } = await putWalletSession({ remainingUses: 0 });

    const reservation = await store.reserveUseCountOnce({
      walletSigningSessionId: 'wallet-session-1',
      curve: 'ed25519',
      thresholdSessionId: 'threshold-session-1',
      operationId: 'operation-1',
      requestDigest: 'digest-1',
      signatureUses: 1,
      expiresAtMs,
    });

    expect(reservation).toMatchObject({
      ok: false,
      code: 'wallet_budget_exhausted',
    });
  });

  test('commit rejects expired reservations and releases visible availability', async () => {
    const { store } = await putWalletSession({ remainingUses: 1 });
    const expiredReservation = await store.reserveUseCountOnce({
      walletSigningSessionId: 'wallet-session-1',
      curve: 'ed25519',
      thresholdSessionId: 'threshold-session-1',
      operationId: 'operation-1',
      requestDigest: 'digest-1',
      signatureUses: 1,
      expiresAtMs: Date.now() + 1,
    });
    expect(expiredReservation.ok).toBe(true);
    if (!expiredReservation.ok) throw new Error(expiredReservation.message);

    await delay(5);

    const committed = await store.commitReservedUseCountOnce({
      walletSigningSessionId: 'wallet-session-1',
      reservationId: expiredReservation.reservation.reservationId,
      operationId: 'operation-1',
      requestDigest: 'digest-1',
    });

    expect(committed).toMatchObject({
      ok: false,
      code: 'wallet_budget_reservation_expired',
    });
    expect(await store.getSessionStatus('wallet-session-1')).toMatchObject({
      committedRemainingUses: 1,
      reservedUses: 0,
      availableUses: 1,
      remainingUses: 1,
    });
  });

  test('commit rejects reservation identity mismatch', async () => {
    const { store, expiresAtMs } = await putWalletSession({ remainingUses: 1 });

    const reservation = await store.reserveUseCountOnce({
      walletSigningSessionId: 'wallet-session-1',
      curve: 'ed25519',
      thresholdSessionId: 'threshold-session-1',
      operationId: 'operation-1',
      requestDigest: 'digest-1',
      signatureUses: 1,
      expiresAtMs,
    });
    expect(reservation.ok).toBe(true);
    if (!reservation.ok) throw new Error(reservation.message);

    const committed = await store.commitReservedUseCountOnce({
      walletSigningSessionId: 'wallet-session-1',
      reservationId: reservation.reservation.reservationId,
      operationId: 'operation-1',
      requestDigest: 'digest-2',
    });

    expect(committed).toMatchObject({
      ok: false,
      code: 'wallet_budget_reservation_mismatch',
    });
    expect(await store.getSessionStatus('wallet-session-1')).toMatchObject({
      committedRemainingUses: 1,
      reservedUses: 1,
      availableUses: 0,
      remainingUses: 0,
    });
  });
});
