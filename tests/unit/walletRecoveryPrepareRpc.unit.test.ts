import { expect, test } from '@playwright/test';
import {
  buildWalletRecoveryCeremonyCustodyJson,
  prepareWalletRecovery,
  type WalletRecoveryPrepareResult,
} from '../../packages/wallet/src/core/rpcClients/relayer/walletRecoveryPrepare';

/**
 * The client's reading of recovery preparation.
 *
 * Two things are load-bearing here, and both are about not being helpful.
 *
 * A rejection carries no guess at *why*. The server merged unknown, spent and
 * malformed on purpose; a client that inferred "you already used this one"
 * from a status would rebuild the oracle on this side of the wire.
 *
 * A 200 whose payload cannot be opened is a failure, not a spend — and this
 * one matters more than the usual incomplete-response case, because the code
 * is burned server-side either way.
 */

function respondWith(status: number, body: unknown): typeof fetch {
  return (async () =>
    new Response(JSON.stringify(body), {
      status,
      headers: { 'Content-Type': 'application/json' },
    })) as unknown as typeof fetch;
}

async function prepare(status: number, body: unknown): Promise<WalletRecoveryPrepareResult> {
  return prepareWalletRecovery({
    relayUrl: 'https://relay.localhost',
    walletId: 'alice.testnet',
    sessionToken: 'app-session',
    challengeId: 'challenge-1',
    otpCode: '123456',
    recoveryCode: 'QUJDREVG',
    reservationId: 'reservation-1',
    fetchImpl: respondWith(status, body),
  });
}

const NONCE_B64U = 'AAAAAAAAAAAAAAAA';
const CIPHERTEXT_B64U = 'AAAAAAAAAAAAAAAAAAAAAAA';
const DIGEST_B64U = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const GOOD_WRAP = {
  nonceB64u: NONCE_B64U,
  wrappedManifestKekB64u: CIPHERTEXT_B64U,
  aadHashB64u: DIGEST_B64U,
};
const GOOD_ENTRY = {
  custodySecretKind: 'wallet_custody_seed_v1',
  nonceB64u: NONCE_B64U,
  wrappedCustodySecretB64u: CIPHERTEXT_B64U,
  aadHashB64u: DIGEST_B64U,
};

test('preparation returns the wrapped payload and exact reservation', async () => {
  const result = await prepare(200, {
    ok: true,
    wrap: GOOD_WRAP,
    entries: [GOOD_ENTRY],
    reservationId: 'reservation-1',
    reservationExpiresAtMs: 60_000,
    storeVersion: '5',
  });
  expect(result.kind).toBe('prepared');
  if (result.kind !== 'prepared') return;
  expect(result.wrap.wrappedManifestKekB64u).toBe(CIPHERTEXT_B64U);
  expect(result.entries).toHaveLength(1);
  expect(
    JSON.parse(
      buildWalletRecoveryCeremonyCustodyJson({
        walletId: 'alice.testnet',
        prepared: result,
      }),
    ),
  ).toEqual({
    walletId: 'alice.testnet',
    wrap: GOOD_WRAP,
    entry: GOOD_ENTRY,
  });
});

test('a 200 with an unusable payload is not reported as prepared', async () => {
  const result = await prepare(200, {
    ok: true,
    wrap: { nonceB64u: 'n' },
    reservationId: 'reservation-1',
    reservationExpiresAtMs: 60_000,
    storeVersion: '5',
  });
  expect(result.kind).toBe('transport_failed');
});

test('a prepared response must carry exactly one complete wallet seed entry', async () => {
  const missing = await prepare(200, {
    ok: true,
    wrap: GOOD_WRAP,
    entries: [],
    reservationId: 'reservation-1',
    reservationExpiresAtMs: 60_000,
    storeVersion: '5',
  });
  const rival = await prepare(200, {
    ok: true,
    wrap: GOOD_WRAP,
    entries: [GOOD_ENTRY, GOOD_ENTRY],
    reservationId: 'reservation-1',
    reservationExpiresAtMs: 60_000,
    storeVersion: '5',
  });
  expect(missing.kind).toBe('transport_failed');
  expect(rival.kind).toBe('transport_failed');
});

test('401 and 400 both read as a plain rejection', async () => {
  const unauthorized = await prepare(401, { ok: false, code: 'recovery_code_rejected' });
  const badRequest = await prepare(400, { ok: false, code: 'invalid_request' });
  expect(unauthorized.kind).toBe('rejected');
  expect(badRequest.kind).toBe('rejected');
});

test('a conflict stays distinct, because the code may still be good', async () => {
  const result = await prepare(409, { ok: false, code: 'recovery_set_conflict' });
  expect(result.kind).toBe('conflict');
});

test('a network failure is never a rejection', async () => {
  const result = await prepareWalletRecovery({
    relayUrl: 'https://relay.localhost',
    walletId: 'alice.testnet',
    sessionToken: 'app-session',
    challengeId: 'challenge-1',
    otpCode: '123456',
    recoveryCode: 'QUJDREVG',
    reservationId: 'reservation-1',
    fetchImpl: (async () => {
      throw new Error('offline');
    }) as unknown as typeof fetch,
  });
  // Reporting this as "that code cannot be used" would tell someone their
  // recovery code is dead when their wifi dropped.
  expect(result).toMatchObject({ kind: 'transport_failed', message: 'offline' });
});
