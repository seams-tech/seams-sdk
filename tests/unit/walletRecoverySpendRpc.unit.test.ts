import { expect, test } from '@playwright/test';
import {
  spendWalletRecoveryCode,
  type WalletRecoverySpendResult,
} from '../../packages/sdk-web/src/core/rpcClients/relayer/walletRecoverySpend';

/**
 * The client's reading of a recovery spend.
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

async function spend(status: number, body: unknown): Promise<WalletRecoverySpendResult> {
  return spendWalletRecoveryCode({
    relayUrl: 'https://relay.localhost',
    walletId: 'alice.testnet',
    recoveryCode: 'QUJDREVG',
    reservationId: 'reservation-1',
    fetchImpl: respondWith(status, body),
  });
}

const GOOD_WRAP = { nonceB64u: 'n', wrappedManifestKekB64u: 'k', aadHashB64u: 'a' };

test('a spend returns the wrapped payload', async () => {
  const result = await spend(200, {
    ok: true,
    wrap: GOOD_WRAP,
    entries: [{ custodySecretKind: 'wallet_custody_seed_v1' }],
    storeVersion: '5',
  });
  expect(result.kind).toBe('spent');
  if (result.kind !== 'spent') return;
  expect(result.wrap.wrappedManifestKekB64u).toBe('k');
  expect(result.entries).toHaveLength(1);
});

test('a 200 with an unusable payload is not reported as a spend', async () => {
  // The code is burned server-side either way, so telling the caller this
  // worked is the worst of the available answers.
  const result = await spend(200, { ok: true, wrap: { nonceB64u: 'n' }, storeVersion: '5' });
  expect(result.kind).toBe('transport_failed');
});

test('401 and 400 both read as a plain rejection', async () => {
  const unauthorized = await spend(401, { ok: false, code: 'recovery_code_rejected' });
  const badRequest = await spend(400, { ok: false, code: 'invalid_request' });
  expect(unauthorized.kind).toBe('rejected');
  expect(badRequest.kind).toBe('rejected');
});

test('a conflict stays distinct, because the code may still be good', async () => {
  const result = await spend(409, { ok: false, code: 'recovery_set_conflict' });
  expect(result.kind).toBe('conflict');
});

test('a network failure is never a rejection', async () => {
  const result = await spendWalletRecoveryCode({
    relayUrl: 'https://relay.localhost',
    walletId: 'alice.testnet',
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
