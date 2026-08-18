import { expect, test } from '@playwright/test';
import {
  fetchPasskeyCustodyEnvelope,
  type PasskeyCustodyEnvelopeFetchResult,
} from '../../packages/wallet/src/core/rpcClients/relayer/passkeyCustodyEnvelope';

/**
 * The client's reading of each server status.
 *
 * The property under test is that they stay *distinct*. A caller has to be
 * able to tell "register on this device" from "use your other credential"
 * from "retry the network", and every one of those arrives as an unsuccessful
 * HTTP response. Collapsing them is the natural mistake and the one that
 * turns a recoverable state into a support ticket.
 */

function respondWith(status: number, body: unknown): typeof fetch {
  return (async () =>
    new Response(JSON.stringify(body), {
      status,
      headers: { 'Content-Type': 'application/json' },
    })) as unknown as typeof fetch;
}

async function fetchWith(
  status: number,
  body: unknown,
): Promise<PasskeyCustodyEnvelopeFetchResult> {
  return fetchPasskeyCustodyEnvelope({
    relayUrl: 'https://relay.localhost',
    locator: { walletId: 'alice.testnet' },
    challengeId: 'challenge-1',
    expectedOrigin: 'https://example.localhost',
    webauthnAuthentication: { id: 'credential-1' },
    fetchImpl: respondWith(status, body),
  });
}

test('an active envelope carries its store version', async () => {
  const result = await fetchWith(200, {
    ok: true,
    envelope: { envelopeId: 'envelope-1' },
    storeVersion: 'v7',
  });
  expect(result).toMatchObject({ kind: 'active', storeVersion: 'v7' });
});

test('a 200 missing its store version is corrupt, not active', async () => {
  // Unlocking against a half-read response would fail later and further from
  // the cause.
  const result = await fetchWith(200, { ok: true, envelope: { envelopeId: 'envelope-1' } });
  expect(result.kind).toBe('corrupt');
});

test('each refusal stays distinct', async () => {
  expect((await fetchWith(404, { ok: false, code: 'envelope_missing' })).kind).toBe('missing');
  expect((await fetchWith(409, { ok: false, code: 'envelope_retired' })).kind).toBe('retired');
  expect((await fetchWith(403, { ok: false, code: 'envelope_revoked' })).kind).toBe(
    'credential_rejected',
  );
  expect((await fetchWith(401, { ok: false, code: 'assertion_rejected' })).kind).toBe(
    'credential_rejected',
  );
  expect((await fetchWith(400, { ok: false, code: 'prf_disclosed' })).kind).toBe(
    'request_rejected',
  );
});

test('a digest mismatch is corrupt rather than retryable', async () => {
  // A 500 is normally worth retrying; this one never is, and must not be
  // reported as a transient failure.
  const result = await fetchWith(500, { ok: false, code: 'envelope_digest_mismatch' });
  expect(result.kind).toBe('corrupt');
});

test('a network failure is never reported as a credential problem', async () => {
  const result = await fetchPasskeyCustodyEnvelope({
    relayUrl: 'https://relay.localhost',
    locator: { walletId: 'alice.testnet' },
    challengeId: 'challenge-1',
    expectedOrigin: 'https://example.localhost',
    webauthnAuthentication: { id: 'credential-1' },
    fetchImpl: (async () => {
      throw new Error('offline');
    }) as unknown as typeof fetch,
  });
  expect(result).toMatchObject({ kind: 'transport_failed', message: 'offline' });
});
