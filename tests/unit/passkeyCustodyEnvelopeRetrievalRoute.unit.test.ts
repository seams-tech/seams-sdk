import { expect, test } from '@playwright/test';
import { passkeyCustodyEnvelopeRetrievalRouteResponse } from '../../packages/sdk-server-ts/src/router/domains/passkeyCustody/passkeyCustodyEnvelopeRetrievalRoute';
import { passkeyCustodyEnvelope } from './helpers/passkeyCustodyEnvelope.fixtures';

/**
 * The route a browser with empty IndexedDB uses to fetch its custody envelope.
 *
 * Every failure is a distinct status, because a client must tell "your
 * credential no longer opens this wallet" from "this wallet has no envelope"
 * from "the stored record is corrupt". The first two a user can act on; the
 * third is an incident, and collapsing them would hide it.
 */

const mapped = passkeyCustodyEnvelopeRetrievalRouteResponse;

test('an active envelope returns its ciphertext and the exact store revision', async () => {
  /* The revision is what lets a client refuse a stale cached copy: without it
     a browser could open a local envelope against a rewrapped server one and
     fail to unlock with a correct credential. */
  const envelope = passkeyCustodyEnvelope();
  const response = mapped({ kind: 'active', envelope, storeVersion: '7' } as never);

  expect(response.status).toBe(200);
  expect(response.body.ok).toBe(true);
  expect(response.body.storeVersion).toBe('7');
  expect(response.body.envelope).toBe(envelope);
});

test('each refusal carries its own status and code', async () => {
  const cases: readonly [Record<string, unknown>, number, string][] = [
    [{ kind: 'prf_disclosed', message: 'prf leaked' }, 400, 'prf_disclosed'],
    [{ kind: 'assertion_rejected', code: 'bad_challenge', message: 'no' }, 401, 'bad_challenge'],
    [{ kind: 'credential_mismatch' }, 403, 'credential_mismatch'],
    [{ kind: 'revoked', revokedAtMs: 2_000 }, 403, 'envelope_revoked'],
    [{ kind: 'retired', retiredAtMs: 2_000 }, 409, 'envelope_retired'],
    [{ kind: 'missing' }, 404, 'envelope_missing'],
    [{ kind: 'digest_mismatch' }, 500, 'envelope_digest_mismatch'],
  ];

  for (const [result, status, code] of cases) {
    const response = mapped(result as never);
    expect(response.status).toBe(status);
    expect(response.body.ok).toBe(false);
    expect(response.body.code).toBe(code);
  }
});

test('a disclosed PRF is a loud client error, never a sanitized success', async () => {
  /* A PRF result that reaches the server has already escaped the worker.
     Serving the envelope anyway would hide the escape behind a working
     unlock. */
  const response = mapped({ kind: 'prf_disclosed', message: 'prf.first present' } as never);
  expect(response.status).toBe(400);
  expect(response.body.ok).toBe(false);
  expect(String(response.body.message)).toContain('prf.first');
});

test('a corrupt stored record is a server fault, not a client one', async () => {
  // 5xx so it pages someone. A 4xx would read as "the user did something
  // wrong" and never falls back to re-deriving a wallet.
  const response = mapped({ kind: 'digest_mismatch' } as never);
  expect(response.status).toBeGreaterThanOrEqual(500);
});
