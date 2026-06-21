import { expect, test } from '@playwright/test';
import {
  parseCurrentSigningSessionSealIdempotencyRouteResult,
  parseCurrentSigningSessionSealIdempotencyStoredEntry,
} from '../../packages/sdk-server-ts/src/threshold/session/signingSessionSeal/postgresRecords';

test.describe('signing session seal postgres records', () => {
  test('preserves current success idempotency result fields including zero remaining uses', () => {
    const parsed = parseCurrentSigningSessionSealIdempotencyRouteResult({
      ok: true,
      ciphertext: 'sealed:ciphertext-b64u',
      keyVersion: 'signing-session-seal-kek-2026-02-r1',
      expiresAtMs: 123_456,
      remainingUses: 0,
    });

    expect(parsed).toEqual({
      ok: true,
      ciphertext: 'sealed:ciphertext-b64u',
      keyVersion: 'signing-session-seal-kek-2026-02-r1',
      expiresAtMs: 123_456,
      remainingUses: 0,
    });
  });

  test('rejects malformed idempotency route results', () => {
    expect(
      parseCurrentSigningSessionSealIdempotencyRouteResult({
        ok: true,
        ciphertext: '',
      }),
    ).toBeNull();

    expect(
      parseCurrentSigningSessionSealIdempotencyRouteResult({
        ok: false,
        code: 'forbidden',
        message: '',
      }),
    ).toBeNull();
  });

  test('parses stored entries only when result and expiry are current shape', () => {
    const parsed = parseCurrentSigningSessionSealIdempotencyStoredEntry({
      result: {
        ok: false,
        code: 'expired',
        message: 'threshold session expired',
      },
      expiresAtMs: 987_654,
    });

    expect(parsed).toEqual({
      result: {
        ok: false,
        code: 'expired',
        message: 'threshold session expired',
      },
      expiresAtMs: 987_654,
    });

    expect(
      parseCurrentSigningSessionSealIdempotencyStoredEntry({
        result: {
          ok: true,
          ciphertext: 'sealed:ciphertext-b64u',
          remainingUses: -1,
        },
        expiresAtMs: 987_654,
      }),
    ).toBeNull();

    expect(
      parseCurrentSigningSessionSealIdempotencyStoredEntry({
        result: {
          ok: true,
          ciphertext: 'sealed:ciphertext-b64u',
        },
        expiresAtMs: 0,
      }),
    ).toBeNull();
  });
});
