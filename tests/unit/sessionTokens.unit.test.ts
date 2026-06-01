import { expect, test } from '@playwright/test';
import {
  appOrThresholdSessionAuthTokenAuth,
  requireAppSessionJwt,
  requireThresholdSessionAuthToken,
} from '@shared/utils/sessionTokens';

function jwtWithPayload(payload: Record<string, unknown>): string {
  const encode = (value: unknown): string =>
    Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${encode({ alg: 'none', typ: 'JWT' })}.${encode(payload)}.sig`;
}

test.describe('session JWT kind helpers', () => {
  test('rejects threshold-session auth tokens at app-session boundaries', () => {
    const jwt = jwtWithPayload({
      kind: 'threshold_ecdsa_session_v2',
      sub: 'alice.testnet',
      walletId: 'alice.testnet',
      walletSigningSessionId: 'wallet-session-1',
      keyHandle: 'key-handle-1',
      ecdsaThresholdKeyId: 'ecdsa-key-1',
    });

    expect(() => requireAppSessionJwt(jwt)).toThrow('must be an app-session JWT');
  });

  test('rejects missing kind at app-session boundaries', () => {
    const jwt = jwtWithPayload({ sub: 'alice.testnet' });

    expect(() => requireAppSessionJwt(jwt)).toThrow('must be an app-session JWT');
  });

  test('rejects unknown kind at app-session boundaries', () => {
    const jwt = jwtWithPayload({ kind: 'unknown_session_v1', sub: 'alice.testnet' });

    expect(() => requireAppSessionJwt(jwt)).toThrow('must be an app-session JWT');
  });

  test('rejects app-session JWTs at threshold-session boundaries', () => {
    const jwt = jwtWithPayload({ kind: 'app_session_v1', sub: 'alice.testnet' });

    expect(() => requireThresholdSessionAuthToken(jwt)).toThrow(
      'must be a threshold-session auth token',
    );
  });

  test('rejects missing kind at threshold-session boundaries', () => {
    const jwt = jwtWithPayload({ sub: 'alice.testnet' });

    expect(() => requireThresholdSessionAuthToken(jwt)).toThrow(
      'must be a threshold-session auth token',
    );
  });

  test('rejects unknown kind at threshold-session boundaries', () => {
    const jwt = jwtWithPayload({ kind: 'unknown_session_v1', sub: 'alice.testnet' });

    expect(() => requireThresholdSessionAuthToken(jwt)).toThrow(
      'must be a threshold-session auth token',
    );
  });

  test('builds discriminated route auth from JWT kind', () => {
    const thresholdAuthToken = jwtWithPayload({
      kind: 'threshold_ecdsa_session_v2',
      sub: 'alice.testnet',
      walletId: 'alice.testnet',
      walletSigningSessionId: 'wallet-session-1',
      keyHandle: 'key-handle-1',
      ecdsaThresholdKeyId: 'ecdsa-key-1',
    });
    const appJwt = jwtWithPayload({ kind: 'app_session_v1', sub: 'alice.testnet' });

    expect(appOrThresholdSessionAuthTokenAuth(thresholdAuthToken)).toEqual({
      kind: 'threshold_session',
      jwt: thresholdAuthToken,
    });
    expect(appOrThresholdSessionAuthTokenAuth(appJwt)).toEqual({
      kind: 'app_session',
      jwt: appJwt,
    });
  });

  test('rejects missing or unknown kind for generic route auth', () => {
    const missingKindJwt = jwtWithPayload({ sub: 'alice.testnet' });
    const unknownKindJwt = jwtWithPayload({
      kind: 'unknown_session_v1',
      sub: 'alice.testnet',
    });

    expect(() => appOrThresholdSessionAuthTokenAuth(missingKindJwt)).toThrow(
      'session auth token must include a valid session kind',
    );
    expect(() => appOrThresholdSessionAuthTokenAuth(unknownKindJwt)).toThrow(
      'session auth token must include a valid session kind',
    );
  });
});
