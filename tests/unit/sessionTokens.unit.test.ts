import { expect, test } from '@playwright/test';
import {
  appOrThresholdSessionJwtAuth,
  requireAppSessionJwt,
  requireThresholdSessionJwt,
} from '@shared/utils/sessionTokens';

function jwtWithPayload(payload: Record<string, unknown>): string {
  const encode = (value: unknown): string =>
    Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${encode({ alg: 'none', typ: 'JWT' })}.${encode(payload)}.sig`;
}

test.describe('session JWT kind helpers', () => {
  test('rejects threshold-session JWTs at app-session boundaries', () => {
    const jwt = jwtWithPayload({
      kind: 'threshold_ecdsa_session_v1',
      sub: 'alice.testnet',
      walletId: 'alice.testnet',
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

    expect(() => requireThresholdSessionJwt(jwt)).toThrow('must be a threshold-session JWT');
  });

  test('rejects missing kind at threshold-session boundaries', () => {
    const jwt = jwtWithPayload({ sub: 'alice.testnet' });

    expect(() => requireThresholdSessionJwt(jwt)).toThrow('must be a threshold-session JWT');
  });

  test('rejects unknown kind at threshold-session boundaries', () => {
    const jwt = jwtWithPayload({ kind: 'unknown_session_v1', sub: 'alice.testnet' });

    expect(() => requireThresholdSessionJwt(jwt)).toThrow('must be a threshold-session JWT');
  });

  test('builds discriminated route auth from JWT kind', () => {
    const thresholdJwt = jwtWithPayload({
      kind: 'threshold_ecdsa_session_v1',
      sub: 'alice.testnet',
      walletId: 'alice.testnet',
    });
    const appJwt = jwtWithPayload({ kind: 'app_session_v1', sub: 'alice.testnet' });

    expect(appOrThresholdSessionJwtAuth(thresholdJwt)).toEqual({
      kind: 'threshold_session',
      jwt: thresholdJwt,
    });
    expect(appOrThresholdSessionJwtAuth(appJwt)).toEqual({
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

    expect(() => appOrThresholdSessionJwtAuth(missingKindJwt)).toThrow(
      'session JWT must include a valid session kind',
    );
    expect(() => appOrThresholdSessionJwtAuth(unknownKindJwt)).toThrow(
      'session JWT must include a valid session kind',
    );
  });
});
