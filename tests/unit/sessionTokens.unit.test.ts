import { expect, test } from '@playwright/test';
import {
  appOrThresholdSessionJwtAuth,
  requireAppSessionJwt,
  requireThresholdSessionJwt,
} from '@shared/utils/sessionTokens';

function jwtWithPayload(payload: Record<string, unknown>): string {
  const encode = (value: unknown): string =>
    Buffer.from(JSON.stringify(value))
      .toString('base64url');
  return `${encode({ alg: 'none', typ: 'JWT' })}.${encode(payload)}.sig`;
}

test.describe('session JWT kind helpers', () => {
  test('rejects threshold-session JWTs at app-session boundaries', () => {
    const jwt = jwtWithPayload({ kind: 'threshold_ecdsa_session_v1', sub: 'alice.testnet' });

    expect(() => requireAppSessionJwt(jwt)).toThrow('must be an app-session JWT');
  });

  test('rejects app-session JWTs at threshold-session boundaries', () => {
    const jwt = jwtWithPayload({ kind: 'app_session_v1', sub: 'alice.testnet' });

    expect(() => requireThresholdSessionJwt(jwt)).toThrow('must be a threshold-session JWT');
  });

  test('builds discriminated route auth from JWT kind', () => {
    const thresholdJwt = jwtWithPayload({
      kind: 'threshold_ecdsa_session_v1',
      sub: 'alice.testnet',
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
});
