import { expect, test } from '@playwright/test';
import {
  appOrWalletSessionJwtAuth,
  ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND,
  requireAppSessionJwt,
  requireWalletSessionJwt,
} from '@shared/utils/sessionTokens';

function jwtWithPayload(payload: Record<string, unknown>): string {
  const encode = (value: unknown): string =>
    Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${encode({ alg: 'none', typ: 'JWT' })}.${encode(payload)}.sig`;
}

test.describe('session JWT kind helpers', () => {
  test('rejects Wallet Session JWTs at app-session boundaries', () => {
    const jwt = jwtWithPayload({
      kind: ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND,
      sub: 'alice.testnet',
      walletId: 'alice.testnet',
      signingGrantId: 'wallet-session-1',
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

  test('rejects app-session JWTs at Wallet Session boundaries', () => {
    const jwt = jwtWithPayload({ kind: 'app_session_v1', sub: 'alice.testnet' });

    expect(() => requireWalletSessionJwt(jwt)).toThrow('must be a Wallet Session JWT');
  });

  test('rejects missing kind at Wallet Session boundaries', () => {
    const jwt = jwtWithPayload({ sub: 'alice.testnet' });

    expect(() => requireWalletSessionJwt(jwt)).toThrow('must be a Wallet Session JWT');
  });

  test('rejects unknown kind at Wallet Session boundaries', () => {
    const jwt = jwtWithPayload({ kind: 'unknown_session_v1', sub: 'alice.testnet' });

    expect(() => requireWalletSessionJwt(jwt)).toThrow('must be a Wallet Session JWT');
  });

  test('builds discriminated route auth from JWT kind', () => {
    const walletSessionJwt = jwtWithPayload({
      kind: ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND,
      sub: 'alice.testnet',
      walletId: 'alice.testnet',
      signingGrantId: 'wallet-session-1',
      keyHandle: 'key-handle-1',
      ecdsaThresholdKeyId: 'ecdsa-key-1',
    });
    const appJwt = jwtWithPayload({ kind: 'app_session_v1', sub: 'alice.testnet' });

    expect(appOrWalletSessionJwtAuth(walletSessionJwt)).toEqual({
      kind: 'wallet_session',
      jwt: walletSessionJwt,
    });
    expect(appOrWalletSessionJwtAuth(appJwt)).toEqual({
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

    expect(() => appOrWalletSessionJwtAuth(missingKindJwt)).toThrow(
      'session JWT must include a valid session kind',
    );
    expect(() => appOrWalletSessionJwtAuth(unknownKindJwt)).toThrow(
      'session JWT must include a valid session kind',
    );
  });
});
