import { expect, test } from '@playwright/test';
import {
  clearAllCachedEcdsaAuthSessions,
  clearCachedEcdsaAuthSession,
  getCachedEcdsaAuthSession,
  getCachedEcdsaAuthSessionBySessionId,
  getCachedEcdsaAuthSessionJwtBySessionId,
  makeEcdsaAuthSessionCacheKey,
  putCachedEcdsaAuthSession,
} from '@/core/signingEngine/threshold/session/ecdsaAuthSession';

function buildEntry(sessionId: string, jwt: string, relayerKeyId = 'rk-1') {
  return {
    sessionKind: 'jwt' as const,
    policy: {
      version: 'threshold_session_v1' as const,
      userId: 'alice.testnet',
      rpId: 'wallet.example.localhost',
      relayerKeyId,
      sessionId,
      participantIds: [1, 2],
      ttlMs: 60_000,
      remainingUses: 3,
    },
    policyJson: '{}',
    sessionPolicyDigest32: `digest-${sessionId}`,
    jwt,
    expiresAtMs: Date.now() + 60_000,
  };
}

test.describe('threshold ecdsa auth session cache', () => {
  test.beforeEach(() => {
    clearAllCachedEcdsaAuthSessions();
  });

  test('supports fallback lookup by sessionId and jwt', () => {
    const cacheKey = makeEcdsaAuthSessionCacheKey({
      userId: 'alice.testnet',
      rpId: 'wallet.example.localhost',
      relayerUrl: 'https://relay.example',
      relayerKeyId: 'rk-1',
      participantIds: [1, 2],
    });

    putCachedEcdsaAuthSession(cacheKey, buildEntry('sess-1', 'jwt-1'));

    expect(getCachedEcdsaAuthSessionBySessionId('sess-1')?.policy?.sessionId).toBe('sess-1');
    expect(getCachedEcdsaAuthSessionJwtBySessionId('sess-1')).toBe('jwt-1');
    expect(getCachedEcdsaAuthSessionJwtBySessionId('missing')).toBeUndefined();
  });

  test('clearing by cache key removes sessionId fallback entry', () => {
    const cacheKey = makeEcdsaAuthSessionCacheKey({
      userId: 'alice.testnet',
      rpId: 'wallet.example.localhost',
      relayerUrl: 'https://relay.example',
      relayerKeyId: 'rk-1',
      participantIds: [1, 2],
    });

    putCachedEcdsaAuthSession(cacheKey, buildEntry('sess-2', 'jwt-2'));

    clearCachedEcdsaAuthSession(cacheKey);

    expect(getCachedEcdsaAuthSession(cacheKey)).toBeNull();
    expect(getCachedEcdsaAuthSessionBySessionId('sess-2')).toBeNull();
    expect(getCachedEcdsaAuthSessionJwtBySessionId('sess-2')).toBeUndefined();
  });

  test('replacing a cache key rotates sessionId fallback entry', () => {
    const cacheKey = makeEcdsaAuthSessionCacheKey({
      userId: 'alice.testnet',
      rpId: 'wallet.example.localhost',
      relayerUrl: 'https://relay.example',
      relayerKeyId: 'rk-1',
      participantIds: [1, 2],
    });

    putCachedEcdsaAuthSession(cacheKey, buildEntry('sess-old', 'jwt-old'));
    putCachedEcdsaAuthSession(cacheKey, buildEntry('sess-new', 'jwt-new'));

    expect(getCachedEcdsaAuthSessionBySessionId('sess-old')).toBeNull();
    expect(getCachedEcdsaAuthSessionJwtBySessionId('sess-old')).toBeUndefined();
    expect(getCachedEcdsaAuthSessionBySessionId('sess-new')?.policy?.sessionId).toBe('sess-new');
    expect(getCachedEcdsaAuthSessionJwtBySessionId('sess-new')).toBe('jwt-new');
  });

  test('sessionId collision moves ownership to latest cache key', () => {
    const firstCacheKey = makeEcdsaAuthSessionCacheKey({
      userId: 'alice.testnet',
      rpId: 'wallet.example.localhost',
      relayerUrl: 'https://relay.example',
      relayerKeyId: 'rk-1',
      participantIds: [1, 2],
    });
    const secondCacheKey = makeEcdsaAuthSessionCacheKey({
      userId: 'alice.testnet',
      rpId: 'wallet.example.localhost',
      relayerUrl: 'https://relay.example',
      relayerKeyId: 'rk-2',
      participantIds: [1, 2],
    });

    putCachedEcdsaAuthSession(firstCacheKey, buildEntry('sess-shared', 'jwt-first', 'rk-1'));
    putCachedEcdsaAuthSession(secondCacheKey, buildEntry('sess-shared', 'jwt-second', 'rk-2'));

    expect(getCachedEcdsaAuthSession(firstCacheKey)).toBeNull();
    expect(getCachedEcdsaAuthSessionBySessionId('sess-shared')?.policy?.relayerKeyId).toBe('rk-2');
    expect(getCachedEcdsaAuthSessionJwtBySessionId('sess-shared')).toBe('jwt-second');
    expect(getCachedEcdsaAuthSession(secondCacheKey)?.jwt).toBe('jwt-second');
  });

  test('mutable entry rotation re-indexes old and new session ids on put', () => {
    const cacheKey = makeEcdsaAuthSessionCacheKey({
      userId: 'alice.testnet',
      rpId: 'wallet.example.localhost',
      relayerUrl: 'https://relay.example',
      relayerKeyId: 'rk-1',
      participantIds: [1, 2],
    });

    const mutableEntry = buildEntry('sess-a', 'jwt-a');
    putCachedEcdsaAuthSession(cacheKey, mutableEntry);

    mutableEntry.policy.sessionId = 'sess-b';
    mutableEntry.jwt = 'jwt-b';
    putCachedEcdsaAuthSession(cacheKey, mutableEntry);

    expect(getCachedEcdsaAuthSessionBySessionId('sess-a')).toBeNull();
    expect(getCachedEcdsaAuthSessionJwtBySessionId('sess-a')).toBeUndefined();
    expect(getCachedEcdsaAuthSessionBySessionId('sess-b')?.policy?.sessionId).toBe('sess-b');
    expect(getCachedEcdsaAuthSessionJwtBySessionId('sess-b')).toBe('jwt-b');
  });
});
