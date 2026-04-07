import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  thresholdSessionAuth:
    '/sdk/esm/core/signingEngine/orchestration/near/shared/thresholdSessionAuth.js',
  ed25519AuthSession: '/sdk/esm/core/signingEngine/threshold/session/ed25519AuthSession.js',
} as const;

test.describe('threshold Ed25519 threshold-session auth helpers', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('keeps canonical cached auth when worker sessionId differs from threshold sessionId', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const authMod = await import(paths.ed25519AuthSession);
        const helperMod = await import(paths.thresholdSessionAuth);

        authMod.clearAllCachedEd25519AuthSessions();

        const cacheKey = authMod.makeEd25519AuthSessionCacheKey({
          nearAccountId: 'alice.testnet',
          rpId: 'example.localhost',
          relayerUrl: 'https://relay.example',
          relayerKeyId: 'rk-1',
          participantIds: [1, 2],
        });

        await authMod.buildAndCacheEd25519AuthSession({
          nearAccountId: 'alice.testnet',
          rpId: 'example.localhost',
          relayerUrl: 'https://relay.example',
          relayerKeyId: 'rk-1',
          participantIds: [1, 2],
          sessionKind: 'jwt',
          sessionId: 'canonical-threshold-session',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 3,
          jwt: 'jwt-canonical',
        });

        const canonicalThresholdSessionId = helperMod.resolveCanonicalThresholdSessionId({
          thresholdSessionCacheKey: cacheKey,
          fallbackSessionId: 'worker-session-id',
        });
        const auth = await helperMod.resolveThresholdSessionAuth({
          thresholdSessionCacheKey: cacheKey,
          thresholdSessionId: 'worker-session-id',
        });
        const cachedAfter = authMod.getCachedEd25519AuthSession(cacheKey);

        authMod.clearAllCachedEd25519AuthSessions();

        return {
          canonicalThresholdSessionId,
          auth,
          cachedAfterSessionId: cachedAfter?.policy?.sessionId || null,
          cachedAfterJwt: cachedAfter?.jwt || null,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.canonicalThresholdSessionId).toBe('canonical-threshold-session');
    expect(result.auth).toEqual({
      sessionKind: 'jwt',
      thresholdSessionJwt: 'jwt-canonical',
    });
    expect(result.cachedAfterSessionId).toBe('canonical-threshold-session');
    expect(result.cachedAfterJwt).toBe('jwt-canonical');
  });
});
