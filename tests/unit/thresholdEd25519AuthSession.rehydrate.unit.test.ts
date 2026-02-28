import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  ed25519AuthSession: '/sdk/esm/core/signingEngine/threshold/session/ed25519AuthSession.js',
  thresholdEd25519SessionStore:
    '/sdk/esm/core/signingEngine/api/thresholdLifecycle/thresholdEd25519SessionStore.js',
} as const;

test.describe('threshold Ed25519 auth-session rehydrate', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('rehydrates JWT from canonical session record into in-memory auth cache', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const authMod = await import(paths.ed25519AuthSession);
        const storeMod = await import(paths.thresholdEd25519SessionStore);

        const nearAccountId = 'alice.testnet';
        const rpId = 'example.localhost';
        const relayerUrl = 'https://relay.example';
        const relayerKeyId = 'rk-ed25519';
        const participantIds = [1, 2];
        const thresholdSessionId = 'tsess-ed25519-rehydrate-1';
        const thresholdSessionJwt = 'jwt-ed25519-rehydrate-1';

        authMod.clearAllCachedEd25519AuthSessions();
        storeMod.clearAllStoredThresholdEd25519SessionRecords();

        storeMod.upsertStoredThresholdEd25519SessionRecord({
          nearAccountId,
          rpId,
          relayerUrl,
          relayerKeyId,
          participantIds,
          thresholdSessionKind: 'jwt',
          thresholdSessionId,
          thresholdSessionJwt,
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 9,
          source: 'login',
        });

        const rehydratedJwt = await authMod.getCachedEd25519AuthSessionJwtBySessionId(
          thresholdSessionId,
        );
        const cacheKey = authMod.makeEd25519AuthSessionCacheKey({
          nearAccountId,
          rpId,
          relayerUrl,
          relayerKeyId,
          participantIds,
        });
        const cacheKeyJwt = authMod.getCachedEd25519AuthSessionJwt(cacheKey);
        const canonicalRecord = storeMod.getStoredThresholdEd25519SessionRecordByThresholdSessionId(
          thresholdSessionId,
        );
        const legacyAuthStoreIndex = sessionStorage.getItem(
          'tatchi:threshold-ed25519-auth-session:v1:index',
        );
        return {
          rehydratedJwt,
          cacheKeyJwt,
          canonicalRecordThresholdSessionId: canonicalRecord?.thresholdSessionId || null,
          legacyAuthStoreIndex,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.rehydratedJwt).toBe('jwt-ed25519-rehydrate-1');
    expect(result.cacheKeyJwt).toBe('jwt-ed25519-rehydrate-1');
    expect(result.canonicalRecordThresholdSessionId).toBe('tsess-ed25519-rehydrate-1');
    expect(result.legacyAuthStoreIndex).toBeNull();
  });
});
