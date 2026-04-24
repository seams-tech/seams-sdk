import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  login: '/sdk/esm/core/TatchiPasskey/login.js',
  indexedDb: '/sdk/esm/core/indexedDB/index.js',
} as const;

test.describe('Email OTP wallet-session readiness', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('treats an active threshold-ECDSA Email OTP session as UI logged in', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const loginMod = await import(paths.login);
        const indexedDbMod = await import(paths.indexedDb);

        const nearAccountId = 'email-otp-alice.testnet';
        const now = Date.now();
        const clientDb = indexedDbMod.IndexedDBManager.clientDB as Record<string, unknown>;
        const originalGetMostRecentNearAccountProjection =
          clientDb.getMostRecentNearAccountProjection;
        const originalResolveNearAccountProfileContinuity =
          clientDb.resolveNearAccountProfileContinuity;

        clientDb.getMostRecentNearAccountProjection = async () => null;
        clientDb.resolveNearAccountProfileContinuity = async () => ({
          chainAccounts: [
            {
              accountModel: 'tempo-native',
              chainIdKey: 'tempo:testnet',
              accountAddress: '0xtempo',
              isPrimary: true,
            },
          ],
        });

        try {
          const context = {
            signingEngine: {
              assertSealedRefreshStartupParity: async () => undefined,
              getLastUser: async () => null,
              getUserBySignerSlot: async () => null,
              getWarmThresholdEd25519SessionStatus: async () => null,
              listWarmThresholdEcdsaSessionStatuses: async (_accountId: string, chain: string) =>
                chain === 'tempo'
                  ? [
                      {
                        sessionId: 'email-otp-ecdsa-session',
                        status: 'active',
                        authMethod: 'email_otp',
                        retention: 'session',
                        remainingUses: 3,
                        expiresAtMs: now + 60_000,
                        createdAtMs: now,
                      },
                    ]
                  : [],
              getThresholdEcdsaSessionRecordForLookup: () => ({
                thresholdEcdsaPublicKeyB64u: 'threshold-ecdsa-public-key',
              }),
            },
            configs: {
              signing: {
                mode: { mode: 'threshold-signer' },
              },
            },
          };

          return await loginMod.getWalletSession(context, nearAccountId);
        } finally {
          clientDb.getMostRecentNearAccountProjection = originalGetMostRecentNearAccountProjection;
          clientDb.resolveNearAccountProfileContinuity =
            originalResolveNearAccountProfileContinuity;
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.login?.isLoggedIn).toBe(true);
    expect(result.login?.nearAccountId).toBe('email-otp-alice.testnet');
    expect(result.login?.publicKey).toBeNull();
    expect(result.login?.thresholdEcdsaPublicKeyB64u).toBe('threshold-ecdsa-public-key');
    expect(result.signingSession?.status).toBe('active');
    expect(result.signingSession?.sessionId).toBe('email-otp-ecdsa-session');
    expect(result.signingSession?.authMethod).toBe('email_otp');
    expect(result.signingSession?.retention).toBe('session');
    expect(result.authMethod).toBe('email_otp');
    expect(result.retention).toBe('session');
    expect(result.login?.authMethod).toBe('email_otp');
  });

  test('does not expose a stale NEAR public key for ECDSA-only Email OTP sessions', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const loginMod = await import(paths.login);
        const indexedDbMod = await import(paths.indexedDb);

        const nearAccountId = 'email-otp-stale-near-key.testnet';
        const now = Date.now();
        const clientDb = indexedDbMod.IndexedDBManager.clientDB as Record<string, unknown>;
        const originalGetMostRecentNearAccountProjection =
          clientDb.getMostRecentNearAccountProjection;
        const originalResolveNearAccountProfileContinuity =
          clientDb.resolveNearAccountProfileContinuity;

        clientDb.getMostRecentNearAccountProjection = async () => null;
        clientDb.resolveNearAccountProfileContinuity = async () => ({
          chainAccounts: [
            {
              accountModel: 'tempo-native',
              chainIdKey: 'tempo:testnet',
              accountAddress: '0xtempo',
              isPrimary: true,
            },
          ],
        });

        try {
          const context = {
            signingEngine: {
              assertSealedRefreshStartupParity: async () => undefined,
              getLastUser: async () => ({
                nearAccountId,
                signerSlot: 1,
                operationalPublicKey: 'ed25519:stale-near-key',
              }),
              getUserBySignerSlot: async () => ({
                nearAccountId,
                signerSlot: 1,
                operationalPublicKey: 'ed25519:stale-near-key',
              }),
              getWarmThresholdEd25519SessionStatus: async () => null,
              listWarmThresholdEcdsaSessionStatuses: async (_accountId: string, chain: string) =>
                chain === 'tempo'
                  ? [
                      {
                        sessionId: 'email-otp-ecdsa-session',
                        status: 'active',
                        authMethod: 'email_otp',
                        retention: 'session',
                        remainingUses: 3,
                        expiresAtMs: now + 60_000,
                        createdAtMs: now,
                      },
                    ]
                  : [],
              getThresholdEcdsaSessionRecordForLookup: () => ({
                thresholdEcdsaPublicKeyB64u: 'threshold-ecdsa-public-key',
              }),
            },
            configs: {
              signing: {
                mode: { mode: 'threshold-signer' },
              },
            },
          };

          return await loginMod.getWalletSession(context, nearAccountId);
        } finally {
          clientDb.getMostRecentNearAccountProjection = originalGetMostRecentNearAccountProjection;
          clientDb.resolveNearAccountProfileContinuity =
            originalResolveNearAccountProfileContinuity;
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.login?.isLoggedIn).toBe(true);
    expect(result.login?.nearAccountId).toBe('email-otp-stale-near-key.testnet');
    expect(result.login?.publicKey).toBeNull();
    expect(result.login?.thresholdEcdsaPublicKeyB64u).toBe('threshold-ecdsa-public-key');
    expect(result.signingSession?.status).toBe('active');
    expect(result.signingSession?.sessionId).toBe('email-otp-ecdsa-session');
    expect(result.signingSession?.authMethod).toBe('email_otp');
    expect(result.authMethod).toBe('email_otp');
    expect(result.login?.authMethod).toBe('email_otp');
  });

  test('reports the lowest active remaining-use budget across Email OTP signing lanes', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const loginMod = await import(paths.login);
        const indexedDbMod = await import(paths.indexedDb);

        const nearAccountId = 'email-otp-budget.testnet';
        const now = Date.now();
        const clientDb = indexedDbMod.IndexedDBManager.clientDB as Record<string, unknown>;
        const originalGetMostRecentNearAccountProjection =
          clientDb.getMostRecentNearAccountProjection;
        const originalResolveNearAccountProfileContinuity =
          clientDb.resolveNearAccountProfileContinuity;

        clientDb.getMostRecentNearAccountProjection = async () => null;
        clientDb.resolveNearAccountProfileContinuity = async () => ({
          chainAccounts: [
            {
              accountModel: 'tempo-native',
              chainIdKey: 'tempo:testnet',
              accountAddress: '0xtempo',
              isPrimary: true,
            },
          ],
        });

        try {
          const context = {
            signingEngine: {
              assertSealedRefreshStartupParity: async () => undefined,
              getLastUser: async () => null,
              getUserBySignerSlot: async () => null,
              getWarmThresholdEd25519SessionStatus: async () => ({
                sessionId: 'email-otp-ed25519-session',
                status: 'active',
                authMethod: 'email_otp',
                retention: 'session',
                remainingUses: 5,
                expiresAtMs: now + 60_000,
                createdAtMs: now,
              }),
              listWarmThresholdEcdsaSessionStatuses: async (_accountId: string, chain: string) =>
                chain === 'tempo'
                  ? [
                      {
                        sessionId: 'email-otp-ecdsa-session',
                        status: 'active',
                        authMethod: 'email_otp',
                        retention: 'session',
                        remainingUses: 1,
                        expiresAtMs: now + 60_000,
                        createdAtMs: now,
                      },
                    ]
                  : [],
              getThresholdEcdsaSessionRecordForLookup: () => ({
                thresholdEcdsaPublicKeyB64u: 'threshold-ecdsa-public-key',
              }),
            },
            configs: {
              signing: {
                mode: { mode: 'threshold-signer' },
              },
            },
          };

          return await loginMod.getWalletSession(context, nearAccountId);
        } finally {
          clientDb.getMostRecentNearAccountProjection = originalGetMostRecentNearAccountProjection;
          clientDb.resolveNearAccountProfileContinuity =
            originalResolveNearAccountProfileContinuity;
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.signingSession?.status).toBe('active');
    expect(result.signingSession?.sessionId).toBe('email-otp-ecdsa-session');
    expect(result.signingSession?.remainingUses).toBe(1);
  });
});
