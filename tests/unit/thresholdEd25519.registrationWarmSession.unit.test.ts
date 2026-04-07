import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  thresholdWarmSessionBootstrap: '/sdk/esm/core/TatchiPasskey/thresholdWarmSessionBootstrap.js',
  login: '/sdk/esm/core/TatchiPasskey/login.js',
  indexedDb: '/sdk/esm/core/indexedDB/index.js',
  thresholdSessionStore:
    '/sdk/esm/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore.js',
  ed25519AuthSession: '/sdk/esm/core/signingEngine/threshold/session/ed25519AuthSession.js',
} as const;

test.describe('threshold Ed25519 registration warm-session', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('awaits warm-session hydrate before registration persistence returns', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const bootstrapMod = await import(paths.thresholdWarmSessionBootstrap);
        const loginMod = await import(paths.login);
        const indexedDbMod = await import(paths.indexedDb);
        const sessionStoreMod = await import(paths.thresholdSessionStore);
        const authSessionMod = await import(paths.ed25519AuthSession);

        const nearAccountId = 'registration-alice.testnet';
        const now = Date.now();
        let warmSessionActive = false;
        let hydrateCalls = 0;

        sessionStoreMod.clearAllStoredThresholdEd25519SessionRecords();
        authSessionMod.clearAllCachedEd25519AuthSessions();

        const clientDb = indexedDbMod.IndexedDBManager.clientDB as Record<string, unknown>;
        const accountKeyMaterialDb = indexedDbMod.IndexedDBManager.accountKeyMaterialDB as Record<
          string,
          unknown
        >;
        const originalResolveProfileAccountContext = clientDb.resolveProfileAccountContext;
        const originalGetMostRecentNearAccountProjection = clientDb.getMostRecentNearAccountProjection;
        const originalResolveNearAccountProfileContinuity =
          clientDb.resolveNearAccountProfileContinuity;
        const originalStoreKeyMaterial = accountKeyMaterialDb.storeKeyMaterial;
        const originalGetKeyMaterial = accountKeyMaterialDb.getKeyMaterial;

        clientDb.resolveProfileAccountContext = async (accountRef: {
          chainIdKey: string;
          accountAddress: string;
        }) =>
          accountRef.chainIdKey === 'near:testnet' &&
          String(accountRef.accountAddress || '').trim() === nearAccountId
            ? { profileId: `legacy-near:${nearAccountId}`, accountRef }
            : null;
        clientDb.getMostRecentNearAccountProjection = async () => null;
        clientDb.resolveNearAccountProfileContinuity = async () => ({ chainAccounts: [] });
        accountKeyMaterialDb.storeKeyMaterial = async () => undefined;
        accountKeyMaterialDb.getKeyMaterial = async () => null;

        try {
          const context = {
            signingEngine: {
              assertSealedRefreshStartupParity: async () => undefined,
              getUserByDevice: async () => ({
                nearAccountId,
                deviceNumber: 1,
                operationalPublicKey: 'ed25519:registration-user',
              }),
              getLastUser: async () => ({
                nearAccountId,
                deviceNumber: 1,
                operationalPublicKey: 'ed25519:registration-user',
              }),
              getWarmThresholdEd25519SessionStatus: async () =>
                warmSessionActive
                  ? {
                      sessionId: 'registration-session-1',
                      status: 'active',
                      remainingUses: 3,
                      expiresAtMs: now + 60_000,
                      createdAtMs: now,
                    }
                  : null,
              hydrateSigningSession: async (input: unknown) => {
                hydrateCalls += 1;
                await new Promise((resolve) => setTimeout(resolve, 25));
                warmSessionActive = true;
                return input;
              },
            },
            configs: {
              signing: {
                mode: { mode: 'threshold-signer' },
              },
              network: {
                relayer: { url: 'https://relay.example' },
              },
            },
          };

          await bootstrapMod.persistRegisteredThresholdEd25519Session({
            signingEngine: context.signingEngine,
            nearAccountId,
            deviceNumber: 1,
            rpId: 'example.localhost',
            relayerUrl: 'https://relay.example',
            prfFirstB64u: 'prf-first-registration',
            registrationSessionPolicy: {
              version: 'threshold_session_v1',
              nearAccountId,
              rpId: 'example.localhost',
              relayerKeyId: 'rk-1',
              sessionId: 'registration-session-1',
              participantIds: [1, 2],
              ttlMs: 60_000,
              remainingUses: 3,
              runtimeSnapshotScope: {
                orgId: 'org-registration',
                environmentId: 'env-registration',
              },
            },
            completedRegistration: {
              registered: {
                keyVersion: 'threshold-ed25519-hss-v1',
                recoveryExportCapable: true,
                publicKey: 'ed25519:registration-public-key',
                relayerKeyId: 'rk-1',
                clientParticipantId: 1,
                relayerParticipantId: 2,
                participantIds: [1, 2],
                session: {
                  sessionKind: 'jwt',
                  sessionId: 'registration-session-1',
                  expiresAtMs: now + 60_000,
                  participantIds: [1, 2],
                  remainingUses: 3,
                  runtimeSnapshotScope: {
                    orgId: 'org-registration',
                    environmentId: 'env-registration',
                  },
                  jwt: 'jwt-registration',
                },
              },
              operationalPublicKey: 'ed25519:registration-user',
            },
          });

          const walletSession = await loginMod.getWalletSession(context, nearAccountId);
          const storedRecord =
            sessionStoreMod.getStoredThresholdEd25519SessionRecordByThresholdSessionId(
              'registration-session-1',
            );

          return {
            hydrateCalls,
            warmSessionActive,
            walletSession,
            storedRecordSessionId: storedRecord?.thresholdSessionId || null,
          };
        } finally {
          clientDb.resolveProfileAccountContext = originalResolveProfileAccountContext;
          clientDb.getMostRecentNearAccountProjection = originalGetMostRecentNearAccountProjection;
          clientDb.resolveNearAccountProfileContinuity = originalResolveNearAccountProfileContinuity;
          accountKeyMaterialDb.storeKeyMaterial = originalStoreKeyMaterial;
          accountKeyMaterialDb.getKeyMaterial = originalGetKeyMaterial;
          sessionStoreMod.clearAllStoredThresholdEd25519SessionRecords();
          authSessionMod.clearAllCachedEd25519AuthSessions();
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.hydrateCalls).toBe(1);
    expect(result.warmSessionActive).toBe(true);
    expect(result.storedRecordSessionId).toBe('registration-session-1');
    expect(result.walletSession.login?.isLoggedIn).toBe(true);
    expect(result.walletSession.login?.nearAccountId).toBe('registration-alice.testnet');
    expect(result.walletSession.signingSession?.status).toBe('active');
    expect(result.walletSession.signingSession?.sessionId).toBe('registration-session-1');
  });

  test('wallet session read ignores Tempo parity failures after registration', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const bootstrapMod = await import(paths.thresholdWarmSessionBootstrap);
        const loginMod = await import(paths.login);
        const indexedDbMod = await import(paths.indexedDb);
        const sessionStoreMod = await import(paths.thresholdSessionStore);
        const authSessionMod = await import(paths.ed25519AuthSession);

        const nearAccountId = 'registration-parity.testnet';
        const now = Date.now();
        let warmSessionActive = false;

        sessionStoreMod.clearAllStoredThresholdEd25519SessionRecords();
        authSessionMod.clearAllCachedEd25519AuthSessions();

        const clientDb = indexedDbMod.IndexedDBManager.clientDB as Record<string, unknown>;
        const accountKeyMaterialDb = indexedDbMod.IndexedDBManager.accountKeyMaterialDB as Record<
          string,
          unknown
        >;
        const originalResolveProfileAccountContext = clientDb.resolveProfileAccountContext;
        const originalGetMostRecentNearAccountProjection = clientDb.getMostRecentNearAccountProjection;
        const originalResolveNearAccountProfileContinuity =
          clientDb.resolveNearAccountProfileContinuity;
        const originalStoreKeyMaterial = accountKeyMaterialDb.storeKeyMaterial;
        const originalGetKeyMaterial = accountKeyMaterialDb.getKeyMaterial;

        clientDb.resolveProfileAccountContext = async (accountRef: {
          chainIdKey: string;
          accountAddress: string;
        }) =>
          accountRef.chainIdKey === 'near:testnet' &&
          String(accountRef.accountAddress || '').trim() === nearAccountId
            ? { profileId: `legacy-near:${nearAccountId}`, accountRef }
            : null;
        clientDb.getMostRecentNearAccountProjection = async () => null;
        clientDb.resolveNearAccountProfileContinuity = async () => ({ chainAccounts: [] });
        accountKeyMaterialDb.storeKeyMaterial = async () => undefined;
        accountKeyMaterialDb.getKeyMaterial = async () => null;

        try {
          const context = {
            signingEngine: {
              assertSealedRefreshStartupParity: async () => {
                throw new Error('[sealed-refresh-parity] Well-known endpoint returned HTTP 502');
              },
              getUserByDevice: async () => ({
                nearAccountId,
                deviceNumber: 1,
                operationalPublicKey: 'ed25519:registration-user',
              }),
              getLastUser: async () => ({
                nearAccountId,
                deviceNumber: 1,
                operationalPublicKey: 'ed25519:registration-user',
              }),
              getWarmThresholdEd25519SessionStatus: async () =>
                warmSessionActive
                  ? {
                      sessionId: 'registration-session-parity',
                      status: 'active',
                      remainingUses: 3,
                      expiresAtMs: now + 60_000,
                      createdAtMs: now,
                    }
                  : null,
              hydrateSigningSession: async (input: unknown) => {
                warmSessionActive = true;
                return input;
              },
            },
            configs: {
              signing: {
                mode: { mode: 'threshold-signer' },
              },
              network: {
                relayer: { url: 'https://relay.example' },
              },
            },
          };

          await bootstrapMod.persistRegisteredThresholdEd25519Session({
            signingEngine: context.signingEngine,
            nearAccountId,
            deviceNumber: 1,
            rpId: 'example.localhost',
            relayerUrl: 'https://relay.example',
            prfFirstB64u: 'prf-first-registration',
            registrationSessionPolicy: {
              version: 'threshold_session_v1',
              nearAccountId,
              rpId: 'example.localhost',
              relayerKeyId: 'rk-1',
              sessionId: 'registration-session-parity',
              participantIds: [1, 2],
              ttlMs: 60_000,
              remainingUses: 3,
              runtimeSnapshotScope: {
                orgId: 'org-registration',
                environmentId: 'env-registration',
              },
            },
            completedRegistration: {
              registered: {
                keyVersion: 'threshold-ed25519-hss-v1',
                recoveryExportCapable: true,
                publicKey: 'ed25519:registration-public-key',
                relayerKeyId: 'rk-1',
                clientParticipantId: 1,
                relayerParticipantId: 2,
                participantIds: [1, 2],
                session: {
                  sessionKind: 'jwt',
                  sessionId: 'registration-session-parity',
                  expiresAtMs: now + 60_000,
                  participantIds: [1, 2],
                  remainingUses: 3,
                  runtimeSnapshotScope: {
                    orgId: 'org-registration',
                    environmentId: 'env-registration',
                  },
                  jwt: 'jwt-registration',
                },
              },
              operationalPublicKey: 'ed25519:registration-user',
            },
          });

          const walletSession = await loginMod.getWalletSession(context, nearAccountId);

          return {
            isLoggedIn: walletSession.login?.isLoggedIn ?? false,
            signingSessionStatus: walletSession.signingSession?.status ?? null,
            sessionId: walletSession.signingSession?.sessionId ?? null,
          };
        } finally {
          clientDb.resolveProfileAccountContext = originalResolveProfileAccountContext;
          clientDb.getMostRecentNearAccountProjection = originalGetMostRecentNearAccountProjection;
          clientDb.resolveNearAccountProfileContinuity = originalResolveNearAccountProfileContinuity;
          accountKeyMaterialDb.storeKeyMaterial = originalStoreKeyMaterial;
          accountKeyMaterialDb.getKeyMaterial = originalGetKeyMaterial;
          sessionStoreMod.clearAllStoredThresholdEd25519SessionRecords();
          authSessionMod.clearAllCachedEd25519AuthSessions();
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.isLoggedIn).toBe(true);
    expect(result.signingSessionStatus).toBe('active');
    expect(result.sessionId).toBe('registration-session-parity');
  });
});
