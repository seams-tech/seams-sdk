import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  thresholdWarmSessionBootstrap: '/sdk/esm/core/SeamsPasskey/thresholdWarmSessionBootstrap.js',
  login: '/sdk/esm/core/SeamsPasskey/login.js',
  indexedDb: '/sdk/esm/core/indexedDB/index.js',
  thresholdSessionStore:
    '/sdk/esm/core/signingEngine/session/persistence/records.js',
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

        const nearAccountId = 'registration-alice.testnet';
        const now = Date.now();
        let warmSessionActive = false;
        let hydrateCalls = 0;

        sessionStoreMod.clearAllStoredThresholdEd25519SessionRecords();

        const clientDb = indexedDbMod.IndexedDBManager as Record<string, unknown>;
        const keyMaterialPort = indexedDbMod.IndexedDBManager as Record<string, unknown>;
        const originalResolveProfileAccountContext = clientDb.resolveProfileAccountContext;
        const originalGetMostRecentNearAccountProjection = clientDb.getMostRecentNearAccountProjection;
        const originalResolveNearAccountProfileContinuity =
          clientDb.resolveNearAccountProfileContinuity;
        const originalStoreKeyMaterial = keyMaterialPort.storeKeyMaterial;
        const originalGetKeyMaterial = keyMaterialPort.getKeyMaterial;

        clientDb.resolveProfileAccountContext = async (accountRef: {
          chainIdKey: string;
          accountAddress: string;
        }) =>
          accountRef.chainIdKey === 'near:testnet' &&
          String(accountRef.accountAddress || '').trim() === nearAccountId
            ? { profileId: `near-profile:${nearAccountId}`, accountRef }
            : null;
        clientDb.getMostRecentNearAccountProjection = async () => null;
        clientDb.resolveNearAccountProfileContinuity = async () => ({ chainAccounts: [] });
        keyMaterialPort.storeKeyMaterial = async () => undefined;
        keyMaterialPort.getKeyMaterial = async () => null;

        try {
          const context = {
            signingEngine: {
              assertSealedRefreshStartupParity: async () => undefined,
              getUserBySignerSlot: async () => ({
                nearAccountId,
                signerSlot: 1,
                operationalPublicKey: 'ed25519:registration-user',
              }),
              getLastUser: async () => ({
                nearAccountId,
                signerSlot: 1,
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
                chains: [],
                relayer: { url: 'https://relay.example' },
              },
            },
          };

          await bootstrapMod.persistRegisteredThresholdEd25519Session({
            signingEngine: context.signingEngine,
            nearAccountId,
            signerSlot: 1,
            auth: { kind: 'passkey' },
            rpId: 'example.localhost',
            relayerUrl: 'https://relay.example',
            prfFirstB64u: 'prf-first-registration',
            registrationSessionPolicy: {
              version: 'threshold_session_v1',
              nearAccountId,
              rpId: 'example.localhost',
              relayerKeyId: 'rk-1',
              sessionId: 'registration-session-1',
              walletSigningSessionId: 'wallet-signing-session-1',
              participantIds: [1, 2],
              ttlMs: 60_000,
              remainingUses: 3,
              runtimePolicyScope: {
                orgId: 'org-registration',
                projectId: 'proj-registration',
                envId: 'env-registration',
                signingRootVersion: 'default',
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
                  walletSigningSessionId: 'wallet-signing-session-1',
                  expiresAtMs: now + 60_000,
                  participantIds: [1, 2],
                  remainingUses: 3,
                  runtimePolicyScope: {
                    orgId: 'org-registration',
                    projectId: 'proj-registration',
                    envId: 'env-registration',
                    signingRootVersion: 'default',
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
          keyMaterialPort.storeKeyMaterial = originalStoreKeyMaterial;
          keyMaterialPort.getKeyMaterial = originalGetKeyMaterial;
          sessionStoreMod.clearAllStoredThresholdEd25519SessionRecords();
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

        const nearAccountId = 'registration-parity.testnet';
        const now = Date.now();
        let warmSessionActive = false;

        sessionStoreMod.clearAllStoredThresholdEd25519SessionRecords();

        const clientDb = indexedDbMod.IndexedDBManager as Record<string, unknown>;
        const keyMaterialPort = indexedDbMod.IndexedDBManager as Record<string, unknown>;
        const originalResolveProfileAccountContext = clientDb.resolveProfileAccountContext;
        const originalGetMostRecentNearAccountProjection = clientDb.getMostRecentNearAccountProjection;
        const originalResolveNearAccountProfileContinuity =
          clientDb.resolveNearAccountProfileContinuity;
        const originalStoreKeyMaterial = keyMaterialPort.storeKeyMaterial;
        const originalGetKeyMaterial = keyMaterialPort.getKeyMaterial;

        clientDb.resolveProfileAccountContext = async (accountRef: {
          chainIdKey: string;
          accountAddress: string;
        }) =>
          accountRef.chainIdKey === 'near:testnet' &&
          String(accountRef.accountAddress || '').trim() === nearAccountId
            ? { profileId: `near-profile:${nearAccountId}`, accountRef }
            : null;
        clientDb.getMostRecentNearAccountProjection = async () => null;
        clientDb.resolveNearAccountProfileContinuity = async () => ({ chainAccounts: [] });
        keyMaterialPort.storeKeyMaterial = async () => undefined;
        keyMaterialPort.getKeyMaterial = async () => null;

        try {
          const context = {
            signingEngine: {
              assertSealedRefreshStartupParity: async () => {
                throw new Error('[sealed-refresh-parity] Well-known endpoint returned HTTP 502');
              },
              getUserBySignerSlot: async () => ({
                nearAccountId,
                signerSlot: 1,
                operationalPublicKey: 'ed25519:registration-user',
              }),
              getLastUser: async () => ({
                nearAccountId,
                signerSlot: 1,
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
                chains: [],
                relayer: { url: 'https://relay.example' },
              },
            },
          };

          await bootstrapMod.persistRegisteredThresholdEd25519Session({
            signingEngine: context.signingEngine,
            nearAccountId,
            signerSlot: 1,
            auth: { kind: 'passkey' },
            rpId: 'example.localhost',
            relayerUrl: 'https://relay.example',
            prfFirstB64u: 'prf-first-registration',
            registrationSessionPolicy: {
              version: 'threshold_session_v1',
              nearAccountId,
              rpId: 'example.localhost',
              relayerKeyId: 'rk-1',
              sessionId: 'registration-session-parity',
              walletSigningSessionId: 'wallet-signing-session-parity',
              participantIds: [1, 2],
              ttlMs: 60_000,
              remainingUses: 3,
              runtimePolicyScope: {
                orgId: 'org-registration',
                projectId: 'proj-registration',
                envId: 'env-registration',
                signingRootVersion: 'default',
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
                  walletSigningSessionId: 'wallet-signing-session-parity',
                  expiresAtMs: now + 60_000,
                  participantIds: [1, 2],
                  remainingUses: 3,
                  runtimePolicyScope: {
                    orgId: 'org-registration',
                    projectId: 'proj-registration',
                    envId: 'env-registration',
                    signingRootVersion: 'default',
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
          keyMaterialPort.storeKeyMaterial = originalStoreKeyMaterial;
          keyMaterialPort.getKeyMaterial = originalGetKeyMaterial;
          sessionStoreMod.clearAllStoredThresholdEd25519SessionRecords();
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.isLoggedIn).toBe(true);
    expect(result.signingSessionStatus).toBe('active');
    expect(result.sessionId).toBe('registration-session-parity');
  });

  test('Email OTP registration reconstructs Ed25519 client-base on the happy path', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const bootstrapMod = await import(paths.thresholdWarmSessionBootstrap);
        const indexedDbMod = await import(paths.indexedDb);
        const sessionStoreMod = await import(paths.thresholdSessionStore);

        const nearAccountId = 'registration-email-otp.testnet';
        const now = Date.now();
        const runtimePolicyScope = {
          orgId: 'org-registration',
          projectId: 'proj-registration',
          envId: 'env-registration',
          signingRootVersion: 'default',
        };
        const signingRootId = 'proj-registration:env-registration';
        let reconstructCall: Record<string, unknown> | null = null;
        let hydratedRecord: Record<string, unknown> | null = null;

        sessionStoreMod.clearAllStoredThresholdEd25519SessionRecords();

        const clientDb = indexedDbMod.IndexedDBManager as Record<string, unknown>;
        const keyMaterialPort = indexedDbMod.IndexedDBManager as Record<string, unknown>;
        const originalResolveProfileAccountContext = clientDb.resolveProfileAccountContext;
        const originalGetMostRecentNearAccountProjection = clientDb.getMostRecentNearAccountProjection;
        const originalResolveNearAccountProfileContinuity =
          clientDb.resolveNearAccountProfileContinuity;
        const originalStoreKeyMaterial = keyMaterialPort.storeKeyMaterial;
        const originalGetKeyMaterial = keyMaterialPort.getKeyMaterial;

        clientDb.resolveProfileAccountContext = async (accountRef: {
          chainIdKey: string;
          accountAddress: string;
        }) =>
          accountRef.chainIdKey === 'near:testnet' &&
          String(accountRef.accountAddress || '').trim() === nearAccountId
            ? { profileId: `near-profile:${nearAccountId}`, accountRef }
            : null;
        clientDb.getMostRecentNearAccountProjection = async () => null;
        clientDb.resolveNearAccountProfileContinuity = async () => ({ chainAccounts: [] });
        keyMaterialPort.storeKeyMaterial = async () => undefined;
        keyMaterialPort.getKeyMaterial = async () => null;

        try {
          await bootstrapMod.persistRegisteredThresholdEd25519Session({
            signingEngine: {
              runThresholdEd25519HssCeremonyWithSession: async (input: Record<string, unknown>) => {
                reconstructCall = input;
                return {
                  ok: true,
                  contextBindingB64u: 'context-binding',
                  preparedSession: {},
                  finalizedReport: {},
                  clientOutput: {
                    xClientBaseB64u: 'email-otp-x-client-base',
                  },
                };
              },
              hydrateSigningSession: async () => {
                hydratedRecord =
                  sessionStoreMod.getStoredThresholdEd25519SessionRecordByThresholdSessionId(
                    'registration-session-email-otp',
                  );
              },
            },
            nearAccountId,
            signerSlot: 1,
            auth: {
              kind: 'email_otp',
              emailOtpAuthContext: {
                policy: 'session',
                retention: 'session',
                reason: 'login',
                authMethod: 'email_otp',
                authSubjectId: 'google:registration-subject',
              },
            },
            rpId: 'example.localhost',
            relayerUrl: 'https://relay.example',
            prfFirstB64u: 'email-otp-prf-first',
            registrationHssClientMaterial: {
              hssContext: {
                signingRootId,
                nearAccountId,
                keyPurpose: 'near-ed25519-signing',
                keyVersion: 'threshold-ed25519-hss-v1',
                participantIds: [1, 2],
                derivationVersion: 1,
              },
              prfFirstB64u: 'email-otp-prf-first',
              clientInputs: {
                contextBindingB64u: 'client-context-binding',
                yClientB64u: 'y-client',
                tauClientB64u: 'tau-client',
              },
            },
            registrationSessionPolicy: {
              version: 'threshold_session_v1',
              nearAccountId,
              rpId: 'example.localhost',
              relayerKeyId: 'rk-email-otp',
              sessionId: 'registration-session-email-otp',
              walletSigningSessionId: 'wallet-signing-session-email-otp',
              participantIds: [1, 2],
              ttlMs: 60_000,
              remainingUses: 3,
              runtimePolicyScope,
            },
            completedRegistration: {
              registered: {
                keyVersion: 'threshold-ed25519-hss-v1',
                recoveryExportCapable: true,
                publicKey: 'ed25519:registration-public-key',
                relayerKeyId: 'rk-email-otp',
                clientParticipantId: 1,
                relayerParticipantId: 2,
                participantIds: [1, 2],
                session: {
                  sessionKind: 'jwt',
                  sessionId: 'registration-session-email-otp',
                  walletSigningSessionId: 'wallet-signing-session-email-otp',
                  expiresAtMs: now + 60_000,
                  participantIds: [1, 2],
                  remainingUses: 3,
                  runtimePolicyScope,
                  jwt: 'jwt-registration-email-otp',
                },
              },
              operationalPublicKey: 'ed25519:registration-user',
            },
          });

          const capturedReconstructCall = reconstructCall as Record<string, unknown> | null;
          const capturedHydratedRecord = hydratedRecord as Record<string, unknown> | null;
          return {
            reconstructOperation: capturedReconstructCall?.operation || null,
            reconstructRelayerKeyId: capturedReconstructCall?.relayerKeyId || null,
            reconstructProjection: capturedReconstructCall?.outputProjection || null,
            hydratedSource: capturedHydratedRecord?.source || null,
            hydratedXClientBaseB64u: capturedHydratedRecord?.xClientBaseB64u || null,
            hydratedSessionId: capturedHydratedRecord?.thresholdSessionId || null,
          };
        } finally {
          clientDb.resolveProfileAccountContext = originalResolveProfileAccountContext;
          clientDb.getMostRecentNearAccountProjection = originalGetMostRecentNearAccountProjection;
          clientDb.resolveNearAccountProfileContinuity = originalResolveNearAccountProfileContinuity;
          keyMaterialPort.storeKeyMaterial = originalStoreKeyMaterial;
          keyMaterialPort.getKeyMaterial = originalGetKeyMaterial;
          sessionStoreMod.clearAllStoredThresholdEd25519SessionRecords();
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.reconstructOperation).toBe('warm_session_reconstruction');
    expect(result.reconstructRelayerKeyId).toBe('rk-email-otp');
    expect(result.reconstructProjection).toEqual({
      kind: 'client-masked-projection',
      clientRecoverableSecretB64u: 'email-otp-prf-first',
    });
    expect(result.hydratedSource).toBe('email_otp');
    expect(result.hydratedXClientBaseB64u).toBe('email-otp-x-client-base');
    expect(result.hydratedSessionId).toBe('registration-session-email-otp');
  });
});
