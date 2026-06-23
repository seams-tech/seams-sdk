import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  thresholdWarmSessionBootstrap:
    '/sdk/esm/SeamsWeb/operations/session/thresholdWarmSessionBootstrap.js',
  login: '/sdk/esm/SeamsWeb/operations/auth/login.js',
  indexedDb: '/sdk/esm/core/indexedDB/index.js',
  keyMaterialBrands: '/sdk/esm/core/signingEngine/session/keyMaterialBrands.js',
  thresholdSessionStore:
    '/sdk/esm/core/signingEngine/session/persistence/records.js',
} as const;

async function evaluateMismatchedWarmSessionIdentity(args: {
  paths: typeof IMPORT_PATHS;
}): Promise<string | null> {
  const bootstrapMod = await import(args.paths.thresholdWarmSessionBootstrap);
  const now = Date.now();
  try {
    bootstrapMod.completeRegisteredThresholdEd25519Registration({
      thresholdEd25519: {
        nearAccountId: 'registration-alice.testnet',
        ed25519KeyScopeId: 'registration-alice.testnet',
        keyVersion: 'threshold-ed25519-hss-v1',
        recoveryExportCapable: true,
        publicKey: 'ed25519:registration-public-key',
        relayerKeyId: 'rk-1',
        clientParticipantId: 1,
        relayerParticipantId: 2,
        participantIds: [1, 2],
        session: {
          sessionKind: 'jwt',
          walletId: 'wallet_alice',
          nearAccountId: 'registration-alice.testnet',
          ed25519KeyScopeId: 'wrong-scope',
          thresholdSessionId: 'registration-session-1',
          signingGrantId: 'signing-grant-1',
          expiresAtMs: now + 60_000,
          participantIds: [1, 2],
          remainingUses: 3,
          routerAbNormalSigning: {
            kind: 'router_ab_ed25519_normal_signing_v1',
            signingWorkerId: 'signing-worker-local',
          },
          jwt: 'jwt-registration',
        },
      },
      expectedSessionPolicy: {
        version: 'threshold_session_v1',
        walletId: 'wallet_alice',
        nearAccountId: 'registration-alice.testnet',
        ed25519KeyScopeId: 'registration-alice.testnet',
        rpId: 'example.localhost',
        relayerKeyId: 'rk-1',
        thresholdSessionId: 'registration-session-1',
        signingGrantId: 'signing-grant-1',
        participantIds: [1, 2],
        ttlMs: 60_000,
        remainingUses: 3,
        routerAbNormalSigning: {
          kind: 'router_ab_ed25519_normal_signing_v1',
          signingWorkerId: 'signing-worker-local',
        },
      },
      expectedIdentity: {
        walletId: 'wallet_alice',
        nearAccountId: 'registration-alice.testnet',
        ed25519KeyScopeId: 'registration-alice.testnet',
      },
    });
    return null;
  } catch (error: unknown) {
    return error instanceof Error ? error.message : String(error);
  }
}

test.describe('threshold Ed25519 registration warm-session', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
  });

  test('rejects returned warm-session identity that differs from expected registration binding', async ({
    page,
  }) => {
    const message = await page.evaluate(evaluateMismatchedWarmSessionIdentity, {
      paths: IMPORT_PATHS,
    });

    expect(message).toBe('threshold-ed25519 warm session ed25519KeyScopeId mismatch');
  });

  test('awaits warm-session hydrate before registration persistence returns', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const bootstrapMod = await import(paths.thresholdWarmSessionBootstrap);
        const loginMod = await import(paths.login);
        const indexedDbMod = await import(paths.indexedDb);
        const keyMaterialBrandsMod = await import(paths.keyMaterialBrands);
        const sessionStoreMod = await import(paths.thresholdSessionStore);

        const nearAccountId = 'registration-alice.testnet';
        const walletId = nearAccountId;
        const ed25519KeyScopeId = nearAccountId;
        const now = Date.now();
        const routerAbNormalSigning = {
          kind: 'router_ab_ed25519_normal_signing_v1',
          signingWorkerId: 'signing-worker-local',
        };
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
                routerAb: {
                  normalSigning: {
                    mode: 'enabled',
                    signingWorkerId: 'signing-worker-local',
                  },
                },
              },
              network: {
                chains: [],
                relayer: { url: 'https://relay.example' },
              },
            },
          };

          await bootstrapMod.persistRegisteredThresholdEd25519Session({
            signingEngine: context.signingEngine,
            walletId,
            nearAccountId,
            ed25519KeyScopeId,
            signerSlot: 1,
            auth: { kind: 'passkey' },
            rpId: 'example.localhost',
            relayerUrl: 'https://relay.example',
            prfFirstB64u: 'prf-first-registration',
            registrationSessionPolicy: {
              version: 'threshold_session_v1',
              walletId,
              nearAccountId,
              ed25519KeyScopeId,
              rpId: 'example.localhost',
              relayerKeyId: 'rk-1',
              sessionId: 'registration-session-1',
              signingGrantId: 'signing-grant-1',
              participantIds: [1, 2],
              ttlMs: 60_000,
              remainingUses: 3,
              runtimePolicyScope: {
                orgId: 'org-registration',
                projectId: 'proj-registration',
                envId: 'env-registration',
                signingRootVersion: 'default',
              },
              routerAbNormalSigning,
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
                  walletId,
                  nearAccountId,
                  ed25519KeyScopeId,
                  thresholdSessionId: 'registration-session-1',
                  signingGrantId: 'signing-grant-1',
                  expiresAtMs: now + 60_000,
                  participantIds: [1, 2],
                  remainingUses: 3,
                  runtimePolicyScope: {
                    orgId: 'org-registration',
                    projectId: 'proj-registration',
                    envId: 'env-registration',
                    signingRootVersion: 'default',
                  },
                  routerAbNormalSigning,
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

  test('registration reconstruction seal refresh uses configured seal keyVersion', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const bootstrapMod = await import(paths.thresholdWarmSessionBootstrap);
        const keyMaterialBrandsMod = await import(paths.keyMaterialBrands);
        const sessionStoreMod = await import(paths.thresholdSessionStore);

        const now = Date.now();
        const nearAccountId = 'registration-reconstruct.testnet';
        const thresholdSessionId = 'registration-session-reconstruct';
        const runtimePolicyScope = {
          orgId: 'org-registration',
          projectId: 'proj-registration',
          envId: 'env-registration',
          signingRootVersion: 'default',
        };
        const routerAbNormalSigning = {
          kind: 'router_ab_ed25519_normal_signing_v1',
          signingWorkerId: 'signing-worker-local',
        };
        const hydrateInputs: Array<Record<string, unknown>> = [];
        let hssContextKeyVersion: string | null = null;
        let sealAuthorizationMaterialKeyId: string | null = null;

        sessionStoreMod.clearAllStoredThresholdEd25519SessionRecords();
        try {
          sessionStoreMod.upsertStoredThresholdEd25519SessionRecord({
            nearAccountId,
            rpId: 'example.localhost',
            relayerUrl: 'https://relay.example',
            relayerKeyId: 'rk-reconstruct',
            participantIds: [1, 2],
            signingRootId: 'proj-registration:env-registration',
            signingRootVersion: 'default',
            runtimePolicyScope,
            routerAbNormalSigning,
            thresholdSessionKind: 'jwt',
            thresholdSessionId,
            signingGrantId: 'signing-grant-reconstruct',
            walletSessionJwt: 'jwt-registration-reconstruct',
            expiresAtMs: now + 60_000,
            remainingUses: 3,
            signerSlot: 1,
            source: 'registration',
          });

          const context = {
            signingEngine: {
              prepareThresholdEd25519HssClientCeremonyFromCredential: async (input: {
                keyVersion: string;
              }) => {
                hssContextKeyVersion = input.keyVersion;
                return {
                  ok: true,
                  participantIds: [1, 2],
                  contextBindingB64u: 'context-binding',
                  yClientB64u: 'y-client',
                  tauClientB64u: 'tau-client',
                };
              },
              prepareThresholdEd25519PasskeyPrfWorkerMaterialSealAuthorization: async () => {
                sealAuthorizationMaterialKeyId = 'material-key-reconstruct';
                return {
                  ok: true,
                  materialKeyId: 'material-key-reconstruct',
                  remainingUses: 1,
                  sealAuthorization: {
                    kind: 'passkey_prf_material_seal_authorization_handle_v1',
                    handle: 'seal-auth-handle',
                    rpId: 'example.localhost',
                    credentialIdB64u: 'credential-id',
                    materialKeyId: 'material-key-reconstruct',
                    expiresAtMs: 0,
                  },
                };
              },
              runThresholdEd25519HssCeremonyWithMaterialHandle: async (input: {
                context: { keyVersion: string };
              }) => ({
                ok: true,
                signingMaterial: {
                  materialHandle: 'worker-material-handle',
                  materialBindingDigest: 'worker-material-binding-digest',
                  sealedWorkerMaterialRef: 'sealed-worker-material-ref',
                  sealedWorkerMaterialB64u: 'sealed-worker-material',
                  materialFormatVersion: 'ed25519_worker_material_v1',
                  materialKeyId: 'material-key-reconstruct',
                  keyVersion: input.context.keyVersion,
                  clientVerifyingShareB64u: 'client-verifier',
                  signerSlot: 1,
                },
              }),
              hydrateSigningSession: async (input: Record<string, unknown>) => {
                hydrateInputs.push(input);
              },
            },
          };

          await bootstrapMod.reconstructThresholdEd25519SigningMaterialFromWarmSession({
            context,
            credential: {
              rawId: 'credential-id',
              id: 'credential-id',
              clientExtensionResults: {
                prf: {
                  results: {
                    first: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                  },
                },
              },
            },
            nearAccountId,
            rpId: 'example.localhost',
            relayerUrl: 'https://relay.example',
            relayerKeyId: 'rk-reconstruct',
            signerSlot: 1,
            session: {
              thresholdSessionId,
              jwt: 'jwt-registration-reconstruct',
              signingGrantId: 'signing-grant-reconstruct',
              expiresAtMs: now + 60_000,
              remainingUses: 3,
              participantIds: [1, 2],
              runtimePolicyScope,
              routerAbNormalSigning,
            },
            ed25519HssKeyVersion: keyMaterialBrandsMod.parseEd25519HssKeyVersion(
              'threshold-ed25519-hss-v1',
            ),
            materialCreatedAtMs: now,
            participantIdsHint: [1, 2],
          });

          const hydrateTransport = hydrateInputs[0]?.transport as Record<string, unknown> | undefined;
          const storedRecord =
            sessionStoreMod.getStoredThresholdEd25519SessionRecordByThresholdSessionId(
              thresholdSessionId,
            );

          return {
            hydrateCalls: hydrateInputs.length,
            hydrateTransportKeyVersion: hydrateTransport?.keyVersion ?? null,
            hydrateTransportWalletSessionJwt: hydrateTransport?.walletSessionJwt ?? null,
            hssContextKeyVersion,
            sealAuthorizationMaterialKeyId,
            storedRecordKeyVersion: storedRecord?.keyVersion ?? null,
            storedRecordMaterialKeyId: storedRecord?.materialKeyId ?? null,
          };
        } finally {
          sessionStoreMod.clearAllStoredThresholdEd25519SessionRecords();
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.hydrateCalls).toBe(1);
    expect(result.hydrateTransportKeyVersion).toBeNull();
    expect(result.hydrateTransportWalletSessionJwt).toBe('jwt-registration-reconstruct');
    expect(result.hssContextKeyVersion).toBe('threshold-ed25519-hss-v1');
    expect(result.sealAuthorizationMaterialKeyId).toBe('material-key-reconstruct');
    expect(result.storedRecordKeyVersion).toBe('threshold-ed25519-hss-v1');
    expect(result.storedRecordMaterialKeyId).toBe('material-key-reconstruct');
  });

  test('wallet session read ignores Tempo parity failures after registration', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const bootstrapMod = await import(paths.thresholdWarmSessionBootstrap);
        const loginMod = await import(paths.login);
        const indexedDbMod = await import(paths.indexedDb);
        const sessionStoreMod = await import(paths.thresholdSessionStore);

        const nearAccountId = 'registration-parity.testnet';
        const walletId = nearAccountId;
        const ed25519KeyScopeId = nearAccountId;
        const now = Date.now();
        const routerAbNormalSigning = {
          kind: 'router_ab_ed25519_normal_signing_v1',
          signingWorkerId: 'signing-worker-local',
        };
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
                routerAb: {
                  normalSigning: {
                    mode: 'enabled',
                    signingWorkerId: 'signing-worker-local',
                  },
                },
              },
              network: {
                chains: [],
                relayer: { url: 'https://relay.example' },
              },
            },
          };

          await bootstrapMod.persistRegisteredThresholdEd25519Session({
            signingEngine: context.signingEngine,
            walletId,
            nearAccountId,
            ed25519KeyScopeId,
            signerSlot: 1,
            auth: { kind: 'passkey' },
            rpId: 'example.localhost',
            relayerUrl: 'https://relay.example',
            prfFirstB64u: 'prf-first-registration',
            registrationSessionPolicy: {
              version: 'threshold_session_v1',
              walletId,
              nearAccountId,
              ed25519KeyScopeId,
              rpId: 'example.localhost',
              relayerKeyId: 'rk-1',
              sessionId: 'registration-session-parity',
              signingGrantId: 'signing-grant-parity',
              participantIds: [1, 2],
              ttlMs: 60_000,
              remainingUses: 3,
              runtimePolicyScope: {
                orgId: 'org-registration',
                projectId: 'proj-registration',
                envId: 'env-registration',
                signingRootVersion: 'default',
              },
              routerAbNormalSigning,
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
                  walletId,
                  nearAccountId,
                  ed25519KeyScopeId,
                  thresholdSessionId: 'registration-session-parity',
                  signingGrantId: 'signing-grant-parity',
                  expiresAtMs: now + 60_000,
                  participantIds: [1, 2],
                  remainingUses: 3,
                  runtimePolicyScope: {
                    orgId: 'org-registration',
                    projectId: 'proj-registration',
                    envId: 'env-registration',
                    signingRootVersion: 'default',
                  },
                  routerAbNormalSigning,
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

  test('Email OTP registration persists sealed Ed25519 worker material before hydrate', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const bootstrapMod = await import(paths.thresholdWarmSessionBootstrap);
        const indexedDbMod = await import(paths.indexedDb);
        const sessionStoreMod = await import(paths.thresholdSessionStore);

        const nearAccountId = 'registration-email-otp.testnet';
        const walletId = nearAccountId;
        const ed25519KeyScopeId = nearAccountId;
        const now = Date.now();
        const runtimePolicyScope = {
          orgId: 'org-registration',
          projectId: 'proj-registration',
          envId: 'env-registration',
          signingRootVersion: 'default',
        };
        const routerAbNormalSigning = {
          kind: 'router_ab_ed25519_normal_signing_v1',
          signingWorkerId: 'signing-worker-local',
        };
        const signingRootId = 'proj-registration:env-registration';
        const recoveryCodeSecret32B64u = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
        const workerRequests: Array<Record<string, unknown>> = [];
        let materialHandleCalls = 0;
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
          const workerCtx = {
            requestWorkerOperation: async (request: Record<string, unknown>) => {
              workerRequests.push(request);
              return {
                ok: true,
                materialKeyId: 'email-otp-material-key',
                remainingUses: 1,
                sealAuthorization: {
                  kind: 'recovery_code_material_seal_authorization_handle_v1',
                  handle: 'email-otp-seal-auth-handle',
                  authSubjectId: 'google:registration-subject',
                  recoveryCodeBindingDigest: 'email-otp-recovery-binding',
                  materialKeyId: 'email-otp-material-key',
                  expiresAtMs: 0,
                },
              };
            },
          };

          await bootstrapMod.persistRegisteredThresholdEd25519Session({
            signingEngine: {
              runThresholdEd25519HssCeremonyWithMaterialHandle: async (input: {
                context: { keyVersion: string };
              }) => {
                materialHandleCalls += 1;
                return {
                  ok: true,
                  signingMaterial: {
                    materialHandle: 'email-otp-worker-material',
                    materialBindingDigest: 'email-otp-worker-binding',
                    sealedWorkerMaterialRef: 'email-otp-sealed-worker-material',
                    sealedWorkerMaterialB64u: 'email-otp-sealed-worker-material-b64u',
                    materialFormatVersion: 'ed25519_worker_material_v1',
                    materialKeyId: 'email-otp-material-key',
                    keyVersion: input.context.keyVersion,
                    clientVerifyingShareB64u: 'email-otp-client-verifier',
                    signerSlot: 1,
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
            walletId,
            nearAccountId,
            ed25519KeyScopeId,
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
            workerCtx,
            rpId: 'example.localhost',
            relayerUrl: 'https://relay.example',
            prfFirstB64u: recoveryCodeSecret32B64u,
            registrationHssClientMaterial: {
              hssContext: {
                signingRootId,
                nearAccountId,
                keyPurpose: 'near-ed25519-signing',
                keyVersion: 'threshold-ed25519-hss-v1',
                participantIds: [1, 2],
                derivationVersion: 1,
              },
              prfFirstB64u: recoveryCodeSecret32B64u,
              clientInputs: {
                contextBindingB64u: 'client-context-binding',
                yClientB64u: 'y-client',
                tauClientB64u: 'tau-client',
              },
            },
            registrationSessionPolicy: {
              version: 'threshold_session_v1',
              walletId,
              nearAccountId,
              ed25519KeyScopeId,
              rpId: 'example.localhost',
              relayerKeyId: 'rk-email-otp',
              sessionId: 'registration-session-email-otp',
              signingGrantId: 'signing-grant-email-otp',
              participantIds: [1, 2],
              ttlMs: 60_000,
              remainingUses: 3,
              runtimePolicyScope,
              routerAbNormalSigning,
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
                  walletId,
                  nearAccountId,
                  ed25519KeyScopeId,
                  thresholdSessionId: 'registration-session-email-otp',
                  signingGrantId: 'signing-grant-email-otp',
                  expiresAtMs: now + 60_000,
                  participantIds: [1, 2],
                  remainingUses: 3,
                  runtimePolicyScope,
                  routerAbNormalSigning,
                  jwt: 'jwt-registration-email-otp',
                },
              },
              operationalPublicKey: 'ed25519:registration-user',
            },
          });

          const capturedHydratedRecord = hydratedRecord as Record<string, unknown> | null;
          return {
            materialHandleCalls,
            workerRequestCount: workerRequests.length,
            hydratedSource: capturedHydratedRecord?.source || null,
            hydratedXClientBaseB64u: capturedHydratedRecord?.xClientBaseB64u || null,
            hydratedSessionId: capturedHydratedRecord?.thresholdSessionId || null,
            hydratedWorkerMaterialHandle:
              capturedHydratedRecord?.ed25519WorkerMaterialHandle || null,
            hydratedClientVerifyingShareB64u:
              capturedHydratedRecord?.clientVerifyingShareB64u || null,
            hydratedMaterialBindingDigest:
              capturedHydratedRecord?.ed25519WorkerMaterialBindingDigest || null,
            hydratedSealedWorkerMaterialRef:
              capturedHydratedRecord?.sealedWorkerMaterialRef || null,
            hydratedMaterialKeyId: capturedHydratedRecord?.materialKeyId || null,
            hydratedMaterialCreatedAtMs: capturedHydratedRecord?.materialCreatedAtMs || null,
            hydratedKeyVersion: capturedHydratedRecord?.keyVersion || null,
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

    expect(result.materialHandleCalls).toBe(1);
    expect(result.workerRequestCount).toBe(1);
    expect(result.hydratedSource).toBe('email_otp');
    expect(result.hydratedXClientBaseB64u).toBeNull();
    expect(result.hydratedSessionId).toBe('registration-session-email-otp');
    expect(result.hydratedWorkerMaterialHandle).toBe('email-otp-worker-material');
    expect(result.hydratedClientVerifyingShareB64u).toBe('email-otp-client-verifier');
    expect(result.hydratedMaterialBindingDigest).toBe('email-otp-worker-binding');
    expect(result.hydratedSealedWorkerMaterialRef).toBe('email-otp-sealed-worker-material');
    expect(result.hydratedMaterialKeyId).toBe('email-otp-material-key');
    expect(typeof result.hydratedMaterialCreatedAtMs).toBe('number');
    expect(result.hydratedKeyVersion).toBe('threshold-ed25519-hss-v1');
  });
});
