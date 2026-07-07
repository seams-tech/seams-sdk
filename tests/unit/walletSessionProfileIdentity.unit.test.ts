import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  login: '/_test-sdk/esm/SeamsWeb/operations/auth/login.js',
  walletUnlockSubject: '/_test-sdk/esm/SeamsWeb/operations/auth/walletUnlockSubject.js',
  indexedDB: '/_test-sdk/esm/core/indexedDB/index.js',
  thresholdSessionStore: '/_test-sdk/esm/core/signingEngine/session/persistence/records.js',
} as const;

test.describe('wallet session profile identity restore', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
  });

  test('restores wallet and NEAR identity from persisted profile when runtime session records are cold', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const loginMod = await import(paths.login);
        const indexedDbMod = await import(paths.indexedDB);
        const thresholdSessionStore = await import(paths.thresholdSessionStore);
        const db = indexedDbMod.IndexedDBManager;
        const walletId = 'refresh-wallet-profile-identity';
        const nearAccountId = 'refresh-profile.testnet';
        const now = Date.now();

        thresholdSessionStore.clearAllStoredThresholdEd25519SessionRecords();
        await db.upsertProfile({
          profileId: walletId,
          defaultSignerSlot: 1,
        });
        await db.activateAccountSigner({
          account: {
            profileId: walletId,
            chainIdKey: 'near:testnet',
            accountAddress: nearAccountId,
            accountModel: 'near-native',
          },
          signer: {
            signerId: 'refresh-profile-signer',
            signerType: 'threshold',
            signerKind: 'threshold-ed25519',
            signerAuthMethod: 'passkey',
            signerSource: 'passkey_registration',
            metadata: {
              walletId,
              nearAccountId,
              nearEd25519SigningKeyId: 'refresh-profile-ed25519-key',
              operationalPublicKey: 'ed25519:refresh-profile-public-key',
              passkeyCredentialId: 'refresh-profile-credential',
              passkeyCredentialRawId: 'refresh-profile-credential',
            },
          },
          activationPolicy: { mode: 'fail_if_occupied', signerSlot: 1 },
          preferredSlot: 1,
          mutation: { routeThroughOutbox: false },
        });

        const session = await loginMod.getWalletSession(
          {
            configs: {
              network: { chains: [] },
              signing: { mode: { mode: 'threshold-signer' } },
            },
            signingEngine: {
              assertSealedRefreshStartupParity: async () => undefined,
              getLastUser: async () => null,
              getUserBySignerSlot: async () => null,
              getWarmThresholdEd25519SessionStatus: async () => ({
                sessionId: 'refresh-profile-session',
                status: 'active',
                remainingUses: 3,
                expiresAtMs: now + 60_000,
                createdAtMs: now,
                authMethod: 'passkey',
              }),
              listWarmThresholdEcdsaSessionStatuses: async () => [],
              listThresholdEcdsaSessionRecordsForWalletTarget: () => [],
              readPersistedAvailableSigningLanes: async () => null,
              getNonceCoordinator: () => ({ getDiagnostics: () => null }),
            },
          },
          walletId,
        );

        return {
          isLoggedIn: session.login.isLoggedIn,
          walletId: String(session.login.walletId || ''),
          nearAccountId: String(session.login.nearAccountId || ''),
          publicKey: session.login.publicKey,
          signingStatus: session.signingSession?.status || null,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toEqual({
      isLoggedIn: true,
      walletId: 'refresh-wallet-profile-identity',
      nearAccountId: 'refresh-profile.testnet',
      publicKey: 'ed25519:refresh-profile-public-key',
      signingStatus: 'active',
    });
  });

  test('restores wallet session from last profile when refresh reads without walletId', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const loginMod = await import(paths.login);
        const subjectMod = await import(paths.walletUnlockSubject);
        const indexedDbMod = await import(paths.indexedDB);
        const thresholdSessionStore = await import(paths.thresholdSessionStore);
        const db = indexedDbMod.IndexedDBManager;
        const walletId = 'refresh-last-profile-wallet';
        const nearAccountId = 'refresh-last-profile.testnet';
        const now = Date.now();

        thresholdSessionStore.clearAllStoredThresholdEd25519SessionRecords();
        await db.upsertProfile({
          profileId: walletId,
          defaultSignerSlot: 1,
        });
        await db.activateAccountSigner({
          account: {
            profileId: walletId,
            chainIdKey: 'near:testnet',
            accountAddress: nearAccountId,
            accountModel: 'near-native',
          },
          signer: {
            signerId: 'refresh-last-profile-signer',
            signerType: 'threshold',
            signerKind: 'threshold-ed25519',
            signerAuthMethod: 'passkey',
            signerSource: 'passkey_registration',
            metadata: {
              walletId,
              nearAccountId,
              nearEd25519SigningKeyId: 'refresh-last-profile-ed25519-key',
              operationalPublicKey: 'ed25519:refresh-last-profile-public-key',
              passkeyCredentialId: 'refresh-last-profile-credential',
              passkeyCredentialRawId: 'refresh-last-profile-credential',
            },
          },
          activationPolicy: { mode: 'fail_if_occupied', signerSlot: 1 },
          preferredSlot: 1,
          mutation: { routeThroughOutbox: false },
        });
        await db.setLastProfileStateForProfile(walletId, 1);

        const context = {
          configs: {
            network: { chains: [] },
            signing: { mode: { mode: 'threshold-signer' } },
          },
          signingEngine: {
            assertSealedRefreshStartupParity: async () => undefined,
            getLastUser: async () => null,
            getUserBySignerSlot: async () => null,
            getWarmThresholdEd25519SessionStatus: async () => ({
              sessionId: 'refresh-last-profile-session',
              status: 'active',
              remainingUses: 3,
              expiresAtMs: now + 60_000,
              createdAtMs: now,
              authMethod: 'passkey',
            }),
            listWarmThresholdEcdsaSessionStatuses: async () => [],
            listThresholdEcdsaSessionRecordsForWalletTarget: () => [],
            readPersistedAvailableSigningLanes: async () => null,
            getNonceCoordinator: () => ({ getDiagnostics: () => null }),
          },
        };

        const resolution = await subjectMod.resolveWalletSessionReadResolution();
        const session = await loginMod.getWalletSession(context);

        return {
          resolutionKind: resolution.kind,
          resolutionWalletId: String(resolution.walletId || ''),
          resolutionSource: resolution.source || null,
          isLoggedIn: session.login.isLoggedIn,
          walletId: String(session.login.walletId || ''),
          nearAccountId: String(session.login.nearAccountId || ''),
          publicKey: session.login.publicKey,
          signingStatus: session.signingSession?.status || null,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toEqual({
      resolutionKind: 'resolved',
      resolutionWalletId: 'refresh-last-profile-wallet',
      resolutionSource: 'host_last_used_profile',
      isLoggedIn: true,
      walletId: 'refresh-last-profile-wallet',
      nearAccountId: 'refresh-last-profile.testnet',
      publicKey: 'ed25519:refresh-last-profile-public-key',
      signingStatus: 'active',
    });
  });

  test('resolves last NEAR profile to wallet session through wallet-bound signer metadata', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const loginMod = await import(paths.login);
        const subjectMod = await import(paths.walletUnlockSubject);
        const indexedDbMod = await import(paths.indexedDB);
        const thresholdSessionStore = await import(paths.thresholdSessionStore);
        const db = indexedDbMod.IndexedDBManager;
        const walletId = 'refresh-near-profile-wallet';
        const nearProfileId = 'near-profile:refresh-near-profile.testnet';
        const nearAccountId = 'refresh-near-profile.testnet';
        const now = Date.now();
        const signer = {
          signerId: 'refresh-near-profile-signer',
          signerType: 'threshold',
          signerKind: 'threshold-ed25519',
          signerAuthMethod: 'passkey',
          signerSource: 'passkey_registration',
          metadata: {
            walletId,
            nearAccountId,
            nearEd25519SigningKeyId: 'refresh-near-profile-ed25519-key',
            operationalPublicKey: 'ed25519:refresh-near-profile-public-key',
            passkeyCredentialId: 'refresh-near-profile-credential',
            passkeyCredentialRawId: 'refresh-near-profile-credential',
          },
        };

        thresholdSessionStore.clearAllStoredThresholdEd25519SessionRecords();
        await db.upsertProfile({
          profileId: walletId,
          defaultSignerSlot: 1,
        });
        await db.upsertProfile({
          profileId: nearProfileId,
          defaultSignerSlot: 1,
        });
        await db.activateAccountSigner({
          account: {
            profileId: walletId,
            chainIdKey: 'wallet:subject',
            accountAddress: walletId,
            accountModel: 'wallet-subject',
          },
          signer,
          activationPolicy: { mode: 'fail_if_occupied', signerSlot: 1 },
          preferredSlot: 1,
          mutation: { routeThroughOutbox: false },
        });
        await db.activateAccountSigner({
          account: {
            profileId: nearProfileId,
            chainIdKey: 'near:testnet',
            accountAddress: nearAccountId,
            accountModel: 'near-native',
          },
          signer,
          activationPolicy: { mode: 'fail_if_occupied', signerSlot: 1 },
          preferredSlot: 1,
          mutation: { routeThroughOutbox: false },
        });
        await db.setLastProfileStateForProfile(nearProfileId, 1);

        const context = {
          configs: {
            network: { chains: [] },
            signing: { mode: { mode: 'threshold-signer' } },
          },
          signingEngine: {
            assertSealedRefreshStartupParity: async () => undefined,
            getLastUser: async () => null,
            getUserBySignerSlot: async () => null,
            getWarmThresholdEd25519SessionStatus: async () => ({
              sessionId: 'refresh-near-profile-session',
              status: 'active',
              remainingUses: 3,
              expiresAtMs: now + 60_000,
              createdAtMs: now,
              authMethod: 'passkey',
            }),
            listWarmThresholdEcdsaSessionStatuses: async () => [],
            listThresholdEcdsaSessionRecordsForWalletTarget: () => [],
            readPersistedAvailableSigningLanes: async () => null,
            getNonceCoordinator: () => ({ getDiagnostics: () => null }),
          },
        };

        const resolution = await subjectMod.resolveWalletSessionReadResolution();
        const session = await loginMod.getWalletSession(context);

        return {
          resolutionKind: resolution.kind,
          resolutionWalletId: String(resolution.walletId || ''),
          resolutionSource: resolution.source || null,
          isLoggedIn: session.login.isLoggedIn,
          walletId: String(session.login.walletId || ''),
          nearAccountId: String(session.login.nearAccountId || ''),
          publicKey: session.login.publicKey,
          signingStatus: session.signingSession?.status || null,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toEqual({
      resolutionKind: 'resolved',
      resolutionWalletId: 'refresh-near-profile-wallet',
      resolutionSource: 'host_last_used_profile',
      isLoggedIn: true,
      walletId: 'refresh-near-profile-wallet',
      nearAccountId: 'refresh-near-profile.testnet',
      publicKey: 'ed25519:refresh-near-profile-public-key',
      signingStatus: 'active',
    });
  });

  test('resolves an ECDSA-only wallet subject without fabricating NEAR identity', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const subjectMod = await import(paths.walletUnlockSubject);
        const indexedDbMod = await import(paths.indexedDB);
        const thresholdSessionStore = await import(paths.thresholdSessionStore);
        const db = indexedDbMod.IndexedDBManager;
        const walletId = 'refresh-wallet-ecdsa-only';
        const thresholdOwnerAddress = '0x1111111111111111111111111111111111111111';
        const chainTarget = {
          kind: 'evm',
          namespace: 'eip155',
          chainId: 5042002,
          networkSlug: 'arc-testnet',
        };
        const evmFamilySigningKeySlotId =
          'wallet-key:evm-family:refresh-wallet-ecdsa-only:proj-refresh:default';

        thresholdSessionStore.clearAllStoredThresholdEd25519SessionRecords();
        await db.upsertProfile({
          profileId: walletId,
          defaultSignerSlot: 1,
        });
        await db.activateAccountSigner({
          account: {
            profileId: walletId,
            chainIdKey: 'evm:eip155:5042002',
            accountAddress: thresholdOwnerAddress,
            accountModel: 'threshold-ecdsa',
          },
          signer: {
            signerId: thresholdOwnerAddress,
            signerType: 'threshold',
            signerKind: 'threshold-ecdsa',
            signerAuthMethod: 'passkey',
            signerSource: 'passkey_registration',
            metadata: {
              walletId,
              keyHandle: 'ehss-key-refresh-ecdsa-only',
              ecdsaThresholdKeyId: 'ehss-refresh-ecdsa-only',
              thresholdOwnerAddress,
              chainTarget,
              thresholdEcdsaPublicKeyB64u: 'A1111111111111111111111111111111111111111111',
              evmFamilySigningKeySlotId,
              walletKeyId: evmFamilySigningKeySlotId,
            },
          },
          activationPolicy: { mode: 'fail_if_occupied', signerSlot: 1 },
          preferredSlot: 1,
          mutation: { routeThroughOutbox: false },
        });

        const resolution = await subjectMod.resolveWalletSessionReadResolution(walletId);

        type BrowserWalletSubject = {
          kind?: unknown;
          walletId?: unknown;
          nearAccountId?: unknown;
          evmFamilySigningKeySlotId?: unknown;
        };

        return {
          kind: resolution.kind,
          walletId: String(resolution.walletId || ''),
          subjects:
            resolution.kind === 'resolved'
              ? resolution.subjectSet.subjects.map((subject: BrowserWalletSubject) => ({
                  kind: subject.kind,
                  walletId: String(subject.walletId || ''),
                  nearAccountId: String(subject.nearAccountId || ''),
                  evmFamilySigningKeySlotId: String(subject.evmFamilySigningKeySlotId || ''),
                }))
              : [],
          source: resolution.source || null,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toEqual({
      kind: 'resolved',
      walletId: 'refresh-wallet-ecdsa-only',
      subjects: [
        {
          kind: 'evm_family_ecdsa_wallet',
          walletId: 'refresh-wallet-ecdsa-only',
          nearAccountId: '',
          evmFamilySigningKeySlotId:
            'wallet-key:evm-family:refresh-wallet-ecdsa-only:proj-refresh:default',
        },
      ],
      source: 'profile_projection',
    });
  });

  test('treats an explicit wallet without capability subjects as logged out without warning', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const loginMod = await import(paths.login);
        const subjectMod = await import(paths.walletUnlockSubject);
        const thresholdSessionStore = await import(paths.thresholdSessionStore);
        const walletId = 'refresh-empty-wallet-selection';
        const warnings: unknown[][] = [];
        const originalWarn = console.warn;
        console.warn = (...args: unknown[]) => {
          warnings.push(args);
        };

        try {
          thresholdSessionStore.clearAllStoredThresholdEd25519SessionRecords();
          const context = {
            configs: {
              network: { chains: [] },
              signing: { mode: { mode: 'threshold-signer' } },
            },
            signingEngine: {
              assertSealedRefreshStartupParity: async () => undefined,
              getLastUser: async () => null,
              getUserBySignerSlot: async () => null,
              getWarmThresholdEd25519SessionStatus: async () => null,
              listWarmThresholdEcdsaSessionStatuses: async () => [],
              listThresholdEcdsaSessionRecordsForWalletTarget: () => [],
              readPersistedAvailableSigningLanes: async () => null,
              getNonceCoordinator: () => ({ getDiagnostics: () => null }),
            },
          };
          const resolution = await subjectMod.resolveWalletSessionReadResolution(walletId);
          const session = await loginMod.getWalletSession(context, walletId);

          return {
            resolutionKind: resolution.kind,
            resolutionWalletId: String(resolution.walletId || ''),
            resolutionReason: resolution.reason || null,
            isLoggedIn: session.login.isLoggedIn,
            walletId: String(session.login.walletId || ''),
            warningCount: warnings.length,
          };
        } finally {
          console.warn = originalWarn;
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toEqual({
      resolutionKind: 'no_session_for_wallet',
      resolutionWalletId: 'refresh-empty-wallet-selection',
      resolutionReason: 'missing_requested_capability_subject',
      isLoggedIn: false,
      walletId: 'refresh-empty-wallet-selection',
      warningCount: 0,
    });
  });
});
