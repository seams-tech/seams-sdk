import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';
import {
  canonicalEcdsaAvailableLane,
  readAvailableLanesFixture,
} from './helpers/availableSigningLanes.fixtures';
import {
  ecdsaCapabilityActivationFixture,
  type EcdsaCapabilityActivationFixture,
} from './helpers/ecdsaCapabilityManifest.fixtures';

const IMPORT_PATHS = {
  login: '/_test-sdk/esm/SeamsWeb/operations/auth/login.js',
  walletUnlockSubject: '/_test-sdk/esm/SeamsWeb/operations/auth/walletUnlockSubject.js',
  indexedDB: '/_test-sdk/esm/core/indexedDB/index.js',
  ecdsaManifestStore: '/_test-sdk/esm/core/indexedDB/seamsWalletDB/ecdsaCapabilityManifestStore.js',
} as const;

async function exerciseCanonicalEcdsaRefreshReconciliation(input: {
  readonly paths: typeof IMPORT_PATHS;
  readonly fixture: EcdsaCapabilityActivationFixture;
  readonly availableLanes: Awaited<ReturnType<typeof readAvailableLanesFixture>>;
}) {
  const loginMod = await import(input.paths.login);
  const storeMod = await import(input.paths.ecdsaManifestStore);
  const store = new storeMod.IndexedDbEcdsaCapabilityManifestStore();
  const prepared = await store.prepareActivation(input.fixture.prepareInput);
  if (prepared.kind !== 'stored' || prepared.journal.kind !== 'activation_prepared') {
    throw new Error(`ECDSA refresh fixture preparation failed: ${prepared.kind}`);
  }
  const committed = await store.recordServerActivation({
    preparedJournal: prepared.journal,
    serverCommit: input.fixture.serverCommit,
  });
  if (committed.kind !== 'stored' || committed.journal.kind !== 'server_activation_committed') {
    throw new Error(`ECDSA refresh fixture commit failed: ${committed.kind}`);
  }
  const finalized = await store.sealAndFinalizeActivation({
    committedJournal: committed.journal,
    ...input.fixture.sealInput,
  });
  if (finalized.kind !== 'committed') {
    throw new Error(`ECDSA refresh fixture finalization failed: ${finalized.kind}`);
  }

  const reconciliationRequests: unknown[] = [];
  const session = await loginMod.getWalletSession(
    {
      configs: {
        network: { chains: [] },
        signing: { mode: { mode: 'threshold-signer' } },
      },
      signingEngine: {
        readWalletAuthenticationState: () => ({ kind: 'signed_out' as const }),
        setWalletAuthenticated: () => undefined,
        getSignerWorkerContext: () => ({
          requestWorkerOperation: async (args: unknown) => {
            reconciliationRequests.push(args);
            return {
              type: 70_117,
              payload: { kind: 'canonical_ecdsa_activation_reconciliation_absent_v1' },
            };
          },
        }),
        assertSealedRefreshStartupParity: async () => undefined,
        getLastUser: async () => null,
        getUserBySignerSlot: async () => null,
        getWarmThresholdEd25519SessionStatus: async () => null,
        listWarmThresholdEcdsaSessionStatuses: async () => [],
        readPersistedAvailableSigningLanes: async () => input.availableLanes,
        getReusableWalletSessionStatus: async () => null,
        getNonceCoordinator: () => ({ getDiagnostics: () => null }),
      },
    },
    input.fixture.prepareInput.activationBinding.signer.authority.walletId,
  );
  const projection = session.capabilityProjection;
  if (projection.kind !== 'resolved') {
    throw new Error(`ECDSA refresh capability projection failed: ${projection.kind}`);
  }
  const subject = projection.subjectSet.subjects[0];
  const appIdentity = session.appIdentity;
  return {
    projectionKind: projection.kind,
    subject,
    reconciliationRequestCount: reconciliationRequests.length,
    thresholdEcdsaEthereumAddress:
      appIdentity.kind === 'resolved' ? appIdentity.thresholdEcdsaEthereumAddress : null,
    thresholdEcdsaPublicKeyB64u:
      appIdentity.kind === 'resolved' ? appIdentity.thresholdEcdsaPublicKeyB64u : null,
  };
}

test.describe('wallet session profile identity restore', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
  });

  test('keeps persisted wallet and NEAR identity logged out when no exact signing lane survives', async ({
    page,
  }) => {
    const availableLanes = await readAvailableLanesFixture({
      walletId: 'refresh-wallet-profile-identity',
    });
    const result = await page.evaluate(
      async ({ paths, availableLanes }) => {
        const loginMod = await import(paths.login);
        const indexedDbMod = await import(paths.indexedDB);
        const db = indexedDbMod.IndexedDBManager;
        const walletId = 'refresh-wallet-profile-identity';
        const nearAccountId = 'refresh-profile.testnet';
        const now = Date.now();

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
              readWalletAuthenticationState: () => ({ kind: 'signed_out' as const }),
              setWalletAuthenticated: () => undefined,
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
              readPersistedAvailableSigningLanes: async () => availableLanes,
              getReusableWalletSessionStatus: async () => null,
              getNonceCoordinator: () => ({ getDiagnostics: () => null }),
            },
          },
          walletId,
        );

        return {
          appIdentityKind: session.appIdentity.kind,
          walletId:
            session.appIdentity.kind === 'resolved' ? String(session.appIdentity.walletId) : '',
          nearAccountId:
            session.appIdentity.kind === 'resolved'
              ? String(session.appIdentity.nearAccountId || '')
              : '',
          publicKey:
            session.appIdentity.kind === 'resolved'
              ? session.appIdentity.nearOperationalPublicKey
              : null,
          walletSessionKind: session.reusableWalletSession.kind,
        };
      },
      { paths: IMPORT_PATHS, availableLanes },
    );

    expect(result).toEqual({
      appIdentityKind: 'resolved',
      walletId: 'refresh-wallet-profile-identity',
      nearAccountId: 'refresh-profile.testnet',
      publicKey: 'ed25519:refresh-profile-public-key',
      walletSessionKind: 'absent',
    });
  });

  test('resolves the last profile without activating a wallet that has no exact signing lane', async ({
    page,
  }) => {
    const availableLanes = await readAvailableLanesFixture({
      walletId: 'refresh-last-profile-wallet',
    });
    const result = await page.evaluate(
      async ({ paths, availableLanes }) => {
        const loginMod = await import(paths.login);
        const subjectMod = await import(paths.walletUnlockSubject);
        const indexedDbMod = await import(paths.indexedDB);
        const db = indexedDbMod.IndexedDBManager;
        const walletId = 'refresh-last-profile-wallet';
        const nearAccountId = 'refresh-last-profile.testnet';
        const now = Date.now();

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
            readWalletAuthenticationState: () => ({ kind: 'signed_out' as const }),
            setWalletAuthenticated: () => undefined,
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
            readPersistedAvailableSigningLanes: async () => availableLanes,
            getReusableWalletSessionStatus: async () => null,
            getNonceCoordinator: () => ({ getDiagnostics: () => null }),
          },
        };

        const resolution = await subjectMod.resolveWalletCapabilitySubjectResolution();
        const session = await loginMod.getWalletSession(context);

        return {
          resolutionKind: resolution.kind,
          resolutionWalletId: String(resolution.walletId || ''),
          resolutionSource: resolution.source || null,
          appIdentityKind: session.appIdentity.kind,
          walletId:
            session.appIdentity.kind === 'resolved' ? String(session.appIdentity.walletId) : '',
          nearAccountId:
            session.appIdentity.kind === 'resolved'
              ? String(session.appIdentity.nearAccountId || '')
              : '',
          publicKey:
            session.appIdentity.kind === 'resolved'
              ? session.appIdentity.nearOperationalPublicKey
              : null,
          walletSessionKind: session.reusableWalletSession.kind,
        };
      },
      { paths: IMPORT_PATHS, availableLanes },
    );

    expect(result).toEqual({
      resolutionKind: 'resolved',
      resolutionWalletId: 'refresh-last-profile-wallet',
      resolutionSource: 'host_last_used_profile',
      appIdentityKind: 'resolved',
      walletId: 'refresh-last-profile-wallet',
      nearAccountId: 'refresh-last-profile.testnet',
      publicKey: 'ed25519:refresh-last-profile-public-key',
      walletSessionKind: 'absent',
    });
  });

  test('resolves the last NEAR profile without activating it from advisory warm status alone', async ({
    page,
  }) => {
    const availableLanes = await readAvailableLanesFixture({
      walletId: 'refresh-near-profile-wallet',
    });
    const result = await page.evaluate(
      async ({ paths, availableLanes }) => {
        const loginMod = await import(paths.login);
        const subjectMod = await import(paths.walletUnlockSubject);
        const indexedDbMod = await import(paths.indexedDB);
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
            readWalletAuthenticationState: () => ({ kind: 'signed_out' as const }),
            setWalletAuthenticated: () => undefined,
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
            readPersistedAvailableSigningLanes: async () => availableLanes,
            getReusableWalletSessionStatus: async () => null,
            getNonceCoordinator: () => ({ getDiagnostics: () => null }),
          },
        };

        const resolution = await subjectMod.resolveWalletCapabilitySubjectResolution();
        const session = await loginMod.getWalletSession(context);

        return {
          resolutionKind: resolution.kind,
          resolutionWalletId: String(resolution.walletId || ''),
          resolutionSource: resolution.source || null,
          appIdentityKind: session.appIdentity.kind,
          walletId:
            session.appIdentity.kind === 'resolved' ? String(session.appIdentity.walletId) : '',
          nearAccountId:
            session.appIdentity.kind === 'resolved'
              ? String(session.appIdentity.nearAccountId || '')
              : '',
          publicKey:
            session.appIdentity.kind === 'resolved'
              ? session.appIdentity.nearOperationalPublicKey
              : null,
          walletSessionKind: session.reusableWalletSession.kind,
        };
      },
      { paths: IMPORT_PATHS, availableLanes },
    );

    expect(result).toEqual({
      resolutionKind: 'resolved',
      resolutionWalletId: 'refresh-near-profile-wallet',
      resolutionSource: 'host_last_used_profile',
      appIdentityKind: 'resolved',
      walletId: 'refresh-near-profile-wallet',
      nearAccountId: 'refresh-near-profile.testnet',
      publicKey: 'ed25519:refresh-near-profile-public-key',
      walletSessionKind: 'absent',
    });
  });

  test('reconciles the exact canonical ECDSA subject during wallet-session refresh', async ({
    page,
  }) => {
    const fixture = ecdsaCapabilityActivationFixture();
    const availableLanes = await readAvailableLanesFixture({
      walletId: fixture.prepareInput.activationBinding.signer.authority.walletId,
    });
    const result = await page.evaluate(exerciseCanonicalEcdsaRefreshReconciliation, {
      paths: IMPORT_PATHS,
      fixture,
      availableLanes,
    });

    expect(result).toEqual({
      projectionKind: 'resolved',
      subject: {
        kind: 'evm_family_ecdsa_wallet',
        walletId: fixture.prepareInput.activationBinding.signer.authority.walletId,
        capability: fixture.prepareInput.activationBinding.signer.capability,
        authority: fixture.prepareInput.activationBinding.signer.authority,
        ecdsaThresholdKeyId:
          fixture.prepareInput.activationBinding.roleLocalBinding.ecdsaThresholdKeyId,
      },
      reconciliationRequestCount: 1,
      thresholdEcdsaEthereumAddress: null,
      thresholdEcdsaPublicKeyB64u: null,
    });
  });

  test('projects the canonical ECDSA public key from an available lane', async ({ page }) => {
    const fixture = ecdsaCapabilityActivationFixture();
    const chainTarget = fixture.prepareInput.activationBinding.signer.scope.targetMemberships[0]!;
    const canonicalLane = canonicalEcdsaAvailableLane({
      walletId: String(fixture.prepareInput.activationBinding.signer.authority.walletId),
      chainTarget,
      thresholdOwnerAddress: '0x1111111111111111111111111111111111111111',
      authMethod: 'email_otp',
    });
    const availableLanes = await readAvailableLanesFixture({
      walletId: fixture.prepareInput.activationBinding.signer.authority.walletId,
      ecdsaChainTargets: [chainTarget],
      canonicalEcdsaLanes: [canonicalLane],
    });
    const result = await page.evaluate(exerciseCanonicalEcdsaRefreshReconciliation, {
      paths: IMPORT_PATHS,
      fixture,
      availableLanes,
    });

    expect(result).toMatchObject({
      thresholdEcdsaEthereumAddress: '0x1111111111111111111111111111111111111111',
      thresholdEcdsaPublicKeyB64u: canonicalLane.publicFacts.publicKeyB64u,
    });
  });

  test('treats an explicit wallet without capability subjects as logged out without warning', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const loginMod = await import(paths.login);
        const subjectMod = await import(paths.walletUnlockSubject);
        const walletId = 'refresh-empty-wallet-selection';
        const warnings: unknown[][] = [];
        const originalWarn = console.warn;
        console.warn = (...args: unknown[]) => {
          warnings.push(args);
        };

        try {
          const context = {
            configs: {
              network: { chains: [] },
              signing: { mode: { mode: 'threshold-signer' } },
            },
            signingEngine: {
              readWalletAuthenticationState: () => ({ kind: 'signed_out' as const }),
              setWalletAuthenticated: () => undefined,
              assertSealedRefreshStartupParity: async () => undefined,
              getLastUser: async () => null,
              getUserBySignerSlot: async () => null,
              getWarmThresholdEd25519SessionStatus: async () => null,
              listWarmThresholdEcdsaSessionStatuses: async () => [],
              readPersistedAvailableSigningLanes: async () => null,
              getReusableWalletSessionStatus: async () => null,
              getNonceCoordinator: () => ({ getDiagnostics: () => null }),
            },
          };
          const resolution = await subjectMod.resolveWalletCapabilitySubjectResolution(walletId);
          const session = await loginMod.getWalletSession(context, walletId);

          return {
            resolutionKind: resolution.kind,
            resolutionWalletId: String(resolution.walletId || ''),
            resolutionReason: resolution.reason || null,
            appIdentityKind: session.appIdentity.kind,
            walletId:
              session.appIdentity.kind === 'anonymous' ? '' : String(session.appIdentity.walletId),
            walletSessionKind: session.reusableWalletSession.kind,
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
      appIdentityKind: 'resolved',
      walletId: 'refresh-empty-wallet-selection',
      walletSessionKind: 'absent',
      warningCount: 0,
    });
  });
});
