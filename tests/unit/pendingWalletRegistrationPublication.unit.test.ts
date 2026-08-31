import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';
import {
  buildEcdsaActivationPublicationFixture,
  buildEmailOtpNearProvisioningProductionPublicationFixture,
  buildEmailNearProvisioningPublicationFixture,
  buildMixedActivationPublicationFixture,
  buildPasskeyNearProvisioningProductionPublicationFixture,
  buildPasskeyNearProvisioningPublicationFixture,
} from './helpers/pendingWalletRegistrationPublication.fixtures';
import type { PendingWalletRegistrationPublicationFixture } from './helpers/pendingWalletRegistrationPublication.fixtures';

const IMPORT_PATHS = {
  indexedDB: '/_test-sdk/esm/core/indexedDB/index.js',
  ecdsa: '/_test-sdk/esm/core/indexedDB/seamsWalletDB/ecdsaCapabilityManifestStore.js',
  schemaNames: '/_test-sdk/esm/core/indexedDB/schemaNames.js',
} as const;

type PublicationState = {
  readonly pending: boolean;
  readonly profile: boolean;
  readonly localAuthMethodCount: number;
  readonly foundingAuthMethod: string | null;
  readonly authority: string | null;
  readonly selectionCount: number;
  readonly signerCount: number;
  readonly accountCount: number;
  readonly keyMaterialCount: number;
};

type ProductionPublicationState = {
  readonly pending: boolean;
  readonly walletProfile: boolean;
  readonly nearProfile: boolean;
  readonly authMethod: boolean;
  readonly authority: boolean;
  readonly selection: boolean;
  readonly nearAccounts: number;
  readonly walletSigners: number;
  readonly nearSigners: number;
  readonly keyMaterials: number;
  readonly walletSessionCount: number;
  readonly walletSessionVersions: readonly string[];
};

type ProductionPublicationRetryResult = {
  readonly firstError: string | null;
  readonly afterFailure: ProductionPublicationState;
  readonly afterRetry: ProductionPublicationState;
};

const PRODUCTION_NEAR_PROFILE_ID = 'near-profile:publication.testnet';

async function publishAndReadState(
  page: Parameters<typeof setupBasicPasskeyTest>[0],
  input: PendingWalletRegistrationPublicationFixture['input'],
  ids: {
    readonly authorityId: string;
    readonly profileId: string;
  },
): Promise<PublicationState> {
  return page.evaluate(
    async ({ paths, input: publicationInput, ids: publicationIds }) => {
      const { UnifiedIndexedDBManager, SeamsWalletDBManager, createSeamsTestWalletDbName } =
        await import(paths.indexedDB);
      const { SEAMS_WALLET_STORES } = await import(paths.schemaNames);
      const seamsWalletDB = new SeamsWalletDBManager();
      seamsWalletDB.setDbName(
        createSeamsTestWalletDbName(`pending-publication-${crypto.randomUUID()}`),
      );
      const db = new UnifiedIndexedDBManager({ seamsWalletDB });
      await db.putPendingWalletRegistrationCommit(publicationInput.pending);
      await db.publishPendingWalletRegistrationCommit(publicationInput);
      const pending = await db.getPendingWalletRegistrationCommit({
        registrationCeremonyId: publicationInput.request.registrationCeremonyId,
        operation: publicationInput.request.operation,
      });
      const database = await seamsWalletDB.getDB();
      const authMethodRows = (await database.getAll(
        SEAMS_WALLET_STORES.walletAuthMethods,
      )) as Array<{
        readonly record?: { readonly version?: string };
      }>;
      const foundingMethod = await db.getWalletAuthMethodV2(
        publicationInput.request.walletAuthMethodId,
      );
      const authority = await db.getWalletAuthority(publicationIds.authorityId);
      const state = {
        pending: pending !== null,
        profile: (await db.getProfile(publicationIds.profileId)) !== null,
        localAuthMethodCount: authMethodRows.filter(
          (row) => row.record?.version === 'wallet_auth_method_v1',
        ).length,
        foundingAuthMethod: foundingMethod?.walletAuthMethodId ?? null,
        authority: authority?.authorityId ?? null,
        selectionCount: (await db.listWalletSelections()).filter(
          (selection: { readonly walletId?: string }) =>
            selection.walletId === publicationIds.profileId,
        ).length,
        signerCount: (await db.listAccountSignersByProfile({ profileId: publicationIds.profileId }))
          .length,
        accountCount: (await db.listChainAccountsByProfile(publicationIds.profileId)).length,
        keyMaterialCount: (await db.listKeyMaterialByProfile(publicationIds.profileId)).length,
      };
      seamsWalletDB.close();
      return state;
    },
    { paths: IMPORT_PATHS, input, ids },
  );
}

async function exerciseProductionPublicationRollbackAndRetry(
  page: Parameters<typeof setupBasicPasskeyTest>[0],
  fixture: PendingWalletRegistrationPublicationFixture,
): Promise<ProductionPublicationRetryResult> {
  return page.evaluate(
    async ({ paths, input: publicationInput, nearProfileId }) => {
      const { UnifiedIndexedDBManager, SeamsWalletDBManager, createSeamsTestWalletDbName } =
        await import(paths.indexedDB);
      const { SEAMS_WALLET_STORES } = await import(paths.schemaNames);
      const seamsWalletDB = new SeamsWalletDBManager();
      seamsWalletDB.setDbName(
        createSeamsTestWalletDbName(`pending-production-publication-${crypto.randomUUID()}`),
      );
      const db = new UnifiedIndexedDBManager({ seamsWalletDB });
      await db.putPendingWalletRegistrationCommit(publicationInput.pending);

      async function readState() {
        const database = await seamsWalletDB.getDB();
        const walletSessionRows = (await database.getAll(
          SEAMS_WALLET_STORES.walletSessionAuthorizations,
        )) as Array<{ readonly record_version?: string }>;
        return {
          pending:
            (await db.getPendingWalletRegistrationCommit({
              registrationCeremonyId: publicationInput.request.registrationCeremonyId,
              operation: publicationInput.request.operation,
            })) !== null,
          walletProfile: (await db.getProfile(publicationInput.request.walletId)) !== null,
          nearProfile: (await db.getProfile(nearProfileId)) !== null,
          authMethod:
            (await db.getWalletAuthMethodV2(publicationInput.request.walletAuthMethodId)) !== null,
          authority:
            (await db.getWalletAuthority(
              publicationInput.foundingAuthority.authority.authorityId,
            )) !== null,
          selection: (await db.listWalletSelections()).some(
            (selection: { readonly walletId?: string }) =>
              selection.walletId === publicationInput.request.walletId,
          ),
          nearAccounts: (await db.listChainAccountsByProfile(nearProfileId)).length,
          walletSigners: (
            await db.listAccountSignersByProfile({ profileId: publicationInput.request.walletId })
          ).length,
          nearSigners: (await db.listAccountSignersByProfile({ profileId: nearProfileId })).length,
          keyMaterials: (await db.listKeyMaterialByProfile(nearProfileId)).length,
          walletSessionCount: walletSessionRows.length,
          walletSessionVersions: walletSessionRows.map((row) => row.record_version || '').sort(),
        } satisfies ProductionPublicationState;
      }

      let firstError: string | null = null;
      try {
        await db.publishPendingWalletRegistrationCommit({
          ...publicationInput,
          registration: {
            ...publicationInput.registration,
            keyMaterials: publicationInput.registration.keyMaterials.filter(
              (keyMaterial: { readonly keyKind?: string }) =>
                keyMaterial.keyKind !== 'threshold_share_v1',
            ),
          },
        });
      } catch (caught) {
        firstError = caught instanceof Error ? caught.message : String(caught);
      }
      const afterFailure = await readState();
      await db.publishPendingWalletRegistrationCommit(publicationInput);
      const afterRetry = await readState();
      seamsWalletDB.close();
      return { firstError, afterFailure, afterRetry };
    },
    {
      paths: IMPORT_PATHS,
      input: fixture.input,
      nearProfileId: PRODUCTION_NEAR_PROFILE_ID,
    },
  );
}

function expectProductionPublicationRollbackAndRetry(
  result: ProductionPublicationRetryResult,
): void {
  expect(result.firstError).toContain('key material');
  expect(result.afterFailure).toEqual({
    pending: true,
    walletProfile: false,
    nearProfile: false,
    authMethod: false,
    authority: false,
    selection: false,
    nearAccounts: 0,
    walletSigners: 0,
    nearSigners: 0,
    keyMaterials: 0,
    walletSessionCount: 0,
    walletSessionVersions: [],
  });
  expect(result.afterRetry).toEqual({
    pending: false,
    walletProfile: true,
    nearProfile: true,
    authMethod: true,
    authority: true,
    selection: true,
    nearAccounts: 1,
    walletSigners: 1,
    nearSigners: 1,
    keyMaterials: 2,
    walletSessionCount: 1,
    walletSessionVersions: ['wallet_session_authorization_v6'],
  });
}

test.describe('pending registration publication', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
  });

  test('publishes all local registration state and deletes terminal pending state', async ({
    page,
  }) => {
    const fixture = await buildPasskeyNearProvisioningPublicationFixture();
    const state = await publishAndReadState(page, fixture.input, fixture);

    expect(state).toEqual({
      pending: false,
      profile: true,
      localAuthMethodCount: 1,
      foundingAuthMethod: fixture.walletAuthMethodId,
      authority: fixture.authorityId,
      selectionCount: 1,
      signerCount: 1,
      accountCount: 1,
      keyMaterialCount: 1,
    });
  });

  test('replaces a same-method predecessor while preserving a same-wallet sibling session', async ({
    page,
  }) => {
    const fixture = await buildPasskeyNearProvisioningPublicationFixture();
    const result = await page.evaluate(
      async ({ paths, input: publicationInput }) => {
        const {
          UnifiedIndexedDBManager,
          SeamsWalletDBManager,
          buildActiveWalletSessionV1,
          createSeamsTestWalletDbName,
          toStoredExactWalletSessionAuthorizationRowV6,
        } = await import(paths.indexedDB);
        const { SEAMS_WALLET_STORES } = await import(paths.schemaNames);
        if (publicationInput.walletSessionPublication.kind !== 'issued') {
          throw new Error('publication fixture must issue a Wallet Session');
        }
        const seamsWalletDB = new SeamsWalletDBManager();
        seamsWalletDB.setDbName(
          createSeamsTestWalletDbName(`pending-publication-${crypto.randomUUID()}`),
        );
        const db = new UnifiedIndexedDBManager({ seamsWalletDB });
        const active = publicationInput.walletSessionPublication.walletSession;
        const predecessor = buildActiveWalletSessionV1({
          ...active,
          authorizationId: 'authorization:r103f-publication-predecessor',
          quotaId: 'quota:r103f-publication-predecessor',
          issuedAtMs: 11,
          expiresAtMs: 10_001,
        });
        const predecessorCredential = {
          kind: 'opaque_wallet_session_operation_credential_v1',
          token: publicationInput.walletSessionPublication.operationCredential.token,
          walletSessionId: 'wallet-session:r103f-publication-predecessor',
        };
        const sibling = buildActiveWalletSessionV1({
          ...active,
          authorityId: 'authority:r103f-publication-sibling',
          authMethodId: 'wallet-auth-method:r103f-publication-sibling',
          authorizationId: 'authorization:r103f-publication-sibling',
          quotaId: 'quota:r103f-publication-sibling',
          issuedAtMs: 12,
          expiresAtMs: 10_002,
        });
        const siblingCredential = {
          kind: 'opaque_wallet_session_operation_credential_v1',
          token: publicationInput.walletSessionPublication.operationCredential.token,
          walletSessionId: 'wallet-session:r103f-publication-sibling',
        };
        const database = await seamsWalletDB.getDB();
        await database.put(
          SEAMS_WALLET_STORES.walletSessionAuthorizations,
          toStoredExactWalletSessionAuthorizationRowV6(predecessor, predecessorCredential),
        );
        await database.put(
          SEAMS_WALLET_STORES.walletSessionAuthorizations,
          toStoredExactWalletSessionAuthorizationRowV6(sibling, siblingCredential),
        );
        await db.putPendingWalletRegistrationCommit(publicationInput.pending);
        await db.publishPendingWalletRegistrationCommit(publicationInput);
        const rows = (await database.getAll(
          SEAMS_WALLET_STORES.walletSessionAuthorizations,
        )) as Array<{ readonly wallet_session_id: string }>;
        seamsWalletDB.close();
        return rows.map((row) => row.wallet_session_id).sort();
      },
      { paths: IMPORT_PATHS, input: fixture.input },
    );

    expect(result).toEqual(
      [
        'wallet-session:r103f-publication-sibling',
        String(
          (fixture.input.walletSessionPublication.kind === 'issued' &&
            fixture.input.walletSessionPublication.operationCredential.walletSessionId) ||
            '',
        ),
      ].sort(),
    );
    expect(result).not.toContain('wallet-session:r103f-publication-predecessor');
  });

  test('rejects credential rotation for the same exact Wallet Session', async ({ page }) => {
    const fixture = await buildPasskeyNearProvisioningPublicationFixture();
    const result = await page.evaluate(
      async ({ paths, input: publicationInput }) => {
        const {
          UnifiedIndexedDBManager,
          SeamsWalletDBManager,
          createSeamsTestWalletDbName,
          toStoredExactWalletSessionAuthorizationRowV6,
        } = await import(paths.indexedDB);
        const { SEAMS_WALLET_STORES } = await import(paths.schemaNames);
        if (publicationInput.walletSessionPublication.kind !== 'issued') {
          throw new Error('publication fixture must issue a Wallet Session');
        }
        const binary = String.fromCharCode(...new Uint8Array(32).fill(31));
        const rotatedToken = `wst_${btoa(binary)
          .replaceAll('+', '-')
          .replaceAll('/', '_')
          .replace(/=+$/, '')}`;
        const existingCredential = {
          ...publicationInput.walletSessionPublication.operationCredential,
          token: rotatedToken,
        };
        const seamsWalletDB = new SeamsWalletDBManager();
        seamsWalletDB.setDbName(
          createSeamsTestWalletDbName(`pending-publication-${crypto.randomUUID()}`),
        );
        const db = new UnifiedIndexedDBManager({ seamsWalletDB });
        const database = await seamsWalletDB.getDB();
        await database.put(
          SEAMS_WALLET_STORES.walletSessionAuthorizations,
          toStoredExactWalletSessionAuthorizationRowV6(
            publicationInput.walletSessionPublication.walletSession,
            existingCredential,
          ),
        );
        await db.putPendingWalletRegistrationCommit(publicationInput.pending);
        let error: string | null = null;
        try {
          await db.publishPendingWalletRegistrationCommit(publicationInput);
        } catch (caught) {
          error = caught instanceof Error ? caught.message : String(caught);
        }
        const rows = (await database.getAll(
          SEAMS_WALLET_STORES.walletSessionAuthorizations,
        )) as Array<{
          readonly operation_credential?: { readonly token?: string };
        }>;
        const pending = await db.getPendingWalletRegistrationCommit(publicationInput.request);
        seamsWalletDB.close();
        return {
          error,
          pending: pending !== null,
          sessionCount: rows.length,
          storedToken: rows[0]?.operation_credential?.token || null,
          rotatedToken,
        };
      },
      { paths: IMPORT_PATHS, input: fixture.input },
    );

    expect(result).toEqual({
      error: 'Stored Wallet Session conflicts with the issued operation credential',
      pending: true,
      sessionCount: 1,
      storedToken: result.rotatedToken,
      rotatedToken: result.rotatedToken,
    });
  });

  test('rejects a request identity mismatch without publishing or deleting pending state', async ({
    page,
  }) => {
    const fixture = await buildPasskeyNearProvisioningPublicationFixture();
    const result = await page.evaluate(
      async ({ paths, input: publicationInput }) => {
        const { UnifiedIndexedDBManager, SeamsWalletDBManager, createSeamsTestWalletDbName } =
          await import(paths.indexedDB);
        const seamsWalletDB = new SeamsWalletDBManager();
        seamsWalletDB.setDbName(
          createSeamsTestWalletDbName(`pending-publication-${crypto.randomUUID()}`),
        );
        const db = new UnifiedIndexedDBManager({ seamsWalletDB });
        await db.putPendingWalletRegistrationCommit(publicationInput.pending);
        let error: string | null = null;
        try {
          await db.publishPendingWalletRegistrationCommit({
            ...publicationInput,
            request: {
              ...publicationInput.request,
              idempotencyKey: `${publicationInput.request.idempotencyKey}-wrong`,
            },
          });
        } catch (caught) {
          error = caught instanceof Error ? caught.message : String(caught);
        }
        const state = {
          pending:
            (await db.getPendingWalletRegistrationCommit({
              registrationCeremonyId: publicationInput.request.registrationCeremonyId,
              operation: publicationInput.request.operation,
            })) !== null,
          profile: (await db.getProfile(publicationInput.request.walletId)) !== null,
          authority:
            (await db.getWalletAuthority(
              publicationInput.foundingAuthority.authority.authorityId,
            )) !== null,
        };
        seamsWalletDB.close();
        return { error, state };
      },
      { paths: IMPORT_PATHS, input: fixture.input },
    );
    expect(result.error).toContain('does not match the request');
    expect(result.state).toEqual({ pending: true, profile: false, authority: false });
  });

  test('rolls back every row on a late signer-material failure and succeeds on retry', async ({
    page,
  }) => {
    const fixture = await buildPasskeyNearProvisioningPublicationFixture();
    const result = await page.evaluate(
      async ({ paths, input: publicationInput }) => {
        const { UnifiedIndexedDBManager, SeamsWalletDBManager, createSeamsTestWalletDbName } =
          await import(paths.indexedDB);
        const seamsWalletDB = new SeamsWalletDBManager();
        seamsWalletDB.setDbName(
          createSeamsTestWalletDbName(`pending-publication-${crypto.randomUUID()}`),
        );
        const db = new UnifiedIndexedDBManager({ seamsWalletDB });
        await db.putPendingWalletRegistrationCommit(publicationInput.pending);
        let firstError: string | null = null;
        try {
          await db.publishPendingWalletRegistrationCommit({
            ...publicationInput,
            registration: {
              ...publicationInput.registration,
              keyMaterials: [],
            },
          });
        } catch (caught) {
          firstError = caught instanceof Error ? caught.message : String(caught);
        }
        const afterFailure = {
          pending:
            (await db.getPendingWalletRegistrationCommit({
              registrationCeremonyId: publicationInput.request.registrationCeremonyId,
              operation: publicationInput.request.operation,
            })) !== null,
          profile: (await db.getProfile(publicationInput.request.walletId)) !== null,
          authority:
            (await db.getWalletAuthority(
              publicationInput.foundingAuthority.authority.authorityId,
            )) !== null,
        };
        await db.publishPendingWalletRegistrationCommit(publicationInput);
        const afterRetry = {
          pending:
            (await db.getPendingWalletRegistrationCommit({
              registrationCeremonyId: publicationInput.request.registrationCeremonyId,
              operation: publicationInput.request.operation,
            })) !== null,
          profile: (await db.getProfile(publicationInput.request.walletId)) !== null,
        };
        seamsWalletDB.close();
        return { firstError, afterFailure, afterRetry };
      },
      { paths: IMPORT_PATHS, input: fixture.input },
    );

    expect(result.firstError).toContain('key material');
    expect(result.afterFailure).toEqual({ pending: true, profile: false, authority: false });
    expect(result.afterRetry).toEqual({ pending: false, profile: true });
  });

  test('retries the production Ed25519 batch without exposing a partial wallet', async ({
    page,
  }) => {
    const fixture = await buildPasskeyNearProvisioningProductionPublicationFixture();
    const result = await exerciseProductionPublicationRollbackAndRetry(page, fixture);
    expectProductionPublicationRollbackAndRetry(result);
  });

  test('retries the production Email OTP batch without exposing a partial wallet', async ({
    page,
  }) => {
    const fixture = await buildEmailOtpNearProvisioningProductionPublicationFixture();
    const result = await exerciseProductionPublicationRollbackAndRetry(page, fixture);
    expectProductionPublicationRollbackAndRetry(result);
  });

  test('publishes Email OTP provider and registration-authority identity atomically', async ({
    page,
  }) => {
    const fixture = await buildEmailNearProvisioningPublicationFixture();
    const state = await publishAndReadState(page, fixture.input, fixture);

    expect(state).toEqual({
      pending: false,
      profile: true,
      localAuthMethodCount: 1,
      foundingAuthMethod: fixture.walletAuthMethodId,
      authority: fixture.authorityId,
      selectionCount: 1,
      signerCount: 1,
      accountCount: 1,
      keyMaterialCount: 1,
    });
  });

  test('rejects an Email OTP provider mismatch before any local publication', async ({ page }) => {
    const fixture = await buildEmailNearProvisioningPublicationFixture();
    const result = await page.evaluate(
      async ({ paths, input: publicationInput }) => {
        const { UnifiedIndexedDBManager, SeamsWalletDBManager, createSeamsTestWalletDbName } =
          await import(paths.indexedDB);
        const seamsWalletDB = new SeamsWalletDBManager();
        seamsWalletDB.setDbName(
          createSeamsTestWalletDbName(`pending-publication-${crypto.randomUUID()}`),
        );
        const db = new UnifiedIndexedDBManager({ seamsWalletDB });
        await db.putPendingWalletRegistrationCommit(publicationInput.pending);
        let error: string | null = null;
        try {
          await db.publishPendingWalletRegistrationCommit({
            ...publicationInput,
            authority: {
              ...publicationInput.authority,
              factor: {
                ...publicationInput.authority.factor,
                providerUserId: `${publicationInput.authority.factor.providerUserId}-wrong`,
              },
            },
          });
        } catch (caught) {
          error = caught instanceof Error ? caught.message : String(caught);
        }
        const state = {
          pending:
            (await db.getPendingWalletRegistrationCommit({
              registrationCeremonyId: publicationInput.request.registrationCeremonyId,
              operation: publicationInput.request.operation,
            })) !== null,
          profile: (await db.getProfile(publicationInput.request.walletId)) !== null,
        };
        seamsWalletDB.close();
        return { error, state };
      },
      { paths: IMPORT_PATHS, input: fixture.input },
    );

    expect(result.error).toContain('Email OTP');
    expect(result.state).toEqual({ pending: true, profile: false });
  });

  test('deletes terminal ECDSA-only activation pending state', async ({ page }) => {
    const fixture = await buildEcdsaActivationPublicationFixture();
    const state = await publishAndReadState(page, fixture.input, fixture);

    expect(state).toMatchObject({
      pending: false,
      profile: true,
      localAuthMethodCount: 1,
      foundingAuthMethod: fixture.walletAuthMethodId,
      authority: fixture.authorityId,
      selectionCount: 1,
    });
  });

  test('rolls back ECDSA continuity and every registration projection on a late failure', async ({
    page,
  }) => {
    const fixture = await buildEcdsaActivationPublicationFixture();
    const result = await page.evaluate(
      async ({ paths, input: publicationInput }) => {
        const { UnifiedIndexedDBManager, SeamsWalletDBManager, createSeamsTestWalletDbName } =
          await import(paths.indexedDB);
        const { IndexedDbEcdsaCapabilityManifestStore } = await import(paths.ecdsa);
        const { SEAMS_WALLET_STORES } = await import(paths.schemaNames);
        if (publicationInput.ecdsaContinuity.length !== 1) {
          throw new Error('ECDSA publication fixture must carry one prepared continuity');
        }
        const seamsWalletDB = new SeamsWalletDBManager();
        seamsWalletDB.setDbName(
          createSeamsTestWalletDbName(`pending-publication-ecdsa-rollback-${crypto.randomUUID()}`),
        );
        const db = new UnifiedIndexedDBManager({ seamsWalletDB });
        await db.putPendingWalletRegistrationCommit(publicationInput.pending);
        let firstError: string | null = null;
        try {
          await db.publishPendingWalletRegistrationCommit({
            ...publicationInput,
            ecdsaContinuity: [
              publicationInput.ecdsaContinuity[0],
              publicationInput.ecdsaContinuity[0],
            ],
          });
        } catch (caught) {
          firstError = caught instanceof Error ? caught.message : String(caught);
        }
        const database = await seamsWalletDB.getDB();
        const ecdsaSubjects = await new IndexedDbEcdsaCapabilityManifestStore(
          seamsWalletDB,
        ).listActiveWalletCapabilitySubjects(publicationInput.request.walletId);
        const sessionRows = await database.getAll(SEAMS_WALLET_STORES.walletSessionAuthorizations);
        const state = {
          firstError,
          pending:
            (await db.getPendingWalletRegistrationCommit({
              registrationCeremonyId: publicationInput.request.registrationCeremonyId,
              operation: publicationInput.request.operation,
            })) !== null,
          ecdsaSubjectCount:
            ecdsaSubjects.kind === 'resolved' ? ecdsaSubjects.subjects.length : -1,
          profile: await db.getProfile(publicationInput.request.walletId),
          authMethod: await db.getWalletAuthMethodV2(publicationInput.request.walletAuthMethodId),
          authority: await db.getWalletAuthority(
            publicationInput.foundingAuthority.authority.authorityId,
          ),
          authenticators: await db.listProfileAuthenticators(publicationInput.request.walletId),
          sessionCount: sessionRows.length,
        };
        seamsWalletDB.close();
        return state;
      },
      { paths: IMPORT_PATHS, input: fixture.input },
    );

    expect(result).toMatchObject({
      firstError: 'ECDSA custody import found an existing active manifest',
      pending: true,
      ecdsaSubjectCount: 0,
      profile: null,
      authMethod: null,
      authority: null,
      authenticators: [],
      sessionCount: 0,
    });
  });

  test('retains mixed activation pending state for deferred NEAR publication', async ({ page }) => {
    const fixture = await buildMixedActivationPublicationFixture();
    const state = await publishAndReadState(page, fixture.input, fixture);

    expect(state).toMatchObject({
      pending: true,
      profile: true,
      localAuthMethodCount: 1,
      foundingAuthMethod: fixture.walletAuthMethodId,
      authority: fixture.authorityId,
      selectionCount: 1,
      signerCount: 0,
      accountCount: 0,
      keyMaterialCount: 0,
    });
  });

  test('credential-free publication promotes the canonical session and preserves its credential', async ({
    page,
  }) => {
    const fixture = await buildMixedActivationPublicationFixture();
    const result = await page.evaluate(
      async ({ paths, input: publicationInput }) => {
        const {
          UnifiedIndexedDBManager,
          SeamsWalletDBManager,
          createSeamsTestWalletDbName,
          buildActiveWalletSessionV1,
          toStoredExactWalletSessionAuthorizationRowV6,
        } = await import(paths.indexedDB);
        const { SEAMS_WALLET_STORES } = await import(paths.schemaNames);
        if (publicationInput.walletSessionPublication.kind !== 'issued') {
          throw new Error('mixed publication fixture must issue a Wallet Session');
        }
        const issued = publicationInput.walletSessionPublication;
        const credentialFreeInput = {
          ...publicationInput,
          walletSessionPublication: {
            kind: 'credential_free_projection' as const,
            walletSession: issued.walletSession,
          },
        };
        const seamsWalletDB = new SeamsWalletDBManager();
        seamsWalletDB.setDbName(
          createSeamsTestWalletDbName(`pending-publication-${crypto.randomUUID()}`),
        );
        const db = new UnifiedIndexedDBManager({ seamsWalletDB });
        const database = await seamsWalletDB.getDB();
        const staleDigest = btoa(String.fromCharCode(...new Uint8Array(32).fill(7)))
          .replaceAll('+', '-')
          .replaceAll('/', '_')
          .replace(/=+$/, '');
        const staleSession = buildActiveWalletSessionV1({
          ...issued.walletSession,
          authorityDigestB64u: staleDigest,
        });
        await database.put(
          SEAMS_WALLET_STORES.walletSessionAuthorizations,
          toStoredExactWalletSessionAuthorizationRowV6(staleSession, issued.operationCredential),
        );
        await db.putPendingWalletRegistrationCommit(publicationInput.pending);
        await db.publishPendingWalletRegistrationCommitAndRetain(credentialFreeInput);
        const pendingAfterPublication = await db.getPendingWalletRegistrationCommit(
          publicationInput.request,
        );
        /* The caller may be interrupted while durable side effects finish. */
        const pendingBeforeTerminalDelete = await db.getPendingWalletRegistrationCommit(
          publicationInput.request,
        );
        await db.deletePendingWalletRegistrationCommit(publicationInput.request);
        const pendingAfterDelete = await db.getPendingWalletRegistrationCommit(
          publicationInput.request,
        );
        const sessionRows = (await database.getAll(
          SEAMS_WALLET_STORES.walletSessionAuthorizations,
        )) as Array<{
          readonly record?: unknown;
          readonly operation_credential?: { readonly token?: string };
        }>;
        seamsWalletDB.close();
        return {
          pendingAfterPublication: pendingAfterPublication !== null,
          pendingBeforeTerminalDelete: pendingBeforeTerminalDelete !== null,
          pendingAfterDelete: pendingAfterDelete !== null,
          sessionCount: sessionRows.length,
          session: sessionRows[0]?.record,
          token: sessionRows[0]?.operation_credential?.token,
          expectedSession: issued.walletSession,
          expectedToken: issued.operationCredential.token,
        };
      },
      {
        paths: IMPORT_PATHS,
        input: fixture.input,
      },
    );

    expect(result.pendingAfterPublication).toBe(true);
    expect(result.pendingBeforeTerminalDelete).toBe(true);
    expect(result.pendingAfterDelete).toBe(false);
    expect(result.sessionCount).toBe(1);
    expect(result.session).toMatchObject(result.expectedSession);
    expect(result.token).toBe(result.expectedToken);
  });
});
