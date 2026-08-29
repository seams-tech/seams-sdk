import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';
import {
  buildEcdsaActivationPublicationFixture,
  buildEmailNearProvisioningPublicationFixture,
  buildMixedActivationPublicationFixture,
  buildPasskeyNearProvisioningProductionPublicationFixture,
  buildPasskeyNearProvisioningPublicationFixture,
} from './helpers/pendingWalletRegistrationPublication.fixtures';
import type { PendingWalletRegistrationPublicationFixture } from './helpers/pendingWalletRegistrationPublication.fixtures';

const IMPORT_PATHS = {
  indexedDB: '/_test-sdk/esm/core/indexedDB/index.js',
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
    const result = await page.evaluate(
      async ({ paths, input: publicationInput, nearProfileId }) => {
        const { UnifiedIndexedDBManager, SeamsWalletDBManager, createSeamsTestWalletDbName } =
          await import(paths.indexedDB);
        const seamsWalletDB = new SeamsWalletDBManager();
        seamsWalletDB.setDbName(
          createSeamsTestWalletDbName(`pending-production-publication-${crypto.randomUUID()}`),
        );
        const db = new UnifiedIndexedDBManager({ seamsWalletDB });
        await db.putPendingWalletRegistrationCommit(publicationInput.pending);
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
        const afterFailure = {
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
        };
        await db.publishPendingWalletRegistrationCommit(publicationInput);
        const afterRetry = {
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
        };
        seamsWalletDB.close();
        return { firstError, afterFailure, afterRetry };
      },
      {
        paths: IMPORT_PATHS,
        input: fixture.input,
        nearProfileId: 'near-profile:publication.testnet',
      },
    );

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
    });
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
});
