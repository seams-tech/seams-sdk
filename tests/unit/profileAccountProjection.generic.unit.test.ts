import { expect, test } from '@playwright/test';
import { sdkEsmPath, setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  unifiedDb: sdkEsmPath('core/indexedDB/index.js'),
  projection: sdkEsmPath('core/indexedDB/profileAccountProjection.js'),
} as const;

test.describe('generic profile/account projection helpers', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
  });

  test('resolves mapped candidates and selects canonical signer slots', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { UnifiedIndexedDBManager, SeamsWalletDBManager, createSeamsTestWalletDbName } =
          await import(paths.unifiedDb);
        const { resolveProfileAccountContextFromCandidates, resolveProfileAccountProjection } =
          await import(paths.projection);

        const suffix =
          typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
            ? crypto.randomUUID()
            : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
        const seamsWalletDB = new SeamsWalletDBManager();
        seamsWalletDB.setDbName(createSeamsTestWalletDbName(`profile-projection-${suffix}`));
        const clientDB = new UnifiedIndexedDBManager({ seamsWalletDB });

        await clientDB.upsertProfile({
          profileId: 'profile-near-projection',
          defaultSignerSlot: 2,
          passkeyCredential: {
            id: 'projection-credential-id',
            rawId: 'projection-credential-raw-id',
          },
        });
        await clientDB.upsertChainAccount({
          profileId: 'profile-near-projection',
          chainIdKey: 'near:testnet',
          accountAddress: 'projection.testnet',
          accountModel: 'near-native',
          isPrimary: true,
        });
        await clientDB.activateAccountSigner({
          account: {
            profileId: 'profile-near-projection',
            chainIdKey: 'near:testnet',
            accountAddress: 'projection.testnet',
            accountModel: 'near-native',
          },
          signer: {
            signerId: 'signer-device-1',
            signerType: 'threshold',
            signerKind: 'threshold-ed25519',
            signerAuthMethod: 'passkey',
            signerSource: 'passkey_registration',
          },
          activationPolicy: { mode: 'fail_if_occupied', signerSlot: 1 },
          preferredSlot: 1,
          mutation: { routeThroughOutbox: false },
        });
        await clientDB.activateAccountSigner({
          account: {
            profileId: 'profile-near-projection',
            chainIdKey: 'near:testnet',
            accountAddress: 'projection.testnet',
            accountModel: 'near-native',
          },
          signer: {
            signerId: 'signer-device-2',
            signerType: 'threshold',
            signerKind: 'threshold-ed25519',
            signerAuthMethod: 'passkey',
            signerSource: 'passkey_registration',
          },
          activationPolicy: { mode: 'fail_if_occupied', signerSlot: 2 },
          preferredSlot: 2,
          mutation: { routeThroughOutbox: false },
        });

        const accountRefs = [
          { chainIdKey: 'tempo:42431', accountAddress: '0xmissing' },
          { chainIdKey: 'near:testnet', accountAddress: 'projection.testnet' },
        ];
        const context = await resolveProfileAccountContextFromCandidates(clientDB, accountRefs);
        const projection = await resolveProfileAccountProjection(clientDB, { accountRefs });
        const explicitProjection = await resolveProfileAccountProjection(clientDB, {
          accountRefs,
          signerSlot: 1,
        });

        return {
          context,
          selectedSignerId: projection?.selectedSigner?.signerId || null,
          explicitSignerId: explicitProjection?.selectedSigner?.signerId || null,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.context).toMatchObject({
      profileId: 'profile-near-projection',
      accountRef: {
        chainIdKey: 'near:testnet',
        accountAddress: 'projection.testnet',
      },
    });
    expect(result.selectedSignerId).toBe('signer-device-2');
    expect(result.explicitSignerId).toBe('signer-device-1');
  });

  test('returns the last selected profile state against generic chain candidates', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { UnifiedIndexedDBManager, SeamsWalletDBManager, createSeamsTestWalletDbName } =
          await import(paths.unifiedDb);
        const { getLastSelectedProfileAccountByChain } = await import(paths.projection);

        const suffix =
          typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
            ? crypto.randomUUID()
            : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
        const seamsWalletDB = new SeamsWalletDBManager();
        seamsWalletDB.setDbName(createSeamsTestWalletDbName(`last-selected-profile-${suffix}`));
        const clientDB = new UnifiedIndexedDBManager({ seamsWalletDB });

        await clientDB.upsertProfile({
          profileId: 'profile-last-selected',
          defaultSignerSlot: 3,
          passkeyCredential: {
            id: 'last-selected-credential-id',
            rawId: 'last-selected-credential-raw-id',
          },
        });
        await clientDB.upsertChainAccount({
          profileId: 'profile-last-selected',
          chainIdKey: 'near:testnet',
          accountAddress: 'primary.testnet',
          accountModel: 'near-native',
          isPrimary: true,
        });
        await clientDB.upsertChainAccount({
          profileId: 'profile-last-selected',
          chainIdKey: 'near:testnet',
          accountAddress: 'secondary.testnet',
          accountModel: 'near-native',
          isPrimary: false,
        });
        await clientDB.activateAccountSigner({
          account: {
            profileId: 'profile-last-selected',
            chainIdKey: 'near:testnet',
            accountAddress: 'primary.testnet',
            accountModel: 'near-native',
          },
          signer: {
            signerId: 'signer-device-3',
            signerType: 'threshold',
            signerKind: 'threshold-ed25519',
            signerAuthMethod: 'passkey',
            signerSource: 'passkey_registration',
          },
          activationPolicy: { mode: 'fail_if_occupied', signerSlot: 3 },
          preferredSlot: 3,
          mutation: { routeThroughOutbox: false },
        });
        await clientDB.setLastProfileStateForProfile('profile-last-selected', 3);

        return await getLastSelectedProfileAccountByChain(clientDB, {
          chainIdKeys: ['tempo:42431', 'near:testnet'],
        });
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toMatchObject({
      profileId: 'profile-last-selected',
      signerSlot: 3,
      chainAccount: {
        chainIdKey: 'near:testnet',
        accountAddress: 'primary.testnet',
        isPrimary: true,
      },
    });
  });
});
