import { expect, test } from '@playwright/test';
import { sdkEsmPath, setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  clientDb: sdkEsmPath('core/indexedDB/passkeyClientDB/manager.js'),
  projection: sdkEsmPath('core/indexedDB/profileAccountProjection.js'),
} as const;

test.describe('generic profile/account projection helpers', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('resolves mapped candidates and selects canonical signer slots', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { PasskeyClientDBManager } = await import(paths.clientDb);
        const {
          resolveProfileAccountContextFromCandidates,
          resolveProfileAccountProjection,
        } = await import(paths.projection);

        const suffix =
          typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
            ? crypto.randomUUID()
            : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
        const clientDB = new PasskeyClientDBManager();
        clientDB.setDbName(`PasskeyClientDB-profileProjection-${suffix}`);

        await clientDB.upsertProfile({
          profileId: 'profile-evm-projection',
          defaultDeviceNumber: 2,
          passkeyCredential: {
            id: 'projection-credential-id',
            rawId: 'projection-credential-raw-id',
          },
        });
        await clientDB.upsertChainAccount({
          profileId: 'profile-evm-projection',
          chainIdKey: 'evm:11155111',
          accountAddress: '0xabc123',
          accountModel: 'erc4337',
          isPrimary: true,
        });
        await clientDB.upsertAccountSigner({
          profileId: 'profile-evm-projection',
          chainIdKey: 'evm:11155111',
          accountAddress: '0xabc123',
          signerId: 'signer-device-1',
          signerSlot: 1,
          signerType: 'device',
          status: 'active',
          mutation: { routeThroughOutbox: false },
        });
        await clientDB.upsertAccountSigner({
          profileId: 'profile-evm-projection',
          chainIdKey: 'evm:11155111',
          accountAddress: '0xabc123',
          signerId: 'signer-device-2',
          signerSlot: 2,
          signerType: 'device',
          status: 'active',
          mutation: { routeThroughOutbox: false },
        });

        const accountRefs = [
          { chainIdKey: 'tempo:42431', accountAddress: '0xmissing' },
          { chainIdKey: 'evm:11155111', accountAddress: '0xabc123' },
        ];
        const context = await resolveProfileAccountContextFromCandidates(clientDB, accountRefs);
        const projection = await resolveProfileAccountProjection(clientDB, { accountRefs });
        const explicitProjection = await resolveProfileAccountProjection(clientDB, {
          accountRefs,
          deviceNumber: 1,
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
      profileId: 'profile-evm-projection',
      accountRef: {
        chainIdKey: 'evm:11155111',
        accountAddress: '0xabc123',
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
        const { PasskeyClientDBManager } = await import(paths.clientDb);
        const { getLastSelectedProfileAccountByChain } = await import(paths.projection);

        const suffix =
          typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
            ? crypto.randomUUID()
            : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
        const clientDB = new PasskeyClientDBManager();
        clientDB.setDbName(`PasskeyClientDB-lastSelectedProfile-${suffix}`);

        await clientDB.upsertProfile({
          profileId: 'profile-last-selected',
          defaultDeviceNumber: 3,
          passkeyCredential: {
            id: 'last-selected-credential-id',
            rawId: 'last-selected-credential-raw-id',
          },
        });
        await clientDB.upsertChainAccount({
          profileId: 'profile-last-selected',
          chainIdKey: 'evm:11155111',
          accountAddress: '0xprimary',
          accountModel: 'erc4337',
          isPrimary: true,
        });
        await clientDB.upsertChainAccount({
          profileId: 'profile-last-selected',
          chainIdKey: 'evm:11155111',
          accountAddress: '0xsecondary',
          accountModel: 'erc4337',
          isPrimary: false,
        });
        await clientDB.upsertAccountSigner({
          profileId: 'profile-last-selected',
          chainIdKey: 'evm:11155111',
          accountAddress: '0xprimary',
          signerId: 'signer-device-3',
          signerSlot: 3,
          signerType: 'device',
          status: 'active',
          mutation: { routeThroughOutbox: false },
        });
        await clientDB.setLastProfileStateForProfile('profile-last-selected', 3);

        return await getLastSelectedProfileAccountByChain(clientDB, {
          chainIdKeys: ['tempo:42431', 'evm:11155111'],
        });
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toMatchObject({
      profileId: 'profile-last-selected',
      deviceNumber: 3,
      chainAccount: {
        chainIdKey: 'evm:11155111',
        accountAddress: '0xprimary',
        isPrimary: true,
      },
    });
  });
});
