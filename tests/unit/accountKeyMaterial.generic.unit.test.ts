import { expect, test } from '@playwright/test';
import { sdkEsmPath, setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  unifiedDb: sdkEsmPath('core/indexedDB/index.js'),
  accountKeyMaterial: sdkEsmPath('core/indexedDB/accountKeyMaterial.js'),
} as const;

test.describe('generic account key material helpers', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('persists and reads non-NEAR key material rows through account refs', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { UnifiedIndexedDBManager, SeamsWalletDBManager, createSeamsTestWalletDbName } =
          await import(paths.unifiedDb);
        const { getAccountKeyMaterial, storeAccountKeyMaterial } = await import(
          paths.accountKeyMaterial
        );

        const suffix =
          typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
            ? crypto.randomUUID()
            : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
        const seamsWalletDB = new SeamsWalletDBManager();
        seamsWalletDB.setDbName(createSeamsTestWalletDbName(`evm-key-material-${suffix}`));
        const indexedDB = new UnifiedIndexedDBManager({ seamsWalletDB });

        await indexedDB.upsertProfile({
          profileId: 'profile-evm-key-material',
          defaultSignerSlot: 1,
          passkeyCredential: {
            id: 'evm-key-material-credential-id',
            rawId: 'evm-key-material-credential-raw-id',
          },
        });
        await indexedDB.upsertChainAccount({
          profileId: 'profile-evm-key-material',
          chainIdKey: 'evm:11155111',
          accountAddress: '0xabc123',
          accountModel: 'threshold-ecdsa',
          isPrimary: true,
        });

        const accountRefs = [
          { chainIdKey: 'tempo:42431', accountAddress: '0xmissing' },
          { chainIdKey: 'evm:11155111', accountAddress: '0xabc123' },
        ];

        await storeAccountKeyMaterial(
          { clientDB: indexedDB, keyMaterialStore: indexedDB },
          {
            accountRefs,
            signerSlot: 1,
            keyKind: 'secp256k1_share_v1',
            algorithm: 'secp256k1',
            publicKey: '0xpubkey-secp256k1',
            signerId: 'signer-evm-1',
            wrapKeySalt: 'salt-evm-1',
            payload: {
              curve: 'secp256k1',
              accountFamily: 'evm',
              chainId: 11155111,
            },
            timestamp: 1712345678901,
          },
        );

        const material = await getAccountKeyMaterial({
          deps: { clientDB: indexedDB, keyMaterialStore: indexedDB },
          accountRefs,
          signerSlot: 1,
          keyKind: 'secp256k1_share_v1',
        });
        const raw = await indexedDB.getKeyMaterial(
          'profile-evm-key-material',
          1,
          'evm:11155111',
          'secp256k1_share_v1',
        );

        return { material, raw };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.material).toMatchObject({
      profileId: 'profile-evm-key-material',
      signerSlot: 1,
      chainIdKey: 'evm:11155111',
      keyKind: 'secp256k1_share_v1',
      algorithm: 'secp256k1',
      publicKey: '0xpubkey-secp256k1',
      signerId: 'signer-evm-1',
      wrapKeySalt: 'salt-evm-1',
      payload: {
        curve: 'secp256k1',
        accountFamily: 'evm',
        chainId: 11155111,
      },
      timestamp: 1712345678901,
    });
    expect(result.raw).toMatchObject({
      profileId: 'profile-evm-key-material',
      chainIdKey: 'evm:11155111',
      keyKind: 'secp256k1_share_v1',
      algorithm: 'secp256k1',
    });
  });

  test('rejects explicit key targets that conflict with mapped account refs', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { UnifiedIndexedDBManager, SeamsWalletDBManager, createSeamsTestWalletDbName } =
          await import(paths.unifiedDb);
        const { storeAccountKeyMaterial } = await import(paths.accountKeyMaterial);

        const suffix =
          typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
            ? crypto.randomUUID()
            : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
        const seamsWalletDB = new SeamsWalletDBManager();
        seamsWalletDB.setDbName(createSeamsTestWalletDbName(`explicit-mismatch-${suffix}`));
        const indexedDB = new UnifiedIndexedDBManager({ seamsWalletDB });

        await indexedDB.upsertProfile({
          profileId: 'profile-evm-explicit',
          defaultSignerSlot: 1,
          passkeyCredential: {
            id: 'explicit-mismatch-credential-id',
            rawId: 'explicit-mismatch-credential-raw-id',
          },
        });
        await indexedDB.upsertChainAccount({
          profileId: 'profile-evm-explicit',
          chainIdKey: 'evm:11155111',
          accountAddress: '0xabc123',
          accountModel: 'threshold-ecdsa',
          isPrimary: true,
        });

        try {
          await storeAccountKeyMaterial(
            { clientDB: indexedDB, keyMaterialStore: indexedDB },
            {
              accountRefs: [{ chainIdKey: 'evm:11155111', accountAddress: '0xabc123' }],
              explicitProfileId: 'profile-other',
              explicitChainIdKey: 'evm:11155111',
              explicitAccountAddress: '0xabc123',
              signerSlot: 1,
              keyKind: 'secp256k1_share_v1',
              algorithm: 'secp256k1',
              publicKey: '0xpubkey-secp256k1',
              signerId: 'signer-evm-explicit',
            },
          );
          return { message: null };
        } catch (error) {
          return {
            message: error instanceof Error ? error.message : String(error),
          };
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.message).toContain('mismatches mapped profile');
  });
});
