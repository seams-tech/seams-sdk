import { expect, test } from '@playwright/test';
import { sdkEsmPath, setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  clientDb: sdkEsmPath('core/indexedDB/passkeyClientDB/manager.js'),
  nearKeysDb: sdkEsmPath('core/indexedDB/passkeyNearKeysDB/manager.js'),
  unifiedDb: sdkEsmPath('core/indexedDB/index.js'),
  wrapKeySalt: sdkEsmPath('core/signingEngine/threshold/ed25519WrapKeySalt.js'),
} as const;

test.describe('NEAR threshold key material persistence', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('threshold key writes persist the canonical wrapKeySalt', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const { PasskeyClientDBManager } = await import(paths.clientDb);
      const { PasskeyNearKeysDBManager } = await import(paths.nearKeysDb);
      const { UnifiedIndexedDBManager } = await import(paths.unifiedDb);
      const { THRESHOLD_ED25519_WRAP_KEY_SALT_B64U } = await import(paths.wrapKeySalt);

      const suffix =
        typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
          ? crypto.randomUUID()
          : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
      const clientDB = new PasskeyClientDBManager();
      clientDB.setDbName(`PasskeyClientDB-nearThresholdSalt-${suffix}`);
      const nearKeysDB = new PasskeyNearKeysDBManager();
      nearKeysDB.setDbName(`PasskeyNearKeys-nearThresholdSalt-${suffix}`);
      const indexedDB = new UnifiedIndexedDBManager({ clientDB, nearKeysDB });
      const nearAccountId = 'alice.testnet';

      await clientDB.upsertNearAccountProjection({
        nearAccountId,
        deviceNumber: 1,
        operationalPublicKey: 'ed25519:threshold-operational',
        lastUpdated: Date.now(),
        passkeyCredential: {
          id: 'credential-id',
          rawId: 'credential-raw-id',
        },
        version: 2,
      });

      await indexedDB.storeNearThresholdKeyMaterial({
        nearAccountId,
        deviceNumber: 1,
        publicKey: 'ed25519:threshold-operational',
        relayerKeyId: 'rk-1',
        recoveryPublicKey: 'ed25519:threshold-recovery',
        artifactKind: 'near-ed25519-option-b-v1',
        keyVersion: 'option-b-v1',
        recoveryExportCapable: true,
        clientShareDerivation: 'prf_first_v1',
        clientExportShareDerivation: 'prf_first_v1',
        participants: [
          { id: 1, role: 'client', verifyingShareB64u: 'AQ' },
          {
            id: 2,
            role: 'relayer',
            relayerKeyId: 'rk-1',
            relayerUrl: 'https://relay.example.test',
            verifyingShareB64u: 'Ag',
          },
        ],
        timestamp: Date.now(),
      });

      const context = await clientDB.resolveNearAccountContext(nearAccountId);
      const raw = context
        ? await nearKeysDB.getKeyMaterial(
            context.profileId,
            1,
            context.sourceChainIdKey,
            'threshold_share_v1',
          )
        : null;
      const material = await indexedDB.getNearThresholdKeyMaterial(nearAccountId, 1);

      return {
        expectedWrapKeySalt: THRESHOLD_ED25519_WRAP_KEY_SALT_B64U,
        rawWrapKeySalt: raw?.wrapKeySalt || '',
        materialWrapKeySalt: material?.wrapKeySalt || '',
      };
    }, { paths: IMPORT_PATHS });

    expect(result.rawWrapKeySalt).toBe(result.expectedWrapKeySalt);
    expect(result.materialWrapKeySalt).toBe(result.expectedWrapKeySalt);
  });

  test('threshold key reads backfill the canonical wrapKeySalt for incomplete records', async ({
    page,
  }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const { PasskeyClientDBManager } = await import(paths.clientDb);
      const { PasskeyNearKeysDBManager } = await import(paths.nearKeysDb);
      const { UnifiedIndexedDBManager } = await import(paths.unifiedDb);
      const { THRESHOLD_ED25519_WRAP_KEY_SALT_B64U } = await import(paths.wrapKeySalt);

      const suffix =
        typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
          ? crypto.randomUUID()
          : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
      const clientDB = new PasskeyClientDBManager();
      clientDB.setDbName(`PasskeyClientDB-nearThresholdRepair-${suffix}`);
      const nearKeysDB = new PasskeyNearKeysDBManager();
      nearKeysDB.setDbName(`PasskeyNearKeys-nearThresholdRepair-${suffix}`);
      const indexedDB = new UnifiedIndexedDBManager({ clientDB, nearKeysDB });
      const nearAccountId = 'alice.testnet';

      await clientDB.upsertNearAccountProjection({
        nearAccountId,
        deviceNumber: 1,
        operationalPublicKey: 'ed25519:threshold-operational',
        lastUpdated: Date.now(),
        passkeyCredential: {
          id: 'credential-id',
          rawId: 'credential-raw-id',
        },
        version: 2,
      });

      const context = await clientDB.resolveNearAccountContext(nearAccountId);
      if (!context) {
        throw new Error('missing near account context');
      }

      await nearKeysDB.storeKeyMaterial({
        profileId: context.profileId,
        deviceNumber: 1,
        chainIdKey: context.sourceChainIdKey,
        keyKind: 'threshold_share_v1',
        algorithm: 'ed25519',
        publicKey: 'ed25519:threshold-operational',
        payload: {
          relayerKeyId: 'rk-1',
          recoveryPublicKey: 'ed25519:threshold-recovery',
          artifactKind: 'near-ed25519-option-b-v1',
          keyVersion: 'option-b-v1',
          recoveryExportCapable: true,
          clientShareDerivation: 'prf_first_v1',
          clientExportShareDerivation: 'prf_first_v1',
          participants: [
            { id: 1, role: 'client', verifyingShareB64u: 'AQ' },
            {
              id: 2,
              role: 'relayer',
              relayerKeyId: 'rk-1',
              relayerUrl: 'https://relay.example.test',
              verifyingShareB64u: 'Ag',
            },
          ],
        },
        timestamp: Date.now(),
        schemaVersion: 1,
      });

      const raw = await nearKeysDB.getKeyMaterial(
        context.profileId,
        1,
        context.sourceChainIdKey,
        'threshold_share_v1',
      );
      const material = await indexedDB.getNearThresholdKeyMaterial(nearAccountId, 1);

      return {
        expectedWrapKeySalt: THRESHOLD_ED25519_WRAP_KEY_SALT_B64U,
        rawWrapKeySalt: raw?.wrapKeySalt || '',
        materialWrapKeySalt: material?.wrapKeySalt || '',
      };
    }, { paths: IMPORT_PATHS });

    expect(result.rawWrapKeySalt).toBe('');
    expect(result.materialWrapKeySalt).toBe(result.expectedWrapKeySalt);
  });
});
