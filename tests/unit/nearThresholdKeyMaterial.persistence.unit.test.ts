import { expect, test } from '@playwright/test';
import { sdkEsmPath, setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  clientDb: sdkEsmPath('core/indexedDB/passkeyClientDB/manager.js'),
  nearDb: sdkEsmPath('core/accountData/near/keyMaterial.js'),
  accountKeyMaterialDb: sdkEsmPath('core/indexedDB/accountKeyMaterialDB/manager.js'),
  unifiedDb: sdkEsmPath('core/indexedDB/index.js'),
} as const;

test.describe('NEAR threshold key material persistence', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('threshold key writes persist the canonical single-key record shape', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { PasskeyClientDBManager } = await import(paths.clientDb);
        const { getNearThresholdKeyMaterial, storeNearThresholdKeyMaterial } = await import(
          paths.nearDb
        );
        const { AccountKeyMaterialDBManager } = await import(paths.accountKeyMaterialDb);
        const { UnifiedIndexedDBManager } = await import(paths.unifiedDb);

        const suffix =
          typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
            ? crypto.randomUUID()
            : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
        const clientDB = new PasskeyClientDBManager();
        clientDB.setDbName(`PasskeyClientDB-nearThresholdCanonical-${suffix}`);
        const accountKeyMaterialDB = new AccountKeyMaterialDBManager();
        accountKeyMaterialDB.setDbName(
          `PasskeyAccountKeyMaterial-nearThresholdCanonical-${suffix}`,
        );
        const indexedDB = new UnifiedIndexedDBManager({ clientDB, accountKeyMaterialDB });
        const nearAccountId = 'alice.testnet';
        const chainIdKey = 'near:testnet';
        const profileId = `profile-near:${nearAccountId}`;

        await clientDB.upsertProfile({
          profileId,
          defaultSignerSlot: 1,
          passkeyCredential: {
            id: 'credential-id',
            rawId: 'credential-raw-id',
          },
        });
        await clientDB.upsertChainAccount({
          profileId,
          chainIdKey,
          accountAddress: nearAccountId,
          accountModel: 'near-native',
          isPrimary: true,
        });
        await clientDB.upsertAccountSigner({
          profileId,
          chainIdKey,
          accountAddress: nearAccountId,
          signerId: 'ed25519:threshold-operational',
          signerSlot: 1,
          signerType: 'threshold',
          signerKind: 'threshold-ed25519',
          signerAuthMethod: 'passkey',
          signerSource: 'passkey_registration',
          status: 'active',
          mutation: { routeThroughOutbox: false },
        });

        await storeNearThresholdKeyMaterial(
          { clientDB, accountKeyMaterialDB },
          {
            nearAccountId,
            signerSlot: 1,
            publicKey: 'ed25519:threshold-operational',
            relayerKeyId: 'rk-1',
            keyVersion: 'threshold-ed25519-hss-v1',
            timestamp: Date.now(),
          },
        );

        const context = await clientDB.resolveProfileAccountContext({
          chainIdKey,
          accountAddress: nearAccountId,
        });
        const raw = context
          ? await accountKeyMaterialDB.getKeyMaterial(
              context.profileId,
              1,
              context.accountRef.chainIdKey,
              'threshold_share_v1',
            )
          : null;
        const material = await getNearThresholdKeyMaterial(
          { clientDB, accountKeyMaterialDB },
          nearAccountId,
          1,
        );
        const rawPayload = (raw?.payload || {}) as Record<string, unknown>;

        return {
          rawWrapKeySalt: raw?.wrapKeySalt || '',
          rawPayload,
          material,
          rawHasRecoveryPublicKey: Object.prototype.hasOwnProperty.call(
            rawPayload,
            'recoveryPublicKey',
          ),
          rawHasArtifactKind: Object.prototype.hasOwnProperty.call(rawPayload, 'artifactKind'),
          rawHasRecoveryExportCapable: Object.prototype.hasOwnProperty.call(
            rawPayload,
            'recoveryExportCapable',
          ),
          materialHasRecoveryPublicKey: Object.prototype.hasOwnProperty.call(
            material || {},
            'recoveryPublicKey',
          ),
          materialHasWrapKeySalt: Object.prototype.hasOwnProperty.call(
            material || {},
            'wrapKeySalt',
          ),
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.rawWrapKeySalt).toBe('');
    expect(result.rawPayload).toMatchObject({
      relayerKeyId: 'rk-1',
      keyVersion: 'threshold-ed25519-hss-v1',
    });
    expect(Array.isArray(result.rawPayload.participants)).toBe(true);
    expect(result.rawHasRecoveryPublicKey).toBe(false);
    expect(result.rawHasArtifactKind).toBe(false);
    expect(result.rawHasRecoveryExportCapable).toBe(false);
    expect(result.material).toMatchObject({
      nearAccountId: 'alice.testnet',
      signerSlot: 1,
      kind: 'threshold_ed25519_v1',
      publicKey: 'ed25519:threshold-operational',
      relayerKeyId: 'rk-1',
      keyVersion: 'threshold-ed25519-hss-v1',
    });
    expect(result.materialHasRecoveryPublicKey).toBe(false);
    expect(result.materialHasWrapKeySalt).toBe(false);
  });

  test('threshold key reads synthesize canonical participants for incomplete threshold payloads', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { PasskeyClientDBManager } = await import(paths.clientDb);
        const { getNearThresholdKeyMaterial } = await import(paths.nearDb);
        const { AccountKeyMaterialDBManager } = await import(paths.accountKeyMaterialDb);
        const { UnifiedIndexedDBManager } = await import(paths.unifiedDb);

        const suffix =
          typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
            ? crypto.randomUUID()
            : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
        const clientDB = new PasskeyClientDBManager();
        clientDB.setDbName(`PasskeyClientDB-nearThresholdFallback-${suffix}`);
        const accountKeyMaterialDB = new AccountKeyMaterialDBManager();
        accountKeyMaterialDB.setDbName(`PasskeyAccountKeyMaterial-nearThresholdFallback-${suffix}`);
        const indexedDB = new UnifiedIndexedDBManager({ clientDB, accountKeyMaterialDB });
        const nearAccountId = 'alice.testnet';
        const chainIdKey = 'near:testnet';
        const profileId = `profile-near:${nearAccountId}`;

        await clientDB.upsertProfile({
          profileId,
          defaultSignerSlot: 1,
          passkeyCredential: {
            id: 'credential-id',
            rawId: 'credential-raw-id',
          },
        });
        await clientDB.upsertChainAccount({
          profileId,
          chainIdKey,
          accountAddress: nearAccountId,
          accountModel: 'near-native',
          isPrimary: true,
        });
        await clientDB.upsertAccountSigner({
          profileId,
          chainIdKey,
          accountAddress: nearAccountId,
          signerId: 'ed25519:threshold-operational',
          signerSlot: 1,
          signerType: 'threshold',
          signerKind: 'threshold-ed25519',
          signerAuthMethod: 'passkey',
          signerSource: 'passkey_registration',
          status: 'active',
          mutation: { routeThroughOutbox: false },
        });

        const context = await clientDB.resolveProfileAccountContext({
          chainIdKey,
          accountAddress: nearAccountId,
        });
        if (!context) {
          throw new Error('missing near account context');
        }

        await accountKeyMaterialDB.storeKeyMaterial({
          profileId: context.profileId,
          signerSlot: 1,
          chainIdKey: context.accountRef.chainIdKey,
          keyKind: 'threshold_share_v1',
          algorithm: 'ed25519',
          publicKey: 'ed25519:threshold-operational',
          payload: {
            relayerKeyId: 'rk-1',
            keyVersion: 'threshold-ed25519-hss-v1',
          },
          timestamp: Date.now(),
          schemaVersion: 1,
        });

        const material = await getNearThresholdKeyMaterial(
          { clientDB, accountKeyMaterialDB },
          nearAccountId,
          1,
        );
        return material;
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toMatchObject({
      nearAccountId: 'alice.testnet',
      signerSlot: 1,
      kind: 'threshold_ed25519_v1',
      publicKey: 'ed25519:threshold-operational',
      relayerKeyId: 'rk-1',
      keyVersion: 'threshold-ed25519-hss-v1',
    });
    expect(Array.isArray(result?.participants)).toBe(true);
    expect(result?.participants).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: 1, role: 'client' }),
        expect.objectContaining({ id: 2, role: 'relayer', relayerKeyId: 'rk-1' }),
      ]),
    );
  });
});
