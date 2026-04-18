import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  clientDb: '/sdk/esm/core/indexedDB/passkeyClientDB/manager.js',
  accountKeyMaterialDb: '/sdk/esm/core/indexedDB/accountKeyMaterialDB/manager.js',
  unifiedDb: '/sdk/esm/core/indexedDB/index.js',
} as const;

test.describe('local signer reconciliation', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('reports missing threshold material, orphaned material, and stale pending signers', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        try {
          const { PasskeyClientDBManager } = await import(paths.clientDb);
          const { AccountKeyMaterialDBManager } = await import(paths.accountKeyMaterialDb);
          const { UnifiedIndexedDBManager } = await import(paths.unifiedDb);

          const suffix =
            typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
              ? crypto.randomUUID()
              : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
          const clientDB = new PasskeyClientDBManager();
          clientDB.setDbName(`PasskeyClientDB-localSignerReconcile-${suffix}`);
          const accountKeyMaterialDB = new AccountKeyMaterialDBManager();
          accountKeyMaterialDB.setDbName(
            `PasskeyAccountKeyMaterial-localSignerReconcile-${suffix}`,
          );
          const indexedDB = new UnifiedIndexedDBManager({ clientDB, accountKeyMaterialDB });
          const profileId = 'profile-near:alice.testnet';
          const chainIdKey = 'near:testnet';
          const accountAddress = 'alice.testnet';

          await clientDB.upsertProfile({
            profileId,
            defaultSignerSlot: 1,
          });
          await clientDB.upsertChainAccount({
            profileId,
            chainIdKey,
            accountAddress,
            accountModel: 'near-native',
            isPrimary: true,
          });
          await clientDB.upsertAccountSigner({
            profileId,
            chainIdKey,
            accountAddress,
            signerId: 'ed25519:missing-material',
            signerSlot: 1,
            signerType: 'threshold',
            signerKind: 'threshold-ed25519',
            signerAuthMethod: 'email_otp',
            signerSource: 'email_otp_registration',
            status: 'active',
            mutation: { routeThroughOutbox: false },
          });
          await clientDB.upsertAccountSigner({
            profileId,
            chainIdKey,
            accountAddress,
            signerId: 'ed25519:stale-pending',
            signerSlot: 2,
            signerType: 'threshold',
            signerKind: 'threshold-ed25519',
            signerAuthMethod: 'email_otp',
            signerSource: 'email_otp_registration',
            status: 'pending',
            mutation: { routeThroughOutbox: false },
          });
          await accountKeyMaterialDB.storeKeyMaterial({
            profileId,
            signerSlot: 9,
            chainIdKey,
            keyKind: 'threshold_share_v1',
            algorithm: 'ed25519',
            publicKey: 'ed25519:orphan',
            payload: { wrappedShare: 'ciphertext-b64u' },
            timestamp: Date.now(),
            schemaVersion: 1,
          });

          const summary = await indexedDB.reconcileLocalSignerState({
            profileId,
            now: Date.now() + 10_000,
            stalePendingSignerMs: 1,
          });

          return {
            scannedProfiles: summary.scannedProfiles,
            scannedSigners: summary.scannedSigners,
            scannedKeyMaterials: summary.scannedKeyMaterials,
            issueCodes: summary.issues.map((issue: any) => issue.code).sort(),
            repairs: summary.repairs,
          };
        } catch (error: any) {
          return { error: error?.message || String(error) };
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.error).toBeUndefined();
    expect(result.scannedProfiles).toBe(1);
    expect(result.scannedSigners).toBe(2);
    expect(result.scannedKeyMaterials).toBe(1);
    expect(result.issueCodes).toEqual([
      'active_signer_missing_key_material',
      'key_material_without_active_signer',
      'stale_pending_signer',
    ]);
    expect(result.repairs).toEqual([]);
  });
});
