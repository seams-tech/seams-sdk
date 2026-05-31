import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
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
          const { UnifiedIndexedDBManager, SeamsWalletDBManager, createSeamsTestWalletDbName } =
            await import(paths.unifiedDb);

          const suffix =
            typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
              ? crypto.randomUUID()
              : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
          const seamsWalletDB = new SeamsWalletDBManager();
          seamsWalletDB.setDbName(createSeamsTestWalletDbName(`local-signer-reconcile-${suffix}`));
          const indexedDB = new UnifiedIndexedDBManager({ seamsWalletDB });
          const profileId = 'profile-near:alice.testnet';
          const chainIdKey = 'near:testnet';
          const accountAddress = 'alice.testnet';

          await indexedDB.upsertProfile({
            profileId,
            defaultSignerSlot: 1,
          });
          await indexedDB.upsertChainAccount({
            profileId,
            chainIdKey,
            accountAddress,
            accountModel: 'near-native',
            isPrimary: true,
          });
          await indexedDB.activateAccountSigner({
            account: {
              profileId,
              chainIdKey,
              accountAddress,
              accountModel: 'near-native',
            },
            signer: {
              signerId: 'ed25519:missing-material',
              signerType: 'threshold',
              signerKind: 'threshold-ed25519',
              signerAuthMethod: 'email_otp',
              signerSource: 'email_otp_registration',
            },
            activationPolicy: { mode: 'fail_if_occupied', signerSlot: 1 },
            preferredSlot: 1,
            mutation: { routeThroughOutbox: false },
          });
          await indexedDB.stageAccountSigner({
            account: {
              profileId,
              chainIdKey,
              accountAddress,
              accountModel: 'near-native',
            },
            signer: {
              signerId: 'ed25519:stale-pending',
              signerSlot: 2,
              signerType: 'threshold',
              signerKind: 'threshold-ed25519',
              signerAuthMethod: 'email_otp',
              signerSource: 'email_otp_registration',
            },
            mutation: { routeThroughOutbox: false },
          });
          await indexedDB.storeKeyMaterial({
            profileId,
            signerSlot: 9,
            chainIdKey,
            accountAddress,
            keyKind: 'threshold_share_v1',
            algorithm: 'ed25519',
            publicKey: 'ed25519:orphan',
            signerId: 'ed25519:orphan',
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
