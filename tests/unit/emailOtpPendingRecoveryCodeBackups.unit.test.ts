import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const RECOVERY_CODES = [
  '0123-4567-89AB-CDEF-GHJK-MNPQ-RSTV-WXYZ',
  '1123-4567-89AB-CDEF-GHJK-MNPQ-RSTV-WXYZ',
  '2123-4567-89AB-CDEF-GHJK-MNPQ-RSTV-WXYZ',
  '3123-4567-89AB-CDEF-GHJK-MNPQ-RSTV-WXYZ',
  '4123-4567-89AB-CDEF-GHJK-MNPQ-RSTV-WXYZ',
  '5123-4567-89AB-CDEF-GHJK-MNPQ-RSTV-WXYZ',
  '6123-4567-89AB-CDEF-GHJK-MNPQ-RSTV-WXYZ',
  '7123-4567-89AB-CDEF-GHJK-MNPQ-RSTV-WXYZ',
  '8123-4567-89AB-CDEF-GHJK-MNPQ-RSTV-WXYZ',
  '9123-4567-89AB-CDEF-GHJK-MNPQ-RSTV-WXYZ',
] as const;

test.describe('Email OTP pending recovery-code backup repository', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
  });

  test('stores pending codes until they are acknowledged and deleted', async ({ page }) => {
    const result = await page.evaluate(async ({ recoveryCodes }) => {
      const { createSeamsTestWalletDbName } = await import('/sdk/esm/core/indexedDB/index.js');
      const indexedDbMod = await import('/sdk/esm/core/indexedDB/index.js');
      const mod = await import(
        '/sdk/esm/core/indexedDB/seamsWalletDB/emailOtpPendingRecoveryCodeBackups.js'
      );
      indexedDbMod.seamsWalletDB.setDisabled(false);
      indexedDbMod.seamsWalletDB.setDbName(
        createSeamsTestWalletDbName(`pending-otp-${crypto.randomUUID()}`),
      );
      const repository = mod.emailOtpPendingRecoveryCodeBackupRepository;

      await repository.write({
        storageScope: 'host_origin_indexeddb',
        walletId: 'alice.testnet',
        enrollmentId: 'enrollment-1',
        enrollmentSealKeyVersion: 'seal-v1',
        recoveryCodesIssuedAtMs: 1_700_000_000_000,
        recoveryKeys: recoveryCodes,
        createdAtMs: 1_700_000_000_000,
        expiresAtMs: 1_700_086_400_000,
      });
      const beforeDelete = await repository.readMatching({
        walletId: 'alice.testnet',
        enrollmentId: 'enrollment-1',
        enrollmentSealKeyVersion: 'seal-v1',
        nowMs: 1_700_000_000_001,
      });
      await repository.delete({ walletId: 'alice.testnet', enrollmentId: 'enrollment-1' });
      const afterDelete = await repository.readMatching({
        walletId: 'alice.testnet',
        enrollmentId: 'enrollment-1',
        enrollmentSealKeyVersion: 'seal-v1',
        nowMs: 1_700_000_000_001,
      });
      return { beforeDelete, afterDelete };
    }, { recoveryCodes: RECOVERY_CODES });

    expect(result.beforeDelete).toMatchObject({
      status: 'pending_backup',
      walletId: 'alice.testnet',
      enrollmentId: 'enrollment-1',
      enrollmentSealKeyVersion: 'seal-v1',
      recoveryKeys: RECOVERY_CODES,
    });
    expect(result.afterDelete).toBeNull();
  });

  test('rejects invalid lifecycle branches and expires stale records', async ({ page }) => {
    const result = await page.evaluate(async ({ recoveryCodes }) => {
      const indexedDbMod = await import('/sdk/esm/core/indexedDB/index.js');
      const mod = await import(
        '/sdk/esm/core/indexedDB/seamsWalletDB/emailOtpPendingRecoveryCodeBackups.js'
      );
      indexedDbMod.seamsWalletDB.setDisabled(false);
      indexedDbMod.seamsWalletDB.setDbName(
        indexedDbMod.createSeamsTestWalletDbName(
          `pending-otp-expire-${crypto.randomUUID()}`,
        ),
      );
      const repository = mod.emailOtpPendingRecoveryCodeBackupRepository;
      const db = await indexedDbMod.seamsWalletDB.getDB();
      const storeName = 'email_otp_pending_recovery_code_backups';

      await db.put(storeName, {
        wallet_id: 'alice.testnet',
        enrollment_id: 'enrollment-active',
        status: 'active',
        expires_at_ms: 1_700_086_400_000,
        backup_record: {
          v: 1,
          secretKind: 'email_otp_recovery_codes_pending_backup',
          storageScope: 'host_origin_indexeddb',
          status: 'active',
          walletId: 'alice.testnet',
          enrollmentId: 'enrollment-active',
          enrollmentSealKeyVersion: 'seal-v1',
          recoveryCodesIssuedAtMs: 1_700_000_000_000,
          recoveryKeys: recoveryCodes,
          createdAtMs: 1_700_000_000_000,
          expiresAtMs: 1_700_086_400_000,
          acknowledgedAtMs: 1_700_000_100_000,
        },
      });
      const invalidActive = await repository.readMatching({
        walletId: 'alice.testnet',
        enrollmentId: 'enrollment-active',
        enrollmentSealKeyVersion: 'seal-v1',
        nowMs: 1_700_000_000_001,
      });
      await db.put(storeName, {
        wallet_id: 'alice.testnet',
        enrollment_id: 'enrollment-invalid-codes',
        status: 'pending_backup',
        expires_at_ms: 1_700_086_400_000,
        backup_record: {
          v: 1,
          secretKind: 'email_otp_recovery_codes_pending_backup',
          storageScope: 'host_origin_indexeddb',
          status: 'pending_backup',
          walletId: 'alice.testnet',
          enrollmentId: 'enrollment-invalid-codes',
          enrollmentSealKeyVersion: 'seal-v1',
          recoveryCodesIssuedAtMs: 1_700_000_000_000,
          recoveryKeys: ['raw-string-array'],
          createdAtMs: 1_700_000_000_000,
          expiresAtMs: 1_700_086_400_000,
        },
      });
      const invalidCodes = await repository.readMatching({
        walletId: 'alice.testnet',
        enrollmentId: 'enrollment-invalid-codes',
        enrollmentSealKeyVersion: 'seal-v1',
        nowMs: 1_700_000_000_001,
      });
      await db.put(storeName, {
        wallet_id: 'alice.testnet',
        enrollment_id: 'enrollment-corrupt-expired',
        status: 'pending_backup',
        expires_at_ms: 1_700_000_000_100,
        backup_record: {
          v: 1,
          secretKind: 'email_otp_recovery_codes_pending_backup',
          storageScope: 'host_origin_indexeddb',
          status: 'pending_backup',
          walletId: 'alice.testnet',
          enrollmentId: 'enrollment-corrupt-expired',
          enrollmentSealKeyVersion: 'seal-v1',
          recoveryCodesIssuedAtMs: 1_700_000_000_000,
          recoveryKeys: recoveryCodes,
          createdAtMs: 1_700_000_000_000,
          expiresAtMs: 1_700_000_000_100,
          acknowledgedAtMs: 1_700_000_000_050,
        },
      });
      const corruptExpiredBeforeCleanup = await db.get(storeName, [
        'alice.testnet',
        'enrollment-corrupt-expired',
      ]);
      await repository.deleteExpired({ nowMs: 1_700_000_000_101 });
      const corruptExpiredAfterCleanup = await db.get(storeName, [
        'alice.testnet',
        'enrollment-corrupt-expired',
      ]);
      await db.put(storeName, {
        wallet_id: 'alice.testnet',
        enrollment_id: 'enrollment-corrupt-missing-expiry',
        status: 'pending_backup',
        backup_record: {
          v: 1,
          secretKind: 'email_otp_recovery_codes_pending_backup',
          storageScope: 'host_origin_indexeddb',
          status: 'pending_backup',
          walletId: 'alice.testnet',
          enrollmentId: 'enrollment-corrupt-missing-expiry',
          enrollmentSealKeyVersion: 'seal-v1',
          recoveryCodesIssuedAtMs: 1_700_000_000_000,
          recoveryKeys: recoveryCodes,
          createdAtMs: 1_700_000_000_000,
        },
      });
      await db.put(storeName, {
        wallet_id: 'alice.testnet',
        enrollment_id: 'enrollment-corrupt-bad-expiry',
        status: 'pending_backup',
        expires_at_ms: 'bad-expiry',
        backup_record: {
          v: 1,
          secretKind: 'email_otp_recovery_codes_pending_backup',
          storageScope: 'host_origin_indexeddb',
          status: 'pending_backup',
          walletId: 'alice.testnet',
          enrollmentId: 'enrollment-corrupt-bad-expiry',
          enrollmentSealKeyVersion: 'seal-v1',
          recoveryCodesIssuedAtMs: 1_700_000_000_000,
          recoveryKeys: recoveryCodes,
          createdAtMs: 1_700_000_000_000,
          expiresAtMs: 'bad-expiry',
        },
      });
      await repository.deleteExpired({ nowMs: 1_700_000_000_101 });
      const corruptMissingExpiryAfterCleanup = await db.get(storeName, [
        'alice.testnet',
        'enrollment-corrupt-missing-expiry',
      ]);
      const corruptBadExpiryAfterCleanup = await db.get(storeName, [
        'alice.testnet',
        'enrollment-corrupt-bad-expiry',
      ]);

      await repository.write({
        storageScope: 'host_origin_indexeddb',
        walletId: 'alice.testnet',
        enrollmentId: 'enrollment-1',
        enrollmentSealKeyVersion: 'seal-v1',
        recoveryCodesIssuedAtMs: 1_700_000_000_000,
        recoveryKeys: recoveryCodes,
        createdAtMs: 1_700_000_000_000,
        expiresAtMs: 1_700_000_000_100,
      });
      const expired = await repository.readMatching({
        walletId: 'alice.testnet',
        enrollmentId: 'enrollment-1',
        enrollmentSealKeyVersion: 'seal-v1',
        nowMs: 1_700_000_000_101,
      });
      return {
        invalidActive,
        invalidCodes,
        corruptExpiredBeforeCleanup,
        corruptExpiredAfterCleanup,
        corruptMissingExpiryAfterCleanup,
        corruptBadExpiryAfterCleanup,
        expired,
      };
    }, { recoveryCodes: RECOVERY_CODES });

    expect(result.invalidActive).toBeNull();
    expect(result.invalidCodes).toBeNull();
    expect(result.corruptExpiredBeforeCleanup).toBeTruthy();
    expect(result.corruptExpiredAfterCleanup).toBeUndefined();
    expect(result.corruptMissingExpiryAfterCleanup).toBeUndefined();
    expect(result.corruptBadExpiryAfterCleanup).toBeUndefined();
    expect(result.expired).toBeNull();
  });
});
