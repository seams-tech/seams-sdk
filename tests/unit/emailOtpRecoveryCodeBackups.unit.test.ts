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

test.describe('Email OTP recovery-code backup repository', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
  });

  test('retains stored codes across display and download metadata updates', async ({ page }) => {
    const result = await page.evaluate(async ({ recoveryCodes }) => {
      const indexedDbMod = await import('/_test-sdk/esm/core/indexedDB/index.js');
      const mod = await import(
        '/_test-sdk/esm/core/indexedDB/seamsWalletDB/emailOtpRecoveryCodeBackups.js'
      );
      indexedDbMod.seamsWalletDB.setDisabled(false);
      indexedDbMod.seamsWalletDB.setDbName(
        indexedDbMod.createSeamsTestWalletDbName(`otp-codes-${crypto.randomUUID()}`),
      );
      const repository = mod.emailOtpRecoveryCodeBackupRepository;

      await repository.write({
        storageScope: 'host_origin_indexeddb',
        walletId: 'alice.testnet',
        enrollmentId: 'enrollment-1',
        enrollmentSealKeyVersion: 'seal-v1',
        recoveryCodesIssuedAtMs: 1_700_000_000_000,
        recoveryKeys: recoveryCodes,
        createdAtMs: 1_700_000_000_000,
      });
      const displayed = await repository.markDisplayed({
        walletId: 'alice.testnet',
        enrollmentId: 'enrollment-1',
        enrollmentSealKeyVersion: 'seal-v1',
        displayedAtMs: 1_700_000_000_100,
      });
      const downloaded = await repository.markDownloaded({
        walletId: 'alice.testnet',
        enrollmentId: 'enrollment-1',
        enrollmentSealKeyVersion: 'seal-v1',
        downloadedAtMs: 1_700_000_000_200,
      });
      const afterDownload = await repository.readMatching({
        walletId: 'alice.testnet',
        enrollmentId: 'enrollment-1',
        enrollmentSealKeyVersion: 'seal-v1',
      });
      return { displayed, downloaded, afterDownload };
    }, { recoveryCodes: RECOVERY_CODES });

    expect(result.displayed).toMatchObject({
      status: 'stored',
      secretKind: 'email_otp_recovery_codes_backup',
      walletId: 'alice.testnet',
      enrollmentId: 'enrollment-1',
      recoveryKeys: RECOVERY_CODES,
      lastDisplayedAtMs: 1_700_000_000_100,
      lastDownloadedAtMs: null,
    });
    expect(result.downloaded).toMatchObject({
      lastDisplayedAtMs: 1_700_000_000_100,
      lastDownloadedAtMs: 1_700_000_000_200,
    });
    expect(result.afterDownload).toMatchObject({
      recoveryKeys: RECOVERY_CODES,
      lastDownloadedAtMs: 1_700_000_000_200,
    });
  });

  test('rejects raw recovery-code arrays and leaves mismatched enrollment seals intact', async ({ page }) => {
    const result = await page.evaluate(async ({ recoveryCodes }) => {
      const indexedDbMod = await import('/_test-sdk/esm/core/indexedDB/index.js');
      const mod = await import(
        '/_test-sdk/esm/core/indexedDB/seamsWalletDB/emailOtpRecoveryCodeBackups.js'
      );
      indexedDbMod.seamsWalletDB.setDisabled(false);
      indexedDbMod.seamsWalletDB.setDbName(
        indexedDbMod.createSeamsTestWalletDbName(`otp-codes-invalid-${crypto.randomUUID()}`),
      );
      const repository = mod.emailOtpRecoveryCodeBackupRepository;
      const db = await indexedDbMod.seamsWalletDB.getDB();
      const storeName = 'email_otp_pending_recovery_code_backups';

      await db.put(storeName, {
        wallet_id: 'alice.testnet',
        enrollment_id: 'bad-codes',
        status: 'stored',
        backup_record: {
          v: 1,
          secretKind: 'email_otp_recovery_codes_backup',
          storageScope: 'host_origin_indexeddb',
          status: 'stored',
          walletId: 'alice.testnet',
          enrollmentId: 'bad-codes',
          enrollmentSealKeyVersion: 'seal-v1',
          recoveryCodesIssuedAtMs: 1_700_000_000_000,
          recoveryKeys: ['raw-string-array'],
          createdAtMs: 1_700_000_000_000,
          lastDisplayedAtMs: null,
          lastDownloadedAtMs: null,
        },
      });
      const invalidCodes = await repository.readMatching({
        walletId: 'alice.testnet',
        enrollmentId: 'bad-codes',
        enrollmentSealKeyVersion: 'seal-v1',
      });

      await repository.write({
        storageScope: 'host_origin_indexeddb',
        walletId: 'alice.testnet',
        enrollmentId: 'enrollment-1',
        enrollmentSealKeyVersion: 'seal-v1',
        recoveryCodesIssuedAtMs: 1_700_000_000_000,
        recoveryKeys: recoveryCodes,
        createdAtMs: 1_700_000_000_000,
      });
      const sealMismatch = await repository.readMatching({
        walletId: 'alice.testnet',
        enrollmentId: 'enrollment-1',
        enrollmentSealKeyVersion: 'seal-v2',
      });
      const afterMismatch = await repository.readMatching({
        walletId: 'alice.testnet',
        enrollmentId: 'enrollment-1',
        enrollmentSealKeyVersion: 'seal-v1',
      });
      const rawInvalidAfterRead = await db.get(storeName, ['alice.testnet', 'bad-codes']);
      return { invalidCodes, sealMismatch, afterMismatch, rawInvalidAfterRead };
    }, { recoveryCodes: RECOVERY_CODES });

    expect(result.invalidCodes).toBeNull();
    expect(result.sealMismatch).toBeNull();
    expect(result.afterMismatch).toMatchObject({
      walletId: 'alice.testnet',
      enrollmentId: 'enrollment-1',
      enrollmentSealKeyVersion: 'seal-v1',
      recoveryKeys: RECOVERY_CODES,
    });
    expect(result.rawInvalidAfterRead).toMatchObject({
      wallet_id: 'alice.testnet',
      enrollment_id: 'bad-codes',
    });
  });

  test('explicit deletion removes plaintext rows without leaving tombstones', async ({ page }) => {
    const result = await page.evaluate(async ({ recoveryCodes }) => {
      const indexedDbMod = await import('/_test-sdk/esm/core/indexedDB/index.js');
      const mod = await import(
        '/_test-sdk/esm/core/indexedDB/seamsWalletDB/emailOtpRecoveryCodeBackups.js'
      );
      indexedDbMod.seamsWalletDB.setDisabled(false);
      indexedDbMod.seamsWalletDB.setDbName(
        indexedDbMod.createSeamsTestWalletDbName(`otp-codes-delete-${crypto.randomUUID()}`),
      );
      const repository = mod.emailOtpRecoveryCodeBackupRepository;
      const db = await indexedDbMod.seamsWalletDB.getDB();
      const storeName = 'email_otp_pending_recovery_code_backups';

      await repository.write({
        storageScope: 'iframe_origin_indexeddb',
        walletId: 'alice.testnet',
        enrollmentId: 'enrollment-1',
        enrollmentSealKeyVersion: 'seal-v1',
        recoveryCodesIssuedAtMs: 1_700_000_000_000,
        recoveryKeys: recoveryCodes,
        createdAtMs: 1_700_000_000_000,
      });
      await repository.delete({
        walletId: 'alice.testnet',
        enrollmentId: 'enrollment-1',
      });
      const afterExplicitDelete = await db.get(storeName, ['alice.testnet', 'enrollment-1']);

      await repository.write({
        storageScope: 'iframe_origin_indexeddb',
        walletId: 'alice.testnet',
        enrollmentId: 'enrollment-2',
        enrollmentSealKeyVersion: 'seal-v1',
        recoveryCodesIssuedAtMs: 1_700_000_000_000,
        recoveryKeys: recoveryCodes,
        createdAtMs: 1_700_000_000_000,
      });
      await repository.deleteForWallet({ walletId: 'alice.testnet' });
      const afterWalletDelete = await db.get(storeName, ['alice.testnet', 'enrollment-2']);

      return { afterExplicitDelete, afterWalletDelete };
    }, { recoveryCodes: RECOVERY_CODES });

    expect(result.afterExplicitDelete).toBeUndefined();
    expect(result.afterWalletDelete).toBeUndefined();
  });
});
