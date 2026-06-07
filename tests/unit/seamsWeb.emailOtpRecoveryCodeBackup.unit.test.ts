import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { setupBasicPasskeyTest } from '../setup';

const repoRoot = fs.existsSync(path.join(process.cwd(), 'client'))
  ? process.cwd()
  : path.resolve(process.cwd(), '..');

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

const ENROLLMENT = {
  thresholdEcdsaClientVerifyingShareB64u: 'threshold-verifier-b64u',
  recoveryKeys: RECOVERY_CODES,
  recoveryCodesIssuedAtMs: 1_700_000_000_000,
  challengeId: 'enroll-1',
  otpChannel: 'email_otp',
  enrollmentId: 'email-otp-device-enrollment-v1:alice.testnet:google:alice',
  enrollmentSealKeyVersion: 'email-otp-kv-1',
  clientUnlockPublicKeyB64u: 'unlock-public-key-b64u',
  unlockKeyVersion: 'email-otp-unlock-v1',
};

const EXPECTED_BACKUP_TEXT = `Seams Email OTP recovery codes

Wallet: alice.testnet
Created: 2023-11-14T22:13:20.000Z

Store these codes somewhere private. Each code can be used once.

01  0123-4567-89AB-CDEF-GHJK-MNPQ-RSTV-WXYZ
02  1123-4567-89AB-CDEF-GHJK-MNPQ-RSTV-WXYZ
03  2123-4567-89AB-CDEF-GHJK-MNPQ-RSTV-WXYZ
04  3123-4567-89AB-CDEF-GHJK-MNPQ-RSTV-WXYZ
05  4123-4567-89AB-CDEF-GHJK-MNPQ-RSTV-WXYZ
06  5123-4567-89AB-CDEF-GHJK-MNPQ-RSTV-WXYZ
07  6123-4567-89AB-CDEF-GHJK-MNPQ-RSTV-WXYZ
08  7123-4567-89AB-CDEF-GHJK-MNPQ-RSTV-WXYZ
09  8123-4567-89AB-CDEF-GHJK-MNPQ-RSTV-WXYZ
10  9123-4567-89AB-CDEF-GHJK-MNPQ-RSTV-WXYZ
`;

async function configureTestDb(page: import('@playwright/test').Page): Promise<void> {
  await page.evaluate(async () => {
    const indexedDbMod = await import('/sdk/esm/core/indexedDB/index.js');
    indexedDbMod.seamsWalletDB.setDisabled(false);
    indexedDbMod.seamsWalletDB.setDbName(
      indexedDbMod.createSeamsTestWalletDbName(`otp-backup-${crypto.randomUUID()}`),
    );
  });
}

async function readStoredBackup(page: import('@playwright/test').Page): Promise<unknown> {
  return await page.evaluate(async ({ enrollment }) => {
    const mod = await import(
      '/sdk/esm/core/indexedDB/seamsWalletDB/emailOtpRecoveryCodeBackups.js'
    );
    return await mod.emailOtpRecoveryCodeBackupRepository.readMatching({
      walletId: 'alice.testnet',
      enrollmentId: enrollment.enrollmentId,
      enrollmentSealKeyVersion: enrollment.enrollmentSealKeyVersion,
    });
  }, { enrollment: ENROLLMENT });
}

test.describe('SeamsWeb Email OTP recovery-code backup persistence', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
    await configureTestDb(page);
  });

  test('stores recovery codes without showing a blocking registration modal', async ({ page }) => {
    const result = await page.evaluate(async ({ enrollment }) => {
      const mod = await import(
        '/sdk/esm/SeamsWeb/operations/authMethods/emailOtp/recoveryCodeBackup.js'
      );
      const beforeDialogs = document.querySelectorAll('[role="dialog"]').length;
      const enrollmentResult = await mod.backupEmailOtpRecoveryCodes({
        relayUrl: 'https://relay.example',
        walletId: 'alice.testnet',
        enrollment,
      });
      const afterDialogs = document.querySelectorAll('[role="dialog"]').length;
      return { enrollmentResult, beforeDialogs, afterDialogs };
    }, { enrollment: ENROLLMENT });

    expect(result.beforeDialogs).toBe(0);
    expect(result.afterDialogs).toBe(0);
    expect(result.enrollmentResult).toMatchObject({
      challengeId: 'enroll-1',
      enrollmentId: ENROLLMENT.enrollmentId,
      recoveryCodeBackup: {
        status: 'active',
        walletId: 'alice.testnet',
        enrollmentId: ENROLLMENT.enrollmentId,
        recoveryCodeCount: 10,
        activeRecoveryCodeCountAtBackup: 10,
      },
    });
    expect(result.enrollmentResult.recoveryCodeBackup.storedAtMs).toBeGreaterThanOrEqual(
      ENROLLMENT.recoveryCodesIssuedAtMs,
    );
    expect(JSON.stringify(result.enrollmentResult)).not.toContain('recoveryKeys');
    expect(await readStoredBackup(page)).toMatchObject({
      status: 'stored',
      secretKind: 'email_otp_recovery_codes_backup',
      walletId: 'alice.testnet',
      enrollmentId: ENROLLMENT.enrollmentId,
      recoveryKeys: RECOVERY_CODES,
      lastDisplayedAtMs: null,
      lastDownloadedAtMs: null,
    });
  });

  test('download helper builds the recovery-code file without deleting storage', async ({ page }) => {
    await page.evaluate(async ({ enrollment }) => {
      const mod = await import(
        '/sdk/esm/SeamsWeb/operations/authMethods/emailOtp/recoveryCodeBackup.js'
      );
      const reactMod = await import(
        '/sdk/esm/react/SeamsWeb/operations/authMethods/emailOtp/recoveryCodeBackup.js'
      );
      await mod.backupEmailOtpRecoveryCodes({
        relayUrl: 'https://relay.example',
        walletId: 'alice.testnet',
        enrollment,
      });
      (window as any).__downloadClicks = 0;
      (window as any).__downloadBlobText = null;
      (window as any).__downloadFilename = null;
      (window as any).__revokedUrl = null;
      URL.createObjectURL = ((blob: Blob) => {
        (window as any).__downloadBlobText = blob.text();
        return 'blob:email-otp-recovery-codes';
      }) as typeof URL.createObjectURL;
      URL.revokeObjectURL = ((url: string) => {
        (window as any).__revokedUrl = url;
      }) as typeof URL.revokeObjectURL;
      HTMLAnchorElement.prototype.click = function patchedAnchorClick(this: HTMLAnchorElement) {
        (window as any).__downloadClicks += 1;
        (window as any).__downloadFilename = this.download;
      };
      reactMod.downloadRecoveryCodes({
        walletId: 'alice.testnet',
        enrollmentId: enrollment.enrollmentId,
        enrollmentSealKeyVersion: enrollment.enrollmentSealKeyVersion,
        recoveryCodesIssuedAtMs: enrollment.recoveryCodesIssuedAtMs,
        recoveryKeys: enrollment.recoveryKeys,
      });
    }, { enrollment: ENROLLMENT });
    await page.waitForFunction(() => (window as any).__revokedUrl === 'blob:email-otp-recovery-codes');

    const download = await page.evaluate(async () => ({
      clicks: (window as any).__downloadClicks,
      filename: (window as any).__downloadFilename,
      text: await (window as any).__downloadBlobText,
      revokedUrl: (window as any).__revokedUrl,
    }));
    expect(download).toEqual({
      clicks: 1,
      filename: 'seams-email-otp-recovery-codes-alice.testnet.txt',
      text: EXPECTED_BACKUP_TEXT,
      revokedUrl: 'blob:email-otp-recovery-codes',
    });
    expect(await readStoredBackup(page)).toMatchObject({
      recoveryKeys: RECOVERY_CODES,
      lastDownloadedAtMs: null,
    });
  });

  test('compact modal distinguishes download failure from download-status update failure', () => {
    const source = fs.readFileSync(
      path.join(
        repoRoot,
        'client/src/SeamsWeb/operations/authMethods/emailOtp/recoveryCodeBackup.ts',
      ),
      'utf8',
    );

    expect(source).toContain("status.textContent = 'Download failed. Try again.';");
    expect(source).toContain('await options.onDownloaded?.();');
    expect(source).toContain(
      "status.textContent = 'Recovery codes downloaded. Last download status was not updated.';",
    );
  });
});
