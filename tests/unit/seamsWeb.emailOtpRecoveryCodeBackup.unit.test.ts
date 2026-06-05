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

async function mountBackupUi(page: import('@playwright/test').Page): Promise<void> {
  await page.evaluate(
    async ({ enrollment }) => {
      const mod = await import(
        '/sdk/esm/web/SeamsWeb/operations/authMethods/emailOtp/recoveryCodeBackup.js'
      );
      (window as any).__backupPromise = mod.backupEmailOtpRecoveryCodes({
        relayUrl: 'https://relay.example',
        walletId: 'alice.testnet',
        enrollment,
        acknowledge: async (args: Record<string, unknown>) => {
          (window as any).__acknowledgeArgs = args;
          return {
            status: 'active',
            walletId: 'alice.testnet',
            enrollmentId: enrollment.enrollmentId,
            recoveryCodeCount: 10,
            issuedAtMs: enrollment.recoveryCodesIssuedAtMs,
            acknowledgedAtMs: 1_700_000_100_000,
            activeRecoveryCodeCountAtAcknowledgement: 10,
          };
        },
      });
    },
    { enrollment: ENROLLMENT },
  );
}

test.describe('SeamsWeb Email OTP recovery-code backup UI', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
  });

  test('renders all codes and acknowledges backup after download', async ({ page }) => {
    await page.evaluate(() => {
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
    });
    await mountBackupUi(page);

    const dialog = page.getByRole('dialog');
    await expect(dialog).toBeVisible();
    await expect(dialog.getByRole('listitem')).toHaveCount(10);
    const downloadButton = dialog.getByRole('button', { name: 'Download' });
    await expect(dialog.getByRole('button').first()).toHaveText('Download');
    await expect(dialog.getByRole('button')).toHaveCount(1);
    const downloadStyle = await downloadButton.evaluate((button) => {
      const style = window.getComputedStyle(button);
      return {
        backgroundColor: style.backgroundColor,
        color: style.color,
        fontWeight: style.fontWeight,
      };
    });
    expect(downloadStyle).toEqual({
      backgroundColor: 'rgb(86, 81, 119)',
      color: 'rgb(255, 250, 243)',
      fontWeight: '700',
    });

    await downloadButton.click();
    await expect(page.getByRole('dialog')).toHaveCount(0);

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

    const finalResult = await page.evaluate(async () => await (window as any).__backupPromise);
    expect(finalResult).toEqual({
      thresholdEcdsaClientVerifyingShareB64u: 'threshold-verifier-b64u',
      recoveryCodesIssuedAtMs: 1_700_000_000_000,
      challengeId: 'enroll-1',
      otpChannel: 'email_otp',
      enrollmentId: 'email-otp-device-enrollment-v1:alice.testnet:google:alice',
      enrollmentSealKeyVersion: 'email-otp-kv-1',
      clientUnlockPublicKeyB64u: 'unlock-public-key-b64u',
      unlockKeyVersion: 'email-otp-unlock-v1',
      recoveryCodeBackup: {
        status: 'active',
        walletId: 'alice.testnet',
        enrollmentId: 'email-otp-device-enrollment-v1:alice.testnet:google:alice',
        recoveryCodeCount: 10,
        issuedAtMs: 1_700_000_000_000,
        acknowledgedAtMs: 1_700_000_100_000,
        activeRecoveryCodeCountAtAcknowledgement: 10,
      },
    });
    expect(JSON.stringify(finalResult)).not.toContain('recoveryKeys');
    const acknowledgeArgs = await page.evaluate(() => (window as any).__acknowledgeArgs);
    expect(acknowledgeArgs).toEqual({
      relayUrl: 'https://relay.example',
      walletId: 'alice.testnet',
      enrollmentId: 'email-otp-device-enrollment-v1:alice.testnet:google:alice',
      enrollmentSealKeyVersion: 'email-otp-kv-1',
    });
  });

  test('keeps the dialog open when download fails', async ({ page }) => {
    await page.evaluate(() => {
      URL.createObjectURL = (() => {
        throw new Error('blob denied');
      }) as typeof URL.createObjectURL;
    });
    await mountBackupUi(page);

    const dialog = page.getByRole('dialog');
    await dialog.getByRole('button', { name: 'Download' }).click();
    await expect(dialog).toBeVisible();
    await expect(dialog.getByText('Download failed. Try again.')).toBeVisible();
    await expect(page.getByRole('dialog')).toHaveCount(1);
    await expect
      .poll(async () => await page.evaluate(() => (window as any).__acknowledgeArgs || null))
      .toBeNull();
  });
});
