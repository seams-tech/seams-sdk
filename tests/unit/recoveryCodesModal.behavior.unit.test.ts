import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { setupBasicPasskeyTest } from '../setup';

const repoRoot = path.resolve(process.cwd(), '..');

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

function readRepoFile(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

test.describe('RecoveryCodesModal behavior', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
  });

  test('loads retained recovery codes from local wallet storage', async ({ page }) => {
    const result = await page.evaluate(async ({ recoveryCodes }) => {
      const mod = await import(
        '/_test-sdk/esm/react/components/AccountMenuButton/RecoveryCodesModalState.js'
      );
      const calls: Array<string | [string, unknown]> = [];
      const status = {
        status: 'ready',
        walletId: 'alice.testnet',
        enrollmentId: 'enrollment-1',
        enrollmentSealKeyVersion: 'seal-v1',
        expectedRecoveryCodeCount: 10,
        activeRecoveryCodeCount: 10,
        consumedRecoveryCodeCount: 0,
        revokedRecoveryCodeCount: 0,
        totalRecoveryCodeCount: 10,
        issuedAtMs: 1_700_000_000_000,
      };
      const backup = {
        v: 1,
        secretKind: 'email_otp_recovery_codes_backup',
        storageScope: 'iframe_origin_indexeddb',
        status: 'stored',
        walletId: 'alice.testnet',
        enrollmentId: 'enrollment-1',
        enrollmentSealKeyVersion: 'seal-v1',
        recoveryCodesIssuedAtMs: 1_700_000_000_000,
        recoveryKeys: recoveryCodes,
        createdAtMs: 1_700_000_000_000,
        lastDisplayedAtMs: null,
        lastDownloadedAtMs: null,
      };
      const displayed = { ...backup, lastDisplayedAtMs: 1_700_000_000_100 };
      const loaded = await mod.loadRecoveryCodesModalLoadedState({
        walletId: 'alice.testnet',
        recovery: {
          getEmailOtpRecoveryCodeStatus: async (args: unknown) => {
            calls.push(['status', args]);
            return status;
          },
        },
        recoveryCodeBackupRepository: {
          readMatching: async (args: unknown) => {
            calls.push(['readMatching', args]);
            return backup;
          },
          markDisplayed: async (args: unknown) => {
            calls.push(['markDisplayed', args]);
            return displayed;
          },
        },
        showRecoveryCodes: async (args: unknown) => {
          calls.push(['presenter', args]);
          return status;
        },
      });
      return { loaded, calls };
    }, { recoveryCodes: RECOVERY_CODES });

    expect(result.loaded).toMatchObject({
      kind: 'loaded',
      status: { status: 'ready', walletId: 'alice.testnet' },
      localBackup: {
        walletId: 'alice.testnet',
        enrollmentId: 'enrollment-1',
        recoveryKeys: RECOVERY_CODES,
        lastDisplayedAtMs: 1_700_000_000_100,
      },
      actionError: '',
    });
    expect(result.calls).toEqual([
      ['status', { walletId: 'alice.testnet' }],
      [
        'readMatching',
        {
          walletId: 'alice.testnet',
          enrollmentId: 'enrollment-1',
          enrollmentSealKeyVersion: 'seal-v1',
        },
      ],
      [
        'markDisplayed',
        {
          walletId: 'alice.testnet',
          enrollmentId: 'enrollment-1',
          enrollmentSealKeyVersion: 'seal-v1',
        },
      ],
    ]);
  });

  test('delegates missing local code display through the iframe presenter', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const mod = await import(
        '/_test-sdk/esm/react/components/AccountMenuButton/RecoveryCodesModalState.js'
      );
      const calls: Array<string | [string, unknown]> = [];
      const status = {
        status: 'ready',
        walletId: 'alice.testnet',
        enrollmentId: 'enrollment-1',
        enrollmentSealKeyVersion: 'seal-v1',
        expectedRecoveryCodeCount: 10,
        activeRecoveryCodeCount: 10,
        consumedRecoveryCodeCount: 0,
        revokedRecoveryCodeCount: 0,
        totalRecoveryCodeCount: 10,
        issuedAtMs: 1_700_000_000_000,
      };
      const loaded = await mod.loadRecoveryCodesModalLoadedState({
        walletId: 'alice.testnet',
        recovery: {
          getEmailOtpRecoveryCodeStatus: async (args: unknown) => {
            calls.push(['status', args]);
            return status;
          },
        },
        recoveryCodeBackupRepository: {
          readMatching: async (args: unknown) => {
            calls.push(['readMatching', args]);
            return null;
          },
          markDisplayed: async (args: unknown) => {
            calls.push(['markDisplayed', args]);
            return null;
          },
        },
        showRecoveryCodes: async (args: unknown) => {
          calls.push(['presenter', args]);
          return { status, displayedStoredCodes: true };
        },
      });
      return { loaded, calls };
    });

    expect(result.loaded).toMatchObject({
      kind: 'delegated_to_iframe',
      status: { status: 'ready', walletId: 'alice.testnet' },
      actionError: '',
    });
    expect(result.calls).toEqual([
      ['status', { walletId: 'alice.testnet' }],
      [
        'readMatching',
        {
          walletId: 'alice.testnet',
          enrollmentId: 'enrollment-1',
          enrollmentSealKeyVersion: 'seal-v1',
        },
      ],
      ['presenter', { walletId: 'alice.testnet' }],
    ]);
  });

  test('keeps local unavailable state when iframe has no stored backup to display', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const mod = await import(
        '/_test-sdk/esm/react/components/AccountMenuButton/RecoveryCodesModalState.js'
      );
      const calls: Array<string | [string, unknown]> = [];
      const status = {
        status: 'ready',
        walletId: 'alice.testnet',
        enrollmentId: 'enrollment-1',
        enrollmentSealKeyVersion: 'seal-v1',
        expectedRecoveryCodeCount: 10,
        activeRecoveryCodeCount: 10,
        consumedRecoveryCodeCount: 0,
        revokedRecoveryCodeCount: 0,
        totalRecoveryCodeCount: 10,
        issuedAtMs: 1_700_000_000_000,
      };
      const loaded = await mod.loadRecoveryCodesModalLoadedState({
        walletId: 'alice.testnet',
        recovery: {
          getEmailOtpRecoveryCodeStatus: async (args: unknown) => {
            calls.push(['status', args]);
            return status;
          },
        },
        recoveryCodeBackupRepository: {
          readMatching: async (args: unknown) => {
            calls.push(['readMatching', args]);
            return null;
          },
          markDisplayed: async (args: unknown) => {
            calls.push(['markDisplayed', args]);
            return null;
          },
        },
        showRecoveryCodes: async (args: unknown) => {
          calls.push(['presenter', args]);
          return { status, displayedStoredCodes: false };
        },
      });
      return { loaded, calls };
    });

    expect(result.loaded).toMatchObject({
      kind: 'loaded',
      status: { status: 'ready', walletId: 'alice.testnet' },
      localBackup: null,
      actionError: '',
    });
    expect(result.calls).toEqual([
      ['status', { walletId: 'alice.testnet' }],
      [
        'readMatching',
        {
          walletId: 'alice.testnet',
          enrollmentId: 'enrollment-1',
          enrollmentSealKeyVersion: 'seal-v1',
        },
      ],
      ['presenter', { walletId: 'alice.testnet' }],
    ]);
  });

  test('wallet iframe recovery-code command never sends recovery keys to the host', () => {
    const messages = readRepoFile('packages/sdk-web/src/SeamsWeb/walletIframe/shared/messages.ts');
    const router = readRepoFile('packages/sdk-web/src/SeamsWeb/walletIframe/client/router.ts');
    const handler = readRepoFile('packages/sdk-web/src/SeamsWeb/walletIframe/host/handlers/emailOtp.ts');

    expect(messages).toContain('PM_SHOW_EMAIL_OTP_RECOVERY_CODES');
    expect(messages).toContain('PMShowEmailOtpRecoveryCodesPayload');
    expect(messages).not.toMatch(/PMShowEmailOtpRecoveryCodesPayload[\s\S]*recoveryKeys/);
    expect(router).toContain('showEmailOtpRecoveryCodes(payload');
    expect(router).toContain("type: 'PM_SHOW_EMAIL_OTP_RECOVERY_CODES'");
    expect(handler).toContain('showEmailOtpRecoveryCodesInIframe');
    expect(handler).toContain('displayedStoredCodes: true');
    expect(handler).toContain('displayedStoredCodes: false');
    expect(handler).toContain('showEmailOtpRecoveryCodeBackupUi(');
    expect(handler).toContain('emailOtpRecoveryCodeBackupRepository.readMatching({');
    expect(handler).toContain('onDownloaded: async () =>');
    expect(handler).toContain('emailOtpRecoveryCodeBackupRepository.markDownloaded({');
  });

  test('iframe recovery-code display stays out of the public recovery capability', () => {
    const publicTypes = readRepoFile('packages/sdk-web/src/SeamsWeb/publicApi/types.ts');
    const publicRecovery = readRepoFile('packages/sdk-web/src/SeamsWeb/publicApi/recovery.ts');
    const sdkFlowProxy = readRepoFile('packages/sdk-web/src/react/context/useSeamsWithSdkFlow.ts');

    expect(publicTypes).not.toContain('showEmailOtpRecoveryCodes');
    expect(publicRecovery).not.toContain('showEmailOtpRecoveryCodes');
    expect(sdkFlowProxy).not.toContain('showEmailOtpRecoveryCodes');
  });

  test('account-menu modal says recovery codes are single-use', () => {
    const modal = readRepoFile(
      'packages/sdk-web/src/react/components/AccountMenuButton/RecoveryCodesModal.tsx',
    );

    expect(modal).toContain('Each code can be used once.');
  });

  test('account-menu modal exposes recovery-code rotation through the public SDK method', () => {
    const modal = readRepoFile(
      'packages/sdk-web/src/react/components/AccountMenuButton/RecoveryCodesModal.tsx',
    );

    expect(modal).toContain('Rotate codes');
    expect(modal).toContain('seams.recovery.rotateEmailOtpRecoveryCodes');
    expect(modal).not.toContain('deleteRecovery');
  });

  test('SeamsAuthMenu prompts rotation after recovery consumes a code', () => {
    const controller = readRepoFile(
      'packages/sdk-web/src/react/components/SeamsAuthMenu/controller/useSeamsAuthMenuController.ts',
    );
    const client = readRepoFile('packages/sdk-web/src/react/components/SeamsAuthMenu/client.tsx');

    expect(controller).toContain('postRecoveryRotationPromptFromSubmitResult');
    expect(controller).toContain('activeRecoveryWrappedEnrollmentEscrowCount');
    expect(controller).toContain('EMAIL_OTP_RECOVERY_KEY_COUNT');
    expect(controller).toContain('rotateEmailOtpRecoveryCodes({ walletId: prompt.walletId })');
    expect(client).toContain('Rotate recovery codes');
    expect(client).toContain('data-post-recovery-rotation-prompt');
  });
});
