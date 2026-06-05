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

  test('loads pending recovery codes from bounded local storage', async ({ page }) => {
    const result = await page.evaluate(async ({ recoveryCodes }) => {
      const mod = await import(
        '/sdk/esm/react/components/AccountMenuButton/RecoveryCodesModalState.js'
      );
      const calls: Array<string | [string, unknown]> = [];
      const pendingStatus = {
        status: 'pending_backup',
        walletId: 'alice.testnet',
        enrollmentId: 'enrollment-1',
        enrollmentSealKeyVersion: 'seal-v1',
        expectedRecoveryCodeCount: 10,
        activeRecoveryCodeCount: 0,
        pendingBackupRecoveryCodeCount: 10,
        consumedRecoveryCodeCount: 0,
        revokedRecoveryCodeCount: 0,
        abandonedRecoveryCodeCount: 0,
        totalRecoveryCodeCount: 10,
        issuedAtMs: 1_700_000_000_000,
        acknowledgedAtMs: null,
      };
      const pendingBackup = {
        v: 1,
        secretKind: 'email_otp_recovery_codes_pending_backup',
        storageScope: 'host_origin_indexeddb',
        status: 'pending_backup',
        walletId: 'alice.testnet',
        enrollmentId: 'enrollment-1',
        enrollmentSealKeyVersion: 'seal-v1',
        recoveryCodesIssuedAtMs: 1_700_000_000_000,
        recoveryKeys: recoveryCodes,
        createdAtMs: 1_700_000_000_000,
        expiresAtMs: 1_700_086_400_000,
      };
      const loaded = await mod.loadRecoveryCodesModalLoadedState({
        walletId: 'alice.testnet',
        recovery: {
          getEmailOtpRecoveryCodeStatus: async (args: unknown) => {
            calls.push(['status', args]);
            return pendingStatus;
          },
        },
        pendingBackupRepository: {
          deleteExpired: async () => {
            calls.push('deleteExpired');
          },
          readMatching: async (args: unknown) => {
            calls.push(['readMatching', args]);
            return pendingBackup;
          },
          delete: async (args: unknown) => {
            calls.push(['delete', args]);
          },
        },
        showPendingBackup: async (args: unknown) => {
          calls.push(['presenter', args]);
          return pendingStatus;
        },
      });
      return { loaded, calls };
    }, { recoveryCodes: RECOVERY_CODES });

    expect(result.loaded).toMatchObject({
      kind: 'loaded',
      status: { status: 'pending_backup', walletId: 'alice.testnet' },
      pendingBackup: {
        walletId: 'alice.testnet',
        enrollmentId: 'enrollment-1',
        recoveryKeys: RECOVERY_CODES,
      },
      actionError: '',
    });
    expect(result.calls).toEqual([
      'deleteExpired',
      ['status', { walletId: 'alice.testnet' }],
      [
        'readMatching',
        {
          walletId: 'alice.testnet',
          enrollmentId: 'enrollment-1',
          enrollmentSealKeyVersion: 'seal-v1',
        },
      ],
    ]);
  });

  test('delegates missing pending backup display through the iframe presenter', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const mod = await import(
        '/sdk/esm/react/components/AccountMenuButton/RecoveryCodesModalState.js'
      );
      const calls: Array<string | [string, unknown]> = [];
      const pendingStatus = {
        status: 'pending_backup',
        walletId: 'alice.testnet',
        enrollmentId: 'enrollment-1',
        enrollmentSealKeyVersion: 'seal-v1',
        expectedRecoveryCodeCount: 10,
        activeRecoveryCodeCount: 0,
        pendingBackupRecoveryCodeCount: 10,
        consumedRecoveryCodeCount: 0,
        revokedRecoveryCodeCount: 0,
        abandonedRecoveryCodeCount: 0,
        totalRecoveryCodeCount: 10,
        issuedAtMs: 1_700_000_000_000,
        acknowledgedAtMs: null,
      };
      const readyStatus = {
        ...pendingStatus,
        status: 'ready',
        activeRecoveryCodeCount: 10,
        pendingBackupRecoveryCodeCount: 0,
        acknowledgedAtMs: 1_700_000_100_000,
      };
      const loaded = await mod.loadRecoveryCodesModalLoadedState({
        walletId: 'alice.testnet',
        recovery: {
          getEmailOtpRecoveryCodeStatus: async (args: unknown) => {
            calls.push(['status', args]);
            return pendingStatus;
          },
        },
        pendingBackupRepository: {
          deleteExpired: async () => {
            calls.push('deleteExpired');
          },
          readMatching: async (args: unknown) => {
            calls.push(['readMatching', args]);
            return null;
          },
          delete: async (args: unknown) => {
            calls.push(['delete', args]);
          },
        },
        showPendingBackup: async (args: unknown) => {
          calls.push(['presenter', args]);
          return readyStatus;
        },
      });
      return { loaded, calls };
    });

    expect(result.loaded).toMatchObject({
      kind: 'loaded',
      status: { status: 'ready', walletId: 'alice.testnet' },
      pendingBackup: null,
      actionError: '',
    });
    expect(result.calls).toEqual([
      'deleteExpired',
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

  test('wallet iframe pending backup command never sends recovery keys to the host', () => {
    const messages = readRepoFile('client/src/SeamsWeb/walletIframe/shared/messages.ts');
    const router = readRepoFile('client/src/SeamsWeb/walletIframe/client/router.ts');
    const handler = readRepoFile('client/src/SeamsWeb/walletIframe/host/handlers/emailOtp.ts');

    expect(messages).toContain('PM_SHOW_EMAIL_OTP_PENDING_RECOVERY_CODE_BACKUP');
    expect(messages).toContain('PMShowEmailOtpPendingRecoveryCodeBackupPayload');
    expect(messages).not.toMatch(/PMShowEmailOtpPendingRecoveryCodeBackupPayload[\s\S]*recoveryKeys/);
    expect(router).toContain('showEmailOtpPendingRecoveryCodeBackup(payload');
    expect(router).toContain("type: 'PM_SHOW_EMAIL_OTP_PENDING_RECOVERY_CODE_BACKUP'");
    expect(handler).toContain('showPendingEmailOtpBackupInIframe');
    expect(handler).toContain('completePendingEmailOtpRecoveryCodeBackup({');
    expect(handler).toContain('emailOtpPendingRecoveryCodeBackupRepository.readMatching({');
  });

  test('iframe pending backup display stays out of the public recovery capability', () => {
    const publicTypes = readRepoFile('client/src/SeamsWeb/publicApi/types.ts');
    const publicRecovery = readRepoFile('client/src/SeamsWeb/publicApi/recovery.ts');
    const sdkFlowProxy = readRepoFile('client/src/react/context/useSeamsWithSdkFlow.ts');

    expect(publicTypes).not.toContain('showEmailOtpPendingRecoveryCodeBackup');
    expect(publicRecovery).not.toContain('showEmailOtpPendingRecoveryCodeBackup');
    expect(sdkFlowProxy).not.toContain('showEmailOtpPendingRecoveryCodeBackup');
  });
});
