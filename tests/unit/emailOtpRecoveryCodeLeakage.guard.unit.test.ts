import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function readRepoSource(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function listTypeScriptFiles(relativeDir: string): string[] {
  const absoluteDir = path.join(repoRoot, relativeDir);
  if (!fs.existsSync(absoluteDir)) return [];
  return fs.readdirSync(absoluteDir, { withFileTypes: true }).flatMap((entry) => {
    const relativePath = path.join(relativeDir, entry.name);
    if (entry.isDirectory()) return listTypeScriptFiles(relativePath);
    return entry.isFile() && /\.tsx?$/.test(entry.name) ? [relativePath] : [];
  });
}

const sourceRoots = [
  'client/src',
  'server/src',
  'shared/src',
] as const;

const recoveryKeysAllowedSourceFiles = new Set([
  'client/src/SeamsWeb/googleEmailOtpWalletAuth.typecheck.ts',
  'client/src/SeamsWeb/operations/authMethods/emailOtp/challenge.ts',
  'client/src/SeamsWeb/operations/authMethods/emailOtp/enrollment.ts',
  'client/src/SeamsWeb/operations/authMethods/emailOtp/registrationOffer.ts',
  'client/src/SeamsWeb/operations/authMethods/emailOtp/recoveryCodeBackup.ts',
  'client/src/SeamsWeb/operations/registration/registration.ts',
  'client/src/SeamsWeb/publicNamespaceApi.typecheck.ts',
  'client/src/SeamsWeb/publicApi/types.ts',
  'client/src/SeamsWeb/walletIframe/client/router.ts',
  'client/src/SeamsWeb/walletIframe/host/handlers/emailOtp.ts',
  'client/src/core/indexedDB/seamsWalletDB/emailOtpDeviceEnrollmentEscrows.ts',
  'client/src/core/indexedDB/seamsWalletDB/emailOtpRecoveryCodeBackups.ts',
  'client/src/core/signingEngine/session/emailOtp/publicTypes.ts',
  'client/src/core/signingEngine/session/emailOtp/publicTypes.typecheck.ts',
  'client/src/core/signingEngine/session/emailOtp/workerEnrollment.ts',
  'client/src/core/signingEngine/workerManager/workerTypes.ts',
  'client/src/core/signingEngine/workerManager/workers/email-otp.worker.ts',
  'client/src/react/components/AccountMenuButton/RecoveryCodesModal.tsx',
  'client/src/react/components/AccountMenuButton/RecoveryCodesModalState.ts',
  'server/src/core/EmailOtpPostgresRecords.ts',
  'server/src/core/EmailOtpStores.ts',
  'server/src/router/emailOtpRouteHandlers.ts',
  'server/src/router/relayWalletRegistration.ts',
]);

const retainedBackupRecordAllowedSourceFiles = new Set([
  'client/src/core/indexedDB/seamsWalletDB/emailOtpRecoveryCodeBackups.ts',
  'client/src/react/components/AccountMenuButton/RecoveryCodesModal.tsx',
  'client/src/react/components/AccountMenuButton/RecoveryCodesModalState.ts',
]);

const recoveryBackupSecretKindAllowedSourceFiles = new Set([
  'client/src/core/indexedDB/seamsWalletDB/emailOtpRecoveryCodeBackups.ts',
]);

const recoveryCodeCastAllowedSourceFiles = new Set([
  'shared/src/utils/emailOtpRecoveryKey.ts',
]);

const recoveryCodeBackupRepositoryAllowedSourceFiles = new Set([
  'client/src/SeamsWeb/operations/authMethods/emailOtp/recoveryCodeBackup.ts',
  'client/src/SeamsWeb/walletIframe/host/handlers/emailOtp.ts',
  'client/src/react/components/AccountMenuButton/RecoveryCodesModal.tsx',
  'client/src/react/components/AccountMenuButton/RecoveryCodesModalState.ts',
]);

function listSourceFiles(): string[] {
  return sourceRoots.flatMap((root) => listTypeScriptFiles(root)).sort();
}

function offendingRecoveryKeyFiles(): string[] {
  return listSourceFiles().filter((relativePath) => {
    if (recoveryKeysAllowedSourceFiles.has(relativePath)) return false;
    return /\brecoveryKeys\b/.test(readRepoSource(relativePath));
  });
}

function filesContaining(pattern: RegExp): string[] {
  return listSourceFiles().filter((relativePath) => pattern.test(readRepoSource(relativePath)));
}

test.describe('Email OTP recovery-code leakage guards', () => {
  test('generated recoveryKeys stay inside explicit boundary files', () => {
    expect(offendingRecoveryKeyFiles()).toEqual([]);
  });

  test('retained plaintext backup record type stays out of host/server/public payloads', () => {
    const offenders = filesContaining(/\bStoredEmailOtpRecoveryCodeBackupRecord\b/).filter(
      (relativePath) => !retainedBackupRecordAllowedSourceFiles.has(relativePath),
    );

    expect(offenders).toEqual([]);
  });

  test('plaintext backup IndexedDB secret kind is only used by its repository', () => {
    const offenders = filesContaining(/email_otp_recovery_codes_backup/).filter(
      (relativePath) => !recoveryBackupSecretKindAllowedSourceFiles.has(relativePath),
    );

    expect(offenders).toEqual([]);
  });

  test('server code may reject recoveryKeys but cannot construct or read them', () => {
    const offenders: string[] = [];
    for (const relativePath of listTypeScriptFiles('server/src')) {
      const source = readRepoSource(relativePath);
      if (!/\brecoveryKeys\b/.test(source)) continue;
      for (const [patternName, pattern] of [
        ['object field', /\brecoveryKeys\s*:/],
        ['property read', /\.recoveryKeys\b/],
        ['destructure binding', /{\s*recoveryKeys\b/],
      ] as const) {
        if (pattern.test(source)) offenders.push(`${relativePath} contains ${patternName}`);
      }
    }

    expect(offenders).toEqual([]);
  });

  test('wallet iframe host messages and progress events cannot expose recoveryKeys', () => {
    const guardedFiles = [
      'client/src/SeamsWeb/walletIframe/shared/messages.ts',
      'client/src/SeamsWeb/walletIframe/host/requestRouter.ts',
      'client/src/SeamsWeb/walletIframe/client/progress/on-events-progress-bus.ts',
    ];
    const offenders = guardedFiles.filter((relativePath) =>
      /\brecoveryKeys\b/.test(readRepoSource(relativePath)),
    );

    expect(offenders).toEqual([]);
  });

  test('logs and telemetry do not mention recovery-code material fields', () => {
    const logOrTelemetryLine = /\b(?:console|logger)\.(?:log|info|warn|error|debug)\b|telemetry/i;
    const secretField = /\b(?:recoveryKeys|recoveryKey|recoveryKek|encS|encSB64u)\b/;
    const offenders: string[] = [];
    for (const relativePath of listSourceFiles()) {
      const lines = readRepoSource(relativePath).split(/\r?\n/);
      lines.forEach((line, index) => {
        if (logOrTelemetryLine.test(line) && secretField.test(line)) {
          offenders.push(`${relativePath}:${index + 1}`);
        }
      });
    }

    expect(offenders).toEqual([]);
  });

  test('recoveryKeys files do not use localStorage or sessionStorage', () => {
    const offenders = [...recoveryKeysAllowedSourceFiles]
      .filter((relativePath) => relativePath.startsWith('client/src/'))
      .filter((relativePath) => fs.existsSync(path.join(repoRoot, relativePath)))
      .filter((relativePath) => /\b(?:localStorage|sessionStorage)\b/.test(readRepoSource(relativePath)));

    expect(offenders).toEqual([]);
  });

  test('recovery-code brand casts stay confined to the shared parser and formatter boundary', () => {
    const offenders = filesContaining(/\bas\s+EmailOtpRecoveryCode(?:Set)?\b/).filter(
      (relativePath) => !recoveryCodeCastAllowedSourceFiles.has(relativePath),
    );

    expect(offenders).toEqual([]);
  });

  test('plaintext backup repository stays confined to wallet-owned UI and backup operations', () => {
    const offenders = filesContaining(/\bemailOtpRecoveryCodeBackupRepository\b/).filter(
      (relativePath) =>
        relativePath !==
          'client/src/core/indexedDB/seamsWalletDB/emailOtpRecoveryCodeBackups.ts' &&
        !recoveryCodeBackupRepositoryAllowedSourceFiles.has(relativePath),
    );

    expect(offenders).toEqual([]);
  });
});
