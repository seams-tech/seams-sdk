#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, '../..');

const sourceRoots = [
  'packages/wallet/src',
  'packages/wallet-server/src',
  'packages/shared-ts/src',
];

const recoveryKeysAllowedSourceFiles = new Set([
  'packages/wallet/src/SeamsWeb/googleEmailOtpWalletAuth.typecheck.ts',
  'packages/wallet/src/SeamsWeb/operations/authMethods/emailOtp/registrationOffer.ts',
  'packages/wallet/src/SeamsWeb/walletIframe/client/router.ts',
]);

const retainedBackupRecordAllowedSourceFiles = new Set();

const recoveryBackupSecretKindAllowedSourceFiles = new Set();

const recoveryCodeCastAllowedSourceFiles = new Set([
  'packages/shared-ts/src/utils/emailOtpRecoveryKey.ts',
]);

const recoveryCodeBackupRepositoryAllowedSourceFiles = new Set();

function absolutePath(relativePath) {
  return path.join(repoRoot, relativePath);
}

function readRepoSource(relativePath) {
  return fs.readFileSync(absolutePath(relativePath), 'utf8');
}

function listTypeScriptFiles(relativeDir) {
  const absoluteDir = absolutePath(relativeDir);
  if (!fs.existsSync(absoluteDir)) return [];

  return fs.readdirSync(absoluteDir, { withFileTypes: true }).flatMap((entry) => {
    const relativePath = path.join(relativeDir, entry.name).split(path.sep).join('/');
    if (entry.isDirectory()) return listTypeScriptFiles(relativePath);
    return entry.isFile() && /\.tsx?$/.test(entry.name) ? [relativePath] : [];
  });
}

function listSourceFiles() {
  return sourceRoots.flatMap((root) => listTypeScriptFiles(root)).sort();
}

function filesContaining(sourceFiles, pattern) {
  return sourceFiles.filter((relativePath) => pattern.test(readRepoSource(relativePath)));
}

function collectRecoveryKeyBoundaryViolations(sourceFiles) {
  return sourceFiles
    .filter((relativePath) => !recoveryKeysAllowedSourceFiles.has(relativePath))
    .filter((relativePath) => /\brecoveryKeys\b/.test(readRepoSource(relativePath)))
    .map((relativePath) => `${relativePath}: recoveryKeys outside explicit boundary files`);
}

function collectRetainedBackupRecordViolations(sourceFiles) {
  return filesContaining(sourceFiles, /\bStoredEmailOtpRecoveryCodeBackupRecord\b/)
    .filter((relativePath) => !retainedBackupRecordAllowedSourceFiles.has(relativePath))
    .map((relativePath) => `${relativePath}: retained plaintext backup record type leaked`);
}

function collectBackupSecretKindViolations(sourceFiles) {
  return filesContaining(sourceFiles, /email_otp_recovery_codes_backup/)
    .filter((relativePath) => !recoveryBackupSecretKindAllowedSourceFiles.has(relativePath))
    .map((relativePath) => `${relativePath}: plaintext backup secret kind outside repository`);
}

function collectServerRecoveryKeyViolations() {
  const violations = [];
  for (const relativePath of listTypeScriptFiles('packages/wallet-server/src')) {
    const source = readRepoSource(relativePath);
    if (!/\brecoveryKeys\b/.test(source)) continue;
    const patterns = [
      ['object field', /\brecoveryKeys\s*:/],
      ['property read', /\.recoveryKeys\b/],
      ['destructure binding', /{\s*recoveryKeys\b/],
    ];
    for (const [patternName, pattern] of patterns) {
      if (pattern.test(source)) {
        violations.push(`${relativePath}: server code contains recoveryKeys ${patternName}`);
      }
    }
  }
  return violations;
}

function collectWalletIframeExposureViolations() {
  const guardedFiles = [
    'packages/wallet/src/SeamsWeb/walletIframe/shared/messages.ts',
    'packages/wallet/src/SeamsWeb/walletIframe/host/requestRouter.ts',
    'packages/wallet/src/SeamsWeb/walletIframe/client/progress/on-events-progress-bus.ts',
  ];

  return guardedFiles
    .filter((relativePath) => /\brecoveryKeys\b/.test(readRepoSource(relativePath)))
    .map((relativePath) => `${relativePath}: wallet iframe surface exposes recoveryKeys`);
}

function collectLogAndTelemetryViolations(sourceFiles) {
  const logOrTelemetryLine = /\b(?:console|logger)\.(?:log|info|warn|error|debug)\b|telemetry/i;
  const secretField = /\b(?:recoveryKeys|recoveryKey|recoveryKek|encS|encSB64u)\b/;
  const violations = [];

  for (const relativePath of sourceFiles) {
    const lines = readRepoSource(relativePath).split(/\r?\n/);
    lines.forEach((line, index) => {
      if (logOrTelemetryLine.test(line) && secretField.test(line)) {
        violations.push(`${relativePath}:${index + 1}: logs or telemetry mention recovery-code material`);
      }
    });
  }

  return violations;
}

function collectStorageViolations() {
  return [...recoveryKeysAllowedSourceFiles]
    .filter((relativePath) => relativePath.startsWith('packages/wallet/src/'))
    .filter((relativePath) => fs.existsSync(absolutePath(relativePath)))
    .filter((relativePath) => /\b(?:localStorage|sessionStorage)\b/.test(readRepoSource(relativePath)))
    .map((relativePath) => `${relativePath}: recoveryKeys boundary uses localStorage/sessionStorage`);
}

function collectRecoveryCodeCastViolations(sourceFiles) {
  return filesContaining(sourceFiles, /\bas\s+EmailOtpRecoveryCode(?:Set)?\b/)
    .filter((relativePath) => !recoveryCodeCastAllowedSourceFiles.has(relativePath))
    .map((relativePath) => `${relativePath}: EmailOtpRecoveryCode cast outside parser boundary`);
}

function collectBackupRepositoryViolations(sourceFiles) {
  return filesContaining(sourceFiles, /\bemailOtpRecoveryCodeBackupRepository\b/)
    .filter((relativePath) => !recoveryCodeBackupRepositoryAllowedSourceFiles.has(relativePath))
    .map((relativePath) => `${relativePath}: recovery-code backup repository outside wallet-owned UI/backup operations`);
}

function main() {
  const sourceFiles = listSourceFiles();
  const violations = [
    ...collectRecoveryKeyBoundaryViolations(sourceFiles),
    ...collectRetainedBackupRecordViolations(sourceFiles),
    ...collectBackupSecretKindViolations(sourceFiles),
    ...collectServerRecoveryKeyViolations(),
    ...collectWalletIframeExposureViolations(),
    ...collectLogAndTelemetryViolations(sourceFiles),
    ...collectStorageViolations(),
    ...collectRecoveryCodeCastViolations(sourceFiles),
    ...collectBackupRepositoryViolations(sourceFiles),
  ];

  if (violations.length > 0) {
    console.error('[check-email-otp-recovery-code-leakage] failed');
    for (const violation of violations) {
      console.error(`- ${violation}`);
    }
    process.exitCode = 1;
    return;
  }

  console.log('[check-email-otp-recovery-code-leakage] passed');
}

main();
