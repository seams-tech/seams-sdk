#!/usr/bin/env node

import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, '../..');

const emailOtpEcdsaSourcePaths = [
  'packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaEnrollment.ts',
  'packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaLogin.ts',
  'packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaPublication.ts',
  'packages/sdk-web/src/core/signingEngine/session/emailOtp/exportRecovery.ts',
  'packages/sdk-web/src/core/signingEngine/session/emailOtp/workerRequests.ts',
  'packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaBootstrapCommit.ts',
];

const temporaryDiagnosticStrings = [
  'unlock completed without Ed25519 session reconstruction',
  'unlock reconstructed Ed25519 signing session',
  '[Registration][postcondition] Ed25519 lane missing after registration',
  '[Registration][postcondition] ECDSA lane missing after registration',
];

function absolutePath(relativePath) {
  return path.join(repoRoot, relativePath);
}

function readRepoSource(relativePath) {
  return readFileSync(absolutePath(relativePath), 'utf8');
}

function listSourceFiles(relativeDir) {
  const absoluteDir = absolutePath(relativeDir);
  return readdirSync(absoluteDir, { withFileTypes: true }).flatMap((entry) => {
    const relativePath = path.join(relativeDir, entry.name).split(path.sep).join('/');
    if (entry.isDirectory()) return listSourceFiles(relativePath);
    return /\.(ts|tsx)$/.test(entry.name) ? [relativePath] : [];
  });
}

function listActiveSourceFiles() {
  return [
    'packages/sdk-web/src',
    'packages/sdk-server-ts/src',
    'packages/shared-ts/src',
  ].flatMap(listSourceFiles);
}

function collectDuplicateDomainBrandViolations() {
  const centralBrandNames = [
    'WalletId',
    'ProviderSubject',
    'ChallengeSubjectId',
    'EmailOtpChallengeId',
    'EmailOtpRegistrationAttemptId',
    'OrgId',
    'AppSessionVersion',
    'SigningGrantId',
    'ThresholdEd25519SessionId',
    'ThresholdEcdsaSessionId',
  ];
  const duplicateBrandDeclaration = new RegExp(
    `export\\s+type\\s+(?:${centralBrandNames.join('|')})\\s*=`,
  );

  return listActiveSourceFiles()
    .filter((relativePath) => relativePath !== 'packages/shared-ts/src/utils/domainIds.ts')
    .filter((relativePath) => duplicateBrandDeclaration.test(readRepoSource(relativePath)))
    .map((relativePath) => `${relativePath}: duplicate domain identity brand declaration`);
}

function collectPasskeyPrfPersistenceViolations() {
  const forbiddenTokens = [
    'ensureEcdsaPrfSealPersisted',
    'sealAndPersistWarmSessionMaterial',
    'touchConfirm.putWarmSessionMaterial',
    "from '../passkey/runtime'",
    "from './runtime'",
  ];
  const violations = [];

  for (const relativePath of emailOtpEcdsaSourcePaths) {
    const source = readRepoSource(relativePath);
    for (const forbiddenToken of forbiddenTokens) {
      if (source.includes(forbiddenToken)) {
        violations.push(`${relativePath}: Email OTP ECDSA runtime contains ${forbiddenToken}`);
      }
    }
  }

  return violations;
}

function collectWalletSubjectVocabularyViolations() {
  const allowedFiles = new Set([
    'packages/sdk-web/src/core/indexedDB/seamsWalletDB/schema.ts',
  ]);

  return listActiveSourceFiles()
    .filter((relativePath) => !allowedFiles.has(relativePath))
    .filter((relativePath) => /walletSubject|wallet_subject/.test(readRepoSource(relativePath)))
    .map((relativePath) => `${relativePath}: wallet-subject vocabulary outside delete-only boundary`);
}

function collectTemporaryDiagnosticViolations() {
  const violations = [];
  for (const relativePath of listActiveSourceFiles()) {
    const source = readRepoSource(relativePath);
    for (const needle of temporaryDiagnosticStrings) {
      if (source.includes(needle)) {
        violations.push(`${relativePath}: contains temporary diagnostic "${needle}"`);
      }
    }
  }
  return violations;
}

function main() {
  const violations = [
    ...collectDuplicateDomainBrandViolations(),
    ...collectPasskeyPrfPersistenceViolations(),
    ...collectWalletSubjectVocabularyViolations(),
    ...collectTemporaryDiagnosticViolations(),
  ];

  if (violations.length > 0) {
    console.error('[check-email-otp-ecdsa-branch-isolation] failed');
    for (const violation of violations) {
      console.error(`- ${violation}`);
    }
    process.exitCode = 1;
    return;
  }

  console.log('[check-email-otp-ecdsa-branch-isolation] passed');
}

main();
