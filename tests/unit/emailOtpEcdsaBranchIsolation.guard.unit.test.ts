import { expect, test } from '@playwright/test';
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const EMAIL_OTP_ECDSA_SOURCE_URLS = [
  '../../packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaEnrollment.ts',
  '../../packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaLogin.ts',
  '../../packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaPublication.ts',
  '../../packages/sdk-web/src/core/signingEngine/session/emailOtp/exportRecovery.ts',
  '../../packages/sdk-web/src/core/signingEngine/session/emailOtp/workerRequests.ts',
  '../../packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaBootstrapCommit.ts',
].map((relativePath) => new URL(relativePath, import.meta.url));

const TEMPORARY_DIAGNOSTIC_STRINGS = [
  'unlock completed without Ed25519 session reconstruction',
  'unlock reconstructed Ed25519 signing session',
  '[Registration][postcondition] Ed25519 lane missing after registration',
  '[Registration][postcondition] ECDSA lane missing after registration',
] as const;

function readSource(url: URL): string {
  return readFileSync(url, 'utf8');
}

function listSourceFiles(relativeDir: string): string[] {
  const absoluteDir = path.join(repoRoot, relativeDir);
  return readdirSync(absoluteDir, { withFileTypes: true }).flatMap((entry) => {
    const relativePath = path.join(relativeDir, entry.name);
    if (entry.isDirectory()) return listSourceFiles(relativePath);
    return /\.(ts|tsx)$/.test(entry.name) ? [relativePath] : [];
  });
}

test.describe('Email OTP ECDSA branch isolation guards', () => {
  test('domain identity brands have one central source of truth', () => {
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
    const duplicateBrandFiles = ['packages/sdk-web/src', 'packages/sdk-server-ts/src', 'packages/shared-ts/src']
      .flatMap(listSourceFiles)
      .filter((relativePath) => relativePath !== 'packages/shared-ts/src/utils/domainIds.ts')
      .filter((relativePath) =>
        duplicateBrandDeclaration.test(readFileSync(path.join(repoRoot, relativePath), 'utf8')),
      );

    expect(duplicateBrandFiles).toEqual([]);
  });

  test('Email OTP ECDSA runtime stays out of passkey PRF seal persistence', () => {
    for (const url of EMAIL_OTP_ECDSA_SOURCE_URLS) {
      const source = readSource(url);
      expect(source, url.pathname).not.toContain('ensureEcdsaPrfSealPersisted');
      expect(source, url.pathname).not.toContain('sealAndPersistWarmSessionMaterial');
      expect(source, url.pathname).not.toContain('touchConfirm.putWarmSessionMaterial');
      expect(source, url.pathname).not.toContain("from '../passkey/runtime'");
      expect(source, url.pathname).not.toContain("from './runtime'");
    }
  });

  test('wallet-subject vocabulary is isolated to migration and delete-only boundaries', () => {
    const allowedFiles = new Set([
      'packages/sdk-web/src/core/indexedDB/seamsWalletDB/schema.ts',
    ]);
    const offenders = ['packages/sdk-web/src', 'packages/sdk-server-ts/src', 'packages/shared-ts/src']
      .flatMap(listSourceFiles)
      .filter((relativePath) => !allowedFiles.has(relativePath))
      .filter((relativePath) => /walletSubject|wallet_subject/.test(readFileSync(path.join(repoRoot, relativePath), 'utf8')));

    expect(offenders).toEqual([]);
  });

  test('temporary registration and unlock diagnostics stay out of runtime source', () => {
    const offenders = ['packages/sdk-web/src', 'packages/sdk-server-ts/src', 'packages/shared-ts/src']
      .flatMap(listSourceFiles)
      .flatMap((relativePath) => {
        const source = readFileSync(path.join(repoRoot, relativePath), 'utf8');
        return TEMPORARY_DIAGNOSTIC_STRINGS.filter((needle) => source.includes(needle)).map(
          (needle) => ({ relativePath, needle }),
        );
      });

    expect(offenders).toEqual([]);
  });
});
