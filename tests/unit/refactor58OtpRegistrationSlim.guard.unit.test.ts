import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const LEGACY_REROLL_FIELD = /rerollRegistrationAttempt|reroll_registration_attempt/;

function readRepoSource(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

test.describe('refactor 58 OTP registration slim guards', () => {
  test('Google SSO Email OTP registration operation stays out of passkey and WebAuthn registration code', () => {
    const source = readRepoSource(
      'packages/sdk-web/src/SeamsWeb/operations/authMethods/emailOtp/googleEmailOtpWalletAuthFlow.ts',
    );
    const importStatements = source.match(/import[\s\S]*?;\n/g) ?? [];

    expect(importStatements.join('\n')).not.toMatch(/authMethods\/passkey/);
    expect(importStatements.join('\n')).not.toMatch(/session\/passkey/);
    expect(importStatements.join('\n')).not.toMatch(/webauthn/i);
    expect(importStatements.join('\n')).not.toMatch(/passkey/i);
  });

  test('Google SSO Email OTP registration branch does not issue OTP login challenges', () => {
    const source = readRepoSource(
      'packages/sdk-web/src/SeamsWeb/operations/authMethods/emailOtp/googleEmailOtpWalletAuthFlow.ts',
    );
    const start = source.indexOf('function createGoogleEmailOtpWalletRegistrationFlow');
    const end = source.indexOf('function createGoogleEmailOtpWalletLoginFlow');
    if (start < 0 || end < start) {
      throw new Error('Missing Google Email OTP registration flow block');
    }
    const registrationFlow = source.slice(start, end);

    expect(registrationFlow).not.toMatch(/\brequestLoginChallenge\b/);
    expect(registrationFlow).not.toMatch(/\brequestEmailOtpChallenge\b/);
    expect(registrationFlow).not.toMatch(/\bloginWithEmailOtpEcdsaCapability\b/);
    expect(registrationFlow).not.toMatch(/\botpCode\b/);
    expect(registrationFlow).not.toMatch(/\bchallengeId\b/);
  });

  test('direct Google SSO Email OTP registration backup does not manufacture a challenge id', () => {
    const source = readRepoSource('packages/sdk-web/src/SeamsWeb/operations/registration/registration.ts');
    const start = source.indexOf('function googleEmailOtpRegistrationMaterialToBackupEnrollment');
    const end = source.indexOf('async function resolveEmailOtpRegistrationEnrollmentMaterial', start);
    if (start < 0 || end < start) {
      throw new Error('Missing Google Email OTP registration backup material adapter');
    }
    const backupMaterialAdapter = source.slice(start, end);

    expect(backupMaterialAdapter).toMatch(/\bregistrationAuthorityId:\s*input\.registrationAuthorityId\b/);
    expect(backupMaterialAdapter).not.toMatch(/\bchallengeId\b/);
    expect(source).not.toMatch(/\bchallengeId:\s*input\.registrationAuthorityId\b/);
  });

  test('Google SSO Email OTP registration reroll stays local to the active offer', () => {
    const source = readRepoSource(
      'packages/sdk-web/src/SeamsWeb/operations/authMethods/emailOtp/googleEmailOtpWalletAuthFlow.ts',
    );
    const start = source.indexOf('rerollWalletId: async');
    const end = source.indexOf('cancel: async', start);
    if (start < 0 || end < start) {
      throw new Error('Missing Google Email OTP registration reroll block');
    }
    const rerollBlock = source.slice(start, end);

    expect(rerollBlock).toMatch(/\brotateOfferCandidate\b/);
    expect(rerollBlock).not.toMatch(/\bexchangeGoogleEmailOtpSession\b/);
    expect(rerollBlock).not.toMatch(/\brequestEmailOtpChallenge\b/);
    expect(rerollBlock).not.toMatch(/\brequestEmailOtpEnrollmentChallenge\b/);
    expect(rerollBlock).not.toMatch(/\bloginWithEmailOtpEcdsaCapability\b/);
    expect(rerollBlock).not.toMatch(/\botpCode\b/);
    expect(rerollBlock).not.toMatch(/\bchallengeId\b/);
    expect(rerollBlock).not.toMatch(/\bsubmit\b/);
    expect(rerollBlock).not.toMatch(/\bresend\b/);
  });

  test('legacy register-mode reroll flag stays out of client and service surfaces', () => {
    const checkedPaths = [
      'packages/sdk-web/src/SeamsWeb/operations/authMethods/emailOtp/challenge.ts',
      'packages/sdk-web/src/SeamsWeb/operations/authMethods/emailOtp/googleEmailOtpWalletAuthFlow.ts',
      'packages/sdk-web/src/SeamsWeb/SeamsWeb.ts',
      'packages/sdk-web/src/SeamsWeb/publicApi/types.ts',
      'packages/sdk-web/src/SeamsWeb/walletIframe/client/router.ts',
      'packages/sdk-web/src/SeamsWeb/walletIframe/shared/messages.ts',
      'packages/sdk-server-ts/src/core/AuthService.ts',
    ];

    for (const relativePath of checkedPaths) {
      expect(readRepoSource(relativePath), relativePath).not.toMatch(LEGACY_REROLL_FIELD);
    }
  });

  test('non-Postgres Google SSO Email OTP registration activates identity before wallet visibility', () => {
    const source = readRepoSource('packages/sdk-server-ts/src/core/AuthService.ts');
    const consumeStart = source.indexOf('private async consumeRegistrationCeremonyAndPersist');
    const consumeEnd = source.indexOf('const pool = await getPostgresPool', consumeStart);
    if (consumeStart < 0 || consumeEnd < consumeStart) {
      throw new Error('Missing non-Postgres registration ceremony persistence block');
    }
    const genericStorePath = source.slice(consumeStart, consumeEnd);

    const preflightIndex = genericStorePath.indexOf(
      'preflightGoogleEmailOtpRegistrationActivationForStores',
    );
    const activationIndex = genericStorePath.indexOf(
      'persistGoogleEmailOtpRegistrationActivationToStores',
    );
    const persistenceIndex = genericStorePath.indexOf('writeRegistrationPersistenceToStores({');
    expect(preflightIndex).toBeGreaterThan(-1);
    expect(activationIndex).toBeGreaterThan(preflightIndex);
    expect(persistenceIndex).toBeGreaterThan(activationIndex);
    expect(genericStorePath).toContain(
      'deferWalletRecordUntilActivation: !!input.googleEmailOtpActivation',
    );
  });

  test('generic Google SSO Email OTP registration persistence defers wallet visibility', () => {
    const source = readRepoSource('packages/sdk-server-ts/src/core/AuthService.ts');
    const writeStart = source.indexOf('private async writeRegistrationPersistenceToStores');
    const writeEnd = source.indexOf('private async writeAddAuthMethodPersistenceToStores', writeStart);
    if (writeStart < 0 || writeEnd < writeStart) {
      throw new Error('Missing generic registration persistence writer');
    }
    const writer = source.slice(writeStart, writeEnd);

    const earlyWalletWriteIndex = writer.indexOf('if (!input.deferWalletRecordUntilActivation)');
    const emailOtpEnrollmentIndex = writer.indexOf('if (records.emailOtpEnrollment)');
    const lateWalletWriteIndex = writer.lastIndexOf('if (input.deferWalletRecordUntilActivation)');
    expect(earlyWalletWriteIndex).toBeGreaterThan(-1);
    expect(emailOtpEnrollmentIndex).toBeGreaterThan(earlyWalletWriteIndex);
    expect(lateWalletWriteIndex).toBeGreaterThan(emailOtpEnrollmentIndex);
  });

  test('OTP-only registration offer parser rejects mixed protocol fields', () => {
    const source = readRepoSource(
      'packages/sdk-web/src/SeamsWeb/operations/authMethods/emailOtp/registrationOffer.ts',
    );

    expect(source).toContain("'webauthn'");
    expect(source).toContain("'webauthnRegistration'");
    expect(source).toContain("'passkey'");
    expect(source).toContain("'challengeId'");
    expect(source).toContain("'otpCode'");
    expect(source).toContain("'walletId'");
    expect(source).toContain("'recoveryKeys'");
    expect(source).toContain("'recoveryCodes'");
  });
});
