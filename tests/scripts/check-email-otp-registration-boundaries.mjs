#!/usr/bin/env node

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const LEGACY_REROLL_FIELD = /rerollRegistrationAttempt|reroll_registration_attempt/;
const GOOGLE_EMAIL_OTP_FLOW_PATH =
  'packages/sdk-web/src/SeamsWeb/operations/authMethods/emailOtp/googleEmailOtpWalletAuthFlow.ts';

function readRepoFile(relativePath) {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function assertDoesNotMatch(source, pattern, label) {
  assert.ok(!pattern.test(source), `${label}: matched ${pattern}`);
}

function extractRequiredBlock(source, startMarker, endMarker, label) {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start);
  assert.ok(start >= 0 && end > start, `Missing ${label}`);
  return source.slice(start, end);
}

function checkGoogleSsoEmailOtpRegistrationStaysOutOfPasskeyCode() {
  const source = readRepoFile(GOOGLE_EMAIL_OTP_FLOW_PATH);
  const importStatements = source.match(/import[\s\S]*?;\n/g) ?? [];
  const imports = importStatements.join('\n');

  const forbiddenPatterns = [/authMethods\/passkey/, /session\/passkey/, /webauthn/i, /passkey/i];
  for (const pattern of forbiddenPatterns) {
    assertDoesNotMatch(
      imports,
      pattern,
      'Google SSO Email OTP registration operation must stay out of passkey and WebAuthn imports',
    );
  }
}

function checkGoogleSsoEmailOtpRegistrationDoesNotIssueLoginChallenges() {
  const source = readRepoFile(GOOGLE_EMAIL_OTP_FLOW_PATH);
  const registrationFlow = extractRequiredBlock(
    source,
    'function createGoogleEmailOtpWalletRegistrationFlow',
    'function createGoogleEmailOtpWalletLoginFlow',
    'Google Email OTP registration flow block',
  );

  const forbiddenPatterns = [
    /\brequestLoginChallenge\b/,
    /\brequestEmailOtpChallenge\b/,
    /\bloginWithEmailOtpEcdsaCapability\b/,
    /\botpCode\b/,
    /\bchallengeId\b/,
  ];
  for (const pattern of forbiddenPatterns) {
    assertDoesNotMatch(
      registrationFlow,
      pattern,
      'Google SSO Email OTP registration branch must not issue OTP login challenges',
    );
  }
}

function checkDirectGoogleSsoEmailOtpRegistrationBackupDoesNotManufactureChallengeId() {
  const source = readRepoFile(
    'packages/sdk-web/src/SeamsWeb/operations/registration/registration.ts',
  );
  assertDoesNotMatch(
    source,
    /\bchallengeId:\s*input\.registrationAuthorityId\b/,
    'registration source must not manufacture challengeId from registrationAuthorityId',
  );
}

function checkGoogleSsoEmailOtpRegistrationRerollStaysLocalToActiveOffer() {
  const source = readRepoFile(GOOGLE_EMAIL_OTP_FLOW_PATH);
  const rerollBlock = extractRequiredBlock(
    source,
    'rerollWalletId: async',
    'cancel: async',
    'Google Email OTP registration reroll block',
  );

  assert.match(rerollBlock, /\brotateOfferCandidate\b/);
  const forbiddenPatterns = [
    /\bexchangeGoogleEmailOtpSession\b/,
    /\brequestEmailOtpChallenge\b/,
    /\brequestEmailOtpEnrollmentChallenge\b/,
    /\bloginWithEmailOtpEcdsaCapability\b/,
    /\botpCode\b/,
    /\bchallengeId\b/,
    /\bsubmit\b/,
    /\bresend\b/,
  ];
  for (const pattern of forbiddenPatterns) {
    assertDoesNotMatch(
      rerollBlock,
      pattern,
      'Google SSO Email OTP registration reroll must stay local to the active offer',
    );
  }
}

function checkLegacyRegisterModeRerollFlagStaysOutOfClientAndServiceSurfaces() {
  const checkedPaths = [
    'packages/sdk-web/src/SeamsWeb/operations/authMethods/emailOtp/challenge.ts',
    GOOGLE_EMAIL_OTP_FLOW_PATH,
    'packages/sdk-web/src/SeamsWeb/SeamsWeb.ts',
    'packages/sdk-web/src/SeamsWeb/publicApi/types.ts',
    'packages/sdk-web/src/SeamsWeb/walletIframe/client/router.ts',
    'packages/sdk-web/src/SeamsWeb/walletIframe/shared/messages.ts',
    'packages/sdk-server-ts/src/core/AuthService.ts',
  ];

  const offenders = [];
  for (const relativePath of checkedPaths) {
    if (LEGACY_REROLL_FIELD.test(readRepoFile(relativePath))) offenders.push(relativePath);
  }
  assert.deepEqual(
    offenders,
    [],
    `legacy register-mode reroll flag must stay out of client and service surfaces\n${offenders.join('\n')}`,
  );
}

function checkOtpOnlyRegistrationOfferParserRejectsMixedProtocolFields() {
  const source = readRepoFile(
    'packages/sdk-web/src/SeamsWeb/operations/authMethods/emailOtp/registrationOffer.ts',
  );
  const requiredMarkers = [
    "'webauthn'",
    "'webauthnRegistration'",
    "'passkey'",
    "'challengeId'",
    "'otpCode'",
    "'walletId'",
    "'recoveryKeys'",
    "'recoveryCodes'",
  ];

  for (const marker of requiredMarkers) {
    assert.ok(
      source.includes(marker),
      `registration offer parser missing rejection marker ${marker}`,
    );
  }
}

checkGoogleSsoEmailOtpRegistrationStaysOutOfPasskeyCode();
checkGoogleSsoEmailOtpRegistrationDoesNotIssueLoginChallenges();
checkDirectGoogleSsoEmailOtpRegistrationBackupDoesNotManufactureChallengeId();
checkGoogleSsoEmailOtpRegistrationRerollStaysLocalToActiveOffer();
checkLegacyRegisterModeRerollFlagStaysOutOfClientAndServiceSurfaces();
checkOtpOnlyRegistrationOfferParserRejectsMixedProtocolFields();

console.log('[check-email-otp-registration-boundaries] passed');
