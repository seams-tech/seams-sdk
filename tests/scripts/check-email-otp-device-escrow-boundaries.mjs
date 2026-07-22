#!/usr/bin/env node

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function readRepoFile(relativePath) {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function sliceBetween(source, startToken, endToken) {
  const start = source.indexOf(startToken);
  assert.ok(start >= 0, `Missing start token: ${startToken}`);
  const end = source.indexOf(endToken, start);
  assert.ok(end > start, `Missing end token after ${startToken}: ${endToken}`);
  return source.slice(start, end);
}

function sliceFromStartToFirstExistingEnd(source, startToken, endTokens) {
  const start = source.indexOf(startToken);
  assert.ok(start >= 0, `Missing start token: ${startToken}`);
  const ends = endTokens
    .map((token) => source.indexOf(token, start + startToken.length))
    .filter((index) => index > start)
    .sort((a, b) => a - b);
  assert.ok(ends.length > 0, `Missing end token after ${startToken}: ${endTokens.join(' | ')}`);
  return source.slice(start, ends[0]);
}

function assertContains(source, token, label) {
  assert.ok(source.includes(token), `${label} must contain \`${token}\``);
}

function assertNotContains(source, token, label) {
  assert.ok(!source.includes(token), `${label} must not contain \`${token}\``);
}

function assertBefore(source, earlierToken, laterToken, label) {
  const earlier = source.indexOf(earlierToken);
  const later = source.indexOf(laterToken);
  assert.ok(earlier >= 0, `${label} missing earlier token \`${earlierToken}\``);
  assert.ok(later >= 0, `${label} missing later token \`${laterToken}\``);
  assert.ok(earlier < later, `${label} expected \`${earlierToken}\` before \`${laterToken}\``);
}

function checkNormalLoginRequiresDeviceLocalEscrow() {
  const workerSource = readRepoFile(
    'packages/sdk-web/src/core/signingEngine/workerManager/workers/email-otp.worker.ts',
  );
  const loginSlice = sliceBetween(
    workerSource,
    'async function loginWithEmailOtpAndUnlockWallet',
    'type ThresholdEcdsaEmailOtpBootstrapFromClientRootShareArgs',
  );

  assertContains(loginSlice, 'readEmailOtpDeviceEnrollmentEscrowRecord', 'normal login');
  assertContains(loginSlice, 'Email OTP device-local enc_s(S) is missing', 'normal login');
  assertContains(loginSlice, 'localEnrollmentEscrow.encSB64u', 'normal login');
  assertContains(loginSlice, "route: emailOtpRoutePath(args.routePlan, 'verifyAndUnseal')", 'normal login');
  assertNotContains(loginSlice, 'verified.enrollmentEscrowCiphertextB64u', 'normal login');
}

function checkServerEnrollmentApisDoNotExposeDirectEscrowStorage() {
  const storesSource = readRepoFile('packages/sdk-server-ts/src/core/EmailOtpStores.ts');
  const authServiceSource = readRepoFile('packages/sdk-server-ts/src/core/authService/AuthService.ts');
  const routeHandlersSource = readRepoFile('packages/sdk-server-ts/src/router/emailOtpRouteHandlers.ts');
  const routeHelpersSource = readRepoFile('packages/sdk-server-ts/src/router/emailOtpSessionRouteHelpers.ts');

  const walletEnrollmentType = sliceBetween(
    storesSource,
    'export type EmailOtpWalletEnrollmentRecord',
    'export interface EmailOtpWalletEnrollmentStore',
  );
  const recoveryWrappedType = sliceBetween(
    storesSource,
    'type EmailOtpRecoveryWrappedEnrollmentEscrowBase',
    'export interface EmailOtpRecoveryWrappedEnrollmentEscrowStore',
  );
  const verifyEnrollmentRequest = sliceFromStartToFirstExistingEnd(
    authServiceSource,
    'async verifyEmailOtpEnrollment(request:',
    ['}): Promise<'],
  );
  const finalizeRoute = sliceFromStartToFirstExistingEnd(
    routeHandlersSource,
    'export async function handleEmailOtpRegistrationFinalizeRoute',
    ['if (result.ok)'],
  );
  const loginVerifyResponse = sliceFromStartToFirstExistingEnd(
    routeHelpersSource,
    'export function emailOtpLoginVerifyResponseBody',
    ['\n}'],
  );

  assertNotContains(walletEnrollmentType, 'enrollmentEscrowCiphertextB64u', 'wallet enrollment record');
  assertContains(walletEnrollmentType, 'enrollmentId', 'wallet enrollment record');
  assertContains(walletEnrollmentType, 'signingRootId', 'wallet enrollment record');
  assertContains(walletEnrollmentType, 'recoveryWrappedEnrollmentEscrowCount', 'wallet enrollment record');
  assertContains(recoveryWrappedType, 'wrappedDeviceEnrollmentEscrowB64u', 'recovery wrapped escrow');
  assertNotContains(verifyEnrollmentRequest, 'enrollmentEscrowCiphertextB64u', 'verify enrollment request');
  assertContains(verifyEnrollmentRequest, 'recoveryWrappedEnrollmentEscrows', 'verify enrollment request');
  assertNotContains(finalizeRoute, 'enrollmentEscrowCiphertextB64u', 'registration finalize route');
  assertContains(finalizeRoute, 'recoveryWrappedEnrollmentEscrows', 'registration finalize route');
  assertNotContains(loginVerifyResponse, 'enrollmentEscrowCiphertextB64u', 'login verify response');
  assertContains(loginVerifyResponse, 'enrollmentSealKeyVersion', 'login verify response');
}

function checkExactLocalEd25519ImportPrecedesFreshSessionAuthority() {
  const workerSource = readRepoFile(
    'packages/sdk-web/src/core/signingEngine/workerManager/workers/email-otp.worker.ts',
  );
  const unlockSlice = sliceBetween(
    workerSource,
    'async function completeEmailOtpUnlockFromSecret32',
    'async function completeEmailOtpEnrollmentFromSecret32',
  );

  assertBefore(
    unlockSlice,
    'importedEd25519Client = await importEmailOtpEd25519YaoLocalMaterial({',
    "route: '/wallet/unlock/verify'",
    'Email OTP exact-local unlock',
  );
  assertContains(
    unlockSlice,
    'expectedThresholdSessionId: args.material.expectedThresholdSessionId',
    'Email OTP exact-local unlock',
  );
  assertContains(
    unlockSlice,
    'removeEmailOtpEd25519YaoActiveClient(importedEd25519Client.activeClientHandle)',
    'Email OTP exact-local unlock',
  );
}

function checkEnrollmentPersistsDeviceLocalEscrowBeforeServerFinalization() {
  const workerSource = readRepoFile(
    'packages/sdk-web/src/core/signingEngine/workerManager/workers/email-otp.worker.ts',
  );
  const enrollSlice = sliceBetween(
    workerSource,
    'async function completeEmailOtpEnrollmentFromSecret32',
    'async function loginWithEmailOtpAndUnlockWallet',
  );

  assertBefore(
    enrollSlice,
    'writeAndVerifyEmailOtpDeviceEnrollmentEscrowRecord',
    "route: emailOtpRoutePath(args.routePlan, 'finalize')",
    'Email OTP enrollment',
  );
  assertContains(workerSource, 'persisted.encSB64u !== record.encSB64u', 'Email OTP enrollment');
  assertContains(
    workerSource,
    'persisted.enrollmentSealKeyVersion !== record.enrollmentSealKeyVersion',
    'Email OTP enrollment',
  );
  assertContains(workerSource, 'persisted.signingRootId !== record.signingRootId', 'Email OTP enrollment');
  assertContains(workerSource, 'persisted.signingRootVersion !== record.signingRootVersion', 'Email OTP enrollment');
  assertContains(enrollSlice, 'Email OTP enrollment did not persist device-local enc_s(S)', 'Email OTP enrollment');
}

function checkRecoveryRestorePersistsDeviceLocalEscrow() {
  const workerSource = readRepoFile(
    'packages/sdk-web/src/core/signingEngine/workerManager/workers/email-otp.worker.ts',
  );
  const restoreSlice = sliceBetween(
    workerSource,
    'async function restoreEmailOtpDeviceEnrollmentEscrowFromRecoveryKey',
    'async function deriveEmailOtpEcdsaClientRootShare32InWorker',
  );

  assertContains(restoreSlice, "route: '/wallet/email-otp/recovery-wrapped-escrows'", 'Email OTP recovery restore');
  assertContains(restoreSlice, 'unwrapEmailOtpDeviceEnrollmentEscrow', 'Email OTP recovery restore');
  assertContains(restoreSlice, 'writeAndVerifyEmailOtpDeviceEnrollmentEscrowRecord', 'Email OTP recovery restore');
  assertContains(restoreSlice, "route: '/wallet/email-otp/recovery-key/consume'", 'Email OTP recovery restore');
  assertContains(workerSource, "route: '/wallet/email-otp/recovery-key/attempt-failed'", 'Email OTP recovery restore');
  assertContains(restoreSlice, 'reportEmailOtpRecoveryKeyAttemptFailure', 'Email OTP recovery restore');
  assertContains(restoreSlice, 'sawRecoveryKeyUnwrapFailure', 'Email OTP recovery restore');
  assertContains(restoreSlice, 'recoveryConsumeGrant', 'Email OTP recovery restore');
  assertContains(restoreSlice, 'Email OTP recovery did not persist device-local enc_s(S)', 'Email OTP recovery restore');
  assertNotContains(restoreSlice, 'loginGrant', 'Email OTP recovery restore');
}

function checkRecoveryKeyIdsAreDerivedConsistently() {
  const workerSource = readRepoFile(
    'packages/sdk-web/src/core/signingEngine/workerManager/workers/email-otp.worker.ts',
  );
  const wrapSlice = sliceBetween(
    workerSource,
    'async function createEmailOtpRecoveryWrappedEnrollmentEscrows',
    'async function parseEmailOtpRecoveryWrappedEnrollmentEscrowPayload',
  );
  const parseSlice = sliceBetween(
    workerSource,
    'async function parseEmailOtpRecoveryWrappedEnrollmentEscrowPayload',
    'async function reportEmailOtpRecoveryKeyAttemptFailure',
  );
  const restoreSlice = sliceBetween(
    workerSource,
    'async function restoreEmailOtpDeviceEnrollmentEscrowFromRecoveryKey',
    'async function rotateEmailOtpRecoveryCodesFromLocalDeviceEnrollment',
  );
  const rotateSlice = sliceBetween(
    workerSource,
    'async function rotateEmailOtpRecoveryCodesFromLocalDeviceEnrollment',
    'async function removeEmailOtpDeviceEnrollmentEscrowFromDevice',
  );

  assertContains(wrapSlice, 'deriveEmailOtpRecoveryKeyId({', 'Email OTP recovery-key wrapping');
  assertContains(wrapSlice, 'recoveryKey: recoveryKeys[index]', 'Email OTP recovery-key wrapping');
  assertContains(parseSlice, 'deriveEmailOtpRecoveryKeyId({', 'Email OTP recovery-key parsing');
  assertContains(parseSlice, 'recoveryKey,', 'Email OTP recovery-key parsing');
  assertContains(restoreSlice, 'parseEmailOtpRecoveryWrappedEnrollmentEscrowPayload(', 'Email OTP recovery restore');
  assertContains(restoreSlice, 'rawRecord,', 'Email OTP recovery restore');
  assertContains(restoreSlice, 'recoveryKey,', 'Email OTP recovery restore');
  assertContains(rotateSlice, 'createEmailOtpRecoveryWrappedEnrollmentEscrows({', 'Email OTP recovery-code rotation');
}

function checkUnwrappedEscrowBuffersAreZeroized() {
  const workerSource = readRepoFile(
    'packages/sdk-web/src/core/signingEngine/workerManager/workers/email-otp.worker.ts',
  );
  const wrapSlice = sliceBetween(
    workerSource,
    'async function createEmailOtpRecoveryWrappedEnrollmentEscrows',
    'async function parseEmailOtpRecoveryWrappedEnrollmentEscrowPayload',
  );
  const restoreSlice = sliceBetween(
    workerSource,
    'async function restoreEmailOtpDeviceEnrollmentEscrowFromRecoveryKey',
    'async function deriveEmailOtpEcdsaClientRootShare32InWorker',
  );

  assertContains(wrapSlice, 'const encS = base64UrlDecode(args.encSB64u)', 'Email OTP recovery wrapping');
  assertContains(wrapSlice, 'zeroizeBytes(encS)', 'Email OTP recovery wrapping');
  assertContains(restoreSlice, 'let encS: Uint8Array | null = null', 'Email OTP recovery restore');
  assertContains(restoreSlice, 'zeroizeBytes(encS)', 'Email OTP recovery restore');
}

function checkLogoutLockKeepsDeviceLocalRecoveryMaterial() {
  const loginSource = readRepoFile('packages/sdk-web/src/SeamsWeb/operations/auth/login.ts');
  const lockSlice = sliceBetween(loginSource, 'export async function lock(', '\n}');
  const workerSource = readRepoFile(
    'packages/sdk-web/src/core/signingEngine/workerManager/workers/email-otp.worker.ts',
  );

  assertContains(lockSlice, 'clearLastProfileSelection', 'logout lock');
  assertNotContains(lockSlice, 'deleteEmailOtpDeviceEnrollmentEscrowRecord', 'logout lock');
  assertNotContains(lockSlice, 'clearAllEmailOtpDeviceEnrollmentEscrowRecords', 'logout lock');
  assertNotContains(lockSlice, 'emailOtpRecoveryCodeBackupRepository', 'logout lock');
  assertContains(workerSource, "case 'removeEmailOtpDeviceEnrollmentEscrowFromDevice'", 'Email OTP worker');
  assertContains(workerSource, 'deleteEmailOtpDeviceEnrollmentEscrowRecord', 'Email OTP worker');
}

checkNormalLoginRequiresDeviceLocalEscrow();
checkExactLocalEd25519ImportPrecedesFreshSessionAuthority();
checkServerEnrollmentApisDoNotExposeDirectEscrowStorage();
checkEnrollmentPersistsDeviceLocalEscrowBeforeServerFinalization();
checkRecoveryRestorePersistsDeviceLocalEscrow();
checkRecoveryKeyIdsAreDerivedConsistently();
checkUnwrappedEscrowBuffersAreZeroized();
checkLogoutLockKeepsDeviceLocalRecoveryMaterial();

console.log('[email-otp-device-escrow-boundaries] ok');
