import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const REPO_ROOT = new URL('../..', import.meta.url).pathname;
test.describe('Email OTP signing-session device escrow guard', () => {
  test('normal Email OTP login requires device-local enc_s(S)', () => {
    const workerSource = readFileSync(
      join(REPO_ROOT, 'packages/sdk-web/src/core/signingEngine/workerManager/workers/email-otp.worker.ts'),
      'utf8',
    );
    const loginSlice = workerSource.slice(
      workerSource.indexOf('async function loginWithEmailOtpAndRecoverClientRootShare'),
      workerSource.indexOf('async function loginWithEmailOtpAndBootstrapEcdsaSession'),
    );

    expect(loginSlice).toContain('readEmailOtpDeviceEnrollmentEscrowRecord');
    expect(loginSlice).toContain('Email OTP device-local enc_s(S) is missing');
    expect(loginSlice).toContain('localEnrollmentEscrow.encSB64u');
    expect(loginSlice).toContain("route: emailOtpRoutePath(args.routePlan, 'verifyAndUnseal')");
    expect(loginSlice).not.toContain('verified.enrollmentEscrowCiphertextB64u');
  });

  test('server enrollment APIs and records do not expose direct enrollment escrow storage', () => {
    const storesSource = readFileSync(join(REPO_ROOT, 'packages/sdk-server-ts/src/core/EmailOtpStores.ts'), 'utf8');
    const authServiceSource = readFileSync(
      join(REPO_ROOT, 'packages/sdk-server-ts/src/core/AuthService.ts'),
      'utf8',
    );
    const routeHandlersSource = readFileSync(
      join(REPO_ROOT, 'packages/sdk-server-ts/src/router/emailOtpRouteHandlers.ts'),
      'utf8',
    );
    const routeHelpersSource = readFileSync(
      join(REPO_ROOT, 'packages/sdk-server-ts/src/router/emailOtpSessionRouteHelpers.ts'),
      'utf8',
    );

    const walletEnrollmentType = storesSource.slice(
      storesSource.indexOf('export type EmailOtpWalletEnrollmentRecord'),
      storesSource.indexOf('export interface EmailOtpWalletEnrollmentStore'),
    );
    const recoveryWrappedType = storesSource.slice(
      storesSource.indexOf('type EmailOtpRecoveryWrappedEnrollmentEscrowBase'),
      storesSource.indexOf('export interface EmailOtpRecoveryWrappedEnrollmentEscrowStore'),
    );
    const verifyEnrollmentRequest = authServiceSource.slice(
      authServiceSource.indexOf('async verifyEmailOtpEnrollment(request:'),
      authServiceSource.indexOf(
        '>): Promise<',
        authServiceSource.indexOf('async verifyEmailOtpEnrollment(request:'),
      ),
    );
    const finalizeRoute = routeHandlersSource.slice(
      routeHandlersSource.indexOf('export async function handleEmailOtpRegistrationFinalizeRoute'),
      routeHandlersSource.indexOf(
        'if (result.ok)',
        routeHandlersSource.indexOf(
          'export async function handleEmailOtpRegistrationFinalizeRoute',
        ),
      ),
    );
    const loginVerifyResponse = routeHelpersSource.slice(
      routeHelpersSource.indexOf('export function emailOtpLoginVerifyResponseBody'),
      routeHelpersSource.indexOf(
        '\n}',
        routeHelpersSource.indexOf('export function emailOtpLoginVerifyResponseBody'),
      ) + 2,
    );

    expect(walletEnrollmentType).not.toContain('enrollmentEscrowCiphertextB64u');
    expect(walletEnrollmentType).toContain('enrollmentId');
    expect(walletEnrollmentType).toContain('signingRootId');
    expect(walletEnrollmentType).toContain('recoveryWrappedEnrollmentEscrowCount');
    expect(recoveryWrappedType).toContain('wrappedDeviceEnrollmentEscrowB64u');
    expect(verifyEnrollmentRequest).not.toContain('enrollmentEscrowCiphertextB64u');
    expect(verifyEnrollmentRequest).toContain('recoveryWrappedEnrollmentEscrows');
    expect(finalizeRoute).not.toContain('enrollmentEscrowCiphertextB64u');
    expect(finalizeRoute).toContain('recoveryWrappedEnrollmentEscrows');
    expect(loginVerifyResponse).not.toContain('enrollmentEscrowCiphertextB64u');
    expect(loginVerifyResponse).toContain('enrollmentSealKeyVersion');
  });

  test('Email OTP enrollment persists device-local enc_s(S) before server finalization', () => {
    const workerSource = readFileSync(
      join(REPO_ROOT, 'packages/sdk-web/src/core/signingEngine/workerManager/workers/email-otp.worker.ts'),
      'utf8',
    );
    const enrollSlice = workerSource.slice(
      workerSource.indexOf('async function completeEmailOtpEnrollmentFromSecret32'),
      workerSource.indexOf('async function loginWithEmailOtpAndRecoverClientRootShare'),
    );

    const persistIndex = enrollSlice.indexOf('writeAndVerifyEmailOtpDeviceEnrollmentEscrowRecord');
    const finalizeIndex = enrollSlice.indexOf(
      "route: emailOtpRoutePath(args.routePlan, 'finalize')",
    );
    expect(persistIndex).toBeGreaterThanOrEqual(0);
    expect(finalizeIndex).toBeGreaterThanOrEqual(0);
    expect(persistIndex).toBeLessThan(finalizeIndex);
    expect(workerSource).toContain('persisted.encSB64u !== record.encSB64u');
    expect(workerSource).toContain(
      'persisted.enrollmentSealKeyVersion !== record.enrollmentSealKeyVersion',
    );
    expect(workerSource).toContain('persisted.signingRootId !== record.signingRootId');
    expect(workerSource).toContain('persisted.signingRootVersion !== record.signingRootVersion');
    expect(enrollSlice).toContain('Email OTP enrollment did not persist device-local enc_s(S)');
  });

  test('Email OTP recovery restore unwraps C_i and persists device-local enc_s(S)', () => {
    const workerSource = readFileSync(
      join(REPO_ROOT, 'packages/sdk-web/src/core/signingEngine/workerManager/workers/email-otp.worker.ts'),
      'utf8',
    );
    const restoreSlice = workerSource.slice(
      workerSource.indexOf('async function restoreEmailOtpDeviceEnrollmentEscrowFromRecoveryKey'),
      workerSource.indexOf('async function deriveEmailOtpEcdsaClientRootShare32InWorker'),
    );

    expect(restoreSlice).toContain("route: '/wallet/email-otp/recovery-wrapped-escrows'");
    expect(restoreSlice).toContain('unwrapEmailOtpDeviceEnrollmentEscrow');
    expect(restoreSlice).toContain('writeAndVerifyEmailOtpDeviceEnrollmentEscrowRecord');
    expect(restoreSlice).toContain("route: '/wallet/email-otp/recovery-key/consume'");
    expect(workerSource).toContain("route: '/wallet/email-otp/recovery-key/attempt-failed'");
    expect(restoreSlice).toContain('reportEmailOtpRecoveryKeyAttemptFailure');
    expect(restoreSlice).toContain('sawRecoveryKeyUnwrapFailure');
    expect(restoreSlice).toContain('recoveryConsumeGrant');
    expect(restoreSlice).toContain('Email OTP recovery did not persist device-local enc_s(S)');
    expect(restoreSlice).not.toContain('loginGrant');
  });

  test('Email OTP worker derives recovery key ids consistently for enrollment, recovery, and rotation', () => {
    const workerSource = readFileSync(
      join(REPO_ROOT, 'packages/sdk-web/src/core/signingEngine/workerManager/workers/email-otp.worker.ts'),
      'utf8',
    );
    const wrapSlice = workerSource.slice(
      workerSource.indexOf('async function createEmailOtpRecoveryWrappedEnrollmentEscrows'),
      workerSource.indexOf('async function parseEmailOtpRecoveryWrappedEnrollmentEscrowPayload'),
    );
    const parseSlice = workerSource.slice(
      workerSource.indexOf('async function parseEmailOtpRecoveryWrappedEnrollmentEscrowPayload'),
      workerSource.indexOf('async function reportEmailOtpRecoveryKeyAttemptFailure'),
    );
    const restoreSlice = workerSource.slice(
      workerSource.indexOf('async function restoreEmailOtpDeviceEnrollmentEscrowFromRecoveryKey'),
      workerSource.indexOf('async function rotateEmailOtpRecoveryCodesFromLocalDeviceEnrollment'),
    );
    const rotateSlice = workerSource.slice(
      workerSource.indexOf('async function rotateEmailOtpRecoveryCodesFromLocalDeviceEnrollment'),
      workerSource.indexOf('async function removeEmailOtpDeviceEnrollmentEscrowFromDevice'),
    );

    expect(wrapSlice).toContain('deriveEmailOtpRecoveryKeyId({');
    expect(wrapSlice).toContain('recoveryKey: recoveryKeys[index]');
    expect(parseSlice).toContain('deriveEmailOtpRecoveryKeyId({');
    expect(parseSlice).toContain('recoveryKey,');
    expect(restoreSlice).toContain('parseEmailOtpRecoveryWrappedEnrollmentEscrowPayload(');
    expect(restoreSlice).toContain('rawRecord,');
    expect(restoreSlice).toContain('recoveryKey,');
    expect(rotateSlice).toContain('createEmailOtpRecoveryWrappedEnrollmentEscrows({');
  });

  test('Email OTP worker zeroizes unwrapped enc_s(S) byte buffers', () => {
    const workerSource = readFileSync(
      join(REPO_ROOT, 'packages/sdk-web/src/core/signingEngine/workerManager/workers/email-otp.worker.ts'),
      'utf8',
    );
    const wrapSlice = workerSource.slice(
      workerSource.indexOf('async function createEmailOtpRecoveryWrappedEnrollmentEscrows'),
      workerSource.indexOf('function parseEmailOtpRecoveryWrappedEnrollmentEscrowPayload'),
    );
    const restoreSlice = workerSource.slice(
      workerSource.indexOf('async function restoreEmailOtpDeviceEnrollmentEscrowFromRecoveryKey'),
      workerSource.indexOf('async function deriveEmailOtpEcdsaClientRootShare32InWorker'),
    );

    expect(wrapSlice).toContain('const encS = base64UrlDecode(args.encSB64u)');
    expect(wrapSlice).toContain('zeroizeBytes(encS)');
    expect(restoreSlice).toContain('let encS: Uint8Array | null = null');
    expect(restoreSlice).toContain('zeroizeBytes(encS)');
  });

  test('logout lock path does not delete device-local Email OTP recovery material', () => {
    const loginSource = readFileSync(
      join(REPO_ROOT, 'packages/sdk-web/src/SeamsWeb/operations/auth/login.ts'),
      'utf8',
    );
    const lockSlice = loginSource.slice(
      loginSource.indexOf('export async function lock('),
      loginSource.indexOf('\n}', loginSource.indexOf('export async function lock(')) + 2,
    );
    const workerSource = readFileSync(
      join(REPO_ROOT, 'packages/sdk-web/src/core/signingEngine/workerManager/workers/email-otp.worker.ts'),
      'utf8',
    );

    expect(lockSlice).toContain('clearLastProfileSelection');
    expect(lockSlice).not.toContain('deleteEmailOtpDeviceEnrollmentEscrowRecord');
    expect(lockSlice).not.toContain('clearAllEmailOtpDeviceEnrollmentEscrowRecords');
    expect(lockSlice).not.toContain('emailOtpRecoveryCodeBackupRepository');
    expect(workerSource).toContain("case 'removeEmailOtpDeviceEnrollmentEscrowFromDevice'");
    expect(workerSource).toContain('deleteEmailOtpDeviceEnrollmentEscrowRecord');
  });
});
