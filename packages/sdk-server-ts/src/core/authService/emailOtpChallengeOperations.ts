import {
  EMAIL_OTP_CHANNEL,
  WALLET_EMAIL_OTP_ACTIONS,
  WALLET_EMAIL_OTP_EXPORT_OPERATION,
  WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
  WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
  WALLET_EMAIL_OTP_UNLOCK_OPERATION,
} from '@shared/utils/emailOtpDomain';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import {
  emailOtpRecoveryWrappedEnrollmentEscrowBoundaryFromRecord,
  type EmailOtpChannel,
  type EmailOtpGrantStore,
  type EmailOtpLoginChallengeOperation,
  type EmailOtpRecoveryWrappedEnrollmentEscrowStore,
} from '../EmailOtpStores';
import type { EmailOtpConfig } from './emailOtpConfig';
import {
  type CreateEmailOtpChallengeWithActionRequest,
  type CreateEmailOtpChallengeWithActionResult,
} from './emailOtpChallenges';
import {
  type EmailOtpRecoveryChallengeEscrow,
  type VerifiedEmailOtpChallengeCodeResult,
  redactEmailOtpRecoveryChallengeEscrow,
} from './emailOtpChallengeProof';
import type { VerifyEmailOtpChallengeCodeRequest } from './emailOtpChallengeVerification';
import type { EmailOtpEnrollmentReadResult } from './emailOtpEnrollment';
import { emailOtpRecoveryEscrowMatchesEnrollment } from './emailOtpRegistrationEnrollment';
import { randomBase64Url } from './bytes';

export type EmailOtpChallengeOperationsInput = {
  readonly createChallengeWithAction: (
    request: CreateEmailOtpChallengeWithActionRequest,
  ) => Promise<CreateEmailOtpChallengeWithActionResult>;
  readonly verifyChallengeCode: (
    request: VerifyEmailOtpChallengeCodeRequest,
  ) => Promise<VerifiedEmailOtpChallengeCodeResult>;
  readonly readActiveEnrollment: (request: {
    readonly walletId?: unknown;
    readonly orgId: unknown;
    readonly providerUserId?: unknown;
  }) => Promise<EmailOtpEnrollmentReadResult>;
  readonly recoveryWrappedEnrollmentEscrowStore: EmailOtpRecoveryWrappedEnrollmentEscrowStore;
  readonly grantStore: EmailOtpGrantStore;
  readonly resolveConfig: () => EmailOtpConfig;
};

export type CreateEmailOtpLoginChallengeRequest = {
  userId?: unknown;
  walletId?: unknown;
  orgId?: unknown;
  email?: unknown;
  otpChannel?: unknown;
  sessionHash?: unknown;
  appSessionVersion?: unknown;
  clientIp?: unknown;
  operation?: unknown;
  reuseActiveChallenge?: unknown;
};

export type CreateEmailOtpLoginChallengeResult =
  | {
      ok: true;
      challenge: {
        challengeId: string;
        issuedAtMs: number;
        expiresAtMs: number;
        userId: string;
        walletId: string;
        orgId: string;
        otpChannel: EmailOtpChannel;
        sessionHash: string;
        appSessionVersion: string;
        action: typeof WALLET_EMAIL_OTP_ACTIONS.login;
        operation: EmailOtpLoginChallengeOperation;
      };
      delivery: {
        status: 'sent' | 'reused';
        mode: 'email_provider' | 'log' | 'memory';
        emailHint: string;
      };
    }
  | { ok: false; code: string; message: string };

export type CreateEmailOtpEnrollmentChallengeRequest = {
  userId?: unknown;
  walletId?: unknown;
  orgId?: unknown;
  email?: unknown;
  otpChannel?: unknown;
  sessionHash?: unknown;
  appSessionVersion?: unknown;
  clientIp?: unknown;
  operation?: unknown;
};

export type CreateEmailOtpEnrollmentChallengeResult =
  | {
      ok: true;
      challenge: {
        challengeId: string;
        issuedAtMs: number;
        expiresAtMs: number;
        userId: string;
        walletId: string;
        orgId: string;
        otpChannel: EmailOtpChannel;
        sessionHash: string;
        appSessionVersion: string;
        action: typeof WALLET_EMAIL_OTP_ACTIONS.registration;
        operation: typeof WALLET_EMAIL_OTP_REGISTRATION_OPERATION;
      };
      delivery: {
        mode: 'email_provider' | 'log' | 'memory';
        emailHint: string;
      };
    }
  | { ok: false; code: string; message: string };

export type CreateEmailOtpDeviceRecoveryChallengeRequest = {
  userId?: unknown;
  walletId?: unknown;
  orgId?: unknown;
  email?: unknown;
  otpChannel?: unknown;
  sessionHash?: unknown;
  appSessionVersion?: unknown;
  clientIp?: unknown;
};

export type CreateEmailOtpDeviceRecoveryChallengeResult =
  | {
      ok: true;
      challenge: {
        challengeId: string;
        issuedAtMs: number;
        expiresAtMs: number;
        userId: string;
        walletId: string;
        orgId: string;
        otpChannel: EmailOtpChannel;
        sessionHash: string;
        appSessionVersion: string;
        action: typeof WALLET_EMAIL_OTP_ACTIONS.deviceRecovery;
        operation: typeof WALLET_EMAIL_OTP_UNLOCK_OPERATION;
      };
      delivery: {
        mode: 'email_provider' | 'log' | 'memory';
        emailHint: string;
      };
    }
  | { ok: false; code: string; message: string };

export type VerifyEmailOtpLoginChallengeRequest = {
  userId?: unknown;
  walletId?: unknown;
  orgId?: unknown;
  challengeId?: unknown;
  otpCode?: unknown;
  otpChannel?: unknown;
  sessionHash?: unknown;
  appSessionVersion?: unknown;
  clientIp?: unknown;
  operation?: unknown;
};

export type VerifyEmailOtpLoginChallengeResult =
  | {
      ok: true;
      challengeId: string;
      loginGrant: string;
      grantExpiresAtMs: number;
      otpChannel: EmailOtpChannel;
    }
  | {
      ok: false;
      code: string;
      message: string;
      attemptsRemaining?: number;
      lockedUntilMs?: number;
    };

export type VerifyEmailOtpDeviceRecoveryChallengeRequest = {
  userId?: unknown;
  walletId?: unknown;
  orgId?: unknown;
  challengeId?: unknown;
  otpCode?: unknown;
  otpChannel?: unknown;
  sessionHash?: unknown;
  appSessionVersion?: unknown;
  clientIp?: unknown;
};

export type VerifyEmailOtpDeviceRecoveryChallengeResult =
  | {
      ok: true;
      challengeId: string;
      otpChannel: EmailOtpChannel;
      recoveryConsumeGrant: string;
      recoveryConsumeGrantExpiresAtMs: number;
      recoveryWrappedEnrollmentEscrows: EmailOtpRecoveryChallengeEscrow[];
      enrollment: {
        walletId: string;
        providerUserId: string;
        orgId: string;
        enrollmentId: string;
        enrollmentVersion: string;
        enrollmentSealKeyVersion: string;
        signingRootId: string;
        signingRootVersion: string;
        recoveryWrappedEnrollmentEscrowCount: number;
      };
    }
  | {
      ok: false;
      code: string;
      message: string;
      attemptsRemaining?: number;
      lockedUntilMs?: number;
    };

function loginOperationFromRequest(
  request: VerifyEmailOtpLoginChallengeRequest,
): EmailOtpLoginChallengeOperation {
  const operationRaw = toOptionalTrimmedString(request.operation);
  return operationRaw === WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION ||
    operationRaw === WALLET_EMAIL_OTP_EXPORT_OPERATION
    ? operationRaw
    : WALLET_EMAIL_OTP_UNLOCK_OPERATION;
}

function createGrantToken(): string | null {
  return typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function'
    ? null
    : randomBase64Url(24);
}

function unsupportedCryptoResult(): { ok: false; code: 'unsupported'; message: string } {
  return {
    ok: false,
    code: 'unsupported',
    message: 'crypto.getRandomValues is unavailable in this runtime',
  };
}

export async function createEmailOtpChallenge(
  input: EmailOtpChallengeOperationsInput,
  request: CreateEmailOtpLoginChallengeRequest,
): Promise<CreateEmailOtpLoginChallengeResult> {
  const result = await input.createChallengeWithAction({
    challengeSubjectId: request.userId,
    walletId: request.walletId,
    orgId: request.orgId,
    email: request.email,
    otpChannel: request.otpChannel,
    sessionHash: request.sessionHash,
    appSessionVersion: request.appSessionVersion,
    clientIp: request.clientIp,
    operation: request.operation,
    reuseActiveChallenge: request.reuseActiveChallenge,
    action: WALLET_EMAIL_OTP_ACTIONS.login,
  });
  if (!result.ok) return result;
  const operation =
    result.challenge.operation === WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION ||
    result.challenge.operation === WALLET_EMAIL_OTP_EXPORT_OPERATION
      ? result.challenge.operation
      : WALLET_EMAIL_OTP_UNLOCK_OPERATION;
  return {
    ok: true,
    challenge: {
      challengeId: result.challenge.challengeId,
      issuedAtMs: result.challenge.issuedAtMs,
      expiresAtMs: result.challenge.expiresAtMs,
      userId: result.challenge.challengeSubjectId,
      walletId: result.challenge.walletId,
      orgId: result.challenge.orgId,
      otpChannel: result.challenge.otpChannel,
      sessionHash: result.challenge.sessionHash,
      appSessionVersion: result.challenge.appSessionVersion,
      action: WALLET_EMAIL_OTP_ACTIONS.login,
      operation,
    },
    delivery: result.delivery,
  };
}

export async function createEmailOtpEnrollmentChallenge(
  input: EmailOtpChallengeOperationsInput,
  request: CreateEmailOtpEnrollmentChallengeRequest,
): Promise<CreateEmailOtpEnrollmentChallengeResult> {
  const result = await input.createChallengeWithAction({
    challengeSubjectId: request.userId,
    walletId: request.walletId,
    orgId: request.orgId,
    email: request.email,
    otpChannel: request.otpChannel,
    sessionHash: request.sessionHash,
    appSessionVersion: request.appSessionVersion,
    clientIp: request.clientIp,
    operation: request.operation,
    action: WALLET_EMAIL_OTP_ACTIONS.registration,
  });
  if (!result.ok) return result;
  return {
    ok: true,
    challenge: {
      challengeId: result.challenge.challengeId,
      issuedAtMs: result.challenge.issuedAtMs,
      expiresAtMs: result.challenge.expiresAtMs,
      userId: result.challenge.challengeSubjectId,
      walletId: result.challenge.walletId,
      orgId: result.challenge.orgId,
      otpChannel: result.challenge.otpChannel,
      sessionHash: result.challenge.sessionHash,
      appSessionVersion: result.challenge.appSessionVersion,
      action: WALLET_EMAIL_OTP_ACTIONS.registration,
      operation: WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
    },
    delivery: result.delivery,
  };
}

export async function createEmailOtpDeviceRecoveryChallenge(
  input: EmailOtpChallengeOperationsInput,
  request: CreateEmailOtpDeviceRecoveryChallengeRequest,
): Promise<CreateEmailOtpDeviceRecoveryChallengeResult> {
  const result = await input.createChallengeWithAction({
    challengeSubjectId: request.userId,
    walletId: request.walletId,
    orgId: request.orgId,
    email: request.email,
    otpChannel: request.otpChannel,
    sessionHash: request.sessionHash,
    appSessionVersion: request.appSessionVersion,
    clientIp: request.clientIp,
    operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
    action: WALLET_EMAIL_OTP_ACTIONS.deviceRecovery,
  });
  if (!result.ok) return result;
  return {
    ok: true,
    challenge: {
      challengeId: result.challenge.challengeId,
      issuedAtMs: result.challenge.issuedAtMs,
      expiresAtMs: result.challenge.expiresAtMs,
      userId: result.challenge.challengeSubjectId,
      walletId: result.challenge.walletId,
      orgId: result.challenge.orgId,
      otpChannel: result.challenge.otpChannel,
      sessionHash: result.challenge.sessionHash,
      appSessionVersion: result.challenge.appSessionVersion,
      action: WALLET_EMAIL_OTP_ACTIONS.deviceRecovery,
      operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
    },
    delivery: result.delivery,
  };
}

export async function verifyEmailOtpChallenge(
  input: EmailOtpChallengeOperationsInput,
  request: VerifyEmailOtpLoginChallengeRequest,
): Promise<VerifyEmailOtpLoginChallengeResult> {
  const expectedOperation = loginOperationFromRequest(request);
  const verified = await input.verifyChallengeCode({
    challengeSubjectId: request.userId,
    walletId: request.walletId,
    orgId: request.orgId,
    challengeId: request.challengeId,
    otpCode: request.otpCode,
    otpChannel: request.otpChannel,
    sessionHash: request.sessionHash,
    appSessionVersion: request.appSessionVersion,
    clientIp: request.clientIp,
    expectedAction: WALLET_EMAIL_OTP_ACTIONS.login,
    expectedOperation,
  });
  if (!verified.ok) return verified;
  const grantToken = createGrantToken();
  if (!grantToken) return unsupportedCryptoResult();
  const otpConfig = input.resolveConfig();
  const issuedAtMs = Date.now();
  const grantExpiresAtMs = issuedAtMs + otpConfig.grantTtlMs;
  await input.grantStore.put({
    version: 'email_otp_grant_v1',
    grantToken,
    userId: verified.challengeSubjectId,
    walletId: verified.walletId,
    orgId: verified.orgId,
    challengeId: verified.challengeId,
    otpChannel: verified.otpChannel,
    sessionHash: String(request.sessionHash || '').trim(),
    appSessionVersion: String(request.appSessionVersion || '').trim(),
    action: WALLET_EMAIL_OTP_ACTIONS.unseal,
    issuedAtMs,
    expiresAtMs: grantExpiresAtMs,
  });
  return {
    ok: true,
    challengeId: verified.challengeId,
    loginGrant: grantToken,
    grantExpiresAtMs,
    otpChannel: verified.otpChannel,
  };
}

export async function verifyEmailOtpDeviceRecoveryChallenge(
  input: EmailOtpChallengeOperationsInput,
  request: VerifyEmailOtpDeviceRecoveryChallengeRequest,
): Promise<VerifyEmailOtpDeviceRecoveryChallengeResult> {
  const verified = await input.verifyChallengeCode({
    challengeSubjectId: request.userId,
    walletId: request.walletId,
    orgId: request.orgId,
    challengeId: request.challengeId,
    otpCode: request.otpCode,
    otpChannel: request.otpChannel,
    sessionHash: request.sessionHash,
    appSessionVersion: request.appSessionVersion,
    clientIp: request.clientIp,
    expectedAction: WALLET_EMAIL_OTP_ACTIONS.deviceRecovery,
    expectedOperation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
  });
  if (!verified.ok) return verified;
  const enrollment = await input.readActiveEnrollment({
    walletId: verified.walletId,
    orgId: verified.orgId,
    providerUserId: verified.challengeSubjectId,
  });
  if (!enrollment.ok) return enrollment;
  const recoveryWrappedEnrollmentEscrows =
    await input.recoveryWrappedEnrollmentEscrowStore.listActiveByWallet(verified.walletId);
  const scopedRecoveryWrappedEnrollmentEscrows = recoveryWrappedEnrollmentEscrows.filter(
    (record) =>
      emailOtpRecoveryEscrowMatchesEnrollment(
        emailOtpRecoveryWrappedEnrollmentEscrowBoundaryFromRecord(record),
        enrollment.enrollment,
      ),
  );
  if (scopedRecoveryWrappedEnrollmentEscrows.length <= 0) {
    return {
      ok: false,
      code: 'recovery_wrapped_escrows_missing',
      message: 'No active Email OTP recovery-wrapped enrollment escrows are available',
    };
  }
  const recoveryConsumeGrant = createGrantToken();
  if (!recoveryConsumeGrant) return unsupportedCryptoResult();
  const otpConfig = input.resolveConfig();
  const issuedAtMs = Date.now();
  const recoveryConsumeGrantExpiresAtMs = issuedAtMs + otpConfig.grantTtlMs;
  await input.grantStore.put({
    version: 'email_otp_grant_v1',
    grantToken: recoveryConsumeGrant,
    userId: verified.challengeSubjectId,
    walletId: verified.walletId,
    orgId: verified.orgId,
    challengeId: verified.challengeId,
    otpChannel: verified.otpChannel,
    sessionHash: String(request.sessionHash || '').trim(),
    appSessionVersion: String(request.appSessionVersion || '').trim(),
    action: WALLET_EMAIL_OTP_ACTIONS.deviceRecovery,
    issuedAtMs,
    expiresAtMs: recoveryConsumeGrantExpiresAtMs,
  });
  return {
    ok: true,
    challengeId: verified.challengeId,
    otpChannel: verified.otpChannel,
    recoveryConsumeGrant,
    recoveryConsumeGrantExpiresAtMs,
    recoveryWrappedEnrollmentEscrows: scopedRecoveryWrappedEnrollmentEscrows.map(
      redactEmailOtpRecoveryChallengeEscrow,
    ),
    enrollment: {
      walletId: enrollment.enrollment.walletId,
      providerUserId: enrollment.enrollment.providerUserId,
      orgId: enrollment.enrollment.orgId,
      enrollmentId: enrollment.enrollment.enrollmentId,
      enrollmentVersion: enrollment.enrollment.enrollmentVersion,
      enrollmentSealKeyVersion: enrollment.enrollment.enrollmentSealKeyVersion,
      signingRootId: enrollment.enrollment.signingRootId,
      signingRootVersion: enrollment.enrollment.signingRootVersion,
      recoveryWrappedEnrollmentEscrowCount:
        enrollment.enrollment.recoveryWrappedEnrollmentEscrowCount,
    },
  };
}
