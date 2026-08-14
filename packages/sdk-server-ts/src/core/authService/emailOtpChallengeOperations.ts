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
  type EmailOtpChannel,
  type EmailOtpGrantStore,
  type EmailOtpLoginChallengeOperation,
} from '../EmailOtpStores';
import type { EmailOtpConfig } from './emailOtpConfig';
import {
  type CreateEmailOtpChallengeWithActionRequest,
  type CreateEmailOtpChallengeWithActionResult,
} from './emailOtpChallenges';
import type { VerifiedEmailOtpChallengeCodeResult } from './emailOtpChallengeProof';
import type { VerifyEmailOtpChallengeCodeRequest } from './emailOtpChallengeVerification';
import { randomBase64Url } from './bytes';

export type EmailOtpChallengeOperationsInput = {
  readonly createChallengeWithAction: (
    request: CreateEmailOtpChallengeWithActionRequest,
  ) => Promise<CreateEmailOtpChallengeWithActionResult>;
  readonly verifyChallengeCode: (
    request: VerifyEmailOtpChallengeCodeRequest,
  ) => Promise<VerifiedEmailOtpChallengeCodeResult>;
  readonly grantStore: EmailOtpGrantStore;
  readonly resolveConfig: () => EmailOtpConfig;
};

export type CreateEmailOtpLoginChallengeRequest = {
  userId?: unknown;
  walletId?: unknown;
  orgId?: unknown;
  email?: unknown;
  otpChannel?: unknown;
  ownerProofBindingDigest?: unknown;
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
        ownerProofBindingDigest: string;
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
  ownerProofBindingDigest?: unknown;
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
        ownerProofBindingDigest: string;
        action: typeof WALLET_EMAIL_OTP_ACTIONS.registration;
        operation: typeof WALLET_EMAIL_OTP_REGISTRATION_OPERATION;
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
  ownerProofBindingDigest?: unknown;
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
    ownerProofBindingDigest: request.ownerProofBindingDigest,
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
      ownerProofBindingDigest: result.challenge.ownerProofBindingDigest,
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
    ownerProofBindingDigest: request.ownerProofBindingDigest,
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
      ownerProofBindingDigest: result.challenge.ownerProofBindingDigest,
      action: WALLET_EMAIL_OTP_ACTIONS.registration,
      operation: WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
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
    ownerProofBindingDigest: request.ownerProofBindingDigest,
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
    ownerProofBindingDigest: String(request.ownerProofBindingDigest || '').trim(),
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
