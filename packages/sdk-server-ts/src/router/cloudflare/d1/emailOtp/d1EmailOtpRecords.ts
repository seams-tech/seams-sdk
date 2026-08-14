import { toOptionalTrimmedString } from '@shared/utils/validation';
import { base64UrlDecode } from '@shared/utils/encoders';
import {
  EMAIL_OTP_CHANNEL,
  WALLET_EMAIL_OTP_ACTIONS,
  WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
  WALLET_EMAIL_OTP_UNLOCK_OPERATION,
  isWalletEmailOtpLoginOperation,
} from '@shared/utils/emailOtpDomain';
import type {
  EmailOtpAuthStateRecord,
  EmailOtpChallengeOperation,
  EmailOtpChallengeRecord,
  EmailOtpGrantAction,
  EmailOtpGrantRecord,
  EmailOtpLoginChallengeOperation,
  EmailOtpUnlockChallengeRecord,
  EmailOtpWalletEnrollmentRecord,
} from '../../../../core/EmailOtpStores';
import {
  isB64uString,
  nonNegativeSafeInteger,
  parseJsonObject,
  positiveSafeInteger,
} from '../auth/d1RouterApiAuthBoundary';

export type EmailOtpChallengeIssueAction =
  | typeof WALLET_EMAIL_OTP_ACTIONS.login
  | typeof WALLET_EMAIL_OTP_ACTIONS.registration
  | typeof WALLET_EMAIL_OTP_ACTIONS.recoveryBootstrap;

export type EmailOtpRateLimitScope = 'challenge' | 'verify' | 'grant' | 'googleRegistrationAttempt';

export type EmailOtpAuthStatePatch = {
  readonly otpFailureCount?: number | null;
  readonly lastOtpFailureAtMs?: number | null;
  readonly otpLockedUntilMs?: number | null;
  readonly lastEmailOtpLoginAtMs?: number | null;
  readonly lastStrongAuthAtMs?: number | null;
};

export type EmailOtpPublicKey33Validator = (input: Uint8Array) => Promise<unknown>;

export type EmailOtpEnrollmentMaterialBoundaryInput = {
  readonly enrollmentSealKeyVersion?: unknown;
  readonly clientUnlockPublicKeyB64u?: unknown;
  readonly unlockKeyVersion?: unknown;
  readonly serverSealedFactorCiphertextB64u?: unknown;
};

export type EmailOtpEnrollmentMaterialValidationResult =
  | {
      readonly ok: true;
      readonly enrollmentSealKeyVersion: string;
      readonly clientUnlockPublicKeyB64u: string;
      readonly unlockKeyVersion: string;
      readonly serverSealedFactorCiphertextB64u: string;
    }
  | {
      readonly ok: false;
      readonly code: string;
      readonly message: string;
    };

export type D1EmailOtpEnrollmentRow = {
  readonly record_json?: unknown;
  readonly updated_at_ms?: unknown;
};

export type D1EmailOtpAuthStateRow = {
  readonly record_json?: unknown;
  readonly updated_at_ms?: unknown;
};

export type D1EmailOtpChallengeRow = {
  readonly challenge_id?: unknown;
  readonly record_json?: unknown;
  readonly expires_at_ms?: unknown;
};

export type EmailOtpRegistrationVerificationReceiptV1 = {
  readonly version: 'email_otp_registration_verification_receipt_v1';
  readonly requestFingerprint: string;
  readonly verified: {
    readonly challengeId: string;
    readonly challengeSubjectId: string;
    readonly walletId: string;
    readonly orgId: string;
    readonly email: string;
    readonly otpChannel: typeof EMAIL_OTP_CHANNEL;
  };
  readonly verifiedAtMs: number;
  readonly expiresAtMs: number;
};

export type D1EmailOtpGrantRow = {
  readonly record_json?: unknown;
  readonly expires_at_ms?: unknown;
};

export type D1EmailOtpUnlockChallengeRow = {
  readonly record_json?: unknown;
  readonly expires_at_ms?: unknown;
};

export type D1EmailOtpRateLimitRow = {
  readonly consumed_count?: unknown;
  readonly reset_at_ms?: unknown;
};

export function maskEmail(email: string): string {
  const trimmed = email.trim().toLowerCase();
  const atIndex = trimmed.indexOf('@');
  if (atIndex <= 0 || atIndex === trimmed.length - 1) return 'hidden';
  const local = trimmed.slice(0, atIndex);
  const domain = trimmed.slice(atIndex + 1);
  const localMask = local.length <= 2 ? `${local[0] || '*'}*` : `${local[0]}***${local.slice(-1)}`;
  const domainParts = domain.split('.');
  const domainName = domainParts[0] || '';
  const domainMask =
    domainName.length <= 2
      ? `${domainName[0] || '*'}*`
      : `${domainName[0]}***${domainName.slice(-1)}`;
  return `${localMask}@${[domainMask, ...domainParts.slice(1)].join('.')}`;
}

export function generateNumericOtp(length: number): string {
  if (typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function') {
    throw new Error('crypto.getRandomValues is unavailable in this runtime');
  }
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  let code = '';
  for (const byte of bytes) code += String(byte % 10);
  return code;
}

export function clampedEmailOtpUnlockTtlMs(input: unknown): number {
  const value = typeof input === 'number' ? input : Number(input);
  if (!Number.isFinite(value) || value <= 0) return 5 * 60_000;
  return Math.min(Math.max(Math.floor(value), 10_000), 10 * 60_000);
}

export function decodeFixedBase64Url(input: string, byteLength: number): Uint8Array | null {
  try {
    const decoded = base64UrlDecode(input);
    return decoded.length === byteLength ? decoded : null;
  } catch {
    return null;
  }
}

export function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= (left[index] || 0) ^ (right[index] || 0);
  }
  return difference === 0;
}

export function emailOtpRateLimitKeys(input: {
  readonly scope: EmailOtpRateLimitScope;
  readonly action?: string;
  readonly policy: {
    readonly limit: number;
    readonly windowMs: number;
  };
  readonly userId?: string;
  readonly walletId?: string;
  readonly providerSubject?: string;
  readonly orgId?: string;
  readonly clientIp?: string;
}): readonly string[] {
  const keySuffix = [
    `scope=${input.scope}`,
    `action=${input.action || 'default'}`,
    `limit=${input.policy.limit}`,
    `windowMs=${input.policy.windowMs}`,
  ].join(':');
  return [
    input.clientIp ? `${keySuffix}:ip:${input.clientIp}` : '',
    input.userId ? `${keySuffix}:user:${input.userId}` : '',
    input.walletId ? `${keySuffix}:wallet:${input.walletId}` : '',
    input.providerSubject ? `${keySuffix}:provider:${input.providerSubject}` : '',
    input.orgId ? `${keySuffix}:org:${input.orgId}` : '',
  ].filter(Boolean);
}

export function emailOtpRateLimitExceeded(row: D1EmailOtpRateLimitRow | null): {
  readonly ok: false;
  readonly code: 'rate_limited';
  readonly message: string;
  readonly retryAfterMs?: number;
  readonly resetAtMs?: number;
} {
  const resetAtMs = positiveSafeInteger(row?.reset_at_ms);
  const retryAfterMs = resetAtMs ? Math.max(0, resetAtMs - Date.now()) : undefined;
  return {
    ok: false,
    code: 'rate_limited',
    message: 'Email OTP rate limit exceeded',
    ...(retryAfterMs !== undefined ? { retryAfterMs } : {}),
    ...(resetAtMs ? { resetAtMs } : {}),
  };
}

export function parseEmailOtpWalletEnrollmentRecord(
  input: unknown,
): EmailOtpWalletEnrollmentRecord | null {
  const record = parseJsonObject(input);
  if (!record || hasRecordField(record, 'enrollmentEscrowCiphertextB64u')) return null;
  const version = toOptionalTrimmedString(record.version);
  const walletId = toOptionalTrimmedString(record.walletId);
  const providerUserId = toOptionalTrimmedString(record.providerUserId);
  const orgId = toOptionalTrimmedString(record.orgId);
  const verifiedEmail = toOptionalTrimmedString(record.verifiedEmail)?.toLowerCase() || '';
  const enrollmentId = toOptionalTrimmedString(record.enrollmentId);
  const enrollmentVersion = toOptionalTrimmedString(record.enrollmentVersion);
  const enrollmentSealKeyVersion = toOptionalTrimmedString(record.enrollmentSealKeyVersion);
  const clientUnlockPublicKeyB64u = toOptionalTrimmedString(record.clientUnlockPublicKeyB64u);
  const unlockKeyVersion = toOptionalTrimmedString(record.unlockKeyVersion);
  const serverSealedFactorCiphertextB64u = toOptionalTrimmedString(
    record.serverSealedFactorCiphertextB64u,
  );
  const createdAtMs = positiveSafeInteger(record.createdAtMs);
  const updatedAtMs = positiveSafeInteger(record.updatedAtMs);
  if (
    version !== 'email_otp_wallet_enrollment_v1' ||
    !walletId ||
    !providerUserId ||
    !orgId ||
    !verifiedEmail ||
    !enrollmentId ||
    !enrollmentVersion ||
    !enrollmentSealKeyVersion ||
    !clientUnlockPublicKeyB64u ||
    !unlockKeyVersion ||
    !serverSealedFactorCiphertextB64u ||
    !createdAtMs ||
    !updatedAtMs ||
    updatedAtMs < createdAtMs
  ) {
    return null;
  }
  return {
    version: 'email_otp_wallet_enrollment_v1',
    walletId,
    providerUserId,
    orgId,
    verifiedEmail,
    enrollmentId,
    enrollmentVersion,
    enrollmentSealKeyVersion,
    clientUnlockPublicKeyB64u,
    unlockKeyVersion,
    serverSealedFactorCiphertextB64u,
    createdAtMs,
    updatedAtMs,
  };
}

export function parseEmailOtpWalletEnrollmentRow(
  row: D1EmailOtpEnrollmentRow | null,
): EmailOtpWalletEnrollmentRecord | null {
  const record = parseEmailOtpWalletEnrollmentRecord(row?.record_json);
  const updatedAtMs = positiveSafeInteger(row?.updated_at_ms);
  if (!record || !updatedAtMs || record.updatedAtMs !== updatedAtMs) return null;
  return record;
}

export function parseEmailOtpAuthStateRecord(input: unknown): EmailOtpAuthStateRecord | null {
  const record = parseJsonObject(input);
  if (!record) return null;
  const version = toOptionalTrimmedString(record.version);
  const walletId = toOptionalTrimmedString(record.walletId);
  const providerUserId = toOptionalTrimmedString(record.providerUserId);
  const orgId = toOptionalTrimmedString(record.orgId);
  const createdAtMs = positiveSafeInteger(record.createdAtMs);
  const updatedAtMs = positiveSafeInteger(record.updatedAtMs);
  const otpFailureCount = optionalNonNegativeSafeIntegerField(record, 'otpFailureCount');
  const lastOtpFailureAtMs = optionalPositiveSafeIntegerField(record, 'lastOtpFailureAtMs');
  const otpLockedUntilMs = optionalPositiveSafeIntegerField(record, 'otpLockedUntilMs');
  const lastEmailOtpLoginAtMs = optionalPositiveSafeIntegerField(record, 'lastEmailOtpLoginAtMs');
  const lastStrongAuthAtMs = optionalPositiveSafeIntegerField(record, 'lastStrongAuthAtMs');
  if (
    version !== 'email_otp_auth_state_v1' ||
    !walletId ||
    !providerUserId ||
    !orgId ||
    !createdAtMs ||
    !updatedAtMs ||
    otpFailureCount === null ||
    lastOtpFailureAtMs === null ||
    otpLockedUntilMs === null ||
    lastEmailOtpLoginAtMs === null ||
    lastStrongAuthAtMs === null ||
    updatedAtMs < createdAtMs
  ) {
    return null;
  }
  return {
    version: 'email_otp_auth_state_v1',
    walletId,
    providerUserId,
    orgId,
    createdAtMs,
    updatedAtMs,
    ...(otpFailureCount != null ? { otpFailureCount } : {}),
    ...(lastOtpFailureAtMs != null ? { lastOtpFailureAtMs } : {}),
    ...(otpLockedUntilMs != null ? { otpLockedUntilMs } : {}),
    ...(lastEmailOtpLoginAtMs != null ? { lastEmailOtpLoginAtMs } : {}),
    ...(lastStrongAuthAtMs != null ? { lastStrongAuthAtMs } : {}),
  };
}

export function parseEmailOtpAuthStateRow(
  row: D1EmailOtpAuthStateRow | null,
): EmailOtpAuthStateRecord | null {
  const record = parseEmailOtpAuthStateRecord(row?.record_json);
  const updatedAtMs = positiveSafeInteger(row?.updated_at_ms);
  if (!record || !updatedAtMs || record.updatedAtMs !== updatedAtMs) return null;
  return record;
}

export function parseEmailOtpChallengeOperation(input: unknown): EmailOtpChallengeOperation | null {
  const operation = toOptionalTrimmedString(input);
  if (!operation) return null;
  if (isWalletEmailOtpLoginOperation(operation)) return operation;
  if (operation === WALLET_EMAIL_OTP_REGISTRATION_OPERATION) return operation;
  return null;
}

export function parseEmailOtpLoginOperation(input: unknown): EmailOtpLoginChallengeOperation {
  const operation = toOptionalTrimmedString(input);
  if (operation && isWalletEmailOtpLoginOperation(operation)) return operation;
  return WALLET_EMAIL_OTP_UNLOCK_OPERATION;
}

export function parseEmailOtpChallengeRecord(input: unknown): EmailOtpChallengeRecord | null {
  const record = parseJsonObject(input);
  if (!record) return null;
  const version = toOptionalTrimmedString(record.version);
  const challengeId = toOptionalTrimmedString(record.challengeId);
  const challengeSubjectId = toOptionalTrimmedString(record.challengeSubjectId);
  const walletId = toOptionalTrimmedString(record.walletId);
  const orgId = toOptionalTrimmedString(record.orgId);
  const otpChannel = toOptionalTrimmedString(record.otpChannel);
  const email = toOptionalTrimmedString(record.email)?.toLowerCase() || '';
  const otpCode = toOptionalTrimmedString(record.otpCode);
  const ownerProofBindingDigest = toOptionalTrimmedString(record.ownerProofBindingDigest);
  const action = parseEmailOtpChallengeAction(record.action);
  const operation = parseEmailOtpChallengeOperation(record.operation);
  const createdAtMs = positiveSafeInteger(record.createdAtMs);
  const expiresAtMs = positiveSafeInteger(record.expiresAtMs);
  const attemptCount = nonNegativeSafeInteger(record.attemptCount);
  const maxAttempts = positiveSafeInteger(record.maxAttempts);
  if (
    version !== 'email_otp_challenge_v1' ||
    !challengeId ||
    !challengeSubjectId ||
    !walletId ||
    !email ||
    !otpCode ||
    !ownerProofBindingDigest ||
    !action ||
    !operation ||
    !emailOtpChallengePurposeIsValid({ action, operation }) ||
    otpChannel !== EMAIL_OTP_CHANNEL ||
    !createdAtMs ||
    !expiresAtMs ||
    attemptCount === null ||
    !maxAttempts ||
    expiresAtMs <= createdAtMs
  ) {
    return null;
  }
  return {
    version: 'email_otp_challenge_v1',
    challengeId,
    challengeSubjectId,
    walletId,
    ...(orgId ? { orgId } : {}),
    otpChannel: EMAIL_OTP_CHANNEL,
    email,
    otpCode,
    ownerProofBindingDigest,
    action,
    operation,
    createdAtMs,
    expiresAtMs,
    attemptCount,
    maxAttempts,
  };
}

export function parseEmailOtpChallengeRow(
  row: D1EmailOtpChallengeRow | null,
): EmailOtpChallengeRecord | null {
  const record = parseEmailOtpChallengeRecord(row?.record_json);
  const expiresAtMs = positiveSafeInteger(row?.expires_at_ms);
  if (!record || !expiresAtMs || record.expiresAtMs !== expiresAtMs) return null;
  return record;
}

export function parseEmailOtpRegistrationVerificationReceiptV1(
  input: unknown,
): EmailOtpRegistrationVerificationReceiptV1 | null {
  const record = parseJsonObject(input);
  if (
    !record ||
    !hasExactRecordFields(record, [
      'version',
      'requestFingerprint',
      'verified',
      'verifiedAtMs',
      'expiresAtMs',
    ]) ||
    record.version !== 'email_otp_registration_verification_receipt_v1'
  ) {
    return null;
  }
  const requestFingerprint = toOptionalTrimmedString(record.requestFingerprint);
  const verified = parseJsonObject(record.verified);
  const verifiedAtMs = positiveSafeInteger(record.verifiedAtMs);
  const expiresAtMs = positiveSafeInteger(record.expiresAtMs);
  if (
    !requestFingerprint ||
    !isB64uString(requestFingerprint) ||
    !verified ||
    !hasExactRecordFields(verified, [
      'challengeId',
      'challengeSubjectId',
      'walletId',
      'orgId',
      'email',
      'otpChannel',
    ]) ||
    !verifiedAtMs ||
    !expiresAtMs ||
    expiresAtMs <= verifiedAtMs
  ) {
    return null;
  }
  const challengeId = toOptionalTrimmedString(verified.challengeId);
  const challengeSubjectId = toOptionalTrimmedString(verified.challengeSubjectId);
  const walletId = toOptionalTrimmedString(verified.walletId);
  const orgId = toOptionalTrimmedString(verified.orgId);
  const email = toOptionalTrimmedString(verified.email)?.toLowerCase() || '';
  if (
    !challengeId ||
    !challengeSubjectId ||
    !walletId ||
    !orgId ||
    !email ||
    verified.otpChannel !== EMAIL_OTP_CHANNEL
  ) {
    return null;
  }
  return {
    version: 'email_otp_registration_verification_receipt_v1',
    requestFingerprint,
    verified: {
      challengeId,
      challengeSubjectId,
      walletId,
      orgId,
      email,
      otpChannel: EMAIL_OTP_CHANNEL,
    },
    verifiedAtMs,
    expiresAtMs,
  };
}

export function parseEmailOtpUnlockChallengeRecord(
  input: unknown,
): EmailOtpUnlockChallengeRecord | null {
  const record = parseJsonObject(input);
  if (!record) return null;
  const version = toOptionalTrimmedString(record.version);
  const challengeId = toOptionalTrimmedString(record.challengeId);
  const walletId = toOptionalTrimmedString(record.walletId);
  const userId = toOptionalTrimmedString(record.userId);
  const orgId = toOptionalTrimmedString(record.orgId);
  const challengeB64u = toOptionalTrimmedString(record.challengeB64u);
  const createdAtMs = positiveSafeInteger(record.createdAtMs);
  const expiresAtMs = positiveSafeInteger(record.expiresAtMs);
  if (
    version !== 'email_otp_unlock_challenge_v1' ||
    !challengeId ||
    !walletId ||
    !userId ||
    !challengeB64u ||
    !createdAtMs ||
    !expiresAtMs ||
    expiresAtMs <= createdAtMs
  ) {
    return null;
  }
  return {
    version: 'email_otp_unlock_challenge_v1',
    challengeId,
    walletId,
    userId,
    ...(orgId ? { orgId } : {}),
    challengeB64u,
    createdAtMs,
    expiresAtMs,
  };
}

export function parseEmailOtpUnlockChallengeRow(
  row: D1EmailOtpUnlockChallengeRow | null,
): EmailOtpUnlockChallengeRecord | null {
  const record = parseEmailOtpUnlockChallengeRecord(row?.record_json);
  const expiresAtMs = positiveSafeInteger(row?.expires_at_ms);
  if (!record || !expiresAtMs || record.expiresAtMs !== expiresAtMs) return null;
  return record;
}

export function emailOtpChallengeContextValues(input: {
  readonly challengeSubjectId: string;
  readonly walletId: string;
  readonly orgId: string;
  readonly ownerProofBindingDigest: string;
  readonly action: EmailOtpChallengeIssueAction;
  readonly operation: EmailOtpChallengeOperation;
}): readonly unknown[] {
  return [
    input.challengeSubjectId,
    input.walletId,
    input.orgId,
    EMAIL_OTP_CHANNEL,
    input.ownerProofBindingDigest,
    input.action,
    input.operation,
  ];
}

export function emailOtpChallengeRecord(input: {
  readonly challengeId: string;
  readonly challengeSubjectId: string;
  readonly walletId: string;
  readonly orgId: string;
  readonly email: string;
  readonly otpCode: string;
  readonly ownerProofBindingDigest: string;
  readonly action: EmailOtpChallengeIssueAction;
  readonly operation: EmailOtpChallengeOperation;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
  readonly maxAttempts: number;
}): EmailOtpChallengeRecord {
  return {
    version: 'email_otp_challenge_v1',
    challengeId: input.challengeId,
    challengeSubjectId: input.challengeSubjectId,
    walletId: input.walletId,
    orgId: input.orgId,
    otpChannel: EMAIL_OTP_CHANNEL,
    email: input.email,
    otpCode: input.otpCode,
    ownerProofBindingDigest: input.ownerProofBindingDigest,
    action: input.action,
    operation: input.operation,
    createdAtMs: input.createdAtMs,
    expiresAtMs: input.expiresAtMs,
    attemptCount: 0,
    maxAttempts: input.maxAttempts,
  };
}

export function emailOtpChallengeWithAttemptCount(
  record: EmailOtpChallengeRecord,
  attemptCount: number,
): EmailOtpChallengeRecord {
  return {
    version: 'email_otp_challenge_v1',
    challengeId: record.challengeId,
    challengeSubjectId: record.challengeSubjectId,
    walletId: record.walletId,
    ...(record.orgId ? { orgId: record.orgId } : {}),
    otpChannel: EMAIL_OTP_CHANNEL,
    email: record.email,
    otpCode: record.otpCode,
    ownerProofBindingDigest: record.ownerProofBindingDigest,
    action: record.action,
    operation: record.operation,
    createdAtMs: record.createdAtMs,
    expiresAtMs: record.expiresAtMs,
    attemptCount,
    maxAttempts: record.maxAttempts,
  };
}

export function emailOtpChallengeBindingMismatchCode(input: {
  readonly record: EmailOtpChallengeRecord;
  readonly userId: string;
  readonly walletId: string;
  readonly orgId: string;
  readonly ownerProofBindingDigest: string;
  readonly action: EmailOtpChallengeIssueAction;
  readonly operation: EmailOtpChallengeOperation;
}): string | null {
  if (input.record.otpChannel !== EMAIL_OTP_CHANNEL) return 'challenge_channel_mismatch';
  if (input.record.challengeSubjectId !== input.userId) return 'challenge_subject_mismatch';
  if (input.record.walletId !== input.walletId) return 'challenge_wallet_mismatch';
  if (String(input.record.orgId || '') !== input.orgId) return 'challenge_org_mismatch';
  if (input.record.action !== input.action) return 'challenge_purpose_mismatch';
  if (input.record.operation !== input.operation) return 'challenge_purpose_mismatch';
  if (input.record.ownerProofBindingDigest !== input.ownerProofBindingDigest) {
    return 'challenge_session_mismatch';
  }
  return null;
}

export function emailOtpRegistrationChallengeBindingMismatchCode(input: {
  readonly record: EmailOtpChallengeRecord;
  readonly providerSubject: string;
  readonly walletId: string;
  readonly orgId: string;
  readonly ownerProofBindingDigest: string;
  readonly proofEmail: string;
}): string | null {
  if (input.record.otpChannel !== EMAIL_OTP_CHANNEL) return 'challenge_channel_mismatch';
  if (input.record.challengeSubjectId !== input.providerSubject) {
    return 'challenge_subject_mismatch';
  }
  if (toOptionalTrimmedString(input.record.email)?.toLowerCase() !== input.proofEmail) {
    return 'challenge_email_mismatch';
  }
  if (String(input.record.orgId || '') !== input.orgId) return 'challenge_org_mismatch';
  if (input.record.action !== WALLET_EMAIL_OTP_ACTIONS.registration) {
    return 'challenge_purpose_mismatch';
  }
  if (input.record.operation !== WALLET_EMAIL_OTP_REGISTRATION_OPERATION) {
    return 'challenge_purpose_mismatch';
  }
  if (input.record.walletId !== input.walletId) return 'challenge_wallet_mismatch';
  if (input.record.ownerProofBindingDigest !== input.ownerProofBindingDigest) {
    return 'challenge_session_mismatch';
  }
  return null;
}

export function emailOtpChallengeInvalidOrExpired(): {
  ok: false;
  code: string;
  message: string;
} {
  return {
    ok: false,
    code: 'challenge_expired_or_invalid',
    message: 'Email OTP challenge expired or invalid',
  };
}

export function emailOtpGrantRecord(input: {
  readonly grantToken: string;
  readonly userId: string;
  readonly walletId: string;
  readonly orgId: string;
  readonly challengeId: string;
  readonly ownerProofBindingDigest: string;
  readonly action: EmailOtpGrantAction;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
}): EmailOtpGrantRecord {
  return {
    version: 'email_otp_grant_v1',
    grantToken: input.grantToken,
    userId: input.userId,
    walletId: input.walletId,
    orgId: input.orgId,
    challengeId: input.challengeId,
    otpChannel: EMAIL_OTP_CHANNEL,
    ownerProofBindingDigest: input.ownerProofBindingDigest,
    action: input.action,
    issuedAtMs: input.issuedAtMs,
    expiresAtMs: input.expiresAtMs,
  };
}

export function emailOtpUnlockChallengeRecord(input: {
  readonly challengeId: string;
  readonly walletId: string;
  readonly userId: string;
  readonly orgId: string;
  readonly challengeB64u: string;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
}): EmailOtpUnlockChallengeRecord {
  return {
    version: 'email_otp_unlock_challenge_v1',
    challengeId: input.challengeId,
    walletId: input.walletId,
    userId: input.userId,
    orgId: input.orgId,
    challengeB64u: input.challengeB64u,
    createdAtMs: input.createdAtMs,
    expiresAtMs: input.expiresAtMs,
  };
}

export function parseEmailOtpGrantRecord(input: unknown): EmailOtpGrantRecord | null {
  const record = parseJsonObject(input);
  if (!record) return null;
  const version = toOptionalTrimmedString(record.version);
  const grantToken = toOptionalTrimmedString(record.grantToken);
  const userId = toOptionalTrimmedString(record.userId);
  const walletId = toOptionalTrimmedString(record.walletId);
  const orgId = toOptionalTrimmedString(record.orgId);
  const challengeId = toOptionalTrimmedString(record.challengeId);
  const otpChannel = toOptionalTrimmedString(record.otpChannel);
  const ownerProofBindingDigest = toOptionalTrimmedString(record.ownerProofBindingDigest);
  const action = toOptionalTrimmedString(record.action);
  const issuedAtMs = positiveSafeInteger(record.issuedAtMs);
  const expiresAtMs = positiveSafeInteger(record.expiresAtMs);
  if (
    version !== 'email_otp_grant_v1' ||
    !grantToken ||
    !userId ||
    !walletId ||
    !challengeId ||
    otpChannel !== EMAIL_OTP_CHANNEL ||
    !ownerProofBindingDigest ||
    !action ||
    !issuedAtMs ||
    !expiresAtMs ||
    expiresAtMs <= issuedAtMs
  ) {
    return null;
  }
  if (
    action !== WALLET_EMAIL_OTP_ACTIONS.unseal &&
    action !== WALLET_EMAIL_OTP_ACTIONS.recoveryBootstrap
  ) {
    return null;
  }
  return {
    version: 'email_otp_grant_v1',
    grantToken,
    userId,
    walletId,
    ...(orgId ? { orgId } : {}),
    challengeId,
    otpChannel: EMAIL_OTP_CHANNEL,
    ownerProofBindingDigest,
    action,
    issuedAtMs,
    expiresAtMs,
  };
}

export function parseEmailOtpGrantRow(row: D1EmailOtpGrantRow | null): EmailOtpGrantRecord | null {
  const record = parseEmailOtpGrantRecord(row?.record_json);
  const expiresAtMs = positiveSafeInteger(row?.expires_at_ms);
  if (!record || !expiresAtMs || record.expiresAtMs !== expiresAtMs) return null;
  return record;
}

export async function validateEmailOtpEnrollmentMaterial(input: {
  readonly material: EmailOtpEnrollmentMaterialBoundaryInput;
  readonly validateSecp256k1PublicKey33: EmailOtpPublicKey33Validator;
}): Promise<EmailOtpEnrollmentMaterialValidationResult> {
  const enrollmentSealKeyVersion = toOptionalTrimmedString(input.material.enrollmentSealKeyVersion);
  const clientUnlockPublicKeyB64u = toOptionalTrimmedString(
    input.material.clientUnlockPublicKeyB64u,
  );
  const unlockKeyVersion = toOptionalTrimmedString(input.material.unlockKeyVersion);
  const serverSealedFactorCiphertextB64u = toOptionalTrimmedString(
    input.material.serverSealedFactorCiphertextB64u,
  );
  if (!enrollmentSealKeyVersion) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'enrollmentSealKeyVersion is required',
    };
  }
  if (!clientUnlockPublicKeyB64u) {
    return { ok: false, code: 'invalid_body', message: 'clientUnlockPublicKeyB64u is required' };
  }
  if (!unlockKeyVersion) {
    return { ok: false, code: 'invalid_body', message: 'unlockKeyVersion is required' };
  }
  if (!serverSealedFactorCiphertextB64u) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'serverSealedFactorCiphertextB64u is required',
    };
  }
  let unlockPublicKeyBytes: Uint8Array;
  try {
    unlockPublicKeyBytes = base64UrlDecode(clientUnlockPublicKeyB64u);
  } catch {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'clientUnlockPublicKeyB64u must be valid base64url',
    };
  }
  if (unlockPublicKeyBytes.length !== 33) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'clientUnlockPublicKeyB64u must decode to 33 bytes (compressed secp256k1 pubkey)',
    };
  }
  try {
    await input.validateSecp256k1PublicKey33(unlockPublicKeyBytes);
  } catch {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'clientUnlockPublicKeyB64u is not a valid secp256k1 public key',
    };
  }

  return {
    ok: true,
    enrollmentSealKeyVersion,
    clientUnlockPublicKeyB64u,
    unlockKeyVersion,
    serverSealedFactorCiphertextB64u,
  };
}

export function emailOtpAuthStateRecord(input: {
  readonly enrollment: EmailOtpWalletEnrollmentRecord;
  readonly existing: EmailOtpAuthStateRecord | null;
  readonly updatedAtMs: number;
  readonly patch: EmailOtpAuthStatePatch;
}): EmailOtpAuthStateRecord {
  const otpFailureCount = patchedNonNegativeAuthStateValue(
    input.existing?.otpFailureCount,
    input.patch.otpFailureCount,
  );
  const lastOtpFailureAtMs = patchedPositiveAuthStateValue(
    input.existing?.lastOtpFailureAtMs,
    input.patch.lastOtpFailureAtMs,
  );
  const otpLockedUntilMs = patchedPositiveAuthStateValue(
    input.existing?.otpLockedUntilMs,
    input.patch.otpLockedUntilMs,
  );
  const lastEmailOtpLoginAtMs = patchedPositiveAuthStateValue(
    input.existing?.lastEmailOtpLoginAtMs,
    input.patch.lastEmailOtpLoginAtMs,
  );
  const lastStrongAuthAtMs = patchedPositiveAuthStateValue(
    input.existing?.lastStrongAuthAtMs,
    input.patch.lastStrongAuthAtMs,
  );
  return {
    version: 'email_otp_auth_state_v1',
    walletId: input.enrollment.walletId,
    providerUserId: input.enrollment.providerUserId,
    orgId: input.enrollment.orgId,
    createdAtMs: input.existing?.createdAtMs ?? input.updatedAtMs,
    updatedAtMs: input.updatedAtMs,
    ...(otpFailureCount != null ? { otpFailureCount } : {}),
    ...(lastOtpFailureAtMs != null ? { lastOtpFailureAtMs } : {}),
    ...(otpLockedUntilMs != null ? { otpLockedUntilMs } : {}),
    ...(lastEmailOtpLoginAtMs != null ? { lastEmailOtpLoginAtMs } : {}),
    ...(lastStrongAuthAtMs != null ? { lastStrongAuthAtMs } : {}),
  };
}

function parseEmailOtpChallengeAction(input: unknown): EmailOtpChallengeIssueAction | null {
  const action = toOptionalTrimmedString(input);
  switch (action) {
    case WALLET_EMAIL_OTP_ACTIONS.login:
    case WALLET_EMAIL_OTP_ACTIONS.registration:
    case WALLET_EMAIL_OTP_ACTIONS.recoveryBootstrap:
      return action;
    default:
      return null;
  }
}

export function emailOtpChallengePurposeIsValid(input: {
  readonly action: EmailOtpChallengeIssueAction;
  readonly operation: EmailOtpChallengeOperation;
}): boolean {
  switch (input.action) {
    case WALLET_EMAIL_OTP_ACTIONS.login:
      return isWalletEmailOtpLoginOperation(input.operation);
    case WALLET_EMAIL_OTP_ACTIONS.registration:
      return input.operation === WALLET_EMAIL_OTP_REGISTRATION_OPERATION;
    case WALLET_EMAIL_OTP_ACTIONS.recoveryBootstrap:
      return input.operation === WALLET_EMAIL_OTP_UNLOCK_OPERATION;
  }
}

function optionalPositiveSafeIntegerField(
  record: Record<string, unknown>,
  field: string,
): number | undefined | null {
  if (!hasRecordField(record, field) || record[field] == null) return undefined;
  return positiveSafeInteger(record[field]);
}

function optionalNonNegativeSafeIntegerField(
  record: Record<string, unknown>,
  field: string,
): number | undefined | null {
  if (!hasRecordField(record, field) || record[field] == null) return undefined;
  return nonNegativeSafeInteger(record[field]);
}

function hasRecordField(record: Record<string, unknown>, field: string): boolean {
  return Object.prototype.hasOwnProperty.call(record, field);
}

function hasExactRecordFields(
  record: Record<string, unknown>,
  expectedFields: readonly string[],
): boolean {
  const actualFields = Object.keys(record).sort();
  const expected = [...expectedFields].sort();
  return (
    actualFields.length === expected.length &&
    actualFields.every((field, index) => field === expected[index])
  );
}

function patchedPositiveAuthStateValue(
  current: number | undefined,
  patch: number | null | undefined,
): number | undefined {
  if (patch === null) return undefined;
  if (patch === undefined) return current;
  return patch > 0 ? Math.floor(patch) : undefined;
}

function patchedNonNegativeAuthStateValue(
  current: number | undefined,
  patch: number | null | undefined,
): number | undefined {
  if (patch === null) return undefined;
  if (patch === undefined) return current;
  return patch >= 0 ? Math.floor(patch) : undefined;
}
