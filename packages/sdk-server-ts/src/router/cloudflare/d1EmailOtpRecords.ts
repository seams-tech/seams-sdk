import { toOptionalTrimmedString } from '@shared/utils/validation';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import {
  EMAIL_OTP_CHANNEL,
  WALLET_EMAIL_OTP_ACTIONS,
  WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
  WALLET_EMAIL_OTP_UNLOCK_OPERATION,
  isWalletEmailOtpLoginOperation,
} from '@shared/utils/emailOtpDomain';
import {
  EMAIL_OTP_RECOVERY_KEY_COUNT,
  EMAIL_OTP_RECOVERY_WRAP_ALG,
  EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND,
  EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND,
  buildEmailOtpRecoveryWrapBinding,
  encodeEmailOtpRecoveryWrappedEnrollmentAad,
} from '@shared/utils/emailOtpRecoveryKey';
import type {
  EmailOtpAuthStateRecord,
  EmailOtpChallengeOperation,
  EmailOtpChallengeRecord,
  EmailOtpGrantAction,
  EmailOtpGrantRecord,
  EmailOtpLoginChallengeOperation,
  EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
  EmailOtpUnlockChallengeRecord,
  EmailOtpWalletEnrollmentRecord,
} from '../../core/EmailOtpStores';
import {
  isB64uString,
  nonNegativeSafeInteger,
  parseJsonObject,
  positiveSafeInteger,
} from './d1RouterApiAuthBoundary';

export type EmailOtpChallengeIssueAction =
  | typeof WALLET_EMAIL_OTP_ACTIONS.login
  | typeof WALLET_EMAIL_OTP_ACTIONS.registration
  | typeof WALLET_EMAIL_OTP_ACTIONS.deviceRecovery;

export type EmailOtpRateLimitScope =
  | 'challenge'
  | 'verify'
  | 'grant'
  | 'recoveryKeyAttempt'
  | 'googleRegistrationAttempt';

export type EmailOtpRecoveryEnrollmentEscrowBoundary = {
  readonly record: EmailOtpRecoveryWrappedEnrollmentEscrowRecord;
  readonly binding: ReturnType<typeof buildEmailOtpRecoveryWrapBinding>;
};

export type EmailOtpAuthStatePatch = {
  readonly otpFailureCount?: number | null;
  readonly lastOtpFailureAtMs?: number | null;
  readonly otpLockedUntilMs?: number | null;
  readonly lastEmailOtpLoginAtMs?: number | null;
  readonly lastStrongAuthAtMs?: number | null;
};

export type EmailOtpRecoveryChallengeEscrow = Omit<
  EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
  | 'recoveryKeyId'
  | 'recoveryKeyStatus'
  | 'issuedAtMs'
  | 'updatedAtMs'
  | 'consumedAtMs'
  | 'revokedAtMs'
>;

export type EmailOtpRecoveryRotationFailure =
  | {
      readonly ok: false;
      readonly code: 'invalid_body';
      readonly message: string;
    }
  | {
      readonly ok: false;
      readonly code: 'recovery_rotation_binding_mismatch';
      readonly message: 'Recovery-code rotation does not match the active Email OTP enrollment';
    };

export type EmailOtpRecoveryRotationHash = (input: Uint8Array) => Promise<Uint8Array>;

export type EmailOtpPublicKey33Validator = (input: Uint8Array) => Promise<unknown>;

export type EmailOtpRecoveryRotationEscrowResult =
  | {
      readonly ok: true;
      readonly record: EmailOtpRecoveryWrappedEnrollmentEscrowRecord;
    }
  | {
      readonly ok: false;
      readonly result: EmailOtpRecoveryRotationFailure;
    };

export type EmailOtpEnrollmentMaterialBoundaryInput = {
  readonly recoveryWrappedEnrollmentEscrows?: unknown;
  readonly enrollmentSealKeyVersion?: unknown;
  readonly clientUnlockPublicKeyB64u?: unknown;
  readonly unlockKeyVersion?: unknown;
  readonly thresholdEcdsaClientVerifyingShareB64u?: unknown;
};

export type EmailOtpEnrollmentMaterialValidationResult =
  | {
      readonly ok: true;
      readonly recoveryWrappedEnrollmentEscrows: EmailOtpRecoveryWrappedEnrollmentEscrowRecord[];
      readonly enrollmentSealKeyVersion: string;
      readonly clientUnlockPublicKeyB64u: string;
      readonly unlockKeyVersion: string;
      readonly thresholdEcdsaClientVerifyingShareB64u: string;
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

export type D1EmailOtpRecoveryEscrowRow = {
  readonly record_json?: unknown;
  readonly updated_at_ms?: unknown;
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
  const localMask =
    local.length <= 2 ? `${local[0] || '*'}*` : `${local[0]}***${local.slice(-1)}`;
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
  const signingRootId = toOptionalTrimmedString(record.signingRootId);
  const signingRootVersion = toOptionalTrimmedString(record.signingRootVersion);
  const recoveryWrappedEnrollmentEscrowCount = positiveSafeInteger(
    record.recoveryWrappedEnrollmentEscrowCount,
  );
  const clientUnlockPublicKeyB64u = toOptionalTrimmedString(record.clientUnlockPublicKeyB64u);
  const unlockKeyVersion = toOptionalTrimmedString(record.unlockKeyVersion);
  const thresholdEcdsaClientVerifyingShareB64u = toOptionalTrimmedString(
    record.thresholdEcdsaClientVerifyingShareB64u,
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
    !signingRootId ||
    !signingRootVersion ||
    !recoveryWrappedEnrollmentEscrowCount ||
    !clientUnlockPublicKeyB64u ||
    !unlockKeyVersion ||
    !thresholdEcdsaClientVerifyingShareB64u ||
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
    signingRootId,
    signingRootVersion,
    recoveryWrappedEnrollmentEscrowCount,
    clientUnlockPublicKeyB64u,
    unlockKeyVersion,
    thresholdEcdsaClientVerifyingShareB64u,
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
  const lastEmailOtpLoginAtMs = optionalPositiveSafeIntegerField(
    record,
    'lastEmailOtpLoginAtMs',
  );
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

export function parseEmailOtpChallengeOperation(
  input: unknown,
): EmailOtpChallengeOperation | null {
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
  const sessionHash = toOptionalTrimmedString(record.sessionHash);
  const appSessionVersion = toOptionalTrimmedString(record.appSessionVersion);
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
    !sessionHash ||
    !appSessionVersion ||
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
    sessionHash,
    appSessionVersion,
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
  readonly sessionHash: string;
  readonly appSessionVersion: string;
  readonly action: EmailOtpChallengeIssueAction;
  readonly operation: EmailOtpChallengeOperation;
}): readonly unknown[] {
  return [
    input.challengeSubjectId,
    input.walletId,
    input.orgId,
    EMAIL_OTP_CHANNEL,
    input.sessionHash,
    input.appSessionVersion,
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
  readonly sessionHash: string;
  readonly appSessionVersion: string;
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
    sessionHash: input.sessionHash,
    appSessionVersion: input.appSessionVersion,
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
    sessionHash: record.sessionHash,
    appSessionVersion: record.appSessionVersion,
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
  readonly sessionHash: string;
  readonly appSessionVersion: string;
  readonly action: EmailOtpChallengeIssueAction;
  readonly operation: EmailOtpChallengeOperation;
}): string | null {
  if (input.record.otpChannel !== EMAIL_OTP_CHANNEL) return 'challenge_channel_mismatch';
  if (input.record.challengeSubjectId !== input.userId) return 'challenge_subject_mismatch';
  if (input.record.walletId !== input.walletId) return 'challenge_wallet_mismatch';
  if (String(input.record.orgId || '') !== input.orgId) return 'challenge_org_mismatch';
  if (input.record.action !== input.action) return 'challenge_purpose_mismatch';
  if (input.record.operation !== input.operation) return 'challenge_purpose_mismatch';
  if (input.record.sessionHash !== input.sessionHash) return 'challenge_session_mismatch';
  if (input.record.appSessionVersion !== input.appSessionVersion) {
    return 'challenge_session_mismatch';
  }
  return null;
}

export function emailOtpRegistrationChallengeBindingMismatchCode(input: {
  readonly record: EmailOtpChallengeRecord;
  readonly providerSubject: string;
  readonly walletId: string;
  readonly orgId: string;
  readonly sessionHash: string;
  readonly appSessionVersion: string;
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
  if (input.record.sessionHash !== input.sessionHash) return 'challenge_session_mismatch';
  if (input.record.appSessionVersion !== input.appSessionVersion) {
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
  readonly sessionHash: string;
  readonly appSessionVersion: string;
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
    sessionHash: input.sessionHash,
    appSessionVersion: input.appSessionVersion,
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
  const sessionHash = toOptionalTrimmedString(record.sessionHash);
  const appSessionVersion = toOptionalTrimmedString(record.appSessionVersion);
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
    !sessionHash ||
    !appSessionVersion ||
    !action ||
    !issuedAtMs ||
    !expiresAtMs ||
    expiresAtMs <= issuedAtMs
  ) {
    return null;
  }
  if (
    action !== WALLET_EMAIL_OTP_ACTIONS.unseal &&
    action !== WALLET_EMAIL_OTP_ACTIONS.deviceRecovery
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
    sessionHash,
    appSessionVersion,
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

export function parseEmailOtpRecoveryEscrowRecord(
  input: unknown,
): EmailOtpRecoveryWrappedEnrollmentEscrowRecord | null {
  const record = parseJsonObject(input);
  if (!record) return null;
  const version = toOptionalTrimmedString(record.version);
  const alg = toOptionalTrimmedString(record.alg);
  const secretKind = toOptionalTrimmedString(record.secretKind);
  const escrowKind = toOptionalTrimmedString(record.escrowKind);
  const walletId = toOptionalTrimmedString(record.walletId);
  const userId = toOptionalTrimmedString(record.userId);
  const authSubjectId = toOptionalTrimmedString(record.authSubjectId);
  const authMethod = toOptionalTrimmedString(record.authMethod);
  const enrollmentId = toOptionalTrimmedString(record.enrollmentId);
  const enrollmentVersion = toOptionalTrimmedString(record.enrollmentVersion);
  const enrollmentSealKeyVersion = toOptionalTrimmedString(record.enrollmentSealKeyVersion);
  const signingRootId = toOptionalTrimmedString(record.signingRootId);
  const signingRootVersion = toOptionalTrimmedString(record.signingRootVersion);
  const recoveryKeyId = toOptionalTrimmedString(record.recoveryKeyId);
  const recoveryKeyLabel = toOptionalTrimmedString(record.recoveryKeyLabel);
  const recoveryKeyStatus = toOptionalTrimmedString(record.recoveryKeyStatus);
  const nonceB64u = toOptionalTrimmedString(record.nonceB64u);
  const wrappedDeviceEnrollmentEscrowB64u = toOptionalTrimmedString(
    record.wrappedDeviceEnrollmentEscrowB64u,
  );
  const aadHashB64u = toOptionalTrimmedString(record.aadHashB64u);
  const issuedAtMs = positiveSafeInteger(record.issuedAtMs);
  const updatedAtMs = positiveSafeInteger(record.updatedAtMs);
  const consumedAtMs =
    record.consumedAtMs == null ? undefined : positiveSafeInteger(record.consumedAtMs);
  const revokedAtMs =
    record.revokedAtMs == null ? undefined : positiveSafeInteger(record.revokedAtMs);
  if (
    version !== 'email_otp_recovery_wrapped_enrollment_escrow_v1' ||
    alg !== EMAIL_OTP_RECOVERY_WRAP_ALG ||
    secretKind !== EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND ||
    escrowKind !== EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND ||
    !walletId ||
    !userId ||
    !authSubjectId ||
    authMethod !== 'google_sso_email_otp' ||
    !enrollmentId ||
    !enrollmentVersion ||
    !enrollmentSealKeyVersion ||
    !signingRootId ||
    !signingRootVersion ||
    !recoveryKeyId ||
    !nonceB64u ||
    !wrappedDeviceEnrollmentEscrowB64u ||
    !aadHashB64u ||
    !recoveryKeyStatus ||
    !issuedAtMs ||
    !updatedAtMs ||
    userId !== authSubjectId ||
    !isB64uString(nonceB64u) ||
    !isB64uString(wrappedDeviceEnrollmentEscrowB64u) ||
    !isB64uString(aadHashB64u) ||
    hasRecordField(record, 'acknowledgedAtMs') ||
    hasRecordField(record, 'abandonedAtMs') ||
    hasRecordField(record, 'cleanupReason') ||
    updatedAtMs < issuedAtMs
  ) {
    return null;
  }
  const base = {
    version: 'email_otp_recovery_wrapped_enrollment_escrow_v1' as const,
    alg: EMAIL_OTP_RECOVERY_WRAP_ALG,
    secretKind: EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND,
    escrowKind: EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND,
    walletId,
    userId,
    authSubjectId,
    authMethod: 'google_sso_email_otp' as const,
    enrollmentId,
    enrollmentVersion,
    enrollmentSealKeyVersion,
    signingRootId,
    signingRootVersion,
    recoveryKeyId,
    ...(recoveryKeyLabel ? { recoveryKeyLabel } : {}),
    nonceB64u,
    wrappedDeviceEnrollmentEscrowB64u,
    aadHashB64u,
    issuedAtMs,
    updatedAtMs,
  };
  switch (recoveryKeyStatus) {
    case 'active':
      if (consumedAtMs !== undefined || revokedAtMs !== undefined) return null;
      return { ...base, recoveryKeyStatus };
    case 'consumed':
      if (consumedAtMs == null || revokedAtMs !== undefined) return null;
      return { ...base, recoveryKeyStatus, consumedAtMs };
    case 'revoked':
      if (consumedAtMs !== undefined || revokedAtMs == null) return null;
      return { ...base, recoveryKeyStatus, revokedAtMs };
    default:
      return null;
  }
}

export function parseEmailOtpRecoveryEnrollmentEscrowBoundary(
  input: unknown,
): EmailOtpRecoveryEnrollmentEscrowBoundary | null {
  const record = parseEmailOtpRecoveryEscrowRecord(input);
  if (!record) return null;
  return {
    record,
    binding: buildEmailOtpRecoveryWrapBinding({
      walletId: record.walletId,
      userId: record.userId,
      authSubjectId: record.authSubjectId,
      authMethod: record.authMethod,
      enrollmentId: record.enrollmentId,
      enrollmentVersion: record.enrollmentVersion,
      enrollmentSealKeyVersion: record.enrollmentSealKeyVersion,
      signingRootId: record.signingRootId,
      signingRootVersion: record.signingRootVersion,
      recoveryKeyId: record.recoveryKeyId,
    }),
  };
}

export function invalidRecoveryRotationBody(message: string): EmailOtpRecoveryRotationFailure {
  return { ok: false, code: 'invalid_body', message };
}

export function recoveryRotationBindingMismatch(): EmailOtpRecoveryRotationFailure {
  return {
    ok: false,
    code: 'recovery_rotation_binding_mismatch',
    message: 'Recovery-code rotation does not match the active Email OTP enrollment',
  };
}

export async function validateEmailOtpEnrollmentMaterial(input: {
  readonly material: EmailOtpEnrollmentMaterialBoundaryInput;
  readonly sha256Bytes: EmailOtpRecoveryRotationHash;
  readonly validateSecp256k1PublicKey33: EmailOtpPublicKey33Validator;
}): Promise<EmailOtpEnrollmentMaterialValidationResult> {
  const enrollmentSealKeyVersion = toOptionalTrimmedString(input.material.enrollmentSealKeyVersion);
  const rawRecoveryWrappedEnrollmentEscrows = Array.isArray(
    input.material.recoveryWrappedEnrollmentEscrows,
  )
    ? input.material.recoveryWrappedEnrollmentEscrows
    : [];
  const parsedRecoveryWrappedEnrollmentEscrows: EmailOtpRecoveryEnrollmentEscrowBoundary[] = [];
  const recoveryWrappedEnrollmentEscrows: EmailOtpRecoveryWrappedEnrollmentEscrowRecord[] = [];
  for (const rawEscrow of rawRecoveryWrappedEnrollmentEscrows) {
    const parsed = parseEmailOtpRecoveryEnrollmentEscrowBoundary(rawEscrow);
    if (!parsed) continue;
    parsedRecoveryWrappedEnrollmentEscrows.push(parsed);
    recoveryWrappedEnrollmentEscrows.push(parsed.record);
  }
  const clientUnlockPublicKeyB64u = toOptionalTrimmedString(
    input.material.clientUnlockPublicKeyB64u,
  );
  const unlockKeyVersion = toOptionalTrimmedString(input.material.unlockKeyVersion);
  const thresholdEcdsaClientVerifyingShareB64u = toOptionalTrimmedString(
    input.material.thresholdEcdsaClientVerifyingShareB64u,
  );
  if (
    rawRecoveryWrappedEnrollmentEscrows.length !== EMAIL_OTP_RECOVERY_KEY_COUNT ||
    recoveryWrappedEnrollmentEscrows.length !== EMAIL_OTP_RECOVERY_KEY_COUNT
  ) {
    return {
      ok: false,
      code: 'invalid_body',
      message: `Exactly ${EMAIL_OTP_RECOVERY_KEY_COUNT} recovery-wrapped enrollment escrows are required`,
    };
  }
  if (!enrollmentSealKeyVersion) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'enrollmentSealKeyVersion is required',
    };
  }
  const escrowSetValidation = await validateEmailOtpRecoveryWrappedEnrollmentEscrowSet({
    records: parsedRecoveryWrappedEnrollmentEscrows,
    sha256Bytes: input.sha256Bytes,
  });
  if (!escrowSetValidation.ok) return escrowSetValidation;
  if (!clientUnlockPublicKeyB64u) {
    return { ok: false, code: 'invalid_body', message: 'clientUnlockPublicKeyB64u is required' };
  }
  if (!unlockKeyVersion) {
    return { ok: false, code: 'invalid_body', message: 'unlockKeyVersion is required' };
  }
  if (!thresholdEcdsaClientVerifyingShareB64u) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'thresholdEcdsaClientVerifyingShareB64u is required',
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

  let clientVerifyingShareBytes: Uint8Array;
  try {
    clientVerifyingShareBytes = base64UrlDecode(thresholdEcdsaClientVerifyingShareB64u);
  } catch {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'thresholdEcdsaClientVerifyingShareB64u must be valid base64url',
    };
  }
  if (clientVerifyingShareBytes.length !== 33) {
    return {
      ok: false,
      code: 'invalid_body',
      message:
        'thresholdEcdsaClientVerifyingShareB64u must decode to 33 bytes (compressed secp256k1 pubkey)',
    };
  }
  try {
    await input.validateSecp256k1PublicKey33(clientVerifyingShareBytes);
  } catch {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'thresholdEcdsaClientVerifyingShareB64u is not a valid secp256k1 public key',
    };
  }

  return {
    ok: true,
    recoveryWrappedEnrollmentEscrows,
    enrollmentSealKeyVersion,
    clientUnlockPublicKeyB64u,
    unlockKeyVersion,
    thresholdEcdsaClientVerifyingShareB64u,
  };
}

export async function activeEmailOtpRecoveryRotationEscrowRecord(input: {
  readonly raw: unknown;
  readonly enrollment: EmailOtpWalletEnrollmentRecord;
  readonly issuedAtMs: number;
  readonly recoveryKeyIds: Set<string>;
  readonly nonceB64us: Set<string>;
  readonly sha256Bytes: EmailOtpRecoveryRotationHash;
}): Promise<EmailOtpRecoveryRotationEscrowResult> {
  const obj = recoveryRotationInputObject(input.raw);
  if (!obj) {
    return {
      ok: false,
      result: invalidRecoveryRotationBody('Invalid recovery escrow input'),
    };
  }
  const recoveryKeyId = toOptionalTrimmedString(obj.recoveryKeyId);
  const nonceB64u = toOptionalTrimmedString(obj.nonceB64u);
  const wrappedDeviceEnrollmentEscrowB64u = toOptionalTrimmedString(
    obj.wrappedDeviceEnrollmentEscrowB64u,
  );
  const aadHashB64u = toOptionalTrimmedString(obj.aadHashB64u);
  if (!recoveryKeyId || !nonceB64u || !wrappedDeviceEnrollmentEscrowB64u || !aadHashB64u) {
    return {
      ok: false,
      result: invalidRecoveryRotationBody(
        'Recovery rotation escrow input is missing required fields',
      ),
    };
  }
  if (input.recoveryKeyIds.has(recoveryKeyId)) {
    return {
      ok: false,
      result: invalidRecoveryRotationBody(
        'Recovery rotation recoveryKeyId values must be unique',
      ),
    };
  }
  if (input.nonceB64us.has(nonceB64u)) {
    return {
      ok: false,
      result: invalidRecoveryRotationBody('Recovery rotation nonce values must be unique'),
    };
  }
  try {
    base64UrlDecode(nonceB64u);
    base64UrlDecode(wrappedDeviceEnrollmentEscrowB64u);
    base64UrlDecode(aadHashB64u);
  } catch {
    return {
      ok: false,
      result: invalidRecoveryRotationBody(
        'Recovery rotation escrow input must use base64url fields',
      ),
    };
  }
  const binding = buildEmailOtpRecoveryWrapBinding({
    walletId: input.enrollment.walletId,
    userId: input.enrollment.providerUserId,
    authSubjectId: input.enrollment.providerUserId,
    authMethod: 'google_sso_email_otp',
    enrollmentId: input.enrollment.enrollmentId,
    enrollmentVersion: input.enrollment.enrollmentVersion,
    enrollmentSealKeyVersion: input.enrollment.enrollmentSealKeyVersion,
    signingRootId: input.enrollment.signingRootId,
    signingRootVersion: input.enrollment.signingRootVersion,
    recoveryKeyId,
  });
  const expectedAadHashB64u = base64UrlEncode(
    await input.sha256Bytes(encodeEmailOtpRecoveryWrappedEnrollmentAad(binding)),
  );
  if (aadHashB64u !== expectedAadHashB64u) {
    return {
      ok: false,
      result: invalidRecoveryRotationBody(
        'Recovery rotation aadHashB64u does not match enrollment metadata',
      ),
    };
  }
  input.recoveryKeyIds.add(recoveryKeyId);
  input.nonceB64us.add(nonceB64u);
  return {
    ok: true,
    record: {
      version: 'email_otp_recovery_wrapped_enrollment_escrow_v1',
      alg: EMAIL_OTP_RECOVERY_WRAP_ALG,
      secretKind: EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND,
      escrowKind: EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND,
      walletId: input.enrollment.walletId,
      userId: input.enrollment.providerUserId,
      authSubjectId: input.enrollment.providerUserId,
      authMethod: 'google_sso_email_otp',
      enrollmentId: input.enrollment.enrollmentId,
      enrollmentVersion: input.enrollment.enrollmentVersion,
      enrollmentSealKeyVersion: input.enrollment.enrollmentSealKeyVersion,
      signingRootId: input.enrollment.signingRootId,
      signingRootVersion: input.enrollment.signingRootVersion,
      recoveryKeyId,
      recoveryKeyStatus: 'active',
      nonceB64u,
      wrappedDeviceEnrollmentEscrowB64u,
      aadHashB64u,
      issuedAtMs: input.issuedAtMs,
      updatedAtMs: input.issuedAtMs,
    },
  };
}

export function parseEmailOtpRecoveryEscrowRow(
  row: D1EmailOtpRecoveryEscrowRow | null,
): EmailOtpRecoveryWrappedEnrollmentEscrowRecord | null {
  const record = parseEmailOtpRecoveryEscrowRecord(row?.record_json);
  const updatedAtMs = positiveSafeInteger(row?.updated_at_ms);
  if (!record || !updatedAtMs || record.updatedAtMs !== updatedAtMs) return null;
  return record;
}

export function emailOtpRecoveryEscrowMatchesEnrollment(input: {
  readonly escrow: EmailOtpRecoveryWrappedEnrollmentEscrowRecord;
  readonly enrollment: EmailOtpWalletEnrollmentRecord;
}): boolean {
  return (
    input.escrow.walletId === input.enrollment.walletId &&
    input.escrow.userId === input.enrollment.providerUserId &&
    input.escrow.authSubjectId === input.enrollment.providerUserId &&
    input.escrow.enrollmentId === input.enrollment.enrollmentId &&
    input.escrow.enrollmentVersion === input.enrollment.enrollmentVersion &&
    input.escrow.enrollmentSealKeyVersion === input.enrollment.enrollmentSealKeyVersion &&
    input.escrow.signingRootId === input.enrollment.signingRootId &&
    input.escrow.signingRootVersion === input.enrollment.signingRootVersion
  );
}

export function activeEmailOtpRecoveryEscrow(
  record: EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
): record is Extract<
  EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
  { readonly recoveryKeyStatus: 'active' }
> {
  return record.recoveryKeyStatus === 'active';
}

export function countActiveEmailOtpRecoveryEscrows(
  records: readonly EmailOtpRecoveryWrappedEnrollmentEscrowRecord[],
): number {
  let count = 0;
  for (const record of records) {
    if (activeEmailOtpRecoveryEscrow(record)) count += 1;
  }
  return count;
}

export function redactEmailOtpRecoveryChallengeEscrow(
  record: EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
): EmailOtpRecoveryChallengeEscrow {
  return {
    version: record.version,
    alg: record.alg,
    secretKind: record.secretKind,
    escrowKind: record.escrowKind,
    walletId: record.walletId,
    userId: record.userId,
    authSubjectId: record.authSubjectId,
    authMethod: record.authMethod,
    enrollmentId: record.enrollmentId,
    enrollmentVersion: record.enrollmentVersion,
    enrollmentSealKeyVersion: record.enrollmentSealKeyVersion,
    signingRootId: record.signingRootId,
    signingRootVersion: record.signingRootVersion,
    nonceB64u: record.nonceB64u,
    wrappedDeviceEnrollmentEscrowB64u: record.wrappedDeviceEnrollmentEscrowB64u,
    aadHashB64u: record.aadHashB64u,
  };
}

export function revokedEmailOtpRecoveryEscrowRecord(input: {
  readonly record: Extract<
    EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
    { readonly recoveryKeyStatus: 'active' }
  >;
  readonly revokedAtMs: number;
}): EmailOtpRecoveryWrappedEnrollmentEscrowRecord {
  return {
    version: input.record.version,
    alg: input.record.alg,
    secretKind: input.record.secretKind,
    escrowKind: input.record.escrowKind,
    walletId: input.record.walletId,
    userId: input.record.userId,
    authSubjectId: input.record.authSubjectId,
    authMethod: input.record.authMethod,
    enrollmentId: input.record.enrollmentId,
    enrollmentVersion: input.record.enrollmentVersion,
    enrollmentSealKeyVersion: input.record.enrollmentSealKeyVersion,
    signingRootId: input.record.signingRootId,
    signingRootVersion: input.record.signingRootVersion,
    recoveryKeyId: input.record.recoveryKeyId,
    ...(input.record.recoveryKeyLabel ? { recoveryKeyLabel: input.record.recoveryKeyLabel } : {}),
    recoveryKeyStatus: 'revoked',
    nonceB64u: input.record.nonceB64u,
    wrappedDeviceEnrollmentEscrowB64u: input.record.wrappedDeviceEnrollmentEscrowB64u,
    aadHashB64u: input.record.aadHashB64u,
    issuedAtMs: input.record.issuedAtMs,
    updatedAtMs: input.revokedAtMs,
    revokedAtMs: input.revokedAtMs,
  };
}

export function consumedEmailOtpRecoveryEscrowRecord(input: {
  readonly record: Extract<
    EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
    { readonly recoveryKeyStatus: 'active' }
  >;
  readonly consumedAtMs: number;
}): EmailOtpRecoveryWrappedEnrollmentEscrowRecord {
  return {
    version: input.record.version,
    alg: input.record.alg,
    secretKind: input.record.secretKind,
    escrowKind: input.record.escrowKind,
    walletId: input.record.walletId,
    userId: input.record.userId,
    authSubjectId: input.record.authSubjectId,
    authMethod: input.record.authMethod,
    enrollmentId: input.record.enrollmentId,
    enrollmentVersion: input.record.enrollmentVersion,
    enrollmentSealKeyVersion: input.record.enrollmentSealKeyVersion,
    signingRootId: input.record.signingRootId,
    signingRootVersion: input.record.signingRootVersion,
    recoveryKeyId: input.record.recoveryKeyId,
    ...(input.record.recoveryKeyLabel ? { recoveryKeyLabel: input.record.recoveryKeyLabel } : {}),
    recoveryKeyStatus: 'consumed',
    nonceB64u: input.record.nonceB64u,
    wrappedDeviceEnrollmentEscrowB64u: input.record.wrappedDeviceEnrollmentEscrowB64u,
    aadHashB64u: input.record.aadHashB64u,
    issuedAtMs: input.record.issuedAtMs,
    updatedAtMs: input.consumedAtMs,
    consumedAtMs: input.consumedAtMs,
  };
}

export function emailOtpRecoveryEscrowWithUpdatedAt(input: {
  readonly record: EmailOtpRecoveryWrappedEnrollmentEscrowRecord;
  readonly updatedAtMs: number;
}): EmailOtpRecoveryWrappedEnrollmentEscrowRecord {
  const base = {
    version: input.record.version,
    alg: input.record.alg,
    secretKind: input.record.secretKind,
    escrowKind: input.record.escrowKind,
    walletId: input.record.walletId,
    userId: input.record.userId,
    authSubjectId: input.record.authSubjectId,
    authMethod: input.record.authMethod,
    enrollmentId: input.record.enrollmentId,
    enrollmentVersion: input.record.enrollmentVersion,
    enrollmentSealKeyVersion: input.record.enrollmentSealKeyVersion,
    signingRootId: input.record.signingRootId,
    signingRootVersion: input.record.signingRootVersion,
    recoveryKeyId: input.record.recoveryKeyId,
    ...(input.record.recoveryKeyLabel ? { recoveryKeyLabel: input.record.recoveryKeyLabel } : {}),
    nonceB64u: input.record.nonceB64u,
    wrappedDeviceEnrollmentEscrowB64u: input.record.wrappedDeviceEnrollmentEscrowB64u,
    aadHashB64u: input.record.aadHashB64u,
    issuedAtMs: input.record.issuedAtMs,
    updatedAtMs: input.updatedAtMs,
  };
  switch (input.record.recoveryKeyStatus) {
    case 'active':
      return {
        ...base,
        recoveryKeyStatus: 'active',
      };
    case 'consumed':
      return {
        ...base,
        recoveryKeyStatus: 'consumed',
        consumedAtMs: input.record.consumedAtMs,
      };
    case 'revoked':
      return {
        ...base,
        recoveryKeyStatus: 'revoked',
        revokedAtMs: input.record.revokedAtMs,
      };
  }
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
    case WALLET_EMAIL_OTP_ACTIONS.deviceRecovery:
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
    case WALLET_EMAIL_OTP_ACTIONS.deviceRecovery:
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

function recoveryRotationInputObject(input: unknown): Record<string, unknown> | null {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return null;
  return input as Record<string, unknown>;
}

async function validateEmailOtpRecoveryWrappedEnrollmentEscrowSet(input: {
  readonly records: readonly EmailOtpRecoveryEnrollmentEscrowBoundary[];
  readonly sha256Bytes: EmailOtpRecoveryRotationHash;
}): Promise<
  | { readonly ok: true }
  | { readonly ok: false; readonly code: string; readonly message: string }
> {
  const first = input.records[0];
  if (!first) {
    return {
      ok: false,
      code: 'invalid_body',
      message: `Exactly ${EMAIL_OTP_RECOVERY_KEY_COUNT} recovery-wrapped enrollment escrows are required`,
    };
  }

  const recoveryKeyIds = new Set<string>();
  const nonceB64us = new Set<string>();
  for (const boundary of input.records) {
    if (boundary.record.recoveryKeyStatus !== 'active') {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Recovery-wrapped enrollment escrows must be active at enrollment',
      };
    }
    const record = boundary.record;
    if (recoveryKeyIds.has(record.recoveryKeyId)) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Recovery-wrapped enrollment escrow recoveryKeyId values must be unique',
      };
    }
    recoveryKeyIds.add(record.recoveryKeyId);

    if (nonceB64us.has(record.nonceB64u)) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Recovery-wrapped enrollment escrow nonce values must be unique',
      };
    }
    nonceB64us.add(record.nonceB64u);

    if (!recoveryEnrollmentEscrowsShareScope(record, first.record)) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Recovery-wrapped enrollment escrow metadata must share one enrollment scope',
      };
    }

    const expectedAadHashB64u = base64UrlEncode(
      await input.sha256Bytes(encodeEmailOtpRecoveryWrappedEnrollmentAad(boundary.binding)),
    );
    if (record.aadHashB64u !== expectedAadHashB64u) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Recovery-wrapped enrollment escrow aadHashB64u does not match metadata',
      };
    }
  }

  if (
    recoveryKeyIds.size !== EMAIL_OTP_RECOVERY_KEY_COUNT ||
    nonceB64us.size !== EMAIL_OTP_RECOVERY_KEY_COUNT
  ) {
    return {
      ok: false,
      code: 'invalid_body',
      message: `Exactly ${EMAIL_OTP_RECOVERY_KEY_COUNT} distinct recovery-wrapped enrollment escrows are required`,
    };
  }

  return { ok: true };
}

function recoveryEnrollmentEscrowsShareScope(
  record: EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
  first: EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
): boolean {
  return (
    record.walletId === first.walletId &&
    record.userId === first.userId &&
    record.authSubjectId === first.authSubjectId &&
    record.authMethod === first.authMethod &&
    record.enrollmentId === first.enrollmentId &&
    record.enrollmentVersion === first.enrollmentVersion &&
    record.enrollmentSealKeyVersion === first.enrollmentSealKeyVersion &&
    record.signingRootId === first.signingRootId &&
    record.signingRootVersion === first.signingRootVersion
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
