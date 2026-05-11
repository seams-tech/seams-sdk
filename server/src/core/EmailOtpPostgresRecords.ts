import type { ThresholdRuntimePolicyScope } from './types';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import {
  EMAIL_OTP_CHANNEL,
  WALLET_EMAIL_OTP_ACTIONS,
  WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
  WALLET_EMAIL_OTP_UNLOCK_OPERATION,
  isWalletEmailOtpLoginOperation,
} from '@shared/utils/emailOtpDomain';
import {
  EMAIL_OTP_RECOVERY_WRAP_ALG,
  EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND,
  EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND,
} from '@shared/utils/emailOtpRecoveryKey';
import type {
  EmailOtpAuthStateRecord,
  EmailOtpChallengeRecord,
  EmailOtpGrantRecord,
  EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
  EmailOtpUnlockChallengeRecord,
  EmailOtpWalletEnrollmentRecord,
  GoogleEmailOtpRegistrationAttemptRecord,
} from './EmailOtpStores';

function parseJsonRecord(raw: unknown): unknown {
  if (typeof raw !== 'string') return raw;
  try {
    return JSON.parse(raw);
  } catch {
    return raw;
  }
}

function toPositiveSafeInt(value: unknown): number | null {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) return null;
  return parsed;
}

function toNonNegativeSafeInt(value: unknown): number | null {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) return null;
  return parsed;
}

function parseRuntimePolicyScope(raw: unknown): ThresholdRuntimePolicyScope | undefined {
  const parsed = parseJsonRecord(raw);
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return undefined;
  const obj = parsed as Record<string, unknown>;
  const orgId = toOptionalTrimmedString(obj.orgId);
  const projectId = toOptionalTrimmedString(obj.projectId);
  const envId = toOptionalTrimmedString(obj.envId);
  const signingRootVersion = toOptionalTrimmedString(obj.signingRootVersion);
  if (!orgId || !projectId || !envId || !signingRootVersion) return undefined;
  return { orgId, projectId, envId, signingRootVersion };
}

const EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_FORBIDDEN_FIELDS = Object.freeze([
  'enrollmentEscrowCiphertextB64u',
  'encSB64u',
  'encS',
  'S',
  'secretS',
  'plaintextS',
  'emailOtpSecretS',
  'clientSecret',
  'clientSecret32',
  'clientSecretB64u',
  'clientSecret32B64u',
  'signingSessionSecretB64u',
  'sealedSecretB64u',
  'thresholdSessionAuthToken',
  'recoveryKey',
  'recoveryKeys',
  'recoveryKek',
  'K_recovery_i',
] as const);

function hasOwnRecordField(record: Record<string, unknown>, field: string): boolean {
  return Object.prototype.hasOwnProperty.call(record, field);
}

function isB64uString(value: string): boolean {
  return /^[A-Za-z0-9_-]+$/.test(value);
}

export function parseCurrentEmailOtpChallengeRecord(
  raw: unknown,
): EmailOtpChallengeRecord | null {
  const parsed = parseJsonRecord(raw);
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
  const obj = parsed as Record<string, unknown>;
  const version = toOptionalTrimmedString(obj.version);
  const challengeId = toOptionalTrimmedString(obj.challengeId);
  const userId = toOptionalTrimmedString(obj.userId);
  const walletId = toOptionalTrimmedString(obj.walletId);
  const orgId = toOptionalTrimmedString(obj.orgId) || undefined;
  const otpChannel = toOptionalTrimmedString(obj.otpChannel);
  const email = toOptionalTrimmedString(obj.email);
  const otpCode = toOptionalTrimmedString(obj.otpCode);
  const sessionHash = toOptionalTrimmedString(obj.sessionHash);
  const appSessionVersion = toOptionalTrimmedString(obj.appSessionVersion);
  const action = toOptionalTrimmedString(obj.action);
  const operationRaw = toOptionalTrimmedString(obj.operation);
  const createdAtMs = toPositiveSafeInt(obj.createdAtMs);
  const expiresAtMs = toPositiveSafeInt(obj.expiresAtMs);
  const attemptCount = toNonNegativeSafeInt(obj.attemptCount);
  const maxAttempts = toPositiveSafeInt(obj.maxAttempts);
  if (version !== 'email_otp_challenge_v1') return null;
  if (
    !challengeId ||
    !userId ||
    !walletId ||
    !email ||
    !otpCode ||
    !sessionHash ||
    !appSessionVersion ||
    !action ||
    !operationRaw ||
    !createdAtMs ||
    !expiresAtMs ||
    attemptCount == null ||
    !maxAttempts
  ) {
    return null;
  }
  if (otpChannel !== EMAIL_OTP_CHANNEL) return null;
  if (
    action !== WALLET_EMAIL_OTP_ACTIONS.login &&
    action !== WALLET_EMAIL_OTP_ACTIONS.registration &&
    action !== WALLET_EMAIL_OTP_ACTIONS.deviceRecovery
  ) {
    return null;
  }
  const operation =
    isWalletEmailOtpLoginOperation(operationRaw) ||
    operationRaw === WALLET_EMAIL_OTP_REGISTRATION_OPERATION ||
    operationRaw === WALLET_EMAIL_OTP_UNLOCK_OPERATION
      ? operationRaw
      : null;
  if (!operation) return null;
  return {
    version: 'email_otp_challenge_v1',
    challengeId,
    userId,
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

export function parseCurrentEmailOtpChallengeRow(input: {
  recordJson: unknown;
  expiresAtMs: unknown;
}): EmailOtpChallengeRecord | null {
  const record = parseCurrentEmailOtpChallengeRecord(input.recordJson);
  const expiresAtMs = toPositiveSafeInt(input.expiresAtMs);
  if (!record || !expiresAtMs) return null;
  if (record.expiresAtMs !== expiresAtMs) return null;
  return record;
}

export function parseCurrentEmailOtpGrantRecord(raw: unknown): EmailOtpGrantRecord | null {
  const parsed = parseJsonRecord(raw);
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
  const obj = parsed as Record<string, unknown>;
  const version = toOptionalTrimmedString(obj.version);
  const grantToken = toOptionalTrimmedString(obj.grantToken);
  const userId = toOptionalTrimmedString(obj.userId);
  const walletId = toOptionalTrimmedString(obj.walletId);
  const orgId = toOptionalTrimmedString(obj.orgId) || undefined;
  const challengeId = toOptionalTrimmedString(obj.challengeId);
  const otpChannel = toOptionalTrimmedString(obj.otpChannel);
  const sessionHash = toOptionalTrimmedString(obj.sessionHash);
  const appSessionVersion = toOptionalTrimmedString(obj.appSessionVersion);
  const action = toOptionalTrimmedString(obj.action);
  const issuedAtMs = toPositiveSafeInt(obj.issuedAtMs);
  const expiresAtMs = toPositiveSafeInt(obj.expiresAtMs);
  if (
    version !== 'email_otp_grant_v1' ||
    !grantToken ||
    !userId ||
    !walletId ||
    !challengeId ||
    !sessionHash ||
    !appSessionVersion ||
    !action ||
    !issuedAtMs ||
    !expiresAtMs
  ) {
    return null;
  }
  if (otpChannel !== EMAIL_OTP_CHANNEL) return null;
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

export function parseCurrentEmailOtpGrantRow(input: {
  recordJson: unknown;
  expiresAtMs: unknown;
}): EmailOtpGrantRecord | null {
  const record = parseCurrentEmailOtpGrantRecord(input.recordJson);
  const expiresAtMs = toPositiveSafeInt(input.expiresAtMs);
  if (!record || !expiresAtMs) return null;
  if (record.expiresAtMs !== expiresAtMs) return null;
  return record;
}

export function parseCurrentEmailOtpUnlockChallengeRecord(
  raw: unknown,
): EmailOtpUnlockChallengeRecord | null {
  const parsed = parseJsonRecord(raw);
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
  const obj = parsed as Record<string, unknown>;
  const version = toOptionalTrimmedString(obj.version);
  const challengeId = toOptionalTrimmedString(obj.challengeId);
  const walletId = toOptionalTrimmedString(obj.walletId);
  const userId = toOptionalTrimmedString(obj.userId);
  const orgId = toOptionalTrimmedString(obj.orgId) || undefined;
  const challengeB64u = toOptionalTrimmedString(obj.challengeB64u);
  const createdAtMs = toPositiveSafeInt(obj.createdAtMs);
  const expiresAtMs = toPositiveSafeInt(obj.expiresAtMs);
  if (
    version !== 'email_otp_unlock_challenge_v1' ||
    !challengeId ||
    !walletId ||
    !userId ||
    !challengeB64u ||
    !createdAtMs ||
    !expiresAtMs
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

export function parseCurrentEmailOtpUnlockChallengeRow(input: {
  recordJson: unknown;
  expiresAtMs: unknown;
}): EmailOtpUnlockChallengeRecord | null {
  const record = parseCurrentEmailOtpUnlockChallengeRecord(input.recordJson);
  const expiresAtMs = toPositiveSafeInt(input.expiresAtMs);
  if (!record || !expiresAtMs) return null;
  if (record.expiresAtMs !== expiresAtMs) return null;
  return record;
}

export function parseCurrentGoogleEmailOtpRegistrationAttemptRecord(
  raw: unknown,
): GoogleEmailOtpRegistrationAttemptRecord | null {
  const parsed = parseJsonRecord(raw);
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
  const obj = parsed as Record<string, unknown>;
  const version = toOptionalTrimmedString(obj.version);
  const attemptId = toOptionalTrimmedString(obj.attemptId);
  const providerSubject = toOptionalTrimmedString(obj.providerSubject);
  const email = toOptionalTrimmedString(obj.email);
  const walletId = toOptionalTrimmedString(obj.walletId);
  const authProvider = toOptionalTrimmedString(obj.authProvider);
  const accountIdSlugVersion = toOptionalTrimmedString(obj.accountIdSlugVersion);
  const collisionCounter = toNonNegativeSafeInt(obj.collisionCounter);
  const state = toOptionalTrimmedString(obj.state);
  const createdAtMs = toPositiveSafeInt(obj.createdAtMs);
  const updatedAtMs = toPositiveSafeInt(obj.updatedAtMs);
  const expiresAtMs = toPositiveSafeInt(obj.expiresAtMs);
  const runtimePolicyScope = parseRuntimePolicyScope(obj.runtimePolicyScope);
  const finalizedPublicKey = toOptionalTrimmedString(obj.finalizedPublicKey) || undefined;
  const failureCode = toOptionalTrimmedString(obj.failureCode) || undefined;
  if (
    version !== 'google_email_otp_registration_attempt_v1' ||
    !attemptId ||
    !providerSubject ||
    !email ||
    !walletId ||
    !authProvider ||
    accountIdSlugVersion !== 'hmac_readable_v1' ||
    collisionCounter == null ||
    !state ||
    !createdAtMs ||
    !updatedAtMs ||
    !expiresAtMs
  ) {
    return null;
  }
  if (
    state !== 'started' &&
    state !== 'key_finalized' &&
    state !== 'active' &&
    state !== 'failed' &&
    state !== 'expired'
  ) {
    return null;
  }
  if (updatedAtMs < createdAtMs) return null;
  return {
    version: 'google_email_otp_registration_attempt_v1',
    attemptId,
    providerSubject,
    email,
    walletId,
    authProvider,
    accountIdSlugVersion: 'hmac_readable_v1',
    collisionCounter,
    state,
    createdAtMs,
    updatedAtMs,
    expiresAtMs,
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    ...(finalizedPublicKey ? { finalizedPublicKey } : {}),
    ...(failureCode ? { failureCode } : {}),
  };
}

export function parseCurrentGoogleEmailOtpRegistrationAttemptRow(input: {
  recordJson: unknown;
  expiresAtMs: unknown;
  updatedAtMs: unknown;
}): GoogleEmailOtpRegistrationAttemptRecord | null {
  const record = parseCurrentGoogleEmailOtpRegistrationAttemptRecord(input.recordJson);
  const expiresAtMs = toPositiveSafeInt(input.expiresAtMs);
  const updatedAtMs = toPositiveSafeInt(input.updatedAtMs);
  if (!record || !expiresAtMs || !updatedAtMs) return null;
  if (record.expiresAtMs !== expiresAtMs || record.updatedAtMs !== updatedAtMs) return null;
  return record;
}

export function parseCurrentEmailOtpWalletEnrollmentRecord(
  raw: unknown,
): EmailOtpWalletEnrollmentRecord | null {
  const parsed = parseJsonRecord(raw);
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
  const obj = parsed as Record<string, unknown>;
  if (hasOwnRecordField(obj, 'enrollmentEscrowCiphertextB64u')) return null;
  const version = toOptionalTrimmedString(obj.version);
  const walletId = toOptionalTrimmedString(obj.walletId);
  const providerUserId = toOptionalTrimmedString(obj.providerUserId);
  const orgId = toOptionalTrimmedString(obj.orgId);
  const verifiedEmail = toOptionalTrimmedString(obj.verifiedEmail)?.toLowerCase() || '';
  const enrollmentId = toOptionalTrimmedString(obj.enrollmentId);
  const enrollmentVersion = toOptionalTrimmedString(obj.enrollmentVersion);
  const enrollmentSealKeyVersion = toOptionalTrimmedString(obj.enrollmentSealKeyVersion);
  const signingRootId = toOptionalTrimmedString(obj.signingRootId);
  const signingRootVersion = toOptionalTrimmedString(obj.signingRootVersion);
  const recoveryWrappedEnrollmentEscrowCount = toPositiveSafeInt(
    obj.recoveryWrappedEnrollmentEscrowCount,
  );
  const clientUnlockPublicKeyB64u = toOptionalTrimmedString(obj.clientUnlockPublicKeyB64u);
  const unlockKeyVersion = toOptionalTrimmedString(obj.unlockKeyVersion);
  const thresholdEcdsaClientVerifyingShareB64u = toOptionalTrimmedString(
    obj.thresholdEcdsaClientVerifyingShareB64u,
  );
  const createdAtMs = toPositiveSafeInt(obj.createdAtMs);
  const updatedAtMs = toPositiveSafeInt(obj.updatedAtMs);
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
    !updatedAtMs
  ) {
    return null;
  }
  if (updatedAtMs < createdAtMs) return null;
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

export function parseCurrentEmailOtpWalletEnrollmentRow(input: {
  recordJson: unknown;
  updatedAtMs: unknown;
}): EmailOtpWalletEnrollmentRecord | null {
  const record = parseCurrentEmailOtpWalletEnrollmentRecord(input.recordJson);
  const updatedAtMs = toPositiveSafeInt(input.updatedAtMs);
  if (!record || !updatedAtMs) return null;
  if (record.updatedAtMs !== updatedAtMs) return null;
  return record;
}

export function parseCurrentEmailOtpRecoveryWrappedEnrollmentEscrowRecord(
  raw: unknown,
): EmailOtpRecoveryWrappedEnrollmentEscrowRecord | null {
  const parsed = parseJsonRecord(raw);
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
  const obj = parsed as Record<string, unknown>;
  for (const field of EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_FORBIDDEN_FIELDS) {
    if (hasOwnRecordField(obj, field)) return null;
  }
  const version = toOptionalTrimmedString(obj.version);
  const alg = toOptionalTrimmedString(obj.alg);
  const secretKind = toOptionalTrimmedString(obj.secretKind);
  const escrowKind = toOptionalTrimmedString(obj.escrowKind);
  const walletId = toOptionalTrimmedString(obj.walletId);
  const userId = toOptionalTrimmedString(obj.userId);
  const authSubjectId = toOptionalTrimmedString(obj.authSubjectId);
  const authMethod = toOptionalTrimmedString(obj.authMethod);
  const enrollmentId = toOptionalTrimmedString(obj.enrollmentId);
  const enrollmentVersion = toOptionalTrimmedString(obj.enrollmentVersion);
  const enrollmentSealKeyVersion = toOptionalTrimmedString(obj.enrollmentSealKeyVersion);
  const signingRootId = toOptionalTrimmedString(obj.signingRootId);
  const signingRootVersion = toOptionalTrimmedString(obj.signingRootVersion);
  const recoveryKeyId = toOptionalTrimmedString(obj.recoveryKeyId);
  const recoveryKeyLabel = toOptionalTrimmedString(obj.recoveryKeyLabel) || undefined;
  const recoveryKeyStatus = toOptionalTrimmedString(obj.recoveryKeyStatus);
  const nonceB64u = toOptionalTrimmedString(obj.nonceB64u);
  const wrappedDeviceEnrollmentEscrowB64u = toOptionalTrimmedString(
    obj.wrappedDeviceEnrollmentEscrowB64u,
  );
  const aadHashB64u = toOptionalTrimmedString(obj.aadHashB64u);
  const issuedAtMs = toPositiveSafeInt(obj.issuedAtMs);
  const updatedAtMs = toPositiveSafeInt(obj.updatedAtMs);
  const consumedAtMs =
    obj.consumedAtMs == null ? undefined : toPositiveSafeInt(obj.consumedAtMs) || undefined;
  const revokedAtMs =
    obj.revokedAtMs == null ? undefined : toPositiveSafeInt(obj.revokedAtMs) || undefined;
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
    !updatedAtMs
  ) {
    return null;
  }
  if (
    !isB64uString(nonceB64u) ||
    !isB64uString(wrappedDeviceEnrollmentEscrowB64u) ||
    !isB64uString(aadHashB64u)
  ) {
    return null;
  }
  if (
    recoveryKeyStatus !== 'active' &&
    recoveryKeyStatus !== 'consumed' &&
    recoveryKeyStatus !== 'revoked'
  ) {
    return null;
  }
  if (updatedAtMs < issuedAtMs) return null;
  if (recoveryKeyStatus === 'active' && (consumedAtMs !== undefined || revokedAtMs !== undefined)) {
    return null;
  }
  if (recoveryKeyStatus === 'consumed' && consumedAtMs === undefined) return null;
  if (recoveryKeyStatus === 'revoked' && revokedAtMs === undefined) return null;
  return {
    version: 'email_otp_recovery_wrapped_enrollment_escrow_v1',
    alg: EMAIL_OTP_RECOVERY_WRAP_ALG,
    secretKind: EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND,
    escrowKind: EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND,
    walletId,
    userId,
    authSubjectId,
    authMethod: 'google_sso_email_otp',
    enrollmentId,
    enrollmentVersion,
    enrollmentSealKeyVersion,
    signingRootId,
    signingRootVersion,
    recoveryKeyId,
    ...(recoveryKeyLabel ? { recoveryKeyLabel } : {}),
    recoveryKeyStatus,
    nonceB64u,
    wrappedDeviceEnrollmentEscrowB64u,
    aadHashB64u,
    issuedAtMs,
    updatedAtMs,
    ...(consumedAtMs !== undefined ? { consumedAtMs } : {}),
    ...(revokedAtMs !== undefined ? { revokedAtMs } : {}),
  };
}

export function parseCurrentEmailOtpRecoveryWrappedEnrollmentEscrowRow(input: {
  recordJson: unknown;
  updatedAtMs: unknown;
}): EmailOtpRecoveryWrappedEnrollmentEscrowRecord | null {
  const record = parseCurrentEmailOtpRecoveryWrappedEnrollmentEscrowRecord(input.recordJson);
  const updatedAtMs = toPositiveSafeInt(input.updatedAtMs);
  if (!record || !updatedAtMs) return null;
  if (record.updatedAtMs !== updatedAtMs) return null;
  return record;
}

export function parseCurrentEmailOtpAuthStateRecord(raw: unknown): EmailOtpAuthStateRecord | null {
  const parsed = parseJsonRecord(raw);
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
  const obj = parsed as Record<string, unknown>;
  const version = toOptionalTrimmedString(obj.version);
  const walletId = toOptionalTrimmedString(obj.walletId);
  const providerUserId = toOptionalTrimmedString(obj.providerUserId);
  const orgId = toOptionalTrimmedString(obj.orgId);
  const createdAtMs = toPositiveSafeInt(obj.createdAtMs);
  const updatedAtMs = toPositiveSafeInt(obj.updatedAtMs);
  const otpFailureCount =
    obj.otpFailureCount == null ? undefined : toNonNegativeSafeInt(obj.otpFailureCount);
  const lastOtpFailureAtMs =
    obj.lastOtpFailureAtMs == null ? undefined : toPositiveSafeInt(obj.lastOtpFailureAtMs);
  const otpLockedUntilMs =
    obj.otpLockedUntilMs == null ? undefined : toPositiveSafeInt(obj.otpLockedUntilMs);
  const lastEmailOtpLoginAtMs =
    obj.lastEmailOtpLoginAtMs == null ? undefined : toPositiveSafeInt(obj.lastEmailOtpLoginAtMs);
  const lastStrongAuthAtMs =
    obj.lastStrongAuthAtMs == null ? undefined : toPositiveSafeInt(obj.lastStrongAuthAtMs);
  if (!raw || version !== 'email_otp_auth_state_v1') return null;
  if (!walletId || !providerUserId || !orgId || !createdAtMs || !updatedAtMs) return null;
  if (
    ('otpFailureCount' in obj && obj.otpFailureCount != null && otpFailureCount === undefined) ||
    ('lastOtpFailureAtMs' in obj &&
      obj.lastOtpFailureAtMs != null &&
      lastOtpFailureAtMs === undefined) ||
    ('otpLockedUntilMs' in obj && obj.otpLockedUntilMs != null && otpLockedUntilMs === undefined) ||
    ('lastEmailOtpLoginAtMs' in obj &&
      obj.lastEmailOtpLoginAtMs != null &&
      lastEmailOtpLoginAtMs === undefined) ||
    ('lastStrongAuthAtMs' in obj &&
      obj.lastStrongAuthAtMs != null &&
      lastStrongAuthAtMs === undefined)
  ) {
    return null;
  }
  if (updatedAtMs < createdAtMs) return null;
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

export function parseCurrentEmailOtpAuthStateRow(input: {
  recordJson: unknown;
  updatedAtMs: unknown;
}): EmailOtpAuthStateRecord | null {
  const record = parseCurrentEmailOtpAuthStateRecord(input.recordJson);
  const updatedAtMs = toPositiveSafeInt(input.updatedAtMs);
  if (!record || !updatedAtMs) return null;
  if (record.updatedAtMs !== updatedAtMs) return null;
  return record;
}
