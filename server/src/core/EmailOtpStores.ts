import type { NormalizedLogger } from './logger';
import type { ThresholdRuntimePolicyScope, ThresholdStoreConfigInput } from './types';
import { THRESHOLD_PREFIX_DEFAULT } from './defaultConfigsServer';
import {
  getPostgresPool,
  getPostgresUrlFromConfig,
  parsePostgresRow,
} from '../storage/postgres';
import { isPlainObject, toOptionalTrimmedString } from '@shared/utils/validation';
import {
  parseCurrentEmailOtpAuthStateRecord,
  parseCurrentEmailOtpChallengeRow,
  parseCurrentEmailOtpChallengeRecord,
  parseCurrentEmailOtpAuthStateRow,
  parseCurrentEmailOtpGrantRecord,
  parseCurrentEmailOtpGrantRow,
  parseCurrentEmailOtpRecoveryWrappedEnrollmentEscrowRecord,
  parseCurrentEmailOtpRecoveryWrappedEnrollmentEscrowRow,
  parseCurrentEmailOtpUnlockChallengeRecord,
  parseCurrentEmailOtpUnlockChallengeRow,
  parseCurrentEmailOtpWalletEnrollmentRecord,
  parseCurrentEmailOtpWalletEnrollmentRow,
  parseCurrentGoogleEmailOtpRegistrationAttemptRecord,
  parseCurrentGoogleEmailOtpRegistrationAttemptRow,
} from './EmailOtpPostgresRecords';
import type {
  WalletEmailOtpChannel,
  WalletEmailOtpLoginOperation,
  WalletEmailOtpOperation,
} from '@shared/utils/emailOtpDomain';
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

export type EmailOtpChannel = WalletEmailOtpChannel;
export type EmailOtpGrantAction =
  | typeof WALLET_EMAIL_OTP_ACTIONS.unseal
  | typeof WALLET_EMAIL_OTP_ACTIONS.deviceRecovery;
export type EmailOtpChallengeAction =
  | typeof WALLET_EMAIL_OTP_ACTIONS.login
  | typeof WALLET_EMAIL_OTP_ACTIONS.registration
  | typeof WALLET_EMAIL_OTP_ACTIONS.deviceRecovery;
export type EmailOtpChallengeOperation = WalletEmailOtpOperation;
export type EmailOtpLoginChallengeOperation = WalletEmailOtpLoginOperation;

export type EmailOtpChallengeRecord = {
  version: 'email_otp_challenge_v1';
  challengeId: string;
  userId: string;
  walletId: string;
  orgId?: string;
  otpChannel: EmailOtpChannel;
  email: string;
  otpCode: string;
  sessionHash: string;
  appSessionVersion: string;
  action: EmailOtpChallengeAction;
  operation: EmailOtpChallengeOperation;
  createdAtMs: number;
  expiresAtMs: number;
  attemptCount: number;
  maxAttempts: number;
};

export interface EmailOtpChallengeStore {
  put(record: EmailOtpChallengeRecord): Promise<void>;
  get(challengeId: string): Promise<EmailOtpChallengeRecord | null>;
  deleteExpired(nowMs: number): Promise<EmailOtpChallengeRecord[]>;
  countActiveByContext(input: {
    userId: string;
    walletId: string;
    orgId?: string;
    otpChannel: EmailOtpChannel;
    sessionHash: string;
    appSessionVersion: string;
    action: EmailOtpChallengeAction;
    operation: EmailOtpChallengeOperation;
    nowMs: number;
  }): Promise<number>;
  deleteOldestActiveByContext(input: {
    userId: string;
    walletId: string;
    orgId?: string;
    otpChannel: EmailOtpChannel;
    sessionHash: string;
    appSessionVersion: string;
    action: EmailOtpChallengeAction;
    operation: EmailOtpChallengeOperation;
    nowMs: number;
  }): Promise<EmailOtpChallengeRecord | null>;
  findActiveByContext(input: {
    userId: string;
    walletId: string;
    orgId?: string;
    otpChannel: EmailOtpChannel;
    sessionHash: string;
    appSessionVersion: string;
    action: EmailOtpChallengeAction;
    operation: EmailOtpChallengeOperation;
    otpCode: string;
    nowMs: number;
  }): Promise<EmailOtpChallengeRecord | null>;
  del(challengeId: string): Promise<void>;
}

export type EmailOtpGrantRecord = {
  version: 'email_otp_grant_v1';
  grantToken: string;
  userId: string;
  walletId: string;
  orgId?: string;
  challengeId: string;
  otpChannel: EmailOtpChannel;
  sessionHash: string;
  appSessionVersion: string;
  action: EmailOtpGrantAction;
  issuedAtMs: number;
  expiresAtMs: number;
};

export interface EmailOtpGrantStore {
  put(record: EmailOtpGrantRecord): Promise<void>;
  get(grantToken: string): Promise<EmailOtpGrantRecord | null>;
  consume(grantToken: string): Promise<EmailOtpGrantRecord | null>;
  del(grantToken: string): Promise<void>;
}

export type EmailOtpWalletEnrollmentRecord = {
  version: 'email_otp_wallet_enrollment_v1';
  walletId: string;
  providerUserId: string;
  orgId: string;
  verifiedEmail: string;
  enrollmentId: string;
  enrollmentVersion: string;
  enrollmentSealKeyVersion: string;
  signingRootId: string;
  signingRootVersion: string;
  recoveryWrappedEnrollmentEscrowCount: number;
  clientUnlockPublicKeyB64u: string;
  unlockKeyVersion: string;
  thresholdEcdsaClientVerifyingShareB64u: string;
  createdAtMs: number;
  updatedAtMs: number;
};

export interface EmailOtpWalletEnrollmentStore {
  get(walletId: string): Promise<EmailOtpWalletEnrollmentRecord | null>;
  getByProviderUserId(input: {
    providerUserId: string;
    orgId: string;
  }): Promise<EmailOtpWalletEnrollmentRecord | null>;
  put(record: EmailOtpWalletEnrollmentRecord): Promise<void>;
  del(walletId: string): Promise<void>;
}

export type EmailOtpRecoveryWrappedEnrollmentEscrowStatus = 'active' | 'consumed' | 'revoked';

export type EmailOtpRecoveryWrappedEnrollmentEscrowRecord = {
  version: 'email_otp_recovery_wrapped_enrollment_escrow_v1';
  alg: typeof EMAIL_OTP_RECOVERY_WRAP_ALG;
  secretKind: typeof EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND;
  escrowKind: typeof EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND;
  walletId: string;
  userId: string;
  authSubjectId: string;
  authMethod: 'google_sso_email_otp';
  enrollmentId: string;
  enrollmentVersion: string;
  enrollmentSealKeyVersion: string;
  signingRootId: string;
  signingRootVersion: string;
  recoveryKeyId: string;
  recoveryKeyLabel?: string;
  recoveryKeyStatus: EmailOtpRecoveryWrappedEnrollmentEscrowStatus;
  nonceB64u: string;
  wrappedDeviceEnrollmentEscrowB64u: string;
  aadHashB64u: string;
  issuedAtMs: number;
  updatedAtMs: number;
  consumedAtMs?: number;
  revokedAtMs?: number;
};

export interface EmailOtpRecoveryWrappedEnrollmentEscrowStore {
  get(input: {
    walletId: string;
    recoveryKeyId: string;
  }): Promise<EmailOtpRecoveryWrappedEnrollmentEscrowRecord | null>;
  listActiveByWallet(walletId: string): Promise<EmailOtpRecoveryWrappedEnrollmentEscrowRecord[]>;
  put(record: EmailOtpRecoveryWrappedEnrollmentEscrowRecord): Promise<void>;
  del(input: { walletId: string; recoveryKeyId: string }): Promise<void>;
}

export type EmailOtpAuthStateRecord = {
  version: 'email_otp_auth_state_v1';
  walletId: string;
  providerUserId: string;
  orgId: string;
  createdAtMs: number;
  updatedAtMs: number;
  otpFailureCount?: number;
  lastOtpFailureAtMs?: number;
  otpLockedUntilMs?: number;
  lastEmailOtpLoginAtMs?: number;
  lastStrongAuthAtMs?: number;
};

export interface EmailOtpAuthStateStore {
  get(walletId: string): Promise<EmailOtpAuthStateRecord | null>;
  put(record: EmailOtpAuthStateRecord): Promise<void>;
  del(walletId: string): Promise<void>;
}

export type EmailOtpUnlockChallengeRecord = {
  version: 'email_otp_unlock_challenge_v1';
  challengeId: string;
  walletId: string;
  userId: string;
  orgId?: string;
  challengeB64u: string;
  createdAtMs: number;
  expiresAtMs: number;
};

export interface EmailOtpUnlockChallengeStore {
  put(record: EmailOtpUnlockChallengeRecord): Promise<void>;
  consume(challengeId: string): Promise<EmailOtpUnlockChallengeRecord | null>;
  del(challengeId: string): Promise<void>;
}

export type GoogleEmailOtpRegistrationAttemptState =
  | 'started'
  | 'key_finalized'
  | 'active'
  | 'failed'
  | 'expired';

export type GoogleEmailOtpRegistrationAttemptRecord = {
  version: 'google_email_otp_registration_attempt_v1';
  attemptId: string;
  providerSubject: string;
  email: string;
  walletId: string;
  authProvider: string;
  accountIdSlugVersion: 'hmac_readable_v1';
  walletIdDerivationNonce: string;
  collisionCounter: number;
  state: GoogleEmailOtpRegistrationAttemptState;
  createdAtMs: number;
  updatedAtMs: number;
  expiresAtMs: number;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  finalizedPublicKey?: string;
  failureCode?: string;
};

export interface EmailOtpRegistrationAttemptStore {
  put(record: GoogleEmailOtpRegistrationAttemptRecord): Promise<void>;
  get(attemptId: string): Promise<GoogleEmailOtpRegistrationAttemptRecord | null>;
  findStartedBySubjectEmail(input: {
    providerSubject: string;
    email: string;
    nowMs: number;
  }): Promise<GoogleEmailOtpRegistrationAttemptRecord | null>;
  hasLiveStartedWalletAttempt(input: { walletId: string; nowMs: number }): Promise<boolean>;
  deleteExpired(nowMs: number): Promise<number>;
}

type EmailOtpStoreFactoryInput = {
  config?: ThresholdStoreConfigInput | null;
  logger?: NormalizedLogger;
  isNode?: boolean;
};

function toPrefixWithColon(prefix: unknown, defaultPrefix: string): string {
  const p = toOptionalTrimmedString(prefix);
  if (!p) return defaultPrefix;
  return p.endsWith(':') ? p : `${p}:`;
}

export function resolveEmailOtpStoreNamespace(config: Record<string, unknown>): string {
  const explicit =
    toOptionalTrimmedString(config.EMAIL_OTP_PREFIX) ||
    toOptionalTrimmedString(config.EMAIL_OTP_STORE_PREFIX);
  if (explicit) return toPrefixWithColon(explicit, '');

  const base = toOptionalTrimmedString(config.THRESHOLD_PREFIX) || THRESHOLD_PREFIX_DEFAULT;
  const baseWithColon = toPrefixWithColon(base, `${THRESHOLD_PREFIX_DEFAULT}:`);
  return `${baseWithColon}email-otp:`;
}

function getStoreConfig(input?: EmailOtpStoreFactoryInput): Record<string, unknown> {
  return (isPlainObject(input?.config) ? input.config : {}) as Record<string, unknown>;
}

function resolvePostgresEmailOtpStore(
  input: EmailOtpStoreFactoryInput | undefined,
  storeLabel: string,
): { postgresUrl: string; namespace: string } | null {
  const config = getStoreConfig(input);
  const kind = toOptionalTrimmedString(config.kind);
  const postgresUrl = getPostgresUrlFromConfig(config);
  const shouldUsePostgres = kind === 'postgres' || (!kind && Boolean(postgresUrl));
  if (!shouldUsePostgres) {
    if (kind && kind !== 'in-memory') {
      input?.logger?.warn(
        `[email-otp] ${kind} ${storeLabel} store is not implemented; using in-memory ${storeLabel} store`,
      );
    }
    return null;
  }
  if (input?.isNode === false) {
    throw new Error(`[email-otp] postgres ${storeLabel} store is not supported in this runtime`);
  }
  if (!postgresUrl) {
    throw new Error(`[email-otp] postgres ${storeLabel} store enabled but POSTGRES_URL is not set`);
  }
  return { postgresUrl, namespace: resolveEmailOtpStoreNamespace(config) };
}

function cloneRecord<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function parseJsonRecord(raw: unknown): unknown {
  if (typeof raw !== 'string') return raw;
  try {
    return JSON.parse(raw);
  } catch {
    return raw;
  }
}

function parseChallengeRecord(raw: unknown): EmailOtpChallengeRecord | null {
  raw = parseJsonRecord(raw);
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const obj = raw as Record<string, unknown>;
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
  const createdAtMs = Number(obj.createdAtMs);
  const expiresAtMs = Number(obj.expiresAtMs);
  const attemptCount = Number(obj.attemptCount);
  const maxAttempts = Number(obj.maxAttempts);
  if (version !== 'email_otp_challenge_v1') return null;
  if (!challengeId || !userId || !walletId || !email || !otpCode || !sessionHash) return null;
  if (otpChannel !== EMAIL_OTP_CHANNEL) return null;
  if (
    action !== WALLET_EMAIL_OTP_ACTIONS.login &&
    action !== WALLET_EMAIL_OTP_ACTIONS.registration &&
    action !== WALLET_EMAIL_OTP_ACTIONS.deviceRecovery
  )
    return null;
  const operation: EmailOtpChallengeOperation =
    operationRaw && isWalletEmailOtpLoginOperation(operationRaw)
      ? operationRaw
      : operationRaw === WALLET_EMAIL_OTP_REGISTRATION_OPERATION
        ? operationRaw
        : WALLET_EMAIL_OTP_UNLOCK_OPERATION;
  if (!appSessionVersion) return null;
  if (!Number.isFinite(createdAtMs) || createdAtMs <= 0) return null;
  if (!Number.isFinite(expiresAtMs) || expiresAtMs <= 0) return null;
  if (!Number.isFinite(attemptCount) || attemptCount < 0) return null;
  if (!Number.isFinite(maxAttempts) || maxAttempts <= 0) return null;
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
    createdAtMs: Math.floor(createdAtMs),
    expiresAtMs: Math.floor(expiresAtMs),
    attemptCount: Math.floor(attemptCount),
    maxAttempts: Math.floor(maxAttempts),
  };
}

function challengeContextMatches(
  record: EmailOtpChallengeRecord,
  input: {
    userId: string;
    walletId: string;
    orgId?: string;
    otpChannel: EmailOtpChannel;
    sessionHash: string;
    appSessionVersion: string;
    action: EmailOtpChallengeAction;
    operation: EmailOtpChallengeOperation;
    nowMs: number;
  },
): boolean {
  return (
    record.expiresAtMs > input.nowMs &&
    record.userId === input.userId &&
    record.walletId === input.walletId &&
    String(record.orgId || '') === String(input.orgId || '') &&
    record.otpChannel === input.otpChannel &&
    record.sessionHash === input.sessionHash &&
    record.appSessionVersion === input.appSessionVersion &&
    record.action === input.action &&
    record.operation === input.operation
  );
}

function parseGrantRecord(raw: unknown): EmailOtpGrantRecord | null {
  raw = parseJsonRecord(raw);
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const obj = raw as Record<string, unknown>;
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
  const issuedAtMs = Number(obj.issuedAtMs);
  const expiresAtMs = Number(obj.expiresAtMs);
  if (version !== 'email_otp_grant_v1') return null;
  if (!grantToken || !userId || !walletId || !challengeId || !sessionHash || !appSessionVersion)
    return null;
  if (otpChannel !== EMAIL_OTP_CHANNEL) return null;
  if (
    action !== WALLET_EMAIL_OTP_ACTIONS.unseal &&
    action !== WALLET_EMAIL_OTP_ACTIONS.deviceRecovery
  ) {
    return null;
  }
  if (!Number.isFinite(issuedAtMs) || issuedAtMs <= 0) return null;
  if (!Number.isFinite(expiresAtMs) || expiresAtMs <= 0) return null;
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
    issuedAtMs: Math.floor(issuedAtMs),
    expiresAtMs: Math.floor(expiresAtMs),
  };
}

function parseWalletEnrollmentRecord(raw: unknown): EmailOtpWalletEnrollmentRecord | null {
  raw = parseJsonRecord(raw);
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const obj = raw as Record<string, unknown>;
  const version = toOptionalTrimmedString(obj.version);
  const walletId = toOptionalTrimmedString(obj.walletId);
  const providerUserId = toOptionalTrimmedString(obj.providerUserId);
  const orgId = toOptionalTrimmedString(obj.orgId);
  const verifiedEmail = toOptionalTrimmedString(obj.verifiedEmail)?.toLowerCase() || '';
  if (Object.prototype.hasOwnProperty.call(obj, 'enrollmentEscrowCiphertextB64u')) return null;
  const enrollmentId = toOptionalTrimmedString(obj.enrollmentId);
  const enrollmentVersion = toOptionalTrimmedString(obj.enrollmentVersion);
  const enrollmentSealKeyVersion = toOptionalTrimmedString(obj.enrollmentSealKeyVersion);
  const signingRootId = toOptionalTrimmedString(obj.signingRootId);
  const signingRootVersion = toOptionalTrimmedString(obj.signingRootVersion);
  const recoveryWrappedEnrollmentEscrowCount = Number(obj.recoveryWrappedEnrollmentEscrowCount);
  const clientUnlockPublicKeyB64u = toOptionalTrimmedString(obj.clientUnlockPublicKeyB64u);
  const unlockKeyVersion = toOptionalTrimmedString(obj.unlockKeyVersion);
  const thresholdEcdsaClientVerifyingShareB64u =
    toOptionalTrimmedString(obj.thresholdEcdsaClientVerifyingShareB64u) || '';
  const createdAtMs = Number(obj.createdAtMs);
  const updatedAtMs = Number(obj.updatedAtMs);
  if (version !== 'email_otp_wallet_enrollment_v1') return null;
  if (
    !walletId ||
    !providerUserId ||
    !orgId ||
    !verifiedEmail ||
    !enrollmentId ||
    !enrollmentVersion ||
    !enrollmentSealKeyVersion ||
    !signingRootId ||
    !signingRootVersion
  ) {
    return null;
  }
  if (
    !Number.isFinite(recoveryWrappedEnrollmentEscrowCount) ||
    recoveryWrappedEnrollmentEscrowCount <= 0
  ) {
    return null;
  }
  if (!clientUnlockPublicKeyB64u || !unlockKeyVersion || !thresholdEcdsaClientVerifyingShareB64u) {
    return null;
  }
  if (!Number.isFinite(createdAtMs) || createdAtMs <= 0) return null;
  if (!Number.isFinite(updatedAtMs) || updatedAtMs <= 0) return null;
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
    recoveryWrappedEnrollmentEscrowCount: Math.floor(recoveryWrappedEnrollmentEscrowCount),
    clientUnlockPublicKeyB64u,
    unlockKeyVersion,
    thresholdEcdsaClientVerifyingShareB64u,
    createdAtMs: Math.floor(createdAtMs),
    updatedAtMs: Math.floor(updatedAtMs),
  };
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

export function normalizeEmailOtpRecoveryWrappedEnrollmentEscrowRecord(
  raw: unknown,
): EmailOtpRecoveryWrappedEnrollmentEscrowRecord | null {
  raw = parseJsonRecord(raw);
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const obj = raw as Record<string, unknown>;
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
  const issuedAtMs = Number(obj.issuedAtMs);
  const updatedAtMs = Number(obj.updatedAtMs);
  const consumedAtMs = obj.consumedAtMs == null ? undefined : Number(obj.consumedAtMs);
  const revokedAtMs = obj.revokedAtMs == null ? undefined : Number(obj.revokedAtMs);

  if (version !== 'email_otp_recovery_wrapped_enrollment_escrow_v1') return null;
  if (alg !== EMAIL_OTP_RECOVERY_WRAP_ALG) return null;
  if (secretKind !== EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND) return null;
  if (escrowKind !== EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND) return null;
  if (
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
    !aadHashB64u
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
  if (!Number.isFinite(issuedAtMs) || issuedAtMs <= 0) return null;
  if (!Number.isFinite(updatedAtMs) || updatedAtMs <= 0) return null;
  if (consumedAtMs !== undefined && (!Number.isFinite(consumedAtMs) || consumedAtMs <= 0)) {
    return null;
  }
  if (revokedAtMs !== undefined && (!Number.isFinite(revokedAtMs) || revokedAtMs <= 0)) {
    return null;
  }
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
    issuedAtMs: Math.floor(issuedAtMs),
    updatedAtMs: Math.floor(updatedAtMs),
    ...(consumedAtMs !== undefined ? { consumedAtMs: Math.floor(consumedAtMs) } : {}),
    ...(revokedAtMs !== undefined ? { revokedAtMs: Math.floor(revokedAtMs) } : {}),
  };
}

function parseAuthStateRecord(raw: unknown): EmailOtpAuthStateRecord | null {
  raw = parseJsonRecord(raw);
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const obj = raw as Record<string, unknown>;
  const version = toOptionalTrimmedString(obj.version);
  const walletId = toOptionalTrimmedString(obj.walletId);
  const providerUserId = toOptionalTrimmedString(obj.providerUserId);
  const orgId = toOptionalTrimmedString(obj.orgId);
  const createdAtMs = Number(obj.createdAtMs);
  const updatedAtMs = Number(obj.updatedAtMs);
  const otpFailureCount = obj.otpFailureCount == null ? undefined : Number(obj.otpFailureCount);
  const lastOtpFailureAtMs =
    obj.lastOtpFailureAtMs == null ? undefined : Number(obj.lastOtpFailureAtMs);
  const otpLockedUntilMs = obj.otpLockedUntilMs == null ? undefined : Number(obj.otpLockedUntilMs);
  const lastEmailOtpLoginAtMs =
    obj.lastEmailOtpLoginAtMs == null ? undefined : Number(obj.lastEmailOtpLoginAtMs);
  const lastStrongAuthAtMs =
    obj.lastStrongAuthAtMs == null ? undefined : Number(obj.lastStrongAuthAtMs);
  if (version !== 'email_otp_auth_state_v1') return null;
  if (!walletId || !providerUserId || !orgId) return null;
  if (!Number.isFinite(createdAtMs) || createdAtMs <= 0) return null;
  if (!Number.isFinite(updatedAtMs) || updatedAtMs <= 0) return null;
  if (otpFailureCount != null && (!Number.isFinite(otpFailureCount) || otpFailureCount < 0)) {
    return null;
  }
  if (
    lastOtpFailureAtMs != null &&
    (!Number.isFinite(lastOtpFailureAtMs) || lastOtpFailureAtMs <= 0)
  ) {
    return null;
  }
  if (otpLockedUntilMs != null && (!Number.isFinite(otpLockedUntilMs) || otpLockedUntilMs <= 0)) {
    return null;
  }
  if (
    lastEmailOtpLoginAtMs != null &&
    (!Number.isFinite(lastEmailOtpLoginAtMs) || lastEmailOtpLoginAtMs <= 0)
  ) {
    return null;
  }
  if (
    lastStrongAuthAtMs != null &&
    (!Number.isFinite(lastStrongAuthAtMs) || lastStrongAuthAtMs <= 0)
  ) {
    return null;
  }
  return {
    version: 'email_otp_auth_state_v1',
    walletId,
    providerUserId,
    orgId,
    createdAtMs: Math.floor(createdAtMs),
    updatedAtMs: Math.floor(updatedAtMs),
    ...(otpFailureCount != null ? { otpFailureCount: Math.floor(otpFailureCount) } : {}),
    ...(lastOtpFailureAtMs != null ? { lastOtpFailureAtMs: Math.floor(lastOtpFailureAtMs) } : {}),
    ...(otpLockedUntilMs != null ? { otpLockedUntilMs: Math.floor(otpLockedUntilMs) } : {}),
    ...(lastEmailOtpLoginAtMs != null
      ? { lastEmailOtpLoginAtMs: Math.floor(lastEmailOtpLoginAtMs) }
      : {}),
    ...(lastStrongAuthAtMs != null ? { lastStrongAuthAtMs: Math.floor(lastStrongAuthAtMs) } : {}),
  };
}

function parseUnlockChallengeRecord(raw: unknown): EmailOtpUnlockChallengeRecord | null {
  raw = parseJsonRecord(raw);
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const obj = raw as Record<string, unknown>;
  const version = toOptionalTrimmedString(obj.version);
  const challengeId = toOptionalTrimmedString(obj.challengeId);
  const walletId = toOptionalTrimmedString(obj.walletId);
  const userId = toOptionalTrimmedString(obj.userId);
  const orgId = toOptionalTrimmedString(obj.orgId) || undefined;
  const challengeB64u = toOptionalTrimmedString(obj.challengeB64u);
  const createdAtMs = Number(obj.createdAtMs);
  const expiresAtMs = Number(obj.expiresAtMs);
  if (version !== 'email_otp_unlock_challenge_v1') return null;
  if (!challengeId || !walletId || !userId || !challengeB64u) return null;
  if (!Number.isFinite(createdAtMs) || createdAtMs <= 0) return null;
  if (!Number.isFinite(expiresAtMs) || expiresAtMs <= 0) return null;
  return {
    version: 'email_otp_unlock_challenge_v1',
    challengeId,
    walletId,
    userId,
    ...(orgId ? { orgId } : {}),
    challengeB64u,
    createdAtMs: Math.floor(createdAtMs),
    expiresAtMs: Math.floor(expiresAtMs),
  };
}

function parseRuntimePolicyScope(raw: unknown): ThresholdRuntimePolicyScope | undefined {
  raw = parseJsonRecord(raw);
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return undefined;
  const obj = raw as Record<string, unknown>;
  const orgId = toOptionalTrimmedString(obj.orgId);
  const projectId = toOptionalTrimmedString(obj.projectId);
  const envId = toOptionalTrimmedString(obj.envId);
  const signingRootVersion = toOptionalTrimmedString(obj.signingRootVersion);
  if (!orgId || !projectId || !envId || !signingRootVersion) return undefined;
  return { orgId, projectId, envId, signingRootVersion };
}

function parseRegistrationAttemptRecord(
  raw: unknown,
): GoogleEmailOtpRegistrationAttemptRecord | null {
  raw = parseJsonRecord(raw);
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const obj = raw as Record<string, unknown>;
  const version = toOptionalTrimmedString(obj.version);
  const attemptId = toOptionalTrimmedString(obj.attemptId);
  const providerSubject = toOptionalTrimmedString(obj.providerSubject);
  const email = toOptionalTrimmedString(obj.email);
  const walletId = toOptionalTrimmedString(obj.walletId);
  const authProvider = toOptionalTrimmedString(obj.authProvider) || 'google_oidc';
  const accountIdSlugVersion =
    toOptionalTrimmedString(obj.accountIdSlugVersion) || 'hmac_readable_v1';
  const walletIdDerivationNonce = toOptionalTrimmedString(obj.walletIdDerivationNonce);
  const collisionCounter = Math.max(0, Math.floor(Number(obj.collisionCounter) || 0));
  const state = toOptionalTrimmedString(obj.state);
  const createdAtMs = Number(obj.createdAtMs);
  const updatedAtMs = Number(obj.updatedAtMs);
  const expiresAtMs = Number(obj.expiresAtMs);
  const runtimePolicyScope = parseRuntimePolicyScope(obj.runtimePolicyScope);
  const finalizedPublicKey = toOptionalTrimmedString(obj.finalizedPublicKey) || undefined;
  const failureCode = toOptionalTrimmedString(obj.failureCode) || undefined;
  if (version !== 'google_email_otp_registration_attempt_v1') return null;
  if (!attemptId || !providerSubject || !email || !walletId) return null;
  if (accountIdSlugVersion !== 'hmac_readable_v1') return null;
  if (!walletIdDerivationNonce) return null;
  if (
    state !== 'started' &&
    state !== 'key_finalized' &&
    state !== 'active' &&
    state !== 'failed' &&
    state !== 'expired'
  ) {
    return null;
  }
  if (!Number.isFinite(createdAtMs) || createdAtMs <= 0) return null;
  if (!Number.isFinite(updatedAtMs) || updatedAtMs <= 0) return null;
  if (!Number.isFinite(expiresAtMs) || expiresAtMs <= 0) return null;
  return {
    version: 'google_email_otp_registration_attempt_v1',
    attemptId,
    providerSubject,
    email,
    walletId,
    authProvider,
    accountIdSlugVersion,
    walletIdDerivationNonce,
    collisionCounter,
    state,
    createdAtMs: Math.floor(createdAtMs),
    updatedAtMs: Math.floor(updatedAtMs),
    expiresAtMs: Math.floor(expiresAtMs),
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    ...(finalizedPublicKey ? { finalizedPublicKey } : {}),
    ...(failureCode ? { failureCode } : {}),
  };
}

class InMemoryEmailOtpChallengeStore implements EmailOtpChallengeStore {
  private readonly map = new Map<string, EmailOtpChallengeRecord>();

  async put(record: EmailOtpChallengeRecord): Promise<void> {
    const parsed = parseCurrentEmailOtpChallengeRecord(record);
    if (!parsed) throw new Error('Invalid Email OTP challenge record');
    this.map.set(parsed.challengeId, cloneRecord(parsed));
  }

  async get(challengeId: string): Promise<EmailOtpChallengeRecord | null> {
    const id = toOptionalTrimmedString(challengeId);
    if (!id) return null;
    const record = this.map.get(id);
    return record ? cloneRecord(record) : null;
  }

  async deleteExpired(nowMs: number): Promise<EmailOtpChallengeRecord[]> {
    const deleted: EmailOtpChallengeRecord[] = [];
    for (const [challengeId, record] of this.map.entries()) {
      if (record.expiresAtMs > nowMs) continue;
      this.map.delete(challengeId);
      deleted.push(cloneRecord(record));
    }
    return deleted;
  }

  async countActiveByContext(input: {
    userId: string;
    walletId: string;
    orgId?: string;
    otpChannel: EmailOtpChannel;
    sessionHash: string;
    appSessionVersion: string;
    action: EmailOtpChallengeAction;
    operation: EmailOtpChallengeOperation;
    nowMs: number;
  }): Promise<number> {
    let count = 0;
    for (const record of this.map.values()) {
      if (!challengeContextMatches(record, input)) continue;
      count += 1;
    }
    return count;
  }

  async deleteOldestActiveByContext(input: {
    userId: string;
    walletId: string;
    orgId?: string;
    otpChannel: EmailOtpChannel;
    sessionHash: string;
    appSessionVersion: string;
    action: EmailOtpChallengeAction;
    operation: EmailOtpChallengeOperation;
    nowMs: number;
  }): Promise<EmailOtpChallengeRecord | null> {
    let oldest: EmailOtpChallengeRecord | null = null;
    for (const record of this.map.values()) {
      if (!challengeContextMatches(record, input)) continue;
      if (!oldest || record.createdAtMs < oldest.createdAtMs) oldest = record;
    }
    if (!oldest) return null;
    this.map.delete(oldest.challengeId);
    return cloneRecord(oldest);
  }

  async findActiveByContext(input: {
    userId: string;
    walletId: string;
    orgId?: string;
    otpChannel: EmailOtpChannel;
    sessionHash: string;
    appSessionVersion: string;
    action: EmailOtpChallengeAction;
    operation: EmailOtpChallengeOperation;
    otpCode: string;
    nowMs: number;
  }): Promise<EmailOtpChallengeRecord | null> {
    for (const record of this.map.values()) {
      if (!challengeContextMatches(record, input)) continue;
      if (record.otpCode !== input.otpCode) continue;
      return cloneRecord(record);
    }
    return null;
  }

  async del(challengeId: string): Promise<void> {
    const id = toOptionalTrimmedString(challengeId);
    if (!id) return;
    this.map.delete(id);
  }
}

class InMemoryEmailOtpGrantStore implements EmailOtpGrantStore {
  private readonly map = new Map<string, EmailOtpGrantRecord>();

  async put(record: EmailOtpGrantRecord): Promise<void> {
    const parsed = parseCurrentEmailOtpGrantRecord(record);
    if (!parsed) throw new Error('Invalid Email OTP grant record');
    this.map.set(parsed.grantToken, cloneRecord(parsed));
  }

  async get(grantToken: string): Promise<EmailOtpGrantRecord | null> {
    const token = toOptionalTrimmedString(grantToken);
    if (!token) return null;
    const record = this.map.get(token);
    return record ? cloneRecord(record) : null;
  }

  async consume(grantToken: string): Promise<EmailOtpGrantRecord | null> {
    const token = toOptionalTrimmedString(grantToken);
    if (!token) return null;
    const record = this.map.get(token);
    this.map.delete(token);
    return record ? cloneRecord(record) : null;
  }

  async del(grantToken: string): Promise<void> {
    const token = toOptionalTrimmedString(grantToken);
    if (!token) return;
    this.map.delete(token);
  }
}

class InMemoryEmailOtpWalletEnrollmentStore implements EmailOtpWalletEnrollmentStore {
  private readonly map = new Map<string, EmailOtpWalletEnrollmentRecord>();

  async get(walletId: string): Promise<EmailOtpWalletEnrollmentRecord | null> {
    const key = toOptionalTrimmedString(walletId);
    if (!key) return null;
    const record = this.map.get(key);
    return record ? cloneRecord(record) : null;
  }

  async getByProviderUserId(input: {
    providerUserId: string;
    orgId: string;
  }): Promise<EmailOtpWalletEnrollmentRecord | null> {
    const providerUserId = toOptionalTrimmedString(input.providerUserId);
    const orgId = toOptionalTrimmedString(input.orgId);
    if (!providerUserId || !orgId) return null;
    const record =
      Array.from(this.map.values()).find(
        (candidate) => candidate.providerUserId === providerUserId && candidate.orgId === orgId,
      ) || null;
    return record ? cloneRecord(record) : null;
  }

  async put(record: EmailOtpWalletEnrollmentRecord): Promise<void> {
    const parsed = parseCurrentEmailOtpWalletEnrollmentRecord(record);
    if (!parsed) throw new Error('Invalid Email OTP wallet enrollment record');
    const duplicate = Array.from(this.map.values()).find(
      (existing) =>
        existing.walletId !== parsed.walletId &&
        existing.orgId === parsed.orgId &&
        existing.providerUserId === parsed.providerUserId,
    );
    if (duplicate) {
      throw new Error('Email OTP wallet enrollment already exists for this provider user in org');
    }
    this.map.set(parsed.walletId, cloneRecord(parsed));
  }

  async del(walletId: string): Promise<void> {
    const key = toOptionalTrimmedString(walletId);
    if (!key) return;
    this.map.delete(key);
  }
}

class InMemoryEmailOtpRecoveryWrappedEnrollmentEscrowStore implements EmailOtpRecoveryWrappedEnrollmentEscrowStore {
  private readonly map = new Map<string, EmailOtpRecoveryWrappedEnrollmentEscrowRecord>();

  private key(input: { walletId: string; recoveryKeyId: string }): string {
    return `${input.walletId}\u0000${input.recoveryKeyId}`;
  }

  async get(input: {
    walletId: string;
    recoveryKeyId: string;
  }): Promise<EmailOtpRecoveryWrappedEnrollmentEscrowRecord | null> {
    const walletId = toOptionalTrimmedString(input.walletId);
    const recoveryKeyId = toOptionalTrimmedString(input.recoveryKeyId);
    if (!walletId || !recoveryKeyId) return null;
    const record = this.map.get(this.key({ walletId, recoveryKeyId }));
    return record ? cloneRecord(record) : null;
  }

  async listActiveByWallet(
    walletId: string,
  ): Promise<EmailOtpRecoveryWrappedEnrollmentEscrowRecord[]> {
    const key = toOptionalTrimmedString(walletId);
    if (!key) return [];
    return Array.from(this.map.values())
      .filter((record) => record.walletId === key && record.recoveryKeyStatus === 'active')
      .map((record) => cloneRecord(record));
  }

  async put(record: EmailOtpRecoveryWrappedEnrollmentEscrowRecord): Promise<void> {
    const parsed = parseCurrentEmailOtpRecoveryWrappedEnrollmentEscrowRecord(record);
    if (!parsed) throw new Error('Invalid Email OTP recovery-wrapped enrollment escrow record');
    this.map.set(this.key(parsed), cloneRecord(parsed));
  }

  async del(input: { walletId: string; recoveryKeyId: string }): Promise<void> {
    const walletId = toOptionalTrimmedString(input.walletId);
    const recoveryKeyId = toOptionalTrimmedString(input.recoveryKeyId);
    if (!walletId || !recoveryKeyId) return;
    this.map.delete(this.key({ walletId, recoveryKeyId }));
  }
}

class InMemoryEmailOtpAuthStateStore implements EmailOtpAuthStateStore {
  private readonly map = new Map<string, EmailOtpAuthStateRecord>();

  async get(walletId: string): Promise<EmailOtpAuthStateRecord | null> {
    const key = toOptionalTrimmedString(walletId);
    if (!key) return null;
    const record = this.map.get(key);
    return record ? cloneRecord(record) : null;
  }

  async put(record: EmailOtpAuthStateRecord): Promise<void> {
    const parsed = parseCurrentEmailOtpAuthStateRecord(record);
    if (!parsed) throw new Error('Invalid Email OTP auth state record');
    this.map.set(parsed.walletId, cloneRecord(parsed));
  }

  async del(walletId: string): Promise<void> {
    const key = toOptionalTrimmedString(walletId);
    if (!key) return;
    this.map.delete(key);
  }
}

class InMemoryEmailOtpUnlockChallengeStore implements EmailOtpUnlockChallengeStore {
  private readonly map = new Map<string, EmailOtpUnlockChallengeRecord>();

  async put(record: EmailOtpUnlockChallengeRecord): Promise<void> {
    const parsed = parseCurrentEmailOtpUnlockChallengeRecord(record);
    if (!parsed) throw new Error('Invalid Email OTP unlock challenge record');
    this.map.set(parsed.challengeId, cloneRecord(parsed));
  }

  async consume(challengeId: string): Promise<EmailOtpUnlockChallengeRecord | null> {
    const id = toOptionalTrimmedString(challengeId);
    if (!id) return null;
    const record = this.map.get(id);
    this.map.delete(id);
    return record ? cloneRecord(record) : null;
  }

  async del(challengeId: string): Promise<void> {
    const id = toOptionalTrimmedString(challengeId);
    if (!id) return;
    this.map.delete(id);
  }
}

class InMemoryEmailOtpRegistrationAttemptStore implements EmailOtpRegistrationAttemptStore {
  private readonly map = new Map<string, GoogleEmailOtpRegistrationAttemptRecord>();

  async put(record: GoogleEmailOtpRegistrationAttemptRecord): Promise<void> {
    const parsed = parseCurrentGoogleEmailOtpRegistrationAttemptRecord(record);
    if (!parsed) throw new Error('Invalid Google Email OTP registration attempt record');
    this.map.set(parsed.attemptId, cloneRecord(parsed));
  }

  async get(attemptId: string): Promise<GoogleEmailOtpRegistrationAttemptRecord | null> {
    const id = toOptionalTrimmedString(attemptId);
    if (!id) return null;
    const record = this.map.get(id);
    return record ? cloneRecord(record) : null;
  }

  async findStartedBySubjectEmail(input: {
    providerSubject: string;
    email: string;
    nowMs: number;
  }): Promise<GoogleEmailOtpRegistrationAttemptRecord | null> {
    for (const record of this.map.values()) {
      if (
        record.providerSubject === input.providerSubject &&
        record.email === input.email &&
        record.state === 'started' &&
        record.expiresAtMs > input.nowMs
      ) {
        return cloneRecord(record);
      }
    }
    return null;
  }

  async hasLiveStartedWalletAttempt(input: { walletId: string; nowMs: number }): Promise<boolean> {
    for (const record of this.map.values()) {
      if (
        record.walletId === input.walletId &&
        record.state === 'started' &&
        record.expiresAtMs > input.nowMs
      ) {
        return true;
      }
    }
    return false;
  }

  async deleteExpired(nowMs: number): Promise<number> {
    let deleted = 0;
    for (const [attemptId, record] of this.map.entries()) {
      if (record.expiresAtMs <= nowMs || record.state === 'expired') {
        this.map.delete(attemptId);
        deleted += 1;
      }
    }
    return deleted;
  }
}

class PostgresEmailOtpChallengeStore implements EmailOtpChallengeStore {
  private readonly poolPromise: Promise<Awaited<ReturnType<typeof getPostgresPool>>>;
  private readonly namespace: string;

  constructor(input: { postgresUrl: string; namespace: string }) {
    this.poolPromise = getPostgresPool(input.postgresUrl);
    this.namespace = input.namespace;
  }

  async put(record: EmailOtpChallengeRecord): Promise<void> {
    const parsed = parseCurrentEmailOtpChallengeRecord(record);
    if (!parsed) throw new Error('Invalid Email OTP challenge record');
    const pool = await this.poolPromise;
    await pool.query(
      `
        INSERT INTO email_otp_challenges (namespace, challenge_id, record_json, expires_at_ms)
        VALUES ($1, $2, $3::jsonb, $4)
        ON CONFLICT (namespace, challenge_id)
        DO UPDATE SET record_json = EXCLUDED.record_json, expires_at_ms = EXCLUDED.expires_at_ms
      `,
      [this.namespace, parsed.challengeId, JSON.stringify(parsed), parsed.expiresAtMs],
    );
  }

  async get(challengeId: string): Promise<EmailOtpChallengeRecord | null> {
    const id = toOptionalTrimmedString(challengeId);
    if (!id) return null;
    const pool = await this.poolPromise;
    const { rows } = await pool.query(
      `
        SELECT record_json, expires_at_ms, challenge_id
        FROM email_otp_challenges
        WHERE namespace = $1 AND challenge_id = $2
      `,
      [this.namespace, id],
    );
    const parsed = parsePostgresRow({
      row: rows[0],
      parser: (row) =>
        parseCurrentEmailOtpChallengeRow({
          recordJson: row.record_json,
          expiresAtMs: row.expires_at_ms,
        }),
    });
    if (parsed.kind === 'missing') {
      return null;
    }
    if (parsed.kind === 'malformed') {
      await this.del(id);
      return null;
    }
    return cloneRecord(parsed.value);
  }

  async deleteExpired(nowMs: number): Promise<EmailOtpChallengeRecord[]> {
    const pool = await this.poolPromise;
    const { rows } = await pool.query(
      `
        DELETE FROM email_otp_challenges
        WHERE namespace = $1 AND expires_at_ms <= $2
        RETURNING record_json, expires_at_ms
      `,
      [this.namespace, nowMs],
    );
    return rows
      .map((row) =>
        parseCurrentEmailOtpChallengeRow({
          recordJson: row.record_json,
          expiresAtMs: row.expires_at_ms,
        }),
      )
      .filter((record): record is EmailOtpChallengeRecord => Boolean(record))
      .map((record) => cloneRecord(record));
  }

  async countActiveByContext(input: {
    userId: string;
    walletId: string;
    orgId?: string;
    otpChannel: EmailOtpChannel;
    sessionHash: string;
    appSessionVersion: string;
    action: EmailOtpChallengeAction;
    operation: EmailOtpChallengeOperation;
    nowMs: number;
  }): Promise<number> {
    const pool = await this.poolPromise;
    const { rows } = await pool.query(
      `
        SELECT COUNT(*) AS count
        FROM email_otp_challenges
        WHERE namespace = $1
          AND expires_at_ms > $2
          AND record_json->>'userId' = $3
          AND record_json->>'walletId' = $4
          AND COALESCE(record_json->>'orgId', '') = $5
          AND record_json->>'otpChannel' = $6
          AND record_json->>'sessionHash' = $7
          AND record_json->>'appSessionVersion' = $8
          AND record_json->>'action' = $9
          AND record_json->>'operation' = $10
      `,
      [
        this.namespace,
        input.nowMs,
        input.userId,
        input.walletId,
        String(input.orgId || ''),
        input.otpChannel,
        input.sessionHash,
        input.appSessionVersion,
        input.action,
        input.operation,
      ],
    );
    return Number(rows[0]?.count || 0);
  }

  async deleteOldestActiveByContext(input: {
    userId: string;
    walletId: string;
    orgId?: string;
    otpChannel: EmailOtpChannel;
    sessionHash: string;
    appSessionVersion: string;
    action: EmailOtpChallengeAction;
    operation: EmailOtpChallengeOperation;
    nowMs: number;
  }): Promise<EmailOtpChallengeRecord | null> {
    const pool = await this.poolPromise;
    const { rows } = await pool.query(
      `
        WITH oldest AS (
          SELECT challenge_id
          FROM email_otp_challenges
          WHERE namespace = $1
            AND expires_at_ms > $2
            AND record_json->>'userId' = $3
            AND record_json->>'walletId' = $4
            AND COALESCE(record_json->>'orgId', '') = $5
            AND record_json->>'otpChannel' = $6
            AND record_json->>'sessionHash' = $7
            AND record_json->>'appSessionVersion' = $8
            AND record_json->>'action' = $9
            AND record_json->>'operation' = $10
          ORDER BY (record_json->>'createdAtMs')::bigint ASC, expires_at_ms ASC
          LIMIT 1
        )
        DELETE FROM email_otp_challenges
        WHERE namespace = $1 AND challenge_id IN (SELECT challenge_id FROM oldest)
        RETURNING record_json, expires_at_ms
      `,
      [
        this.namespace,
        input.nowMs,
        input.userId,
        input.walletId,
        String(input.orgId || ''),
        input.otpChannel,
        input.sessionHash,
        input.appSessionVersion,
        input.action,
        input.operation,
      ],
    );
    const parsed = parsePostgresRow({
      row: rows[0],
      parser: (row) =>
        parseCurrentEmailOtpChallengeRow({
          recordJson: row.record_json,
          expiresAtMs: row.expires_at_ms,
        }),
    });
    if (parsed.kind === 'missing') {
      return null;
    }
    if (parsed.kind === 'malformed') {
      const challengeId = toOptionalTrimmedString(
        (rows[0] as { challenge_id?: unknown } | undefined)?.challenge_id,
      );
      if (challengeId) await this.del(challengeId);
      return null;
    }
    return cloneRecord(parsed.value);
  }

  async findActiveByContext(input: {
    userId: string;
    walletId: string;
    orgId?: string;
    otpChannel: EmailOtpChannel;
    sessionHash: string;
    appSessionVersion: string;
    action: EmailOtpChallengeAction;
    operation: EmailOtpChallengeOperation;
    otpCode: string;
    nowMs: number;
  }): Promise<EmailOtpChallengeRecord | null> {
    const pool = await this.poolPromise;
    const { rows } = await pool.query(
      `
        SELECT record_json, expires_at_ms, challenge_id
        FROM email_otp_challenges
        WHERE namespace = $1
          AND expires_at_ms > $2
          AND record_json->>'userId' = $3
          AND record_json->>'walletId' = $4
          AND COALESCE(record_json->>'orgId', '') = $5
          AND record_json->>'otpChannel' = $6
          AND record_json->>'sessionHash' = $7
          AND record_json->>'appSessionVersion' = $8
          AND record_json->>'action' = $9
          AND record_json->>'operation' = $10
          AND record_json->>'otpCode' = $11
        ORDER BY expires_at_ms DESC
        LIMIT 1
      `,
      [
        this.namespace,
        input.nowMs,
        input.userId,
        input.walletId,
        String(input.orgId || ''),
        input.otpChannel,
        input.sessionHash,
        input.appSessionVersion,
        input.action,
        input.operation,
        input.otpCode,
      ],
    );
    const parsed = parsePostgresRow({
      row: rows[0],
      parser: (row) =>
        parseCurrentEmailOtpChallengeRow({
          recordJson: row.record_json,
          expiresAtMs: row.expires_at_ms,
        }),
    });
    if (parsed.kind === 'current') {
      return cloneRecord(parsed.value);
    }
    if (parsed.kind === 'malformed') {
      const challengeId = toOptionalTrimmedString(
        (rows[0] as { challenge_id?: unknown } | undefined)?.challenge_id,
      );
      if (challengeId) await this.del(challengeId);
    }
    return null;
  }

  async del(challengeId: string): Promise<void> {
    const id = toOptionalTrimmedString(challengeId);
    if (!id) return;
    const pool = await this.poolPromise;
    await pool.query(
      'DELETE FROM email_otp_challenges WHERE namespace = $1 AND challenge_id = $2',
      [this.namespace, id],
    );
  }
}

class PostgresEmailOtpGrantStore implements EmailOtpGrantStore {
  private readonly poolPromise: Promise<Awaited<ReturnType<typeof getPostgresPool>>>;
  private readonly namespace: string;

  constructor(input: { postgresUrl: string; namespace: string }) {
    this.poolPromise = getPostgresPool(input.postgresUrl);
    this.namespace = input.namespace;
  }

  async put(record: EmailOtpGrantRecord): Promise<void> {
    const parsed = parseCurrentEmailOtpGrantRecord(record);
    if (!parsed) throw new Error('Invalid Email OTP grant record');
    const pool = await this.poolPromise;
    await pool.query(
      `
        INSERT INTO email_otp_grants (namespace, grant_token, record_json, expires_at_ms)
        VALUES ($1, $2, $3::jsonb, $4)
        ON CONFLICT (namespace, grant_token)
        DO UPDATE SET record_json = EXCLUDED.record_json, expires_at_ms = EXCLUDED.expires_at_ms
      `,
      [this.namespace, parsed.grantToken, JSON.stringify(parsed), parsed.expiresAtMs],
    );
  }

  async consume(grantToken: string): Promise<EmailOtpGrantRecord | null> {
    const token = toOptionalTrimmedString(grantToken);
    if (!token) return null;
    const pool = await this.poolPromise;
    const { rows } = await pool.query(
      `
        DELETE FROM email_otp_grants
        WHERE namespace = $1 AND grant_token = $2
        RETURNING record_json, expires_at_ms
      `,
      [this.namespace, token],
    );
    const parsed = parsePostgresRow({
      row: rows[0],
      parser: (row) =>
        parseCurrentEmailOtpGrantRow({
          recordJson: row.record_json,
          expiresAtMs: row.expires_at_ms,
        }),
    });
    if (parsed.kind !== 'current') return null;
    return cloneRecord(parsed.value);
  }

  async get(grantToken: string): Promise<EmailOtpGrantRecord | null> {
    const token = toOptionalTrimmedString(grantToken);
    if (!token) return null;
    const pool = await this.poolPromise;
    const { rows } = await pool.query(
      `
        SELECT record_json, expires_at_ms
        FROM email_otp_grants
        WHERE namespace = $1 AND grant_token = $2
      `,
      [this.namespace, token],
    );
    const parsed = parsePostgresRow({
      row: rows[0],
      parser: (row) =>
        parseCurrentEmailOtpGrantRow({
          recordJson: row.record_json,
          expiresAtMs: row.expires_at_ms,
        }),
    });
    if (parsed.kind === 'missing') {
      return null;
    }
    if (parsed.kind === 'malformed') {
      await this.del(token);
      return null;
    }
    return cloneRecord(parsed.value);
  }

  async del(grantToken: string): Promise<void> {
    const token = toOptionalTrimmedString(grantToken);
    if (!token) return;
    const pool = await this.poolPromise;
    await pool.query('DELETE FROM email_otp_grants WHERE namespace = $1 AND grant_token = $2', [
      this.namespace,
      token,
    ]);
  }
}

class PostgresEmailOtpWalletEnrollmentStore implements EmailOtpWalletEnrollmentStore {
  private readonly poolPromise: Promise<Awaited<ReturnType<typeof getPostgresPool>>>;
  private readonly namespace: string;

  constructor(input: { postgresUrl: string; namespace: string }) {
    this.poolPromise = getPostgresPool(input.postgresUrl);
    this.namespace = input.namespace;
  }

  async get(walletId: string): Promise<EmailOtpWalletEnrollmentRecord | null> {
    const key = toOptionalTrimmedString(walletId);
    if (!key) return null;
    const pool = await this.poolPromise;
    const { rows } = await pool.query(
      `
        SELECT record_json, updated_at_ms, wallet_id
        FROM email_otp_wallet_enrollments
        WHERE namespace = $1 AND wallet_id = $2
      `,
      [this.namespace, key],
    );
    const parsed = parsePostgresRow({
      row: rows[0],
      parser: (row) =>
        parseCurrentEmailOtpWalletEnrollmentRow({
          recordJson: row.record_json,
          updatedAtMs: row.updated_at_ms,
        }),
    });
    if (parsed.kind === 'missing') {
      return null;
    }
    if (parsed.kind === 'malformed') {
      await this.del(key);
      return null;
    }
    return cloneRecord(parsed.value);
  }

  async getByProviderUserId(input: {
    providerUserId: string;
    orgId: string;
  }): Promise<EmailOtpWalletEnrollmentRecord | null> {
    const providerUserId = toOptionalTrimmedString(input.providerUserId);
    const orgId = toOptionalTrimmedString(input.orgId);
    if (!providerUserId || !orgId) return null;
    const pool = await this.poolPromise;
    const { rows } = await pool.query(
      `
        SELECT record_json, updated_at_ms, wallet_id
        FROM email_otp_wallet_enrollments
        WHERE namespace = $1
          AND org_id = $2
          AND record_json->>'providerUserId' = $3
        ORDER BY updated_at_ms DESC
        LIMIT 1
      `,
      [this.namespace, orgId, providerUserId],
    );
    const parsed = parsePostgresRow({
      row: rows[0],
      parser: (row) =>
        parseCurrentEmailOtpWalletEnrollmentRow({
          recordJson: row.record_json,
          updatedAtMs: row.updated_at_ms,
        }),
    });
    if (parsed.kind === 'missing') {
      return null;
    }
    if (parsed.kind === 'malformed') {
      const walletId = toOptionalTrimmedString(
        (rows[0] as { wallet_id?: unknown } | undefined)?.wallet_id,
      );
      if (walletId) await this.del(walletId);
      return null;
    }
    return cloneRecord(parsed.value);
  }

  async put(record: EmailOtpWalletEnrollmentRecord): Promise<void> {
    const parsed = parseCurrentEmailOtpWalletEnrollmentRecord(record);
    if (!parsed) throw new Error('Invalid Email OTP wallet enrollment record');
    const pool = await this.poolPromise;
    await pool.query(
      `
        INSERT INTO email_otp_wallet_enrollments (namespace, wallet_id, org_id, record_json, updated_at_ms)
        VALUES ($1, $2, $3, $4::jsonb, $5)
        ON CONFLICT (namespace, wallet_id)
        DO UPDATE SET
          org_id = EXCLUDED.org_id,
          record_json = EXCLUDED.record_json,
          updated_at_ms = EXCLUDED.updated_at_ms
      `,
      [this.namespace, parsed.walletId, parsed.orgId, JSON.stringify(parsed), parsed.updatedAtMs],
    );
  }

  async del(walletId: string): Promise<void> {
    const key = toOptionalTrimmedString(walletId);
    if (!key) return;
    const pool = await this.poolPromise;
    await pool.query(
      'DELETE FROM email_otp_wallet_enrollments WHERE namespace = $1 AND wallet_id = $2',
      [this.namespace, key],
    );
  }
}

class PostgresEmailOtpRecoveryWrappedEnrollmentEscrowStore implements EmailOtpRecoveryWrappedEnrollmentEscrowStore {
  private readonly poolPromise: Promise<Awaited<ReturnType<typeof getPostgresPool>>>;
  private readonly namespace: string;

  constructor(input: { postgresUrl: string; namespace: string }) {
    this.poolPromise = getPostgresPool(input.postgresUrl);
    this.namespace = input.namespace;
  }

  async get(input: {
    walletId: string;
    recoveryKeyId: string;
  }): Promise<EmailOtpRecoveryWrappedEnrollmentEscrowRecord | null> {
    const walletId = toOptionalTrimmedString(input.walletId);
    const recoveryKeyId = toOptionalTrimmedString(input.recoveryKeyId);
    if (!walletId || !recoveryKeyId) return null;
    const pool = await this.poolPromise;
    const { rows } = await pool.query(
      `
        SELECT record_json, updated_at_ms, recovery_key_id
        FROM email_otp_recovery_wrapped_enrollment_escrows
        WHERE namespace = $1 AND wallet_id = $2 AND recovery_key_id = $3
      `,
      [this.namespace, walletId, recoveryKeyId],
    );
    const parsed = parsePostgresRow({
      row: rows[0],
      parser: (row) =>
        parseCurrentEmailOtpRecoveryWrappedEnrollmentEscrowRow({
          recordJson: row.record_json,
          updatedAtMs: row.updated_at_ms,
        }),
    });
    if (parsed.kind === 'missing') {
      return null;
    }
    if (parsed.kind === 'malformed') {
      await this.del({ walletId, recoveryKeyId });
      return null;
    }
    return cloneRecord(parsed.value);
  }

  async listActiveByWallet(
    walletId: string,
  ): Promise<EmailOtpRecoveryWrappedEnrollmentEscrowRecord[]> {
    const key = toOptionalTrimmedString(walletId);
    if (!key) return [];
    const pool = await this.poolPromise;
    const { rows } = await pool.query(
      `
        SELECT record_json, updated_at_ms
        FROM email_otp_recovery_wrapped_enrollment_escrows
        WHERE namespace = $1 AND wallet_id = $2 AND recovery_key_status = 'active'
        ORDER BY updated_at_ms DESC, recovery_key_id ASC
      `,
      [this.namespace, key],
    );
    const records: EmailOtpRecoveryWrappedEnrollmentEscrowRecord[] = [];
    const malformedRecoveryKeyIds: string[] = [];
    for (const row of rows) {
      const parsed = parseCurrentEmailOtpRecoveryWrappedEnrollmentEscrowRow({
        recordJson: row.record_json,
        updatedAtMs: row.updated_at_ms,
      });
      if (parsed) {
        records.push(cloneRecord(parsed));
        continue;
      }
      const recoveryKeyId = toOptionalTrimmedString(row.recovery_key_id);
      if (recoveryKeyId) malformedRecoveryKeyIds.push(recoveryKeyId);
    }
    await Promise.all(
      malformedRecoveryKeyIds.map((recoveryKeyId) => this.del({ walletId: key, recoveryKeyId })),
    );
    return records;
  }

  async put(record: EmailOtpRecoveryWrappedEnrollmentEscrowRecord): Promise<void> {
    const parsed = parseCurrentEmailOtpRecoveryWrappedEnrollmentEscrowRecord(record);
    if (!parsed) throw new Error('Invalid Email OTP recovery-wrapped enrollment escrow record');
    const pool = await this.poolPromise;
    await pool.query(
      `
        INSERT INTO email_otp_recovery_wrapped_enrollment_escrows (
          namespace,
          wallet_id,
          recovery_key_id,
          recovery_key_status,
          record_json,
          updated_at_ms
        )
        VALUES ($1, $2, $3, $4, $5::jsonb, $6)
        ON CONFLICT (namespace, wallet_id, recovery_key_id)
        DO UPDATE SET
          recovery_key_status = EXCLUDED.recovery_key_status,
          record_json = EXCLUDED.record_json,
          updated_at_ms = EXCLUDED.updated_at_ms
      `,
      [
        this.namespace,
        parsed.walletId,
        parsed.recoveryKeyId,
        parsed.recoveryKeyStatus,
        JSON.stringify(parsed),
        parsed.updatedAtMs,
      ],
    );
  }

  async del(input: { walletId: string; recoveryKeyId: string }): Promise<void> {
    const walletId = toOptionalTrimmedString(input.walletId);
    const recoveryKeyId = toOptionalTrimmedString(input.recoveryKeyId);
    if (!walletId || !recoveryKeyId) return;
    const pool = await this.poolPromise;
    await pool.query(
      `
        DELETE FROM email_otp_recovery_wrapped_enrollment_escrows
        WHERE namespace = $1 AND wallet_id = $2 AND recovery_key_id = $3
      `,
      [this.namespace, walletId, recoveryKeyId],
    );
  }
}

class PostgresEmailOtpAuthStateStore implements EmailOtpAuthStateStore {
  private readonly poolPromise: Promise<Awaited<ReturnType<typeof getPostgresPool>>>;
  private readonly namespace: string;

  constructor(input: { postgresUrl: string; namespace: string }) {
    this.poolPromise = getPostgresPool(input.postgresUrl);
    this.namespace = input.namespace;
  }

  async get(walletId: string): Promise<EmailOtpAuthStateRecord | null> {
    const key = toOptionalTrimmedString(walletId);
    if (!key) return null;
    const pool = await this.poolPromise;
    const { rows } = await pool.query(
      `
        SELECT record_json, updated_at_ms
        FROM email_otp_auth_states
        WHERE namespace = $1 AND wallet_id = $2
      `,
      [this.namespace, key],
    );
    const parsed = parsePostgresRow({
      row: rows[0],
      parser: (row) =>
        parseCurrentEmailOtpAuthStateRow({
          recordJson: row.record_json,
          updatedAtMs: row.updated_at_ms,
        }),
    });
    if (parsed.kind === 'missing') {
      return null;
    }
    if (parsed.kind === 'malformed') {
      await this.del(key);
      return null;
    }
    return cloneRecord(parsed.value);
  }

  async put(record: EmailOtpAuthStateRecord): Promise<void> {
    const parsed = parseCurrentEmailOtpAuthStateRecord(record);
    if (!parsed) throw new Error('Invalid Email OTP auth state record');
    const pool = await this.poolPromise;
    await pool.query(
      `
        INSERT INTO email_otp_auth_states (namespace, wallet_id, org_id, record_json, updated_at_ms)
        VALUES ($1, $2, $3, $4::jsonb, $5)
        ON CONFLICT (namespace, wallet_id)
        DO UPDATE SET
          org_id = EXCLUDED.org_id,
          record_json = EXCLUDED.record_json,
          updated_at_ms = EXCLUDED.updated_at_ms
      `,
      [this.namespace, parsed.walletId, parsed.orgId, JSON.stringify(parsed), parsed.updatedAtMs],
    );
  }

  async del(walletId: string): Promise<void> {
    const key = toOptionalTrimmedString(walletId);
    if (!key) return;
    const pool = await this.poolPromise;
    await pool.query('DELETE FROM email_otp_auth_states WHERE namespace = $1 AND wallet_id = $2', [
      this.namespace,
      key,
    ]);
  }
}

class PostgresEmailOtpUnlockChallengeStore implements EmailOtpUnlockChallengeStore {
  private readonly poolPromise: Promise<Awaited<ReturnType<typeof getPostgresPool>>>;
  private readonly namespace: string;

  constructor(input: { postgresUrl: string; namespace: string }) {
    this.poolPromise = getPostgresPool(input.postgresUrl);
    this.namespace = input.namespace;
  }

  async put(record: EmailOtpUnlockChallengeRecord): Promise<void> {
    const parsed = parseCurrentEmailOtpUnlockChallengeRecord(record);
    if (!parsed) throw new Error('Invalid Email OTP unlock challenge record');
    const pool = await this.poolPromise;
    await pool.query(
      `
        INSERT INTO email_otp_unlock_challenges (namespace, challenge_id, record_json, expires_at_ms)
        VALUES ($1, $2, $3::jsonb, $4)
        ON CONFLICT (namespace, challenge_id)
        DO UPDATE SET record_json = EXCLUDED.record_json, expires_at_ms = EXCLUDED.expires_at_ms
      `,
      [this.namespace, parsed.challengeId, JSON.stringify(parsed), parsed.expiresAtMs],
    );
  }

  async consume(challengeId: string): Promise<EmailOtpUnlockChallengeRecord | null> {
    const id = toOptionalTrimmedString(challengeId);
    if (!id) return null;
    const pool = await this.poolPromise;
    const { rows } = await pool.query(
      `
        DELETE FROM email_otp_unlock_challenges
        WHERE namespace = $1 AND challenge_id = $2
        RETURNING record_json, expires_at_ms
      `,
      [this.namespace, id],
    );
    const parsed = parsePostgresRow({
      row: rows[0],
      parser: (row) =>
        parseCurrentEmailOtpUnlockChallengeRow({
          recordJson: row.record_json,
          expiresAtMs: row.expires_at_ms,
        }),
    });
    if (parsed.kind !== 'current') return null;
    return cloneRecord(parsed.value);
  }

  async del(challengeId: string): Promise<void> {
    const id = toOptionalTrimmedString(challengeId);
    if (!id) return;
    const pool = await this.poolPromise;
    await pool.query(
      'DELETE FROM email_otp_unlock_challenges WHERE namespace = $1 AND challenge_id = $2',
      [this.namespace, id],
    );
  }
}

class PostgresEmailOtpRegistrationAttemptStore implements EmailOtpRegistrationAttemptStore {
  private readonly poolPromise: Promise<Awaited<ReturnType<typeof getPostgresPool>>>;
  private readonly namespace: string;

  constructor(input: { postgresUrl: string; namespace: string }) {
    this.poolPromise = getPostgresPool(input.postgresUrl);
    this.namespace = input.namespace;
  }

  private async deleteAttempt(attemptId: string): Promise<void> {
    const id = toOptionalTrimmedString(attemptId);
    if (!id) return;
    const pool = await this.poolPromise;
    await pool.query(
      `
        DELETE FROM email_otp_registration_attempts
        WHERE namespace = $1 AND attempt_id = $2
      `,
      [this.namespace, id],
    );
  }

  async put(record: GoogleEmailOtpRegistrationAttemptRecord): Promise<void> {
    const parsed = parseCurrentGoogleEmailOtpRegistrationAttemptRecord(record);
    if (!parsed) throw new Error('Invalid Google Email OTP registration attempt record');
    const pool = await this.poolPromise;
    await pool.query(
      `
        INSERT INTO email_otp_registration_attempts (
          namespace,
          attempt_id,
          provider_subject,
          email,
          wallet_id,
          state,
          record_json,
          expires_at_ms,
          updated_at_ms
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9)
        ON CONFLICT (namespace, attempt_id)
        DO UPDATE SET
          provider_subject = EXCLUDED.provider_subject,
          email = EXCLUDED.email,
          wallet_id = EXCLUDED.wallet_id,
          state = EXCLUDED.state,
          record_json = EXCLUDED.record_json,
          expires_at_ms = EXCLUDED.expires_at_ms,
          updated_at_ms = EXCLUDED.updated_at_ms
      `,
      [
        this.namespace,
        parsed.attemptId,
        parsed.providerSubject,
        parsed.email,
        parsed.walletId,
        parsed.state,
        JSON.stringify(parsed),
        parsed.expiresAtMs,
        parsed.updatedAtMs,
      ],
    );
  }

  async get(attemptId: string): Promise<GoogleEmailOtpRegistrationAttemptRecord | null> {
    const id = toOptionalTrimmedString(attemptId);
    if (!id) return null;
    const pool = await this.poolPromise;
    const { rows } = await pool.query(
      `
        SELECT record_json, expires_at_ms, updated_at_ms
        FROM email_otp_registration_attempts
        WHERE namespace = $1 AND attempt_id = $2
      `,
      [this.namespace, id],
    );
    const parsed = parsePostgresRow({
      row: rows[0],
      parser: (row) =>
        parseCurrentGoogleEmailOtpRegistrationAttemptRow({
          recordJson: row.record_json,
          expiresAtMs: row.expires_at_ms,
          updatedAtMs: row.updated_at_ms,
        }),
    });
    if (parsed.kind === 'missing') {
      return null;
    }
    if (parsed.kind === 'malformed') {
      await this.deleteAttempt(id);
      return null;
    }
    return cloneRecord(parsed.value);
  }

  async findStartedBySubjectEmail(input: {
    providerSubject: string;
    email: string;
    nowMs: number;
  }): Promise<GoogleEmailOtpRegistrationAttemptRecord | null> {
    const pool = await this.poolPromise;
    const { rows } = await pool.query(
      `
        SELECT record_json, expires_at_ms, updated_at_ms, attempt_id
        FROM email_otp_registration_attempts
        WHERE namespace = $1
          AND provider_subject = $2
          AND email = $3
          AND state = 'started'
          AND expires_at_ms > $4
        ORDER BY updated_at_ms DESC
        LIMIT 1
      `,
      [this.namespace, input.providerSubject, input.email, input.nowMs],
    );
    const parsed = parsePostgresRow({
      row: rows[0],
      parser: (row) =>
        parseCurrentGoogleEmailOtpRegistrationAttemptRow({
          recordJson: row.record_json,
          expiresAtMs: row.expires_at_ms,
          updatedAtMs: row.updated_at_ms,
        }),
    });
    if (parsed.kind === 'missing') {
      return null;
    }
    if (parsed.kind === 'malformed') {
      const attemptId = toOptionalTrimmedString(
        (rows[0] as { attempt_id?: unknown } | undefined)?.attempt_id,
      );
      if (attemptId) await this.deleteAttempt(attemptId);
      return null;
    }
    return cloneRecord(parsed.value);
  }

  async hasLiveStartedWalletAttempt(input: { walletId: string; nowMs: number }): Promise<boolean> {
    const pool = await this.poolPromise;
    const { rows } = await pool.query(
      `
        SELECT 1
        FROM email_otp_registration_attempts
        WHERE namespace = $1
          AND wallet_id = $2
          AND state = 'started'
          AND expires_at_ms > $3
        LIMIT 1
      `,
      [this.namespace, input.walletId, input.nowMs],
    );
    return rows.length > 0;
  }

  async deleteExpired(nowMs: number): Promise<number> {
    const pool = await this.poolPromise;
    const result = await pool.query(
      `
        DELETE FROM email_otp_registration_attempts
        WHERE namespace = $1 AND (expires_at_ms <= $2 OR state = 'expired')
      `,
      [this.namespace, nowMs],
    );
    return Number(result.rowCount || 0);
  }
}

export function createEmailOtpChallengeStore(
  input?: EmailOtpStoreFactoryInput,
): EmailOtpChallengeStore {
  const postgres = resolvePostgresEmailOtpStore(input, 'challenge');
  if (postgres) {
    input?.logger?.info('[email-otp] Using Postgres challenge store');
    return new PostgresEmailOtpChallengeStore(postgres);
  }
  input?.logger?.info('[email-otp] Using in-memory challenge store (non-persistent)');
  return new InMemoryEmailOtpChallengeStore();
}

export function createEmailOtpGrantStore(input?: EmailOtpStoreFactoryInput): EmailOtpGrantStore {
  const postgres = resolvePostgresEmailOtpStore(input, 'grant');
  if (postgres) {
    input?.logger?.info('[email-otp] Using Postgres grant store');
    return new PostgresEmailOtpGrantStore(postgres);
  }
  input?.logger?.info('[email-otp] Using in-memory grant store (non-persistent)');
  return new InMemoryEmailOtpGrantStore();
}

export function createEmailOtpWalletEnrollmentStore(
  input?: EmailOtpStoreFactoryInput,
): EmailOtpWalletEnrollmentStore {
  const postgres = resolvePostgresEmailOtpStore(input, 'enrollment');
  if (postgres) {
    input?.logger?.info('[email-otp] Using Postgres wallet enrollment store');
    return new PostgresEmailOtpWalletEnrollmentStore(postgres);
  }
  input?.logger?.info('[email-otp] Using in-memory wallet enrollment store (non-persistent)');
  return new InMemoryEmailOtpWalletEnrollmentStore();
}

export function createEmailOtpRecoveryWrappedEnrollmentEscrowStore(
  input?: EmailOtpStoreFactoryInput,
): EmailOtpRecoveryWrappedEnrollmentEscrowStore {
  const postgres = resolvePostgresEmailOtpStore(input, 'recovery-wrapped enrollment escrow');
  if (postgres) {
    input?.logger?.info('[email-otp] Using Postgres recovery-wrapped enrollment escrow store');
    return new PostgresEmailOtpRecoveryWrappedEnrollmentEscrowStore(postgres);
  }
  input?.logger?.info(
    '[email-otp] Using in-memory recovery-wrapped enrollment escrow store (non-persistent)',
  );
  return new InMemoryEmailOtpRecoveryWrappedEnrollmentEscrowStore();
}

export function createEmailOtpAuthStateStore(
  input?: EmailOtpStoreFactoryInput,
): EmailOtpAuthStateStore {
  const postgres = resolvePostgresEmailOtpStore(input, 'auth state');
  if (postgres) {
    input?.logger?.info('[email-otp] Using Postgres auth state store');
    return new PostgresEmailOtpAuthStateStore(postgres);
  }
  input?.logger?.info('[email-otp] Using in-memory auth state store (non-persistent)');
  return new InMemoryEmailOtpAuthStateStore();
}

export function createEmailOtpUnlockChallengeStore(
  input?: EmailOtpStoreFactoryInput,
): EmailOtpUnlockChallengeStore {
  const postgres = resolvePostgresEmailOtpStore(input, 'unlock challenge');
  if (postgres) {
    input?.logger?.info('[email-otp] Using Postgres unlock challenge store');
    return new PostgresEmailOtpUnlockChallengeStore(postgres);
  }
  input?.logger?.info('[email-otp] Using in-memory unlock challenge store (non-persistent)');
  return new InMemoryEmailOtpUnlockChallengeStore();
}

export function createEmailOtpRegistrationAttemptStore(
  input?: EmailOtpStoreFactoryInput,
): EmailOtpRegistrationAttemptStore {
  const postgres = resolvePostgresEmailOtpStore(input, 'registration attempt');
  if (postgres) {
    input?.logger?.info('[email-otp] Using Postgres registration attempt store');
    return new PostgresEmailOtpRegistrationAttemptStore(postgres);
  }
  input?.logger?.info('[email-otp] Using in-memory registration attempt store (non-persistent)');
  return new InMemoryEmailOtpRegistrationAttemptStore();
}
