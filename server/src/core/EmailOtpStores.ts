import type { NormalizedLogger } from './logger';
import type { ThresholdRuntimePolicyScope, ThresholdStoreConfigInput } from './types';
import { THRESHOLD_PREFIX_DEFAULT } from './defaultConfigsServer';
import { getPostgresPool, getPostgresUrlFromConfig } from '../storage/postgres';
import { isPlainObject, toOptionalTrimmedString } from '@shared/utils/validation';
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

export type EmailOtpChannel = WalletEmailOtpChannel;
export type EmailOtpGrantAction = typeof WALLET_EMAIL_OTP_ACTIONS.unseal;
export type EmailOtpChallengeAction =
  | typeof WALLET_EMAIL_OTP_ACTIONS.login
  | typeof WALLET_EMAIL_OTP_ACTIONS.registration;
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
  consume(grantToken: string): Promise<EmailOtpGrantRecord | null>;
  del(grantToken: string): Promise<void>;
}

export type EmailOtpEnrollmentRecord = {
  version: 'email_otp_enrollment_v1';
  walletId: string;
  userId: string;
  orgId?: string;
  enrollmentDeviceId?: string;
  otpChannel: EmailOtpChannel;
  emailOtpEscrowBlob: string;
  emailOtpKeyVersion: string;
  unlockPublicKey: string;
  unlockKeyVersion: string;
  thresholdEcdsaClientVerifyingShareB64u?: string;
  createdAtMs: number;
  updatedAtMs: number;
  otpFailureCount?: number;
  lastOtpFailureAtMs?: number;
  otpLockedUntilMs?: number;
  lastEmailOtpLoginAtMs?: number;
  lastStrongAuthAtMs?: number;
};

export interface EmailOtpEnrollmentStore {
  get(walletId: string): Promise<EmailOtpEnrollmentRecord | null>;
  put(record: EmailOtpEnrollmentRecord): Promise<void>;
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

function toEmailOtpPrefix(config: Record<string, unknown>): string {
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
  return { postgresUrl, namespace: toEmailOtpPrefix(config) };
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
    action !== WALLET_EMAIL_OTP_ACTIONS.registration
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
  if (action !== WALLET_EMAIL_OTP_ACTIONS.unseal) return null;
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
    action: WALLET_EMAIL_OTP_ACTIONS.unseal,
    issuedAtMs: Math.floor(issuedAtMs),
    expiresAtMs: Math.floor(expiresAtMs),
  };
}

function parseEnrollmentRecord(raw: unknown): EmailOtpEnrollmentRecord | null {
  raw = parseJsonRecord(raw);
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const obj = raw as Record<string, unknown>;
  const version = toOptionalTrimmedString(obj.version);
  const walletId = toOptionalTrimmedString(obj.walletId);
  const userId = toOptionalTrimmedString(obj.userId);
  const orgId = toOptionalTrimmedString(obj.orgId) || undefined;
  const enrollmentDeviceId = toOptionalTrimmedString(obj.enrollmentDeviceId) || undefined;
  const otpChannel = toOptionalTrimmedString(obj.otpChannel);
  const emailOtpEscrowBlob = toOptionalTrimmedString(obj.emailOtpEscrowBlob);
  const emailOtpKeyVersion = toOptionalTrimmedString(obj.emailOtpKeyVersion);
  const unlockPublicKey = toOptionalTrimmedString(obj.unlockPublicKey);
  const unlockKeyVersion = toOptionalTrimmedString(obj.unlockKeyVersion);
  const thresholdEcdsaClientVerifyingShareB64u =
    toOptionalTrimmedString(obj.thresholdEcdsaClientVerifyingShareB64u) || undefined;
  const createdAtMs = Number(obj.createdAtMs);
  const updatedAtMs = Number(obj.updatedAtMs);
  const otpFailureCount = obj.otpFailureCount == null ? undefined : Number(obj.otpFailureCount);
  const lastOtpFailureAtMs =
    obj.lastOtpFailureAtMs == null ? undefined : Number(obj.lastOtpFailureAtMs);
  const otpLockedUntilMs =
    obj.otpLockedUntilMs == null ? undefined : Number(obj.otpLockedUntilMs);
  const lastEmailOtpLoginAtMs =
    obj.lastEmailOtpLoginAtMs == null ? undefined : Number(obj.lastEmailOtpLoginAtMs);
  const lastStrongAuthAtMs =
    obj.lastStrongAuthAtMs == null ? undefined : Number(obj.lastStrongAuthAtMs);
  if (version !== 'email_otp_enrollment_v1') return null;
  if (!walletId || !userId || !emailOtpEscrowBlob || !emailOtpKeyVersion) return null;
  if (!unlockPublicKey || !unlockKeyVersion) return null;
  if (otpChannel !== EMAIL_OTP_CHANNEL) return null;
  if (!Number.isFinite(createdAtMs) || createdAtMs <= 0) return null;
  if (!Number.isFinite(updatedAtMs) || updatedAtMs <= 0) return null;
  if (otpFailureCount != null && (!Number.isFinite(otpFailureCount) || otpFailureCount < 0)) {
    return null;
  }
  if (lastOtpFailureAtMs != null && (!Number.isFinite(lastOtpFailureAtMs) || lastOtpFailureAtMs <= 0)) {
    return null;
  }
  if (otpLockedUntilMs != null && (!Number.isFinite(otpLockedUntilMs) || otpLockedUntilMs <= 0)) {
    return null;
  }
  if (lastEmailOtpLoginAtMs != null && (!Number.isFinite(lastEmailOtpLoginAtMs) || lastEmailOtpLoginAtMs <= 0)) {
    return null;
  }
  if (lastStrongAuthAtMs != null && (!Number.isFinite(lastStrongAuthAtMs) || lastStrongAuthAtMs <= 0)) {
    return null;
  }
  return {
    version: 'email_otp_enrollment_v1',
    walletId,
    userId,
    ...(orgId ? { orgId } : {}),
    ...(enrollmentDeviceId ? { enrollmentDeviceId } : {}),
    otpChannel: EMAIL_OTP_CHANNEL,
    emailOtpEscrowBlob,
    emailOtpKeyVersion,
    unlockPublicKey,
    unlockKeyVersion,
    ...(thresholdEcdsaClientVerifyingShareB64u ? { thresholdEcdsaClientVerifyingShareB64u } : {}),
    createdAtMs: Math.floor(createdAtMs),
    updatedAtMs: Math.floor(updatedAtMs),
    ...(otpFailureCount != null ? { otpFailureCount: Math.floor(otpFailureCount) } : {}),
    ...(lastOtpFailureAtMs != null ? { lastOtpFailureAtMs: Math.floor(lastOtpFailureAtMs) } : {}),
    ...(otpLockedUntilMs != null ? { otpLockedUntilMs: Math.floor(otpLockedUntilMs) } : {}),
    ...(lastEmailOtpLoginAtMs != null ? { lastEmailOtpLoginAtMs: Math.floor(lastEmailOtpLoginAtMs) } : {}),
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
  if (!orgId || !projectId || !envId) return undefined;
  return { orgId, projectId, envId };
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
  const state = toOptionalTrimmedString(obj.state);
  const createdAtMs = Number(obj.createdAtMs);
  const updatedAtMs = Number(obj.updatedAtMs);
  const expiresAtMs = Number(obj.expiresAtMs);
  const runtimePolicyScope = parseRuntimePolicyScope(obj.runtimePolicyScope);
  const finalizedPublicKey = toOptionalTrimmedString(obj.finalizedPublicKey) || undefined;
  const failureCode = toOptionalTrimmedString(obj.failureCode) || undefined;
  if (version !== 'google_email_otp_registration_attempt_v1') return null;
  if (!attemptId || !providerSubject || !email || !walletId) return null;
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
    const parsed = parseChallengeRecord(record);
    if (!parsed) throw new Error('Invalid Email OTP challenge record');
    this.map.set(parsed.challengeId, cloneRecord(parsed));
  }

  async get(challengeId: string): Promise<EmailOtpChallengeRecord | null> {
    const id = toOptionalTrimmedString(challengeId);
    if (!id) return null;
    const record = this.map.get(id);
    return record ? cloneRecord(record) : null;
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
    const parsed = parseGrantRecord(record);
    if (!parsed) throw new Error('Invalid Email OTP grant record');
    this.map.set(parsed.grantToken, cloneRecord(parsed));
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

class InMemoryEmailOtpEnrollmentStore implements EmailOtpEnrollmentStore {
  private readonly map = new Map<string, EmailOtpEnrollmentRecord>();

  async get(walletId: string): Promise<EmailOtpEnrollmentRecord | null> {
    const key = toOptionalTrimmedString(walletId);
    if (!key) return null;
    const record = this.map.get(key);
    return record ? cloneRecord(record) : null;
  }

  async put(record: EmailOtpEnrollmentRecord): Promise<void> {
    const parsed = parseEnrollmentRecord(record);
    if (!parsed) throw new Error('Invalid Email OTP enrollment record');
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
    const parsed = parseUnlockChallengeRecord(record);
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
    const parsed = parseRegistrationAttemptRecord(record);
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
    const parsed = parseChallengeRecord(record);
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
        SELECT record_json
        FROM email_otp_challenges
        WHERE namespace = $1 AND challenge_id = $2
      `,
      [this.namespace, id],
    );
    const parsed = parseChallengeRecord(rows[0]?.record_json);
    if (!parsed) {
      if (rows[0]) await this.del(id);
      return null;
    }
    return cloneRecord(parsed);
  }

  async del(challengeId: string): Promise<void> {
    const id = toOptionalTrimmedString(challengeId);
    if (!id) return;
    const pool = await this.poolPromise;
    await pool.query('DELETE FROM email_otp_challenges WHERE namespace = $1 AND challenge_id = $2', [
      this.namespace,
      id,
    ]);
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
    const parsed = parseGrantRecord(record);
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
        RETURNING record_json
      `,
      [this.namespace, token],
    );
    const parsed = parseGrantRecord(rows[0]?.record_json);
    if (!parsed) return null;
    return cloneRecord(parsed);
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

class PostgresEmailOtpEnrollmentStore implements EmailOtpEnrollmentStore {
  private readonly poolPromise: Promise<Awaited<ReturnType<typeof getPostgresPool>>>;
  private readonly namespace: string;

  constructor(input: { postgresUrl: string; namespace: string }) {
    this.poolPromise = getPostgresPool(input.postgresUrl);
    this.namespace = input.namespace;
  }

  async get(walletId: string): Promise<EmailOtpEnrollmentRecord | null> {
    const key = toOptionalTrimmedString(walletId);
    if (!key) return null;
    const pool = await this.poolPromise;
    const { rows } = await pool.query(
      `
        SELECT record_json
        FROM email_otp_enrollments
        WHERE namespace = $1 AND wallet_id = $2
      `,
      [this.namespace, key],
    );
    const parsed = parseEnrollmentRecord(rows[0]?.record_json);
    if (!parsed) {
      if (rows[0]) await this.del(key);
      return null;
    }
    return cloneRecord(parsed);
  }

  async put(record: EmailOtpEnrollmentRecord): Promise<void> {
    const parsed = parseEnrollmentRecord(record);
    if (!parsed) throw new Error('Invalid Email OTP enrollment record');
    const pool = await this.poolPromise;
    await pool.query(
      `
        INSERT INTO email_otp_enrollments (namespace, wallet_id, record_json, updated_at_ms)
        VALUES ($1, $2, $3::jsonb, $4)
        ON CONFLICT (namespace, wallet_id)
        DO UPDATE SET record_json = EXCLUDED.record_json, updated_at_ms = EXCLUDED.updated_at_ms
      `,
      [this.namespace, parsed.walletId, JSON.stringify(parsed), parsed.updatedAtMs],
    );
  }

  async del(walletId: string): Promise<void> {
    const key = toOptionalTrimmedString(walletId);
    if (!key) return;
    const pool = await this.poolPromise;
    await pool.query('DELETE FROM email_otp_enrollments WHERE namespace = $1 AND wallet_id = $2', [
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
    const parsed = parseUnlockChallengeRecord(record);
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
        RETURNING record_json
      `,
      [this.namespace, id],
    );
    const parsed = parseUnlockChallengeRecord(rows[0]?.record_json);
    if (!parsed) return null;
    return cloneRecord(parsed);
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

  async put(record: GoogleEmailOtpRegistrationAttemptRecord): Promise<void> {
    const parsed = parseRegistrationAttemptRecord(record);
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
        SELECT record_json
        FROM email_otp_registration_attempts
        WHERE namespace = $1 AND attempt_id = $2
      `,
      [this.namespace, id],
    );
    const parsed = parseRegistrationAttemptRecord(rows[0]?.record_json);
    if (!parsed) return null;
    return cloneRecord(parsed);
  }

  async findStartedBySubjectEmail(input: {
    providerSubject: string;
    email: string;
    nowMs: number;
  }): Promise<GoogleEmailOtpRegistrationAttemptRecord | null> {
    const pool = await this.poolPromise;
    const { rows } = await pool.query(
      `
        SELECT record_json
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
    const parsed = parseRegistrationAttemptRecord(rows[0]?.record_json);
    return parsed ? cloneRecord(parsed) : null;
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

export function createEmailOtpEnrollmentStore(
  input?: EmailOtpStoreFactoryInput,
): EmailOtpEnrollmentStore {
  const postgres = resolvePostgresEmailOtpStore(input, 'enrollment');
  if (postgres) {
    input?.logger?.info('[email-otp] Using Postgres enrollment store');
    return new PostgresEmailOtpEnrollmentStore(postgres);
  }
  input?.logger?.info('[email-otp] Using in-memory enrollment store (non-persistent)');
  return new InMemoryEmailOtpEnrollmentStore();
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
