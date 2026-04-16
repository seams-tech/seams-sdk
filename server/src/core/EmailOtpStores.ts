import { toOptionalTrimmedString } from '@shared/utils/validation';

export type EmailOtpChannel = 'email_otp';
export type EmailOtpGrantAction = 'wallet_email_otp_unseal';
export type EmailOtpChallengeAction = 'wallet_email_otp_authorize' | 'wallet_email_otp_enroll';

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

function cloneRecord<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function parseChallengeRecord(raw: unknown): EmailOtpChallengeRecord | null {
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
  const createdAtMs = Number(obj.createdAtMs);
  const expiresAtMs = Number(obj.expiresAtMs);
  const attemptCount = Number(obj.attemptCount);
  const maxAttempts = Number(obj.maxAttempts);
  if (version !== 'email_otp_challenge_v1') return null;
  if (!challengeId || !userId || !walletId || !email || !otpCode || !sessionHash) return null;
  if (otpChannel !== 'email_otp') return null;
  if (action !== 'wallet_email_otp_authorize' && action !== 'wallet_email_otp_enroll') return null;
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
    otpChannel: 'email_otp',
    email,
    otpCode,
    sessionHash,
    appSessionVersion,
    action,
    createdAtMs: Math.floor(createdAtMs),
    expiresAtMs: Math.floor(expiresAtMs),
    attemptCount: Math.floor(attemptCount),
    maxAttempts: Math.floor(maxAttempts),
  };
}

function parseGrantRecord(raw: unknown): EmailOtpGrantRecord | null {
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
  if (otpChannel !== 'email_otp') return null;
  if (action !== 'wallet_email_otp_unseal') return null;
  if (!Number.isFinite(issuedAtMs) || issuedAtMs <= 0) return null;
  if (!Number.isFinite(expiresAtMs) || expiresAtMs <= 0) return null;
  return {
    version: 'email_otp_grant_v1',
    grantToken,
    userId,
    walletId,
    ...(orgId ? { orgId } : {}),
    challengeId,
    otpChannel: 'email_otp',
    sessionHash,
    appSessionVersion,
    action: 'wallet_email_otp_unseal',
    issuedAtMs: Math.floor(issuedAtMs),
    expiresAtMs: Math.floor(expiresAtMs),
  };
}

function parseEnrollmentRecord(raw: unknown): EmailOtpEnrollmentRecord | null {
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
  if (otpChannel !== 'email_otp') return null;
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
    otpChannel: 'email_otp',
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

export function createEmailOtpChallengeStore(): EmailOtpChallengeStore {
  return new InMemoryEmailOtpChallengeStore();
}

export function createEmailOtpGrantStore(): EmailOtpGrantStore {
  return new InMemoryEmailOtpGrantStore();
}

export function createEmailOtpEnrollmentStore(): EmailOtpEnrollmentStore {
  return new InMemoryEmailOtpEnrollmentStore();
}

export function createEmailOtpUnlockChallengeStore(): EmailOtpUnlockChallengeStore {
  return new InMemoryEmailOtpUnlockChallengeStore();
}
