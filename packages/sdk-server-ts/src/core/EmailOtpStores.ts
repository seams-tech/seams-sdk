import type { NormalizedLogger } from './logger';
import type { ThresholdRuntimePolicyScope, ThresholdStoreConfigInput } from './types';
import { THRESHOLD_PREFIX_DEFAULT } from './defaultConfigsServer';
import {
  d1ChangedRows,
  formatD1ExecStatement,
  resolveD1DatabaseFromConfig,
} from '../storage/d1Sql';
import type { D1DatabaseLike, D1PreparedStatementLike } from '../storage/tenantRoute';
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
} from './EmailOtpRecords';
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
  buildEmailOtpRecoveryWrapBinding,
  type EmailOtpRecoveryWrapBinding,
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
  /**
   * Subject that owns the OTP challenge.
   * For Google registration this is the OIDC provider subject. For existing-wallet
   * Email OTP flows this is the enrolled provider subject.
   */
  challengeSubjectId: string;
  /** Wallet being registered or unlocked. Registration rerolls may change this after issuance. */
  walletId: string;
  /** Tenant scope that prevents cross-org challenge reuse. */
  orgId?: string;
  otpChannel: EmailOtpChannel;
  /** Normalized email address that received the OTP code. */
  email: string;
  otpCode: string;
  /** App-session binding hash for non-reroll flows. */
  sessionHash: string;
  appSessionVersion: string;
  action: EmailOtpChallengeAction;
  operation: EmailOtpChallengeOperation;
  createdAtMs: number;
  expiresAtMs: number;
  attemptCount: number;
  maxAttempts: number;
};

export type EmailOtpChallengeContextInput = {
  challengeSubjectId: string;
  walletId: string;
  orgId?: string;
  otpChannel: EmailOtpChannel;
  sessionHash: string;
  appSessionVersion: string;
  action: EmailOtpChallengeAction;
  operation: EmailOtpChallengeOperation;
  nowMs: number;
};

export interface EmailOtpChallengeStore {
  put(record: EmailOtpChallengeRecord): Promise<void>;
  get(challengeId: string): Promise<EmailOtpChallengeRecord | null>;
  deleteExpired(nowMs: number): Promise<EmailOtpChallengeRecord[]>;
  countActiveByContext(input: EmailOtpChallengeContextInput): Promise<number>;
  findLatestActiveByContext(input: EmailOtpChallengeContextInput): Promise<EmailOtpChallengeRecord | null>;
  deleteOldestActiveByContext(
    input: EmailOtpChallengeContextInput,
  ): Promise<EmailOtpChallengeRecord | null>;
  findActiveByContext(
    input: EmailOtpChallengeContextInput & {
      otpCode: string;
    },
  ): Promise<EmailOtpChallengeRecord | null>;
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

type EmailOtpRecoveryWrappedEnrollmentEscrowBase = {
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
};

export type ActiveEmailOtpRecoveryWrappedEnrollmentEscrowRecord =
  EmailOtpRecoveryWrappedEnrollmentEscrowBase & {
    recoveryKeyStatus: 'active';
    consumedAtMs?: never;
    revokedAtMs?: never;
  };

export type ConsumedEmailOtpRecoveryWrappedEnrollmentEscrowRecord =
  EmailOtpRecoveryWrappedEnrollmentEscrowBase & {
    recoveryKeyStatus: 'consumed';
    consumedAtMs: number;
    revokedAtMs?: never;
  };

export type RevokedEmailOtpRecoveryWrappedEnrollmentEscrowRecord =
  EmailOtpRecoveryWrappedEnrollmentEscrowBase & {
    recoveryKeyStatus: 'revoked';
    consumedAtMs?: never;
    revokedAtMs: number;
  };

export type EmailOtpRecoveryWrappedEnrollmentEscrowRecord =
  | ActiveEmailOtpRecoveryWrappedEnrollmentEscrowRecord
  | ConsumedEmailOtpRecoveryWrappedEnrollmentEscrowRecord
  | RevokedEmailOtpRecoveryWrappedEnrollmentEscrowRecord;

export type EmailOtpRecoveryWrappedEnrollmentEscrowBoundary =
  | {
      record: ActiveEmailOtpRecoveryWrappedEnrollmentEscrowRecord;
      binding: EmailOtpRecoveryWrapBinding;
      lifecycle: {
        status: 'active';
        consumedAtMs?: never;
        revokedAtMs?: never;
      };
    }
  | {
      record: ConsumedEmailOtpRecoveryWrappedEnrollmentEscrowRecord;
      binding: EmailOtpRecoveryWrapBinding;
      lifecycle: {
        status: 'consumed';
        consumedAtMs: number;
        revokedAtMs?: never;
      };
    }
  | {
      record: RevokedEmailOtpRecoveryWrappedEnrollmentEscrowRecord;
      binding: EmailOtpRecoveryWrapBinding;
      lifecycle: {
        status: 'revoked';
        consumedAtMs?: never;
        revokedAtMs: number;
      };
    };

export interface EmailOtpRecoveryWrappedEnrollmentEscrowStore {
  get(input: {
    walletId: string;
    recoveryKeyId: string;
  }): Promise<EmailOtpRecoveryWrappedEnrollmentEscrowRecord | null>;
  listByWallet(walletId: string): Promise<EmailOtpRecoveryWrappedEnrollmentEscrowRecord[]>;
  listActiveByWallet(walletId: string): Promise<EmailOtpRecoveryWrappedEnrollmentEscrowRecord[]>;
  put(record: EmailOtpRecoveryWrappedEnrollmentEscrowRecord): Promise<void>;
  putMany(records: readonly EmailOtpRecoveryWrappedEnrollmentEscrowRecord[]): Promise<void>;
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
  | 'abandoned'
  | 'failed'
  | 'expired';

export type GoogleEmailOtpRegistrationOfferCandidateRecord = {
  candidateId: string;
  walletId: string;
  collisionCounter: number;
};

export type NonEmptyGoogleEmailOtpRegistrationOfferCandidates = readonly [
  GoogleEmailOtpRegistrationOfferCandidateRecord,
  ...GoogleEmailOtpRegistrationOfferCandidateRecord[],
];

type GoogleEmailOtpRegistrationOfferBinding = {
  offerId: string;
  offerCandidates: NonEmptyGoogleEmailOtpRegistrationOfferCandidates;
  selectedCandidateId: string;
};

type GoogleEmailOtpRegistrationAttemptBaseRecord = {
  version: 'google_email_otp_registration_attempt_v1';
  attemptId: string;
  providerSubject: string;
  email: string;
  walletId: string;
  appSessionVersion: string;
  authProvider: string;
  accountIdSlugVersion: 'hmac_readable_v1';
  walletIdDerivationNonce: string;
  collisionCounter: number;
  createdAtMs: number;
  updatedAtMs: number;
  expiresAtMs: number;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
};

export type StartedGoogleEmailOtpRegistrationAttemptRecord =
  GoogleEmailOtpRegistrationAttemptBaseRecord &
    GoogleEmailOtpRegistrationOfferBinding & {
      state: 'started';
      finalizedPublicKey?: never;
      failureCode?: never;
    };

export type KeyFinalizedGoogleEmailOtpRegistrationAttemptRecord =
  GoogleEmailOtpRegistrationAttemptBaseRecord &
    GoogleEmailOtpRegistrationOfferBinding & {
      state: 'key_finalized';
      finalizedPublicKey: string;
      failureCode?: never;
    };

export type ActiveGoogleEmailOtpRegistrationAttemptRecord =
  GoogleEmailOtpRegistrationAttemptBaseRecord &
    GoogleEmailOtpRegistrationOfferBinding & {
      state: 'active';
      finalizedPublicKey?: string;
      failureCode?: never;
    };

export type AbandonedGoogleEmailOtpRegistrationAttemptRecord =
  GoogleEmailOtpRegistrationAttemptBaseRecord &
    GoogleEmailOtpRegistrationOfferBinding & {
      state: 'abandoned';
      finalizedPublicKey?: string;
      failureCode: string;
    };

export type FailedGoogleEmailOtpRegistrationAttemptRecord =
  GoogleEmailOtpRegistrationAttemptBaseRecord &
    GoogleEmailOtpRegistrationOfferBinding & {
      state: 'failed';
      finalizedPublicKey?: string;
      failureCode: string;
    };

export type ExpiredGoogleEmailOtpRegistrationAttemptRecord =
  GoogleEmailOtpRegistrationAttemptBaseRecord &
    GoogleEmailOtpRegistrationOfferBinding & {
      state: 'expired';
      finalizedPublicKey?: string;
      failureCode?: string;
    };

export type GoogleEmailOtpRegistrationAttemptRecord =
  | StartedGoogleEmailOtpRegistrationAttemptRecord
  | KeyFinalizedGoogleEmailOtpRegistrationAttemptRecord
  | ActiveGoogleEmailOtpRegistrationAttemptRecord
  | AbandonedGoogleEmailOtpRegistrationAttemptRecord
  | FailedGoogleEmailOtpRegistrationAttemptRecord
  | ExpiredGoogleEmailOtpRegistrationAttemptRecord;

export type PendingGoogleEmailOtpRegistrationAttemptRecord =
  | StartedGoogleEmailOtpRegistrationAttemptRecord
  | KeyFinalizedGoogleEmailOtpRegistrationAttemptRecord;

export type GoogleEmailOtpRegistrationAttemptWithFinalizedPublicKey =
  | KeyFinalizedGoogleEmailOtpRegistrationAttemptRecord
  | ActiveGoogleEmailOtpRegistrationAttemptRecord
  | AbandonedGoogleEmailOtpRegistrationAttemptRecord
  | FailedGoogleEmailOtpRegistrationAttemptRecord
  | ExpiredGoogleEmailOtpRegistrationAttemptRecord;

export interface EmailOtpRegistrationAttemptStore {
  put(record: GoogleEmailOtpRegistrationAttemptRecord): Promise<void>;
  get(attemptId: string): Promise<GoogleEmailOtpRegistrationAttemptRecord | null>;
  findStartedBySubjectEmail(input: {
    providerSubject: string;
    email: string;
    orgId: string;
    appSessionVersion: string;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
    nowMs: number;
  }): Promise<PendingGoogleEmailOtpRegistrationAttemptRecord | null>;
  abandonStartedBySubjectEmailExceptAppSession(input: {
    providerSubject: string;
    email: string;
    orgId: string;
    appSessionVersion: string;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
    nowMs: number;
    failureCode: 'app_session_version_replaced';
  }): Promise<number>;
  hasLiveStartedWalletAttempt(input: { walletId: string; nowMs: number }): Promise<boolean>;
  deleteExpired(nowMs: number): Promise<number>;
}

function runtimePolicyScopeKey(scope: ThresholdRuntimePolicyScope | undefined): string {
  if (!scope) return '';
  return `${scope.orgId}\n${scope.projectId}\n${scope.envId}\n${scope.signingRootVersion}`;
}

function registrationAttemptMatchesStartedScope(
  record: GoogleEmailOtpRegistrationAttemptRecord,
  input: {
    providerSubject: string;
    email: string;
    orgId: string;
    appSessionVersion: string;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
    nowMs: number;
  },
): record is PendingGoogleEmailOtpRegistrationAttemptRecord {
  return (
    record.providerSubject === input.providerSubject &&
    record.email === input.email &&
    record.appSessionVersion === input.appSessionVersion &&
    record.runtimePolicyScope?.orgId === input.orgId &&
    runtimePolicyScopeKey(record.runtimePolicyScope) ===
      runtimePolicyScopeKey(input.runtimePolicyScope) &&
    (record.state === 'started' || record.state === 'key_finalized') &&
    record.expiresAtMs > input.nowMs
  );
}

function registrationAttemptMatchesReplacementScope(
  record: GoogleEmailOtpRegistrationAttemptRecord,
  input: {
    providerSubject: string;
    email: string;
    orgId: string;
    appSessionVersion: string;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
    nowMs: number;
  },
): record is PendingGoogleEmailOtpRegistrationAttemptRecord {
  return (
    record.providerSubject === input.providerSubject &&
    record.email === input.email &&
    record.appSessionVersion !== input.appSessionVersion &&
    record.runtimePolicyScope?.orgId === input.orgId &&
    runtimePolicyScopeKey(record.runtimePolicyScope) ===
      runtimePolicyScopeKey(input.runtimePolicyScope) &&
    (record.state === 'started' || record.state === 'key_finalized') &&
    record.expiresAtMs > input.nowMs
  );
}

type EmailOtpStoreFactoryInput = {
  config?: ThresholdStoreConfigInput | null;
  logger?: NormalizedLogger;
  isNode?: boolean;
};

export interface D1EmailOtpStoreSchemaOptions {
  readonly database: D1DatabaseLike;
}

export interface D1EmailOtpStoreOptions {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly ensureSchema?: boolean;
}

type NormalizedD1EmailOtpStoreOptions = {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly ensureSchema: boolean;
};

type D1EmailOtpScope = {
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
};

type D1EmailOtpRecordRow = {
  readonly record_json?: unknown;
  readonly expires_at_ms?: unknown;
  readonly updated_at_ms?: unknown;
  readonly challenge_id?: unknown;
  readonly wallet_id?: unknown;
  readonly recovery_key_id?: unknown;
  readonly attempt_id?: unknown;
};

export const EMAIL_OTP_STORE_D1_SCHEMA_SQL = Object.freeze([
  `
    CREATE TABLE IF NOT EXISTS email_otp_challenges (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      env_id TEXT NOT NULL,
      challenge_id TEXT NOT NULL,
      challenge_subject_id TEXT NOT NULL,
      wallet_id TEXT NOT NULL,
      record_org_id TEXT NOT NULL,
      otp_channel TEXT NOT NULL,
      session_hash TEXT NOT NULL,
      app_session_version TEXT NOT NULL,
      action TEXT NOT NULL,
      operation TEXT NOT NULL,
      otp_code TEXT NOT NULL,
      record_json TEXT NOT NULL,
      created_at_ms INTEGER NOT NULL,
      expires_at_ms INTEGER NOT NULL,
      PRIMARY KEY (namespace, org_id, project_id, env_id, challenge_id),
      CHECK (length(challenge_id) > 0),
      CHECK (length(challenge_subject_id) > 0),
      CHECK (length(wallet_id) > 0),
      CHECK (otp_channel = 'email_otp'),
      CHECK (length(session_hash) > 0),
      CHECK (length(app_session_version) > 0),
      CHECK (length(action) > 0),
      CHECK (length(operation) > 0),
      CHECK (length(otp_code) > 0),
      CHECK (json_valid(record_json)),
      CHECK (created_at_ms > 0),
      CHECK (expires_at_ms > created_at_ms)
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS email_otp_challenges_context_idx
      ON email_otp_challenges (
        namespace,
        org_id,
        project_id,
        env_id,
        challenge_subject_id,
        wallet_id,
        record_org_id,
        otp_channel,
        session_hash,
        app_session_version,
        action,
        operation,
        expires_at_ms
      )
  `,
  `
    CREATE INDEX IF NOT EXISTS email_otp_challenges_expires_idx
      ON email_otp_challenges (
        namespace,
        org_id,
        project_id,
        env_id,
        expires_at_ms
      )
  `,
  `
    CREATE TABLE IF NOT EXISTS email_otp_grants (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      env_id TEXT NOT NULL,
      grant_token TEXT NOT NULL,
      user_id TEXT NOT NULL,
      wallet_id TEXT NOT NULL,
      record_org_id TEXT NOT NULL,
      challenge_id TEXT NOT NULL,
      action TEXT NOT NULL,
      record_json TEXT NOT NULL,
      issued_at_ms INTEGER NOT NULL,
      expires_at_ms INTEGER NOT NULL,
      PRIMARY KEY (namespace, org_id, project_id, env_id, grant_token),
      CHECK (length(grant_token) > 0),
      CHECK (length(user_id) > 0),
      CHECK (length(wallet_id) > 0),
      CHECK (length(challenge_id) > 0),
      CHECK (length(action) > 0),
      CHECK (json_valid(record_json)),
      CHECK (issued_at_ms > 0),
      CHECK (expires_at_ms > issued_at_ms)
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS email_otp_grants_expires_idx
      ON email_otp_grants (
        namespace,
        org_id,
        project_id,
        env_id,
        expires_at_ms
      )
  `,
  `
    CREATE TABLE IF NOT EXISTS email_otp_wallet_enrollments (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      env_id TEXT NOT NULL,
      wallet_id TEXT NOT NULL,
      provider_user_id TEXT NOT NULL,
      record_org_id TEXT NOT NULL,
      verified_email TEXT NOT NULL,
      record_json TEXT NOT NULL,
      created_at_ms INTEGER NOT NULL,
      updated_at_ms INTEGER NOT NULL,
      PRIMARY KEY (namespace, org_id, project_id, env_id, wallet_id),
      UNIQUE (namespace, org_id, project_id, env_id, record_org_id, provider_user_id),
      CHECK (length(wallet_id) > 0),
      CHECK (length(provider_user_id) > 0),
      CHECK (length(record_org_id) > 0),
      CHECK (length(verified_email) > 0),
      CHECK (json_valid(record_json)),
      CHECK (created_at_ms > 0),
      CHECK (updated_at_ms > 0)
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS email_otp_wallet_enrollments_provider_idx
      ON email_otp_wallet_enrollments (
        namespace,
        org_id,
        project_id,
        env_id,
        record_org_id,
        provider_user_id,
        updated_at_ms
      )
  `,
  `
    CREATE TABLE IF NOT EXISTS email_otp_recovery_wrapped_enrollment_escrows (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      env_id TEXT NOT NULL,
      wallet_id TEXT NOT NULL,
      recovery_key_id TEXT NOT NULL,
      recovery_key_status TEXT NOT NULL,
      record_json TEXT NOT NULL,
      issued_at_ms INTEGER NOT NULL,
      updated_at_ms INTEGER NOT NULL,
      PRIMARY KEY (namespace, org_id, project_id, env_id, wallet_id, recovery_key_id),
      CHECK (length(wallet_id) > 0),
      CHECK (length(recovery_key_id) > 0),
      CHECK (recovery_key_status IN ('active', 'consumed', 'revoked')),
      CHECK (json_valid(record_json)),
      CHECK (issued_at_ms > 0),
      CHECK (updated_at_ms > 0)
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS email_otp_recovery_wrapped_escrows_wallet_idx
      ON email_otp_recovery_wrapped_enrollment_escrows (
        namespace,
        org_id,
        project_id,
        env_id,
        wallet_id,
        recovery_key_status,
        updated_at_ms
      )
  `,
  `
    CREATE TABLE IF NOT EXISTS email_otp_auth_states (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      env_id TEXT NOT NULL,
      wallet_id TEXT NOT NULL,
      provider_user_id TEXT NOT NULL,
      record_org_id TEXT NOT NULL,
      record_json TEXT NOT NULL,
      created_at_ms INTEGER NOT NULL,
      updated_at_ms INTEGER NOT NULL,
      PRIMARY KEY (namespace, org_id, project_id, env_id, wallet_id),
      CHECK (length(wallet_id) > 0),
      CHECK (length(provider_user_id) > 0),
      CHECK (length(record_org_id) > 0),
      CHECK (json_valid(record_json)),
      CHECK (created_at_ms > 0),
      CHECK (updated_at_ms > 0)
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS email_otp_unlock_challenges (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      env_id TEXT NOT NULL,
      challenge_id TEXT NOT NULL,
      wallet_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      record_org_id TEXT NOT NULL,
      record_json TEXT NOT NULL,
      created_at_ms INTEGER NOT NULL,
      expires_at_ms INTEGER NOT NULL,
      PRIMARY KEY (namespace, org_id, project_id, env_id, challenge_id),
      CHECK (length(challenge_id) > 0),
      CHECK (length(wallet_id) > 0),
      CHECK (length(user_id) > 0),
      CHECK (json_valid(record_json)),
      CHECK (created_at_ms > 0),
      CHECK (expires_at_ms > created_at_ms)
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS email_otp_unlock_challenges_expires_idx
      ON email_otp_unlock_challenges (
        namespace,
        org_id,
        project_id,
        env_id,
        expires_at_ms
      )
  `,
  `
    CREATE TABLE IF NOT EXISTS email_otp_registration_attempts (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      env_id TEXT NOT NULL,
      attempt_id TEXT NOT NULL,
      provider_subject TEXT NOT NULL,
      email TEXT NOT NULL,
      wallet_id TEXT NOT NULL,
      state TEXT NOT NULL,
      app_session_version TEXT NOT NULL,
      runtime_org_id TEXT NOT NULL,
      runtime_policy_key TEXT NOT NULL,
      offer_wallet_ids_json TEXT NOT NULL,
      record_json TEXT NOT NULL,
      created_at_ms INTEGER NOT NULL,
      updated_at_ms INTEGER NOT NULL,
      expires_at_ms INTEGER NOT NULL,
      PRIMARY KEY (namespace, org_id, project_id, env_id, attempt_id),
      CHECK (length(attempt_id) > 0),
      CHECK (length(provider_subject) > 0),
      CHECK (length(email) > 0),
      CHECK (length(wallet_id) > 0),
      CHECK (state IN ('started', 'key_finalized', 'active', 'abandoned', 'failed', 'expired')),
      CHECK (length(app_session_version) > 0),
      CHECK (json_valid(offer_wallet_ids_json)),
      CHECK (json_valid(record_json)),
      CHECK (created_at_ms > 0),
      CHECK (updated_at_ms > 0),
      CHECK (expires_at_ms > 0)
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS email_otp_registration_attempts_subject_idx
      ON email_otp_registration_attempts (
        namespace,
        org_id,
        project_id,
        env_id,
        provider_subject,
        email,
        state,
        expires_at_ms,
        app_session_version,
        runtime_org_id,
        runtime_policy_key,
        updated_at_ms
      )
  `,
  `
    CREATE INDEX IF NOT EXISTS email_otp_registration_attempts_wallet_idx
      ON email_otp_registration_attempts (
        namespace,
        org_id,
        project_id,
        env_id,
        wallet_id,
        state,
        expires_at_ms
      )
  `,
] as const);

export async function ensureEmailOtpStoreD1Schema(
  options: D1EmailOtpStoreSchemaOptions,
): Promise<void> {
  for (const statement of EMAIL_OTP_STORE_D1_SCHEMA_SQL) {
    await options.database.exec(formatD1ExecStatement(statement));
  }
}

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

function requireD1ScopeString(input: unknown, field: string): string {
  const normalized = toOptionalTrimmedString(input);
  if (!normalized) throw new Error(`${field} is required for D1 Email OTP store`);
  return normalized;
}

function normalizeD1EmailOtpStoreOptions(
  input: D1EmailOtpStoreOptions,
): NormalizedD1EmailOtpStoreOptions {
  return {
    database: input.database,
    namespace: requireD1ScopeString(input.namespace, 'namespace'),
    orgId: requireD1ScopeString(input.orgId, 'orgId'),
    projectId: requireD1ScopeString(input.projectId, 'projectId'),
    envId: requireD1ScopeString(input.envId, 'envId'),
    ensureSchema: input.ensureSchema !== false,
  };
}

function d1ScopeFromConfig(input: {
  readonly config: Record<string, unknown>;
  readonly namespace: string;
}): Omit<D1EmailOtpStoreOptions, 'database'> {
  return {
    namespace: requireD1ScopeString(input.namespace, 'namespace'),
    orgId: requireD1ScopeString(input.config.orgId || input.config.ORG_ID, 'orgId'),
    projectId: requireD1ScopeString(input.config.projectId || input.config.PROJECT_ID, 'projectId'),
    envId: requireD1ScopeString(input.config.envId || input.config.ENV_ID, 'envId'),
  };
}

function bindD1EmailOtpScope(
  database: D1DatabaseLike,
  scope: D1EmailOtpScope,
  statement: string,
  values: readonly unknown[] = [],
): D1PreparedStatementLike {
  return database
    .prepare(statement)
    .bind(scope.namespace, scope.orgId, scope.projectId, scope.envId, ...values);
}

function assertD1EmailOtpOrgScope(input: {
  readonly recordOrgId: string | undefined;
  readonly scope: D1EmailOtpScope;
  readonly label: string;
}): void {
  if (!input.recordOrgId) return;
  if (input.recordOrgId !== input.scope.orgId) {
    throw new Error(`${input.label} orgId must match D1 Email OTP store orgId`);
  }
}

function resolveD1EmailOtpStoreOptions(
  input: EmailOtpStoreFactoryInput | undefined,
  storeLabel: string,
): D1EmailOtpStoreOptions | null {
  const config = getStoreConfig(input);
  if (toOptionalTrimmedString(config.kind) !== 'd1') return null;
  const database = resolveD1DatabaseFromConfig(config);
  if (!database) {
    throw new Error(`[email-otp] D1 ${storeLabel} store selected but no D1 database was provided`);
  }
  return {
    database,
    ...d1ScopeFromConfig({ config, namespace: resolveEmailOtpStoreNamespace(config) }),
  };
}

function assertEmailOtpStoreKindKnown(
  input: EmailOtpStoreFactoryInput | undefined,
  storeLabel: string,
): void {
  const config = getStoreConfig(input);
  const kind = toOptionalTrimmedString(config.kind);
  if (!kind || kind === 'in-memory') return;
  throw new Error(`[email-otp] Unknown ${storeLabel} store kind: ${kind}`);
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
  const challengeSubjectId = toOptionalTrimmedString(obj.challengeSubjectId);
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
  if (!challengeId || !challengeSubjectId || !walletId || !email || !otpCode || !sessionHash)
    return null;
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
    createdAtMs: Math.floor(createdAtMs),
    expiresAtMs: Math.floor(expiresAtMs),
    attemptCount: Math.floor(attemptCount),
    maxAttempts: Math.floor(maxAttempts),
  };
}

function challengeContextMatches(
  record: EmailOtpChallengeRecord,
  input: EmailOtpChallengeContextInput,
): boolean {
  return (
    record.expiresAtMs > input.nowMs &&
    record.challengeSubjectId === input.challengeSubjectId &&
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

export function emailOtpRecoveryWrappedEnrollmentEscrowBoundaryFromRecord(
  record: EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
): EmailOtpRecoveryWrappedEnrollmentEscrowBoundary {
  const binding = buildEmailOtpRecoveryWrapBinding({
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
  });
  switch (record.recoveryKeyStatus) {
    case 'active':
      return {
        record,
        binding,
        lifecycle: {
          status: 'active',
        },
      };
    case 'consumed':
      return {
        record,
        binding,
        lifecycle: {
          status: 'consumed',
          consumedAtMs: record.consumedAtMs,
        },
      };
    case 'revoked':
      return {
        record,
        binding,
        lifecycle: {
          status: 'revoked',
          revokedAtMs: record.revokedAtMs,
        },
      };
    default: {
      const _exhaustive: never = record;
      throw new Error(`Unsupported Email OTP recovery escrow lifecycle: ${String(_exhaustive)}`);
    }
  }
}

export function parseEmailOtpRecoveryWrappedEnrollmentEscrowBoundary(
  raw: unknown,
): EmailOtpRecoveryWrappedEnrollmentEscrowBoundary | null {
  const record = parseCurrentEmailOtpRecoveryWrappedEnrollmentEscrowRecord(raw);
  return record ? emailOtpRecoveryWrappedEnrollmentEscrowBoundaryFromRecord(record) : null;
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

function parseGoogleEmailOtpRegistrationOfferCandidates(
  raw: unknown,
): NonEmptyGoogleEmailOtpRegistrationOfferCandidates | null {
  if (!Array.isArray(raw) || raw.length < 1) return null;
  const candidates: GoogleEmailOtpRegistrationOfferCandidateRecord[] = [];
  for (const candidate of raw) {
    if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) return null;
    const record = candidate as Record<string, unknown>;
    const candidateId = toOptionalTrimmedString(record.candidateId);
    const walletId = toOptionalTrimmedString(record.walletId);
    const collisionCounter = Number(record.collisionCounter);
    if (!candidateId || !walletId) return null;
    if (!Number.isSafeInteger(collisionCounter) || collisionCounter < 0) return null;
    candidates.push({ candidateId, walletId, collisionCounter });
  }
  const [firstCandidate, ...remainingCandidates] = candidates;
  if (!firstCandidate) return null;
  return [firstCandidate, ...remainingCandidates];
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
  const offerId = toOptionalTrimmedString(obj.offerId);
  const offerCandidates = parseGoogleEmailOtpRegistrationOfferCandidates(obj.offerCandidates);
  const selectedCandidateId = toOptionalTrimmedString(obj.selectedCandidateId);
  const appSessionVersion = toOptionalTrimmedString(obj.appSessionVersion);
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
  if (
    !attemptId ||
    !providerSubject ||
    !email ||
    !walletId ||
    !offerId ||
    !offerCandidates ||
    !selectedCandidateId ||
    !offerCandidates.some((candidate) => candidate.candidateId === selectedCandidateId) ||
    !appSessionVersion
  ) {
    return null;
  }
  if (accountIdSlugVersion !== 'hmac_readable_v1') return null;
  if (!walletIdDerivationNonce) return null;
  if (
    state !== 'started' &&
    state !== 'key_finalized' &&
    state !== 'active' &&
    state !== 'abandoned' &&
    state !== 'failed' &&
    state !== 'expired'
  ) {
    return null;
  }
  if (!Number.isFinite(createdAtMs) || createdAtMs <= 0) return null;
  if (!Number.isFinite(updatedAtMs) || updatedAtMs <= 0) return null;
  if (!Number.isFinite(expiresAtMs) || expiresAtMs <= 0) return null;
  if (state === 'key_finalized' && !finalizedPublicKey) return null;
  if ((state === 'abandoned' || state === 'failed') && !failureCode) return null;
  const base = {
    version: 'google_email_otp_registration_attempt_v1' as const,
    attemptId,
    providerSubject,
    email,
    walletId,
    offerId,
    offerCandidates,
    selectedCandidateId,
    appSessionVersion,
    authProvider,
    accountIdSlugVersion: 'hmac_readable_v1' as const,
    walletIdDerivationNonce,
    collisionCounter,
    createdAtMs: Math.floor(createdAtMs),
    updatedAtMs: Math.floor(updatedAtMs),
    expiresAtMs: Math.floor(expiresAtMs),
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
  };
  switch (state) {
    case 'started':
      return { ...base, state };
    case 'key_finalized': {
      if (!finalizedPublicKey) return null;
      return { ...base, state, finalizedPublicKey };
    }
    case 'active':
      return { ...base, state, ...(finalizedPublicKey ? { finalizedPublicKey } : {}) };
    case 'abandoned':
    case 'failed': {
      if (!failureCode) return null;
      return {
        ...base,
        state,
        ...(finalizedPublicKey ? { finalizedPublicKey } : {}),
        failureCode,
      };
    }
    case 'expired':
      return {
        ...base,
        state,
        ...(finalizedPublicKey ? { finalizedPublicKey } : {}),
        ...(failureCode ? { failureCode } : {}),
      };
  }
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

  async countActiveByContext(input: EmailOtpChallengeContextInput): Promise<number> {
    let count = 0;
    for (const record of this.map.values()) {
      if (!challengeContextMatches(record, input)) continue;
      count += 1;
    }
    return count;
  }

  async findLatestActiveByContext(
    input: EmailOtpChallengeContextInput,
  ): Promise<EmailOtpChallengeRecord | null> {
    let latest: EmailOtpChallengeRecord | null = null;
    for (const record of this.map.values()) {
      if (!challengeContextMatches(record, input)) continue;
      if (!latest || record.expiresAtMs > latest.expiresAtMs) latest = record;
    }
    return latest ? cloneRecord(latest) : null;
  }

  async deleteOldestActiveByContext(
    input: EmailOtpChallengeContextInput,
  ): Promise<EmailOtpChallengeRecord | null> {
    let oldest: EmailOtpChallengeRecord | null = null;
    for (const record of this.map.values()) {
      if (!challengeContextMatches(record, input)) continue;
      if (!oldest || record.createdAtMs < oldest.createdAtMs) oldest = record;
    }
    if (!oldest) return null;
    this.map.delete(oldest.challengeId);
    return cloneRecord(oldest);
  }

  async findActiveByContext(
    input: EmailOtpChallengeContextInput & { otpCode: string },
  ): Promise<EmailOtpChallengeRecord | null> {
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

  async listByWallet(walletId: string): Promise<EmailOtpRecoveryWrappedEnrollmentEscrowRecord[]> {
    const key = toOptionalTrimmedString(walletId);
    if (!key) return [];
    return Array.from(this.map.values())
      .filter((record) => record.walletId === key)
      .map((record) => cloneRecord(record));
  }

  async put(record: EmailOtpRecoveryWrappedEnrollmentEscrowRecord): Promise<void> {
    const parsed = parseCurrentEmailOtpRecoveryWrappedEnrollmentEscrowRecord(record);
    if (!parsed) throw new Error('Invalid Email OTP recovery-wrapped enrollment escrow record');
    this.map.set(this.key(parsed), cloneRecord(parsed));
  }

  async putMany(records: readonly EmailOtpRecoveryWrappedEnrollmentEscrowRecord[]): Promise<void> {
    const parsedRecords = records.map((record) => {
      const parsed = parseCurrentEmailOtpRecoveryWrappedEnrollmentEscrowRecord(record);
      if (!parsed) throw new Error('Invalid Email OTP recovery-wrapped enrollment escrow record');
      return parsed;
    });
    for (const parsed of parsedRecords) {
      this.map.set(this.key(parsed), cloneRecord(parsed));
    }
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
    orgId: string;
    appSessionVersion: string;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
    nowMs: number;
  }): Promise<PendingGoogleEmailOtpRegistrationAttemptRecord | null> {
    for (const record of this.map.values()) {
      if (registrationAttemptMatchesStartedScope(record, input)) {
        return cloneRecord(record);
      }
    }
    return null;
  }

  async abandonStartedBySubjectEmailExceptAppSession(input: {
    providerSubject: string;
    email: string;
    orgId: string;
    appSessionVersion: string;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
    nowMs: number;
    failureCode: 'app_session_version_replaced';
  }): Promise<number> {
    let abandoned = 0;
    for (const record of this.map.values()) {
      if (!registrationAttemptMatchesReplacementScope(record, input)) continue;
      this.map.set(record.attemptId, {
        ...cloneRecord(record),
        state: 'abandoned',
        failureCode: input.failureCode,
        updatedAtMs: input.nowMs,
      });
      abandoned += 1;
    }
    return abandoned;
  }

  async hasLiveStartedWalletAttempt(input: { walletId: string; nowMs: number }): Promise<boolean> {
    for (const record of this.map.values()) {
      if (
        (record.state === 'started' || record.state === 'key_finalized') &&
        record.expiresAtMs > input.nowMs &&
        (record.walletId === input.walletId ||
          record.offerCandidates.some((candidate) => candidate.walletId === input.walletId))
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

abstract class D1EmailOtpStoreBase {
  protected readonly database: D1DatabaseLike;
  protected readonly scope: D1EmailOtpScope;
  private readonly ensureSchemaOnUse: boolean;
  private schemaReady = false;

  constructor(input: D1EmailOtpStoreOptions) {
    const normalized = normalizeD1EmailOtpStoreOptions(input);
    this.database = normalized.database;
    this.scope = {
      namespace: normalized.namespace,
      orgId: normalized.orgId,
      projectId: normalized.projectId,
      envId: normalized.envId,
    };
    this.ensureSchemaOnUse = normalized.ensureSchema;
  }

  protected async ensureSchema(): Promise<void> {
    if (!this.ensureSchemaOnUse || this.schemaReady) return;
    await ensureEmailOtpStoreD1Schema({ database: this.database });
    this.schemaReady = true;
  }

  protected bindScope(
    statement: string,
    values: readonly unknown[] = [],
  ): D1PreparedStatementLike {
    return bindD1EmailOtpScope(this.database, this.scope, statement, values);
  }
}

export class D1EmailOtpChallengeStore
  extends D1EmailOtpStoreBase
  implements EmailOtpChallengeStore
{
  readonly adapterKind = 'd1';

  async put(record: EmailOtpChallengeRecord): Promise<void> {
    await this.ensureSchema();
    const parsed = parseCurrentEmailOtpChallengeRecord(record);
    if (!parsed) throw new Error('Invalid Email OTP challenge record');
    assertD1EmailOtpOrgScope({
      recordOrgId: parsed.orgId,
      scope: this.scope,
      label: 'Email OTP challenge',
    });
    await this.bindScope(
      `INSERT INTO email_otp_challenges (
        namespace,
        org_id,
        project_id,
        env_id,
        challenge_id,
        challenge_subject_id,
        wallet_id,
        record_org_id,
        otp_channel,
        session_hash,
        app_session_version,
        action,
        operation,
        otp_code,
        record_json,
        created_at_ms,
        expires_at_ms
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (namespace, org_id, project_id, env_id, challenge_id)
      DO UPDATE SET
        challenge_subject_id = EXCLUDED.challenge_subject_id,
        wallet_id = EXCLUDED.wallet_id,
        record_org_id = EXCLUDED.record_org_id,
        otp_channel = EXCLUDED.otp_channel,
        session_hash = EXCLUDED.session_hash,
        app_session_version = EXCLUDED.app_session_version,
        action = EXCLUDED.action,
        operation = EXCLUDED.operation,
        otp_code = EXCLUDED.otp_code,
        record_json = EXCLUDED.record_json,
        created_at_ms = EXCLUDED.created_at_ms,
        expires_at_ms = EXCLUDED.expires_at_ms`,
      [
        parsed.challengeId,
        parsed.challengeSubjectId,
        parsed.walletId,
        parsed.orgId || '',
        parsed.otpChannel,
        parsed.sessionHash,
        parsed.appSessionVersion,
        parsed.action,
        parsed.operation,
        parsed.otpCode,
        JSON.stringify(parsed),
        parsed.createdAtMs,
        parsed.expiresAtMs,
      ],
    ).run();
  }

  async get(challengeId: string): Promise<EmailOtpChallengeRecord | null> {
    await this.ensureSchema();
    const id = toOptionalTrimmedString(challengeId);
    if (!id) return null;
    const row = await this.bindScope(
      `SELECT record_json, expires_at_ms, challenge_id
         FROM email_otp_challenges
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND challenge_id = ?
        LIMIT 1`,
      [id],
    ).first<D1EmailOtpRecordRow>();
    const parsed = parseCurrentEmailOtpChallengeRow({
      recordJson: parseJsonRecord(row?.record_json),
      expiresAtMs: row?.expires_at_ms,
    });
    if (!row) return null;
    if (!parsed) {
      await this.del(id);
      return null;
    }
    return cloneRecord(parsed);
  }

  async deleteExpired(nowMs: number): Promise<EmailOtpChallengeRecord[]> {
    await this.ensureSchema();
    const result = await this.bindScope(
      `DELETE FROM email_otp_challenges
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND expires_at_ms <= ?
        RETURNING record_json, expires_at_ms`,
      [nowMs],
    ).all<D1EmailOtpRecordRow>();
    return (result.results || [])
      .map((row) =>
        parseCurrentEmailOtpChallengeRow({
          recordJson: parseJsonRecord(row.record_json),
          expiresAtMs: row.expires_at_ms,
        }),
      )
      .filter((record): record is EmailOtpChallengeRecord => Boolean(record))
      .map((record) => cloneRecord(record));
  }

  async countActiveByContext(input: EmailOtpChallengeContextInput): Promise<number> {
    await this.ensureSchema();
    const row = await this.bindScope(
      `SELECT COUNT(*) AS count
         FROM email_otp_challenges
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND expires_at_ms > ?
          AND challenge_subject_id = ?
          AND wallet_id = ?
          AND record_org_id = ?
          AND otp_channel = ?
          AND session_hash = ?
          AND app_session_version = ?
          AND action = ?
          AND operation = ?`,
      [
        input.nowMs,
        input.challengeSubjectId,
        input.walletId,
        String(input.orgId || ''),
        input.otpChannel,
        input.sessionHash,
        input.appSessionVersion,
        input.action,
        input.operation,
      ],
    ).first<{ count?: unknown }>();
    return Number(row?.count || 0);
  }

  async findLatestActiveByContext(
    input: EmailOtpChallengeContextInput,
  ): Promise<EmailOtpChallengeRecord | null> {
    await this.ensureSchema();
    const row = await this.bindScope(
      `SELECT record_json, expires_at_ms, challenge_id
         FROM email_otp_challenges
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND expires_at_ms > ?
          AND challenge_subject_id = ?
          AND wallet_id = ?
          AND record_org_id = ?
          AND otp_channel = ?
          AND session_hash = ?
          AND app_session_version = ?
          AND action = ?
          AND operation = ?
        ORDER BY expires_at_ms DESC, created_at_ms DESC
        LIMIT 1`,
      [
        input.nowMs,
        input.challengeSubjectId,
        input.walletId,
        String(input.orgId || ''),
        input.otpChannel,
        input.sessionHash,
        input.appSessionVersion,
        input.action,
        input.operation,
      ],
    ).first<D1EmailOtpRecordRow>();
    const parsed = parseCurrentEmailOtpChallengeRow({
      recordJson: parseJsonRecord(row?.record_json),
      expiresAtMs: row?.expires_at_ms,
    });
    if (parsed) return cloneRecord(parsed);
    const malformedId = toOptionalTrimmedString(row?.challenge_id);
    if (malformedId) await this.del(malformedId);
    return null;
  }

  async deleteOldestActiveByContext(
    input: EmailOtpChallengeContextInput,
  ): Promise<EmailOtpChallengeRecord | null> {
    await this.ensureSchema();
    const row = await this.bindScope(
      `WITH oldest AS (
        SELECT challenge_id
          FROM email_otp_challenges
         WHERE namespace = ?
           AND org_id = ?
           AND project_id = ?
           AND env_id = ?
           AND expires_at_ms > ?
           AND challenge_subject_id = ?
           AND wallet_id = ?
           AND record_org_id = ?
           AND otp_channel = ?
           AND session_hash = ?
           AND app_session_version = ?
           AND action = ?
           AND operation = ?
         ORDER BY created_at_ms ASC, expires_at_ms ASC
         LIMIT 1
      )
      DELETE FROM email_otp_challenges
       WHERE namespace = ?
         AND org_id = ?
         AND project_id = ?
         AND env_id = ?
         AND challenge_id IN (SELECT challenge_id FROM oldest)
      RETURNING record_json, expires_at_ms, challenge_id`,
      [
        input.nowMs,
        input.challengeSubjectId,
        input.walletId,
        String(input.orgId || ''),
        input.otpChannel,
        input.sessionHash,
        input.appSessionVersion,
        input.action,
        input.operation,
        this.scope.namespace,
        this.scope.orgId,
        this.scope.projectId,
        this.scope.envId,
      ],
    ).first<D1EmailOtpRecordRow>();
    const parsed = parseCurrentEmailOtpChallengeRow({
      recordJson: parseJsonRecord(row?.record_json),
      expiresAtMs: row?.expires_at_ms,
    });
    if (parsed) return cloneRecord(parsed);
    const malformedId = toOptionalTrimmedString(row?.challenge_id);
    if (malformedId) await this.del(malformedId);
    return null;
  }

  async findActiveByContext(
    input: EmailOtpChallengeContextInput & { otpCode: string },
  ): Promise<EmailOtpChallengeRecord | null> {
    await this.ensureSchema();
    const row = await this.bindScope(
      `SELECT record_json, expires_at_ms, challenge_id
         FROM email_otp_challenges
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND expires_at_ms > ?
          AND challenge_subject_id = ?
          AND wallet_id = ?
          AND record_org_id = ?
          AND otp_channel = ?
          AND session_hash = ?
          AND app_session_version = ?
          AND action = ?
          AND operation = ?
          AND otp_code = ?
        ORDER BY expires_at_ms DESC
        LIMIT 1`,
      [
        input.nowMs,
        input.challengeSubjectId,
        input.walletId,
        String(input.orgId || ''),
        input.otpChannel,
        input.sessionHash,
        input.appSessionVersion,
        input.action,
        input.operation,
        input.otpCode,
      ],
    ).first<D1EmailOtpRecordRow>();
    const parsed = parseCurrentEmailOtpChallengeRow({
      recordJson: parseJsonRecord(row?.record_json),
      expiresAtMs: row?.expires_at_ms,
    });
    if (parsed) return cloneRecord(parsed);
    const malformedId = toOptionalTrimmedString(row?.challenge_id);
    if (malformedId) await this.del(malformedId);
    return null;
  }

  async del(challengeId: string): Promise<void> {
    await this.ensureSchema();
    const id = toOptionalTrimmedString(challengeId);
    if (!id) return;
    await this.bindScope(
      `DELETE FROM email_otp_challenges
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND challenge_id = ?`,
      [id],
    ).run();
  }
}

export class D1EmailOtpGrantStore extends D1EmailOtpStoreBase implements EmailOtpGrantStore {
  readonly adapterKind = 'd1';

  async put(record: EmailOtpGrantRecord): Promise<void> {
    await this.ensureSchema();
    const parsed = parseCurrentEmailOtpGrantRecord(record);
    if (!parsed) throw new Error('Invalid Email OTP grant record');
    assertD1EmailOtpOrgScope({
      recordOrgId: parsed.orgId,
      scope: this.scope,
      label: 'Email OTP grant',
    });
    await this.bindScope(
      `INSERT INTO email_otp_grants (
        namespace,
        org_id,
        project_id,
        env_id,
        grant_token,
        user_id,
        wallet_id,
        record_org_id,
        challenge_id,
        action,
        record_json,
        issued_at_ms,
        expires_at_ms
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (namespace, org_id, project_id, env_id, grant_token)
      DO UPDATE SET
        user_id = EXCLUDED.user_id,
        wallet_id = EXCLUDED.wallet_id,
        record_org_id = EXCLUDED.record_org_id,
        challenge_id = EXCLUDED.challenge_id,
        action = EXCLUDED.action,
        record_json = EXCLUDED.record_json,
        issued_at_ms = EXCLUDED.issued_at_ms,
        expires_at_ms = EXCLUDED.expires_at_ms`,
      [
        parsed.grantToken,
        parsed.userId,
        parsed.walletId,
        parsed.orgId || '',
        parsed.challengeId,
        parsed.action,
        JSON.stringify(parsed),
        parsed.issuedAtMs,
        parsed.expiresAtMs,
      ],
    ).run();
  }

  async get(grantToken: string): Promise<EmailOtpGrantRecord | null> {
    await this.ensureSchema();
    const token = toOptionalTrimmedString(grantToken);
    if (!token) return null;
    const row = await this.bindScope(
      `SELECT record_json, expires_at_ms
         FROM email_otp_grants
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND grant_token = ?
        LIMIT 1`,
      [token],
    ).first<D1EmailOtpRecordRow>();
    const parsed = parseCurrentEmailOtpGrantRow({
      recordJson: parseJsonRecord(row?.record_json),
      expiresAtMs: row?.expires_at_ms,
    });
    if (!row) return null;
    if (!parsed) {
      await this.del(token);
      return null;
    }
    return cloneRecord(parsed);
  }

  async consume(grantToken: string): Promise<EmailOtpGrantRecord | null> {
    await this.ensureSchema();
    const token = toOptionalTrimmedString(grantToken);
    if (!token) return null;
    const row = await this.bindScope(
      `DELETE FROM email_otp_grants
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND grant_token = ?
      RETURNING record_json, expires_at_ms`,
      [token],
    ).first<D1EmailOtpRecordRow>();
    const parsed = parseCurrentEmailOtpGrantRow({
      recordJson: parseJsonRecord(row?.record_json),
      expiresAtMs: row?.expires_at_ms,
    });
    return parsed ? cloneRecord(parsed) : null;
  }

  async del(grantToken: string): Promise<void> {
    await this.ensureSchema();
    const token = toOptionalTrimmedString(grantToken);
    if (!token) return;
    await this.bindScope(
      `DELETE FROM email_otp_grants
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND grant_token = ?`,
      [token],
    ).run();
  }
}

export class D1EmailOtpWalletEnrollmentStore
  extends D1EmailOtpStoreBase
  implements EmailOtpWalletEnrollmentStore
{
  readonly adapterKind = 'd1';

  async get(walletId: string): Promise<EmailOtpWalletEnrollmentRecord | null> {
    await this.ensureSchema();
    const key = toOptionalTrimmedString(walletId);
    if (!key) return null;
    const row = await this.bindScope(
      `SELECT record_json, updated_at_ms, wallet_id
         FROM email_otp_wallet_enrollments
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND wallet_id = ?
        LIMIT 1`,
      [key],
    ).first<D1EmailOtpRecordRow>();
    const parsed = parseCurrentEmailOtpWalletEnrollmentRow({
      recordJson: parseJsonRecord(row?.record_json),
      updatedAtMs: row?.updated_at_ms,
    });
    if (!row) return null;
    if (!parsed) {
      await this.del(key);
      return null;
    }
    return cloneRecord(parsed);
  }

  async getByProviderUserId(input: {
    providerUserId: string;
    orgId: string;
  }): Promise<EmailOtpWalletEnrollmentRecord | null> {
    await this.ensureSchema();
    const providerUserId = toOptionalTrimmedString(input.providerUserId);
    const orgId = toOptionalTrimmedString(input.orgId);
    if (!providerUserId || !orgId) return null;
    const row = await this.bindScope(
      `SELECT record_json, updated_at_ms, wallet_id
         FROM email_otp_wallet_enrollments
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND record_org_id = ?
          AND provider_user_id = ?
        ORDER BY updated_at_ms DESC
        LIMIT 1`,
      [orgId, providerUserId],
    ).first<D1EmailOtpRecordRow>();
    const parsed = parseCurrentEmailOtpWalletEnrollmentRow({
      recordJson: parseJsonRecord(row?.record_json),
      updatedAtMs: row?.updated_at_ms,
    });
    if (parsed) return cloneRecord(parsed);
    const malformedWalletId = toOptionalTrimmedString(row?.wallet_id);
    if (malformedWalletId) await this.del(malformedWalletId);
    return null;
  }

  async put(record: EmailOtpWalletEnrollmentRecord): Promise<void> {
    await this.ensureSchema();
    const parsed = parseCurrentEmailOtpWalletEnrollmentRecord(record);
    if (!parsed) throw new Error('Invalid Email OTP wallet enrollment record');
    assertD1EmailOtpOrgScope({
      recordOrgId: parsed.orgId,
      scope: this.scope,
      label: 'Email OTP wallet enrollment',
    });
    await this.bindScope(
      `INSERT INTO email_otp_wallet_enrollments (
        namespace,
        org_id,
        project_id,
        env_id,
        wallet_id,
        provider_user_id,
        record_org_id,
        verified_email,
        record_json,
        created_at_ms,
        updated_at_ms
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (namespace, org_id, project_id, env_id, wallet_id)
      DO UPDATE SET
        provider_user_id = EXCLUDED.provider_user_id,
        record_org_id = EXCLUDED.record_org_id,
        verified_email = EXCLUDED.verified_email,
        record_json = EXCLUDED.record_json,
        created_at_ms = EXCLUDED.created_at_ms,
        updated_at_ms = EXCLUDED.updated_at_ms`,
      [
        parsed.walletId,
        parsed.providerUserId,
        parsed.orgId,
        parsed.verifiedEmail,
        JSON.stringify(parsed),
        parsed.createdAtMs,
        parsed.updatedAtMs,
      ],
    ).run();
  }

  async del(walletId: string): Promise<void> {
    await this.ensureSchema();
    const key = toOptionalTrimmedString(walletId);
    if (!key) return;
    await this.bindScope(
      `DELETE FROM email_otp_wallet_enrollments
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND wallet_id = ?`,
      [key],
    ).run();
  }
}

export class D1EmailOtpRecoveryWrappedEnrollmentEscrowStore
  extends D1EmailOtpStoreBase
  implements EmailOtpRecoveryWrappedEnrollmentEscrowStore
{
  readonly adapterKind = 'd1';

  async get(input: {
    walletId: string;
    recoveryKeyId: string;
  }): Promise<EmailOtpRecoveryWrappedEnrollmentEscrowRecord | null> {
    await this.ensureSchema();
    const walletId = toOptionalTrimmedString(input.walletId);
    const recoveryKeyId = toOptionalTrimmedString(input.recoveryKeyId);
    if (!walletId || !recoveryKeyId) return null;
    const row = await this.bindScope(
      `SELECT record_json, updated_at_ms, recovery_key_id
         FROM email_otp_recovery_wrapped_enrollment_escrows
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND wallet_id = ?
          AND recovery_key_id = ?
        LIMIT 1`,
      [walletId, recoveryKeyId],
    ).first<D1EmailOtpRecordRow>();
    const parsed = parseCurrentEmailOtpRecoveryWrappedEnrollmentEscrowRow({
      recordJson: parseJsonRecord(row?.record_json),
      updatedAtMs: row?.updated_at_ms,
    });
    if (!row) return null;
    if (!parsed) {
      await this.del({ walletId, recoveryKeyId });
      return null;
    }
    return cloneRecord(parsed);
  }

  async listActiveByWallet(
    walletId: string,
  ): Promise<EmailOtpRecoveryWrappedEnrollmentEscrowRecord[]> {
    return await this.listByWalletAndStatus({ walletId, status: 'active' });
  }

  async listByWallet(walletId: string): Promise<EmailOtpRecoveryWrappedEnrollmentEscrowRecord[]> {
    return await this.listByWalletAndStatus({ walletId, status: null });
  }

  private async listByWalletAndStatus(input: {
    walletId: string;
    status: EmailOtpRecoveryWrappedEnrollmentEscrowStatus | null;
  }): Promise<EmailOtpRecoveryWrappedEnrollmentEscrowRecord[]> {
    await this.ensureSchema();
    const key = toOptionalTrimmedString(input.walletId);
    if (!key) return [];
    const rows = await this.bindScope(
      `SELECT record_json, updated_at_ms, recovery_key_id
         FROM email_otp_recovery_wrapped_enrollment_escrows
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND wallet_id = ?
          AND (? IS NULL OR recovery_key_status = ?)
        ORDER BY updated_at_ms DESC, recovery_key_id ASC`,
      [key, input.status, input.status],
    ).all<D1EmailOtpRecordRow>();
    const records: EmailOtpRecoveryWrappedEnrollmentEscrowRecord[] = [];
    const malformedRecoveryKeyIds: string[] = [];
    for (const row of rows.results || []) {
      const parsed = parseCurrentEmailOtpRecoveryWrappedEnrollmentEscrowRow({
        recordJson: parseJsonRecord(row.record_json),
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
    await this.ensureSchema();
    const parsed = parseCurrentEmailOtpRecoveryWrappedEnrollmentEscrowRecord(record);
    if (!parsed) throw new Error('Invalid Email OTP recovery-wrapped enrollment escrow record');
    await this.putParsed(parsed);
  }

  async putMany(records: readonly EmailOtpRecoveryWrappedEnrollmentEscrowRecord[]): Promise<void> {
    await this.ensureSchema();
    const statements: D1PreparedStatementLike[] = [];
    for (const record of records) {
      const parsed = parseCurrentEmailOtpRecoveryWrappedEnrollmentEscrowRecord(record);
      if (!parsed) throw new Error('Invalid Email OTP recovery-wrapped enrollment escrow record');
      statements.push(this.putParsedStatement(parsed));
    }
    if (statements.length === 0) return;
    await this.database.batch(statements);
  }

  private async putParsed(
    parsed: EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
  ): Promise<void> {
    await this.putParsedStatement(parsed).run();
  }

  private putParsedStatement(
    parsed: EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
  ): D1PreparedStatementLike {
    return this.bindScope(
      `INSERT INTO email_otp_recovery_wrapped_enrollment_escrows (
        namespace,
        org_id,
        project_id,
        env_id,
        wallet_id,
        recovery_key_id,
        recovery_key_status,
        record_json,
        issued_at_ms,
        updated_at_ms
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (namespace, org_id, project_id, env_id, wallet_id, recovery_key_id)
      DO UPDATE SET
        recovery_key_status = EXCLUDED.recovery_key_status,
        record_json = EXCLUDED.record_json,
        issued_at_ms = EXCLUDED.issued_at_ms,
        updated_at_ms = EXCLUDED.updated_at_ms`,
      [
        parsed.walletId,
        parsed.recoveryKeyId,
        parsed.recoveryKeyStatus,
        JSON.stringify(parsed),
        parsed.issuedAtMs,
        parsed.updatedAtMs,
      ],
    );
  }

  async del(input: { walletId: string; recoveryKeyId: string }): Promise<void> {
    await this.ensureSchema();
    const walletId = toOptionalTrimmedString(input.walletId);
    const recoveryKeyId = toOptionalTrimmedString(input.recoveryKeyId);
    if (!walletId || !recoveryKeyId) return;
    await this.bindScope(
      `DELETE FROM email_otp_recovery_wrapped_enrollment_escrows
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND wallet_id = ?
          AND recovery_key_id = ?`,
      [walletId, recoveryKeyId],
    ).run();
  }
}

export class D1EmailOtpAuthStateStore
  extends D1EmailOtpStoreBase
  implements EmailOtpAuthStateStore
{
  readonly adapterKind = 'd1';

  async get(walletId: string): Promise<EmailOtpAuthStateRecord | null> {
    await this.ensureSchema();
    const key = toOptionalTrimmedString(walletId);
    if (!key) return null;
    const row = await this.bindScope(
      `SELECT record_json, updated_at_ms
         FROM email_otp_auth_states
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND wallet_id = ?
        LIMIT 1`,
      [key],
    ).first<D1EmailOtpRecordRow>();
    const parsed = parseCurrentEmailOtpAuthStateRow({
      recordJson: parseJsonRecord(row?.record_json),
      updatedAtMs: row?.updated_at_ms,
    });
    if (!row) return null;
    if (!parsed) {
      await this.del(key);
      return null;
    }
    return cloneRecord(parsed);
  }

  async put(record: EmailOtpAuthStateRecord): Promise<void> {
    await this.ensureSchema();
    const parsed = parseCurrentEmailOtpAuthStateRecord(record);
    if (!parsed) throw new Error('Invalid Email OTP auth state record');
    assertD1EmailOtpOrgScope({
      recordOrgId: parsed.orgId,
      scope: this.scope,
      label: 'Email OTP auth state',
    });
    await this.bindScope(
      `INSERT INTO email_otp_auth_states (
        namespace,
        org_id,
        project_id,
        env_id,
        wallet_id,
        provider_user_id,
        record_org_id,
        record_json,
        created_at_ms,
        updated_at_ms
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (namespace, org_id, project_id, env_id, wallet_id)
      DO UPDATE SET
        provider_user_id = EXCLUDED.provider_user_id,
        record_org_id = EXCLUDED.record_org_id,
        record_json = EXCLUDED.record_json,
        created_at_ms = EXCLUDED.created_at_ms,
        updated_at_ms = EXCLUDED.updated_at_ms`,
      [
        parsed.walletId,
        parsed.providerUserId,
        parsed.orgId,
        JSON.stringify(parsed),
        parsed.createdAtMs,
        parsed.updatedAtMs,
      ],
    ).run();
  }

  async del(walletId: string): Promise<void> {
    await this.ensureSchema();
    const key = toOptionalTrimmedString(walletId);
    if (!key) return;
    await this.bindScope(
      `DELETE FROM email_otp_auth_states
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND wallet_id = ?`,
      [key],
    ).run();
  }
}

export class D1EmailOtpUnlockChallengeStore
  extends D1EmailOtpStoreBase
  implements EmailOtpUnlockChallengeStore
{
  readonly adapterKind = 'd1';

  async put(record: EmailOtpUnlockChallengeRecord): Promise<void> {
    await this.ensureSchema();
    const parsed = parseCurrentEmailOtpUnlockChallengeRecord(record);
    if (!parsed) throw new Error('Invalid Email OTP unlock challenge record');
    assertD1EmailOtpOrgScope({
      recordOrgId: parsed.orgId,
      scope: this.scope,
      label: 'Email OTP unlock challenge',
    });
    await this.bindScope(
      `INSERT INTO email_otp_unlock_challenges (
        namespace,
        org_id,
        project_id,
        env_id,
        challenge_id,
        wallet_id,
        user_id,
        record_org_id,
        record_json,
        created_at_ms,
        expires_at_ms
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (namespace, org_id, project_id, env_id, challenge_id)
      DO UPDATE SET
        wallet_id = EXCLUDED.wallet_id,
        user_id = EXCLUDED.user_id,
        record_org_id = EXCLUDED.record_org_id,
        record_json = EXCLUDED.record_json,
        created_at_ms = EXCLUDED.created_at_ms,
        expires_at_ms = EXCLUDED.expires_at_ms`,
      [
        parsed.challengeId,
        parsed.walletId,
        parsed.userId,
        parsed.orgId || '',
        JSON.stringify(parsed),
        parsed.createdAtMs,
        parsed.expiresAtMs,
      ],
    ).run();
  }

  async consume(challengeId: string): Promise<EmailOtpUnlockChallengeRecord | null> {
    await this.ensureSchema();
    const id = toOptionalTrimmedString(challengeId);
    if (!id) return null;
    const row = await this.bindScope(
      `DELETE FROM email_otp_unlock_challenges
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND challenge_id = ?
      RETURNING record_json, expires_at_ms`,
      [id],
    ).first<D1EmailOtpRecordRow>();
    const parsed = parseCurrentEmailOtpUnlockChallengeRow({
      recordJson: parseJsonRecord(row?.record_json),
      expiresAtMs: row?.expires_at_ms,
    });
    return parsed ? cloneRecord(parsed) : null;
  }

  async del(challengeId: string): Promise<void> {
    await this.ensureSchema();
    const id = toOptionalTrimmedString(challengeId);
    if (!id) return;
    await this.bindScope(
      `DELETE FROM email_otp_unlock_challenges
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND challenge_id = ?`,
      [id],
    ).run();
  }
}

export class D1EmailOtpRegistrationAttemptStore
  extends D1EmailOtpStoreBase
  implements EmailOtpRegistrationAttemptStore
{
  readonly adapterKind = 'd1';

  async put(record: GoogleEmailOtpRegistrationAttemptRecord): Promise<void> {
    await this.ensureSchema();
    const parsed = parseCurrentGoogleEmailOtpRegistrationAttemptRecord(record);
    if (!parsed) throw new Error('Invalid Google Email OTP registration attempt record');
    assertD1EmailOtpOrgScope({
      recordOrgId: parsed.runtimePolicyScope?.orgId,
      scope: this.scope,
      label: 'Google Email OTP registration attempt',
    });
    await this.bindScope(
      `INSERT INTO email_otp_registration_attempts (
        namespace,
        org_id,
        project_id,
        env_id,
        attempt_id,
        provider_subject,
        email,
        wallet_id,
        state,
        app_session_version,
        runtime_org_id,
        runtime_policy_key,
        offer_wallet_ids_json,
        record_json,
        created_at_ms,
        updated_at_ms,
        expires_at_ms
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (namespace, org_id, project_id, env_id, attempt_id)
      DO UPDATE SET
        provider_subject = EXCLUDED.provider_subject,
        email = EXCLUDED.email,
        wallet_id = EXCLUDED.wallet_id,
        state = EXCLUDED.state,
        app_session_version = EXCLUDED.app_session_version,
        runtime_org_id = EXCLUDED.runtime_org_id,
        runtime_policy_key = EXCLUDED.runtime_policy_key,
        offer_wallet_ids_json = EXCLUDED.offer_wallet_ids_json,
        record_json = EXCLUDED.record_json,
        created_at_ms = EXCLUDED.created_at_ms,
        updated_at_ms = EXCLUDED.updated_at_ms,
        expires_at_ms = EXCLUDED.expires_at_ms`,
      [
        parsed.attemptId,
        parsed.providerSubject,
        parsed.email,
        parsed.walletId,
        parsed.state,
        parsed.appSessionVersion,
        parsed.runtimePolicyScope?.orgId || '',
        runtimePolicyScopeKey(parsed.runtimePolicyScope),
        JSON.stringify(parsed.offerCandidates.map((candidate) => candidate.walletId)),
        JSON.stringify(parsed),
        parsed.createdAtMs,
        parsed.updatedAtMs,
        parsed.expiresAtMs,
      ],
    ).run();
  }

  async get(attemptId: string): Promise<GoogleEmailOtpRegistrationAttemptRecord | null> {
    await this.ensureSchema();
    const id = toOptionalTrimmedString(attemptId);
    if (!id) return null;
    const row = await this.bindScope(
      `SELECT record_json, expires_at_ms, updated_at_ms, attempt_id
         FROM email_otp_registration_attempts
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND attempt_id = ?
        LIMIT 1`,
      [id],
    ).first<D1EmailOtpRecordRow>();
    const parsed = parseCurrentGoogleEmailOtpRegistrationAttemptRow({
      recordJson: parseJsonRecord(row?.record_json),
      expiresAtMs: row?.expires_at_ms,
      updatedAtMs: row?.updated_at_ms,
    });
    if (!row) return null;
    if (!parsed) {
      await this.deleteAttempt(id);
      return null;
    }
    return cloneRecord(parsed);
  }

  async findStartedBySubjectEmail(input: {
    providerSubject: string;
    email: string;
    orgId: string;
    appSessionVersion: string;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
    nowMs: number;
  }): Promise<PendingGoogleEmailOtpRegistrationAttemptRecord | null> {
    await this.ensureSchema();
    const row = await this.bindScope(
      `SELECT record_json, expires_at_ms, updated_at_ms, attempt_id
         FROM email_otp_registration_attempts
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND provider_subject = ?
          AND email = ?
          AND state IN ('started', 'key_finalized')
          AND expires_at_ms > ?
          AND app_session_version = ?
          AND runtime_org_id = ?
          AND runtime_policy_key = ?
        ORDER BY updated_at_ms DESC
        LIMIT 1`,
      [
        input.providerSubject,
        input.email,
        input.nowMs,
        input.appSessionVersion,
        input.orgId,
        runtimePolicyScopeKey(input.runtimePolicyScope),
      ],
    ).first<D1EmailOtpRecordRow>();
    const parsed = parseCurrentGoogleEmailOtpRegistrationAttemptRow({
      recordJson: parseJsonRecord(row?.record_json),
      expiresAtMs: row?.expires_at_ms,
      updatedAtMs: row?.updated_at_ms,
    });
    if (parsed && registrationAttemptMatchesStartedScope(parsed, input)) {
      return cloneRecord(parsed);
    }
    const malformedAttemptId = toOptionalTrimmedString(row?.attempt_id);
    if (row && !parsed && malformedAttemptId) await this.deleteAttempt(malformedAttemptId);
    return null;
  }

  async abandonStartedBySubjectEmailExceptAppSession(input: {
    providerSubject: string;
    email: string;
    orgId: string;
    appSessionVersion: string;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
    nowMs: number;
    failureCode: 'app_session_version_replaced';
  }): Promise<number> {
    await this.ensureSchema();
    const result = await this.bindScope(
      `SELECT record_json, expires_at_ms, updated_at_ms, attempt_id
         FROM email_otp_registration_attempts
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND provider_subject = ?
          AND email = ?
          AND state IN ('started', 'key_finalized')
          AND expires_at_ms > ?`,
      [input.providerSubject, input.email, input.nowMs],
    ).all<D1EmailOtpRecordRow>();
    let abandoned = 0;
    for (const row of result.results || []) {
      const parsed = parseCurrentGoogleEmailOtpRegistrationAttemptRow({
        recordJson: parseJsonRecord(row.record_json),
        expiresAtMs: row.expires_at_ms,
        updatedAtMs: row.updated_at_ms,
      });
      if (!parsed) {
        const attemptId = toOptionalTrimmedString(row.attempt_id);
        if (attemptId) await this.deleteAttempt(attemptId);
        continue;
      }
      if (!registrationAttemptMatchesReplacementScope(parsed, input)) continue;
      await this.put({
        ...parsed,
        state: 'abandoned',
        failureCode: input.failureCode,
        updatedAtMs: input.nowMs,
      });
      abandoned += 1;
    }
    return abandoned;
  }

  async hasLiveStartedWalletAttempt(input: { walletId: string; nowMs: number }): Promise<boolean> {
    await this.ensureSchema();
    const walletId = toOptionalTrimmedString(input.walletId);
    if (!walletId) return false;
    const row = await this.bindScope(
      `SELECT 1 AS found
         FROM email_otp_registration_attempts
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND state IN ('started', 'key_finalized')
          AND expires_at_ms > ?
          AND (
            wallet_id = ?
            OR EXISTS (
              SELECT 1
                FROM json_each(offer_wallet_ids_json)
               WHERE value = ?
            )
          )
        LIMIT 1`,
      [input.nowMs, walletId, walletId],
    ).first<{ found?: unknown }>();
    return Boolean(row);
  }

  async deleteExpired(nowMs: number): Promise<number> {
    await this.ensureSchema();
    const result = await this.bindScope(
      `DELETE FROM email_otp_registration_attempts
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND (expires_at_ms <= ? OR state = 'expired')`,
      [nowMs],
    ).run();
    return d1ChangedRows(result);
  }

  private async deleteAttempt(attemptId: string): Promise<void> {
    const id = toOptionalTrimmedString(attemptId);
    if (!id) return;
    await this.bindScope(
      `DELETE FROM email_otp_registration_attempts
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND attempt_id = ?`,
      [id],
    ).run();
  }
}

export function createEmailOtpChallengeStore(
  input?: EmailOtpStoreFactoryInput,
): EmailOtpChallengeStore {
  const d1 = resolveD1EmailOtpStoreOptions(input, 'challenge');
  if (d1) {
    input?.logger?.info('[email-otp] Using D1 challenge store');
    return new D1EmailOtpChallengeStore(d1);
  }
  assertEmailOtpStoreKindKnown(input, 'challenge');
  input?.logger?.info('[email-otp] Using in-memory challenge store (non-persistent)');
  return new InMemoryEmailOtpChallengeStore();
}

export function createEmailOtpGrantStore(input?: EmailOtpStoreFactoryInput): EmailOtpGrantStore {
  const d1 = resolveD1EmailOtpStoreOptions(input, 'grant');
  if (d1) {
    input?.logger?.info('[email-otp] Using D1 grant store');
    return new D1EmailOtpGrantStore(d1);
  }
  assertEmailOtpStoreKindKnown(input, 'grant');
  input?.logger?.info('[email-otp] Using in-memory grant store (non-persistent)');
  return new InMemoryEmailOtpGrantStore();
}

export function createEmailOtpWalletEnrollmentStore(
  input?: EmailOtpStoreFactoryInput,
): EmailOtpWalletEnrollmentStore {
  const d1 = resolveD1EmailOtpStoreOptions(input, 'wallet enrollment');
  if (d1) {
    input?.logger?.info('[email-otp] Using D1 wallet enrollment store');
    return new D1EmailOtpWalletEnrollmentStore(d1);
  }
  assertEmailOtpStoreKindKnown(input, 'enrollment');
  input?.logger?.info('[email-otp] Using in-memory wallet enrollment store (non-persistent)');
  return new InMemoryEmailOtpWalletEnrollmentStore();
}

export function createEmailOtpRecoveryWrappedEnrollmentEscrowStore(
  input?: EmailOtpStoreFactoryInput,
): EmailOtpRecoveryWrappedEnrollmentEscrowStore {
  const d1 = resolveD1EmailOtpStoreOptions(input, 'recovery-wrapped enrollment escrow');
  if (d1) {
    input?.logger?.info('[email-otp] Using D1 recovery-wrapped enrollment escrow store');
    return new D1EmailOtpRecoveryWrappedEnrollmentEscrowStore(d1);
  }
  assertEmailOtpStoreKindKnown(input, 'recovery-wrapped enrollment escrow');
  input?.logger?.info(
    '[email-otp] Using in-memory recovery-wrapped enrollment escrow store (non-persistent)',
  );
  return new InMemoryEmailOtpRecoveryWrappedEnrollmentEscrowStore();
}

export function createEmailOtpAuthStateStore(
  input?: EmailOtpStoreFactoryInput,
): EmailOtpAuthStateStore {
  const d1 = resolveD1EmailOtpStoreOptions(input, 'auth state');
  if (d1) {
    input?.logger?.info('[email-otp] Using D1 auth state store');
    return new D1EmailOtpAuthStateStore(d1);
  }
  assertEmailOtpStoreKindKnown(input, 'auth state');
  input?.logger?.info('[email-otp] Using in-memory auth state store (non-persistent)');
  return new InMemoryEmailOtpAuthStateStore();
}

export function createEmailOtpUnlockChallengeStore(
  input?: EmailOtpStoreFactoryInput,
): EmailOtpUnlockChallengeStore {
  const d1 = resolveD1EmailOtpStoreOptions(input, 'unlock challenge');
  if (d1) {
    input?.logger?.info('[email-otp] Using D1 unlock challenge store');
    return new D1EmailOtpUnlockChallengeStore(d1);
  }
  assertEmailOtpStoreKindKnown(input, 'unlock challenge');
  input?.logger?.info('[email-otp] Using in-memory unlock challenge store (non-persistent)');
  return new InMemoryEmailOtpUnlockChallengeStore();
}

export function createEmailOtpRegistrationAttemptStore(
  input?: EmailOtpStoreFactoryInput,
): EmailOtpRegistrationAttemptStore {
  const d1 = resolveD1EmailOtpStoreOptions(input, 'registration attempt');
  if (d1) {
    input?.logger?.info('[email-otp] Using D1 registration attempt store');
    return new D1EmailOtpRegistrationAttemptStore(d1);
  }
  assertEmailOtpStoreKindKnown(input, 'registration attempt');
  input?.logger?.info('[email-otp] Using in-memory registration attempt store (non-persistent)');
  return new InMemoryEmailOtpRegistrationAttemptStore();
}
