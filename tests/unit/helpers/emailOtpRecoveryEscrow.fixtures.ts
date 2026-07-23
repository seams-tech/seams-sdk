import {
  parseEmailOtpRecoveryWrappedEnrollmentEscrowBoundary,
  type ActiveEmailOtpRecoveryWrappedEnrollmentEscrowRecord,
  type ConsumedEmailOtpRecoveryWrappedEnrollmentEscrowRecord,
  type EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
  type RevokedEmailOtpRecoveryWrappedEnrollmentEscrowRecord,
} from '@server/core/EmailOtpStores';
import {
  EMAIL_OTP_RECOVERY_WRAP_ALG,
  EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND,
  EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND,
} from '@shared/utils/emailOtpRecoveryKey';

/** Overrides shared by every recovery-wrapped enrollment escrow lifecycle branch.
 * Lifecycle fields (recoveryKeyStatus/consumedAtMs/revokedAtMs) are owned by the
 * branch-specific builders below. */
export type EmailOtpRecoveryEscrowSeedOverrides = Partial<
  Omit<
    ActiveEmailOtpRecoveryWrappedEnrollmentEscrowRecord,
    'recoveryKeyStatus' | 'consumedAtMs' | 'revokedAtMs'
  >
>;

const ESCROW_RECORD_DEFAULTS = {
  version: 'email_otp_recovery_wrapped_enrollment_escrow_v1',
  alg: EMAIL_OTP_RECOVERY_WRAP_ALG,
  secretKind: EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND,
  escrowKind: EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND,
  walletId: 'alice.testnet',
  authSubjectId: 'google-sub-1',
  userId: 'google-sub-1',
  authMethod: 'google_sso_email_otp',
  enrollmentId: 'enrollment-1',
  enrollmentVersion: '1',
  enrollmentSealKeyVersion: 'seal-v1',
  signingRootId: 'root-1',
  signingRootVersion: 'root-v1',
  recoveryKeyId: 'recovery-key-1',
  nonceB64u: 'AQIDBAUGBwgJCgsM',
  wrappedDeviceEnrollmentEscrowB64u: 'AQIDBAUGBwg',
  aadHashB64u: 'CQoLDA0ODxA',
  issuedAtMs: 1000,
  updatedAtMs: 2000,
} as const;

function parseEscrowRecordThroughBoundary(
  raw: Record<string, unknown>,
): EmailOtpRecoveryWrappedEnrollmentEscrowRecord {
  const boundary = parseEmailOtpRecoveryWrappedEnrollmentEscrowBoundary(raw);
  if (!boundary) {
    throw new Error(
      'emailOtpRecoveryEscrow fixture no longer parses through the production escrow boundary',
    );
  }
  return boundary.record;
}

export function seedActiveEmailOtpRecoveryEscrowRecord(
  overrides: EmailOtpRecoveryEscrowSeedOverrides = {},
): ActiveEmailOtpRecoveryWrappedEnrollmentEscrowRecord {
  const record = parseEscrowRecordThroughBoundary({
    ...ESCROW_RECORD_DEFAULTS,
    ...overrides,
    recoveryKeyStatus: 'active',
  });
  if (record.recoveryKeyStatus !== 'active') {
    throw new Error('emailOtpRecoveryEscrow fixture expected an active escrow record');
  }
  return record;
}

export function seedConsumedEmailOtpRecoveryEscrowRecord(
  overrides: EmailOtpRecoveryEscrowSeedOverrides & { consumedAtMs?: number } = {},
): ConsumedEmailOtpRecoveryWrappedEnrollmentEscrowRecord {
  const { consumedAtMs, ...rest } = overrides;
  const record = parseEscrowRecordThroughBoundary({
    ...ESCROW_RECORD_DEFAULTS,
    ...rest,
    recoveryKeyStatus: 'consumed',
    consumedAtMs: consumedAtMs ?? 3000,
  });
  if (record.recoveryKeyStatus !== 'consumed') {
    throw new Error('emailOtpRecoveryEscrow fixture expected a consumed escrow record');
  }
  return record;
}

export function seedRevokedEmailOtpRecoveryEscrowRecord(
  overrides: EmailOtpRecoveryEscrowSeedOverrides & { revokedAtMs?: number } = {},
): RevokedEmailOtpRecoveryWrappedEnrollmentEscrowRecord {
  const { revokedAtMs, ...rest } = overrides;
  const record = parseEscrowRecordThroughBoundary({
    ...ESCROW_RECORD_DEFAULTS,
    ...rest,
    recoveryKeyStatus: 'revoked',
    revokedAtMs: revokedAtMs ?? 3500,
  });
  if (record.recoveryKeyStatus !== 'revoked') {
    throw new Error('emailOtpRecoveryEscrow fixture expected a revoked escrow record');
  }
  return record;
}
