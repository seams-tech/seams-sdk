import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import {
  EMAIL_OTP_RECOVERY_KEY_COUNT,
  EMAIL_OTP_RECOVERY_WRAP_ALG,
  EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND,
  EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND,
  buildEmailOtpRecoveryWrapBinding,
  encodeEmailOtpRecoveryWrappedEnrollmentAad,
} from '@shared/utils/emailOtpRecoveryKey';
import { EMAIL_OTP_CHANNEL, WALLET_EMAIL_OTP_ACTIONS } from '@shared/utils/emailOtpDomain';
import { errorMessage } from '@shared/utils/errors';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import type {
  EmailOtpGrantStore,
  EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
  EmailOtpRecoveryWrappedEnrollmentEscrowStore,
  EmailOtpWalletEnrollmentRecord,
} from '../EmailOtpStores';
import { emailOtpRecoveryWrappedEnrollmentEscrowBoundaryFromRecord } from '../EmailOtpStores';
import { sha256BytesPortable } from './portableCrypto';
import type { EmailOtpConfig } from './emailOtpConfig';
import type { EmailOtpEnrollmentReadResult } from './emailOtpEnrollment';
import { emailOtpRecoveryEscrowMatchesEnrollment } from './emailOtpRegistrationEnrollment';
import type { RateLimitResult } from './rateLimits';

export type EmailOtpRecoveryRateLimitConsumer = (input: {
  scope: 'grant' | 'recoveryKeyAttempt';
  action?: string;
  userId: string;
  walletId: string;
  orgId: string;
  clientIp?: string;
}) => Promise<RateLimitResult>;

export type EmailOtpRecoveryCodeStatusRequest = {
  userId?: unknown;
  walletId?: unknown;
  orgId?: unknown;
};

export type EmailOtpRecoveryCodeStatusResult =
  | {
      ok: true;
      status: 'ready' | 'incomplete' | 'not_enrolled';
      walletId: string;
      enrollmentId: string;
      enrollmentSealKeyVersion: string;
      expectedRecoveryCodeCount: number;
      activeRecoveryCodeCount: number;
      consumedRecoveryCodeCount: number;
      revokedRecoveryCodeCount: number;
      totalRecoveryCodeCount: number;
      issuedAtMs: number | null;
    }
  | { ok: false; code: string; message: string };

export type EmailOtpRecoveryKeyConsumeRequest = {
  recoveryConsumeGrant?: unknown;
  userId?: unknown;
  walletId?: unknown;
  orgId?: unknown;
  recoveryKeyId?: unknown;
  clientIp?: unknown;
};

export type EmailOtpRecoveryKeyConsumeResult =
  | {
      ok: true;
      walletId: string;
      recoveryKeyId: string;
      consumedAtMs: number;
      activeRecoveryWrappedEnrollmentEscrowCount: number;
    }
  | { ok: false; code: string; message: string };

export type EmailOtpRecoveryKeysRotateRequest = {
  userId?: unknown;
  walletId?: unknown;
  orgId?: unknown;
  enrollmentId?: unknown;
  enrollmentSealKeyVersion?: unknown;
  recoveryWrappedEnrollmentEscrows?: unknown;
};

export type EmailOtpRecoveryKeysRotateResult =
  | {
      ok: true;
      walletId: string;
      enrollmentId: string;
      enrollmentSealKeyVersion: string;
      activeRecoveryCodeCount: number;
      revokedRecoveryCodeCount: number;
      totalRecoveryCodeCount: number;
      issuedAtMs: number;
    }
  | { ok: false; code: string; message: string };

export type EmailOtpRecoveryKeyAttemptFailureRequest = {
  recoveryConsumeGrant?: unknown;
  userId?: unknown;
  walletId?: unknown;
  orgId?: unknown;
  clientIp?: unknown;
};

export type EmailOtpRecoveryKeyAttemptFailureResult =
  | {
      ok: true;
      walletId: string;
      recordedAtMs: number;
    }
  | { ok: false; code: string; message: string; retryAfterMs?: number; resetAtMs?: number };

type ActiveEnrollmentReader = (input: {
  walletId: string;
  orgId: string;
  providerUserId: string;
}) => Promise<EmailOtpEnrollmentReadResult>;

type EnrollmentAuthStateReader = (
  enrollment: EmailOtpWalletEnrollmentRecord,
) => Promise<
  | { ok: true; state: { lastStrongAuthAtMs?: number } | null }
  | { ok: false; code: string; message: string }
>;

type EnrollmentAuthStateWriter = (
  enrollment: EmailOtpWalletEnrollmentRecord,
  patch: { lastStrongAuthAtMs?: number },
) => Promise<unknown>;

type EmailOtpRecoveryKeysStores = {
  grantStore: EmailOtpGrantStore;
  recoveryWrappedEnrollmentEscrowStore: EmailOtpRecoveryWrappedEnrollmentEscrowStore;
};

type EmailOtpRecoveryKeysPorts = {
  readActiveEnrollment: ActiveEnrollmentReader;
  readEnrollmentAuthState: EnrollmentAuthStateReader;
  putEnrollmentAuthState: EnrollmentAuthStateWriter;
  consumeRateLimit: EmailOtpRecoveryRateLimitConsumer;
  resolveConfig: () => EmailOtpConfig;
};

function notEnrolledRecoveryStatus(walletId: string): EmailOtpRecoveryCodeStatusResult {
  return {
    ok: true,
    status: 'not_enrolled',
    walletId,
    enrollmentId: '',
    enrollmentSealKeyVersion: '',
    expectedRecoveryCodeCount: EMAIL_OTP_RECOVERY_KEY_COUNT,
    activeRecoveryCodeCount: 0,
    consumedRecoveryCodeCount: 0,
    revokedRecoveryCodeCount: 0,
    totalRecoveryCodeCount: 0,
    issuedAtMs: null,
  };
}

function recordsForEnrollment(input: {
  records: readonly EmailOtpRecoveryWrappedEnrollmentEscrowRecord[];
  enrollment: EmailOtpWalletEnrollmentRecord;
}): EmailOtpRecoveryWrappedEnrollmentEscrowRecord[] {
  return input.records.filter((record) =>
    emailOtpRecoveryEscrowMatchesEnrollment(
      emailOtpRecoveryWrappedEnrollmentEscrowBoundaryFromRecord(record),
      input.enrollment,
    ),
  );
}

function recoveryGrantBindingMatches(input: {
  record: {
    userId: string;
    walletId: string;
    orgId?: string;
    otpChannel: string;
  };
  userId: string;
  walletId: string;
  orgId: string;
}): boolean {
  return (
    input.record.userId === input.userId &&
    input.record.walletId === input.walletId &&
    input.record.otpChannel === EMAIL_OTP_CHANNEL &&
    input.record.orgId === input.orgId
  );
}

function invalidRecoveryGrant() {
  return {
    ok: false as const,
    code: 'recovery_consume_grant_invalid_or_expired',
    message: 'Recovery consume grant is invalid or expired',
  };
}

function parseRecoveryEscrowInput(
  raw: unknown,
): {
  recoveryKeyId: string;
  nonceB64u: string;
  wrappedDeviceEnrollmentEscrowB64u: string;
  aadHashB64u: string;
} | null {
  const obj =
    raw && typeof raw === 'object' && !Array.isArray(raw)
      ? (raw as Record<string, unknown>)
      : null;
  if (!obj) return null;
  const recoveryKeyId = toOptionalTrimmedString(obj.recoveryKeyId);
  const nonceB64u = toOptionalTrimmedString(obj.nonceB64u);
  const wrappedDeviceEnrollmentEscrowB64u = toOptionalTrimmedString(
    obj.wrappedDeviceEnrollmentEscrowB64u,
  );
  const aadHashB64u = toOptionalTrimmedString(obj.aadHashB64u);
  if (!recoveryKeyId || !nonceB64u || !wrappedDeviceEnrollmentEscrowB64u || !aadHashB64u) {
    return null;
  }
  try {
    base64UrlDecode(nonceB64u);
    base64UrlDecode(wrappedDeviceEnrollmentEscrowB64u);
    base64UrlDecode(aadHashB64u);
  } catch {
    return null;
  }
  return {
    recoveryKeyId,
    nonceB64u,
    wrappedDeviceEnrollmentEscrowB64u,
    aadHashB64u,
  };
}

async function activeRecoveryEscrowCount(input: {
  store: EmailOtpRecoveryWrappedEnrollmentEscrowStore;
  walletId: string;
  enrollment: EmailOtpWalletEnrollmentRecord;
}): Promise<number> {
  return recordsForEnrollment({
    records: await input.store.listActiveByWallet(input.walletId),
    enrollment: input.enrollment,
  }).length;
}

export async function getEmailOtpRecoveryCodeStatus(input: {
  request: EmailOtpRecoveryCodeStatusRequest;
  recoveryWrappedEnrollmentEscrowStore: EmailOtpRecoveryWrappedEnrollmentEscrowStore;
  readActiveEnrollment: ActiveEnrollmentReader;
}): Promise<EmailOtpRecoveryCodeStatusResult> {
  try {
    const userId = toOptionalTrimmedString(input.request.userId);
    const walletId = toOptionalTrimmedString(input.request.walletId);
    const orgId = toOptionalTrimmedString(input.request.orgId) || '';
    if (!userId) return { ok: false, code: 'invalid_body', message: 'Missing userId' };
    if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
    if (!orgId) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };

    const enrollment = await input.readActiveEnrollment({
      walletId,
      orgId,
      providerUserId: userId,
    });
    if (!enrollment.ok) {
      if (enrollment.code === 'not_found') return notEnrolledRecoveryStatus(walletId);
      return enrollment;
    }

    const records = recordsForEnrollment({
      records: await input.recoveryWrappedEnrollmentEscrowStore.listByWallet(walletId),
      enrollment: enrollment.enrollment,
    });
    const activeRecords = records.filter((record) => record.recoveryKeyStatus === 'active');
    const consumedRecords = records.filter((record) => record.recoveryKeyStatus === 'consumed');
    const revokedRecords = records.filter((record) => record.recoveryKeyStatus === 'revoked');
    const issuedAtValues = records.map((record) => record.issuedAtMs);
    const status = activeRecords.length === EMAIL_OTP_RECOVERY_KEY_COUNT ? 'ready' : 'incomplete';
    return {
      ok: true,
      status,
      walletId,
      enrollmentId: enrollment.enrollment.enrollmentId,
      enrollmentSealKeyVersion: enrollment.enrollment.enrollmentSealKeyVersion,
      expectedRecoveryCodeCount: EMAIL_OTP_RECOVERY_KEY_COUNT,
      activeRecoveryCodeCount: activeRecords.length,
      consumedRecoveryCodeCount: consumedRecords.length,
      revokedRecoveryCodeCount: revokedRecords.length,
      totalRecoveryCodeCount: records.length,
      issuedAtMs: issuedAtValues.length > 0 ? Math.min(...issuedAtValues) : null,
    };
  } catch (e: unknown) {
    return {
      ok: false,
      code: 'internal',
      message: errorMessage(e) || 'Failed to read Email OTP recovery-code status',
    };
  }
}

export async function consumeEmailOtpRecoveryKey(input: {
  request: EmailOtpRecoveryKeyConsumeRequest;
  stores: EmailOtpRecoveryKeysStores;
  ports: EmailOtpRecoveryKeysPorts;
}): Promise<EmailOtpRecoveryKeyConsumeResult> {
  try {
    const recoveryConsumeGrant = toOptionalTrimmedString(input.request.recoveryConsumeGrant);
    const userId = toOptionalTrimmedString(input.request.userId);
    const walletId = toOptionalTrimmedString(input.request.walletId);
    const orgId = toOptionalTrimmedString(input.request.orgId) || '';
    const recoveryKeyId = toOptionalTrimmedString(input.request.recoveryKeyId);
    const clientIp = toOptionalTrimmedString(input.request.clientIp) || undefined;
    if (!recoveryConsumeGrant) {
      return { ok: false, code: 'invalid_body', message: 'Missing recoveryConsumeGrant' };
    }
    if (!userId) return { ok: false, code: 'invalid_body', message: 'Missing userId' };
    if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
    if (!orgId) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };
    if (!recoveryKeyId) {
      return { ok: false, code: 'invalid_body', message: 'Missing recoveryKeyId' };
    }
    const rateLimit = await input.ports.consumeRateLimit({
      scope: 'grant',
      userId,
      walletId,
      orgId,
      clientIp,
    });
    if (!rateLimit.ok) return rateLimit;

    const record = await input.stores.grantStore.consume(recoveryConsumeGrant);
    if (!record || Date.now() > record.expiresAtMs) return invalidRecoveryGrant();
    if (record.action !== WALLET_EMAIL_OTP_ACTIONS.deviceRecovery) return invalidRecoveryGrant();
    if (
      !recoveryGrantBindingMatches({
        record,
        userId,
        walletId,
        orgId,
      })
    ) {
      return {
        ok: false,
        code: 'recovery_grant_binding_mismatch',
        message: 'Recovery grant is not valid for the current Email OTP authority',
      };
    }

    const enrollment = await input.ports.readActiveEnrollment({
      walletId,
      orgId,
      providerUserId: userId,
    });
    if (!enrollment.ok) return enrollment;

    const recoveryRecord = await input.stores.recoveryWrappedEnrollmentEscrowStore.get({
      walletId,
      recoveryKeyId,
    });
    if (!recoveryRecord || recoveryRecord.recoveryKeyStatus !== 'active') {
      return {
        ok: false,
        code: 'recovery_key_not_active',
        message: 'Recovery key is not active',
      };
    }
    if (
      !emailOtpRecoveryEscrowMatchesEnrollment(
        emailOtpRecoveryWrappedEnrollmentEscrowBoundaryFromRecord(recoveryRecord),
        enrollment.enrollment,
      )
    ) {
      return {
        ok: false,
        code: 'recovery_key_binding_mismatch',
        message: 'Recovery key is not valid for this Email OTP enrollment',
      };
    }

    const consumedAtMs = Date.now();
    await input.stores.recoveryWrappedEnrollmentEscrowStore.put({
      ...recoveryRecord,
      recoveryKeyStatus: 'consumed',
      consumedAtMs,
      updatedAtMs: consumedAtMs,
    });
    await input.ports.putEnrollmentAuthState(enrollment.enrollment, {
      lastStrongAuthAtMs: consumedAtMs,
    });
    const activeRecoveryWrappedEnrollmentEscrowCount = await activeRecoveryEscrowCount({
      store: input.stores.recoveryWrappedEnrollmentEscrowStore,
      walletId,
      enrollment: enrollment.enrollment,
    });

    return {
      ok: true,
      walletId,
      recoveryKeyId,
      consumedAtMs,
      activeRecoveryWrappedEnrollmentEscrowCount,
    };
  } catch (e: unknown) {
    return {
      ok: false,
      code: 'internal',
      message: errorMessage(e) || 'Failed to consume Email OTP recovery key',
    };
  }
}

export async function rotateEmailOtpRecoveryKeys(input: {
  request: EmailOtpRecoveryKeysRotateRequest;
  store: EmailOtpRecoveryWrappedEnrollmentEscrowStore;
  readActiveEnrollment: ActiveEnrollmentReader;
  readEnrollmentAuthState: EnrollmentAuthStateReader;
  resolveConfig: () => EmailOtpConfig;
}): Promise<EmailOtpRecoveryKeysRotateResult> {
  try {
    const userId = toOptionalTrimmedString(input.request.userId);
    const walletId = toOptionalTrimmedString(input.request.walletId);
    const orgId = toOptionalTrimmedString(input.request.orgId) || '';
    const enrollmentId = toOptionalTrimmedString(input.request.enrollmentId);
    const enrollmentSealKeyVersion = toOptionalTrimmedString(input.request.enrollmentSealKeyVersion);
    if (!userId) return { ok: false, code: 'invalid_body', message: 'Missing userId' };
    if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
    if (!orgId) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };
    if (!enrollmentId) {
      return { ok: false, code: 'invalid_body', message: 'Missing enrollmentId' };
    }
    if (!enrollmentSealKeyVersion) {
      return { ok: false, code: 'invalid_body', message: 'Missing enrollmentSealKeyVersion' };
    }
    const rawEscrows = Array.isArray(input.request.recoveryWrappedEnrollmentEscrows)
      ? input.request.recoveryWrappedEnrollmentEscrows
      : [];
    if (rawEscrows.length !== EMAIL_OTP_RECOVERY_KEY_COUNT) {
      return {
        ok: false,
        code: 'invalid_body',
        message: `Exactly ${EMAIL_OTP_RECOVERY_KEY_COUNT} recovery-wrapped enrollment escrows are required`,
      };
    }

    const enrollment = await input.readActiveEnrollment({
      walletId,
      orgId,
      providerUserId: userId,
    });
    if (!enrollment.ok) return enrollment;
    if (
      enrollment.enrollment.enrollmentId !== enrollmentId ||
      enrollment.enrollment.enrollmentSealKeyVersion !== enrollmentSealKeyVersion
    ) {
      return {
        ok: false,
        code: 'recovery_rotation_binding_mismatch',
        message: 'Recovery-code rotation does not match the active Email OTP enrollment',
      };
    }

    const authState = await input.readEnrollmentAuthState(enrollment.enrollment);
    if (!authState.ok) return authState;
    const lastStrongAuthAtMs =
      typeof authState.state?.lastStrongAuthAtMs === 'number'
        ? authState.state.lastStrongAuthAtMs
        : 0;
    const nowMs = Date.now();
    const otpConfig = input.resolveConfig();
    if (!lastStrongAuthAtMs || nowMs > lastStrongAuthAtMs + otpConfig.grantTtlMs) {
      return {
        ok: false,
        code: 'fresh_auth_required',
        message: 'Fresh account authentication is required to rotate recovery codes',
      };
    }

    const issuedAtMs = nowMs;
    const recoveryKeyIds = new Set<string>();
    const nonceB64us = new Set<string>();
    const nextActiveRecords: EmailOtpRecoveryWrappedEnrollmentEscrowRecord[] = [];
    for (const raw of rawEscrows) {
      const parsed = parseRecoveryEscrowInput(raw);
      if (!parsed) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Recovery rotation escrow input is missing required fields',
        };
      }
      if (recoveryKeyIds.has(parsed.recoveryKeyId)) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Recovery rotation recoveryKeyId values must be unique',
        };
      }
      if (nonceB64us.has(parsed.nonceB64u)) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Recovery rotation nonce values must be unique',
        };
      }
      recoveryKeyIds.add(parsed.recoveryKeyId);
      nonceB64us.add(parsed.nonceB64u);
      const binding = buildEmailOtpRecoveryWrapBinding({
        walletId: enrollment.enrollment.walletId,
        userId: enrollment.enrollment.providerUserId,
        authSubjectId: enrollment.enrollment.providerUserId,
        authMethod: 'google_sso_email_otp',
        enrollmentId: enrollment.enrollment.enrollmentId,
        enrollmentVersion: enrollment.enrollment.enrollmentVersion,
        enrollmentSealKeyVersion: enrollment.enrollment.enrollmentSealKeyVersion,
        signingRootId: enrollment.enrollment.signingRootId,
        signingRootVersion: enrollment.enrollment.signingRootVersion,
        recoveryKeyId: parsed.recoveryKeyId,
      });
      const expectedAadHashB64u = base64UrlEncode(
        await sha256BytesPortable(encodeEmailOtpRecoveryWrappedEnrollmentAad(binding)),
      );
      if (parsed.aadHashB64u !== expectedAadHashB64u) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Recovery rotation aadHashB64u does not match enrollment metadata',
        };
      }
      nextActiveRecords.push({
        version: 'email_otp_recovery_wrapped_enrollment_escrow_v1',
        alg: EMAIL_OTP_RECOVERY_WRAP_ALG,
        secretKind: EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND,
        escrowKind: EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND,
        walletId: enrollment.enrollment.walletId,
        userId: enrollment.enrollment.providerUserId,
        authSubjectId: enrollment.enrollment.providerUserId,
        authMethod: 'google_sso_email_otp',
        enrollmentId: enrollment.enrollment.enrollmentId,
        enrollmentVersion: enrollment.enrollment.enrollmentVersion,
        enrollmentSealKeyVersion: enrollment.enrollment.enrollmentSealKeyVersion,
        signingRootId: enrollment.enrollment.signingRootId,
        signingRootVersion: enrollment.enrollment.signingRootVersion,
        recoveryKeyId: parsed.recoveryKeyId,
        recoveryKeyStatus: 'active',
        nonceB64u: parsed.nonceB64u,
        wrappedDeviceEnrollmentEscrowB64u: parsed.wrappedDeviceEnrollmentEscrowB64u,
        aadHashB64u: parsed.aadHashB64u,
        issuedAtMs,
        updatedAtMs: issuedAtMs,
      });
    }

    const oldActiveRecords = recordsForEnrollment({
      records: await input.store.listActiveByWallet(walletId),
      enrollment: enrollment.enrollment,
    });
    const revokedRecords: EmailOtpRecoveryWrappedEnrollmentEscrowRecord[] = oldActiveRecords.map(
      (record) => ({
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
        recoveryKeyId: record.recoveryKeyId,
        recoveryKeyLabel: record.recoveryKeyLabel,
        recoveryKeyStatus: 'revoked',
        nonceB64u: record.nonceB64u,
        wrappedDeviceEnrollmentEscrowB64u: record.wrappedDeviceEnrollmentEscrowB64u,
        aadHashB64u: record.aadHashB64u,
        issuedAtMs: record.issuedAtMs,
        updatedAtMs: issuedAtMs,
        revokedAtMs: issuedAtMs,
      }),
    );
    await input.store.putMany([...revokedRecords, ...nextActiveRecords]);
    const activeRecoveryCodeCount = await activeRecoveryEscrowCount({
      store: input.store,
      walletId,
      enrollment: enrollment.enrollment,
    });
    if (activeRecoveryCodeCount !== EMAIL_OTP_RECOVERY_KEY_COUNT) {
      return {
        ok: false,
        code: 'internal',
        message: `Email OTP recovery-code rotation left ${activeRecoveryCodeCount} active codes; expected ${EMAIL_OTP_RECOVERY_KEY_COUNT}`,
      };
    }
    const totalRecoveryCodeCount = recordsForEnrollment({
      records: await input.store.listByWallet(walletId),
      enrollment: enrollment.enrollment,
    }).length;
    return {
      ok: true,
      walletId,
      enrollmentId,
      enrollmentSealKeyVersion,
      activeRecoveryCodeCount,
      revokedRecoveryCodeCount: revokedRecords.length,
      totalRecoveryCodeCount,
      issuedAtMs,
    };
  } catch (e: unknown) {
    return {
      ok: false,
      code: 'internal',
      message: errorMessage(e) || 'Failed to rotate Email OTP recovery codes',
    };
  }
}

export async function recordEmailOtpRecoveryKeyAttemptFailure(input: {
  request: EmailOtpRecoveryKeyAttemptFailureRequest;
  stores: EmailOtpRecoveryKeysStores;
  ports: EmailOtpRecoveryKeysPorts;
}): Promise<EmailOtpRecoveryKeyAttemptFailureResult> {
  try {
    const recoveryConsumeGrant = toOptionalTrimmedString(input.request.recoveryConsumeGrant);
    const userId = toOptionalTrimmedString(input.request.userId);
    const walletId = toOptionalTrimmedString(input.request.walletId);
    const orgId = toOptionalTrimmedString(input.request.orgId) || '';
    const clientIp = toOptionalTrimmedString(input.request.clientIp) || undefined;
    if (!recoveryConsumeGrant) {
      return { ok: false, code: 'invalid_body', message: 'Missing recoveryConsumeGrant' };
    }
    if (!userId) return { ok: false, code: 'invalid_body', message: 'Missing userId' };
    if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
    if (!orgId) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };

    const record = await input.stores.grantStore.get(recoveryConsumeGrant);
    if (!record || Date.now() > record.expiresAtMs) {
      if (record && Date.now() > record.expiresAtMs) {
        await input.stores.grantStore.del(recoveryConsumeGrant);
      }
      return invalidRecoveryGrant();
    }
    if (record.action !== WALLET_EMAIL_OTP_ACTIONS.deviceRecovery) return invalidRecoveryGrant();
    if (
      !recoveryGrantBindingMatches({
        record,
        userId,
        walletId,
        orgId,
      })
    ) {
      return {
        ok: false,
        code: 'recovery_grant_binding_mismatch',
        message: 'Recovery grant is not valid for the current Email OTP authority',
      };
    }

    const rateLimit = await input.ports.consumeRateLimit({
      scope: 'recoveryKeyAttempt',
      action: WALLET_EMAIL_OTP_ACTIONS.deviceRecovery,
      userId,
      walletId,
      orgId,
      clientIp,
    });
    if (!rateLimit.ok) return rateLimit;

    const enrollment = await input.ports.readActiveEnrollment({
      walletId,
      orgId,
      providerUserId: userId,
    });
    if (!enrollment.ok) return enrollment;

    const activeRecoveryWrappedEnrollmentEscrowCount = await activeRecoveryEscrowCount({
      store: input.stores.recoveryWrappedEnrollmentEscrowStore,
      walletId,
      enrollment: enrollment.enrollment,
    });
    if (activeRecoveryWrappedEnrollmentEscrowCount <= 0) {
      return {
        ok: false,
        code: 'recovery_wrapped_escrows_missing',
        message: 'No active Email OTP recovery-wrapped enrollment escrows are available',
      };
    }

    return {
      ok: true,
      walletId,
      recordedAtMs: Date.now(),
    };
  } catch (e: unknown) {
    return {
      ok: false,
      code: 'internal',
      message: errorMessage(e) || 'Failed to record Email OTP recovery-key failure',
    };
  }
}
