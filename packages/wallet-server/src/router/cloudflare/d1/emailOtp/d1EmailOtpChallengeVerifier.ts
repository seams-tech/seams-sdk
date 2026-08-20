import {
  EMAIL_OTP_CHANNEL,
  WALLET_EMAIL_OTP_ACTIONS,
  WALLET_EMAIL_OTP_DEVICE_LINK_OPERATION,
  WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
} from '@shared/utils/emailOtpDomain';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';
import type {
  EmailOtpAuthStateRecord,
  EmailOtpChallengeRecord,
  EmailOtpLoginChallengeOperation,
  EmailOtpWalletEnrollmentRecord,
} from '../../../../core/EmailOtpStores';
import type { CloudflareD1EmailOtpChallengeStore } from './d1EmailOtpChallengeStore';
import type { CloudflareD1EmailOtpEnrollmentStore } from './d1EmailOtpEnrollmentStore';
import type { CloudflareD1EmailOtpRateLimitStore } from './d1EmailOtpRateLimitStore';
import {
  emailOtpChallengeBindingMismatchCode,
  emailOtpChallengeInvalidOrExpired,
  emailOtpRegistrationChallengeBindingMismatchCode,
  type EmailOtpRegistrationVerificationReceiptV1,
} from './d1EmailOtpRecords';

export type EmailOtpExistingChallengeVerifyBaseInput = {
  readonly userId?: unknown;
  readonly walletId?: unknown;
  readonly orgId?: unknown;
  readonly challengeId?: unknown;
  readonly otpCode?: unknown;
  readonly otpChannel?: unknown;
  readonly ownerProofBindingDigest?: unknown;
  readonly clientIp?: unknown;
};

export type EmailOtpExistingChallengeVerifyInput =
  | (EmailOtpExistingChallengeVerifyBaseInput & {
      readonly action: typeof WALLET_EMAIL_OTP_ACTIONS.login;
      readonly operation: EmailOtpLoginChallengeOperation;
    })
  | (EmailOtpExistingChallengeVerifyBaseInput & {
      readonly action: typeof WALLET_EMAIL_OTP_ACTIONS.deviceLink;
      readonly operation: typeof WALLET_EMAIL_OTP_DEVICE_LINK_OPERATION;
    });

export type EmailOtpExistingChallengeVerifyResult =
  | {
      ok: true;
      readonly challengeId: string;
      readonly userId: string;
      readonly walletId: string;
      readonly orgId: string;
      readonly otpChannel: typeof EMAIL_OTP_CHANNEL;
      readonly ownerProofBindingDigest: string;
      readonly enrollment: EmailOtpWalletEnrollmentRecord;
    }
  | {
      ok: false;
      code: string;
      message: string;
      attemptsRemaining?: number;
      lockedUntilMs?: number;
      retryAfterMs?: number;
      resetAtMs?: number;
    };

export type EmailOtpRegistrationChallengeVerifyInput = {
  readonly providerSubject?: unknown;
  readonly walletId?: unknown;
  readonly orgId?: unknown;
  readonly challengeId?: unknown;
  readonly otpCode?: unknown;
  readonly otpChannel?: unknown;
  readonly ownerProofBindingDigest?: unknown;
  readonly proofEmail?: unknown;
  readonly clientIp?: unknown;
};

export type EmailOtpRegistrationChallengeResumableVerifyInput =
  EmailOtpRegistrationChallengeVerifyInput & {
    readonly operationId: unknown;
    readonly receiptExpiresAtMs: unknown;
  };

export type EmailOtpRegistrationChallengeVerifyResult =
  | {
      ok: true;
      readonly challengeId: string;
      readonly challengeSubjectId: string;
      readonly walletId: string;
      readonly orgId: string;
      readonly email: string;
      readonly otpChannel: typeof EMAIL_OTP_CHANNEL;
    }
  | {
      ok: false;
      code: string;
      message: string;
      attemptsRemaining?: number;
      lockedUntilMs?: number;
      retryAfterMs?: number;
      resetAtMs?: number;
    };

export type ActiveEmailOtpEnrollmentResult =
  | { readonly ok: true; readonly enrollment: EmailOtpWalletEnrollmentRecord }
  | { readonly ok: false; readonly code: string; readonly message: string };

type EmailOtpRegistrationConsumption =
  | { readonly kind: 'single_use' }
  | {
      readonly kind: 'resumable_registration_start';
      readonly operationId: string;
      readonly receiptExpiresAtMs: number;
    };

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error || '');
}

function emailOtpEnrollmentTenantMismatch(): ActiveEmailOtpEnrollmentResult {
  return {
    ok: false,
    code: 'tenant_scope_mismatch',
    message: 'Email OTP enrollment does not match the requested orgId',
  };
}

async function emailOtpRegistrationVerificationFingerprint(input: {
  readonly operationId: string;
  readonly providerSubject: string;
  readonly walletId: string;
  readonly orgId: string;
  readonly challengeId: string;
  readonly otpCode: string;
  readonly ownerProofBindingDigest: string;
  readonly proofEmail: string;
}): Promise<string> {
  return base64UrlEncode(
    await sha256BytesUtf8(
      alphabetizeStringify({
        version: 'email_otp_registration_verification_fingerprint_v1',
        operationId: input.operationId,
        action: WALLET_EMAIL_OTP_ACTIONS.registration,
        operation: WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
        providerSubject: input.providerSubject,
        walletId: input.walletId,
        orgId: input.orgId,
        challengeId: input.challengeId,
        otpCode: input.otpCode,
        otpChannel: EMAIL_OTP_CHANNEL,
        ownerProofBindingDigest: input.ownerProofBindingDigest,
        proofEmail: input.proofEmail,
      }),
    ),
  );
}

function emailOtpProviderIdentityMismatch(): ActiveEmailOtpEnrollmentResult {
  return {
    ok: false,
    code: 'provider_identity_mismatch',
    message: 'Email OTP enrollment does not match the requested provider user',
  };
}

export class CloudflareD1EmailOtpChallengeVerifier {
  private readonly emailOtpChallenges: CloudflareD1EmailOtpChallengeStore;
  private readonly emailOtpEnrollments: CloudflareD1EmailOtpEnrollmentStore;
  private readonly emailOtpRateLimits: CloudflareD1EmailOtpRateLimitStore;
  private readonly lockoutTtlMs: number;

  constructor(input: {
    readonly emailOtpChallenges: CloudflareD1EmailOtpChallengeStore;
    readonly emailOtpEnrollments: CloudflareD1EmailOtpEnrollmentStore;
    readonly emailOtpRateLimits: CloudflareD1EmailOtpRateLimitStore;
    readonly lockoutTtlMs: number;
  }) {
    this.emailOtpChallenges = input.emailOtpChallenges;
    this.emailOtpEnrollments = input.emailOtpEnrollments;
    this.emailOtpRateLimits = input.emailOtpRateLimits;
    this.lockoutTtlMs = input.lockoutTtlMs;
  }

  async readActiveEnrollmentForWallet(input: {
    readonly walletId: string;
    readonly orgId: string;
    readonly providerUserId: string;
  }): Promise<ActiveEmailOtpEnrollmentResult> {
    return await this.readActiveEnrollment(input);
  }

  async verifyExisting(
    input: EmailOtpExistingChallengeVerifyInput,
  ): Promise<EmailOtpExistingChallengeVerifyResult> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      const walletId = toOptionalTrimmedString(input.walletId);
      const orgId = toOptionalTrimmedString(input.orgId);
      const challengeId = toOptionalTrimmedString(input.challengeId);
      const otpCode = toOptionalTrimmedString(input.otpCode);
      const otpChannel = toOptionalTrimmedString(input.otpChannel);
      const ownerProofBindingDigest = toOptionalTrimmedString(input.ownerProofBindingDigest);
      const clientIp = toOptionalTrimmedString(input.clientIp);
      const action = input.action;
      const operation = input.operation;
      if (!userId) return { ok: false, code: 'invalid_body', message: 'Missing userId' };
      if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
      if (!orgId) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };
      if (!challengeId) {
        return { ok: false, code: 'invalid_body', message: 'Missing challengeId' };
      }
      if (!otpCode) return { ok: false, code: 'invalid_body', message: 'Missing otpCode' };
      if (otpChannel !== EMAIL_OTP_CHANNEL) {
        return { ok: false, code: 'invalid_body', message: 'otpChannel must be email_otp' };
      }
      if (!ownerProofBindingDigest) {
        return { ok: false, code: 'invalid_body', message: 'Missing ownerProofBindingDigest' };
      }

      const rateLimit = await this.emailOtpRateLimits.consume({
        scope: 'verify',
        action,
        userId,
        walletId,
        orgId,
        clientIp,
      });
      if (!rateLimit.ok) return rateLimit;

      const enrollment = await this.readActiveEnrollment({
        walletId,
        orgId,
        providerUserId: userId,
      });
      if (!enrollment.ok) return enrollment;
      const authState = await this.emailOtpEnrollments.readAuthStateForEnrollment(
        enrollment.enrollment,
      );
      if (!authState.ok) return authState;
      if (authState.state?.otpLockedUntilMs && authState.state.otpLockedUntilMs > Date.now()) {
        return {
          ok: false,
          code: 'otp_locked_out',
          message: 'Email OTP is temporarily locked for this wallet',
          lockedUntilMs: authState.state.otpLockedUntilMs,
        };
      }

      const nowMs = Date.now();
      await this.emailOtpChallenges.pruneExpired(nowMs);
      const record = await this.emailOtpChallenges.read(challengeId);
      if (!record) return emailOtpChallengeInvalidOrExpired();
      if (nowMs > record.expiresAtMs) {
        await this.emailOtpChallenges.delete(record.challengeId);
        return emailOtpChallengeInvalidOrExpired();
      }

      const bindingMismatch = emailOtpChallengeBindingMismatchCode({
        record,
        userId,
        walletId,
        orgId,
        ownerProofBindingDigest,
        action,
        operation,
      });
      if (bindingMismatch) {
        return {
          ok: false,
          code: bindingMismatch,
          message: 'Email OTP challenge is not valid for the current owner proof binding',
        };
      }

      if (record.otpCode !== otpCode) {
        return await this.recordInvalidAttempt({
          enrollment: enrollment.enrollment,
          authState: authState.state,
          record,
        });
      }

      const consumed = await this.emailOtpChallenges.consume(record.challengeId);
      if (!consumed) return emailOtpChallengeInvalidOrExpired();
      await this.emailOtpEnrollments.resetFailureState({
        enrollment: enrollment.enrollment,
        authState: authState.state,
      });

      return {
        ok: true,
        challengeId: consumed.challengeId,
        userId,
        walletId,
        orgId,
        otpChannel: EMAIL_OTP_CHANNEL,
        ownerProofBindingDigest,
        enrollment: enrollment.enrollment,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to verify Email OTP challenge',
      };
    }
  }

  async verifyRegistration(
    input: EmailOtpRegistrationChallengeVerifyInput,
  ): Promise<EmailOtpRegistrationChallengeVerifyResult> {
    return await this.verifyRegistrationWithConsumption(input, { kind: 'single_use' });
  }

  async verifyRegistrationResumable(
    input: EmailOtpRegistrationChallengeResumableVerifyInput,
  ): Promise<EmailOtpRegistrationChallengeVerifyResult> {
    const operationId = toOptionalTrimmedString(input.operationId);
    const receiptExpiresAtMs = Number(input.receiptExpiresAtMs);
    if (!operationId) {
      return { ok: false, code: 'invalid_body', message: 'Missing verification operationId' };
    }
    if (!Number.isSafeInteger(receiptExpiresAtMs) || receiptExpiresAtMs <= Date.now()) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Verification receipt expiry must be in the future',
      };
    }
    return await this.verifyRegistrationWithConsumption(input, {
      kind: 'resumable_registration_start',
      operationId,
      receiptExpiresAtMs,
    });
  }

  private async verifyRegistrationWithConsumption(
    input: EmailOtpRegistrationChallengeVerifyInput,
    consumption: EmailOtpRegistrationConsumption,
  ): Promise<EmailOtpRegistrationChallengeVerifyResult> {
    try {
      const providerSubject = toOptionalTrimmedString(input.providerSubject);
      const walletId = toOptionalTrimmedString(input.walletId);
      const orgId = toOptionalTrimmedString(input.orgId);
      const challengeId = toOptionalTrimmedString(input.challengeId);
      const otpCode = toOptionalTrimmedString(input.otpCode);
      const otpChannel = toOptionalTrimmedString(input.otpChannel);
      const ownerProofBindingDigest = toOptionalTrimmedString(input.ownerProofBindingDigest);
      const proofEmail = toOptionalTrimmedString(input.proofEmail)?.toLowerCase() || '';
      const clientIp = toOptionalTrimmedString(input.clientIp);
      if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
      if (!orgId) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };
      if (!challengeId) {
        return { ok: false, code: 'invalid_body', message: 'Missing challengeId' };
      }
      if (!otpCode) return { ok: false, code: 'invalid_body', message: 'Missing otpCode' };
      if (otpChannel !== EMAIL_OTP_CHANNEL) {
        return { ok: false, code: 'invalid_body', message: 'otpChannel must be email_otp' };
      }
      if (!ownerProofBindingDigest) {
        return { ok: false, code: 'invalid_body', message: 'Missing ownerProofBindingDigest' };
      }
      if (!proofEmail) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Email OTP registration requires proofEmail',
        };
      }

      const requestFingerprint =
        consumption.kind === 'resumable_registration_start'
          ? await emailOtpRegistrationVerificationFingerprint({
              operationId: consumption.operationId,
              providerSubject: providerSubject || walletId || '',
              walletId,
              orgId,
              challengeId,
              otpCode,
              ownerProofBindingDigest,
              proofEmail,
            })
          : null;
      if (consumption.kind === 'resumable_registration_start' && requestFingerprint) {
        const receipt = await this.emailOtpChallenges.readRegistrationVerificationReceipt(
          challengeId,
          Date.now(),
        );
        if (receipt) {
          if (
            receipt.requestFingerprint !== requestFingerprint ||
            receipt.expiresAtMs !== consumption.receiptExpiresAtMs
          ) {
            return {
              ok: false,
              code: 'verification_receipt_conflict',
              message: 'Email OTP verification receipt belongs to another registration start',
            };
          }
          await this.resetRegistrationFailureStateForReceipt(receipt);
          return {
            ok: true,
            challengeId: receipt.verified.challengeId,
            challengeSubjectId: receipt.verified.challengeSubjectId,
            walletId: receipt.verified.walletId,
            orgId: receipt.verified.orgId,
            email: receipt.verified.email,
            otpChannel: receipt.verified.otpChannel,
          };
        }
      }

      const rateLimit = await this.emailOtpRateLimits.consume({
        scope: 'verify',
        action: WALLET_EMAIL_OTP_ACTIONS.registration,
        userId: providerSubject || walletId,
        walletId,
        orgId,
        clientIp,
      });
      if (!rateLimit.ok) return rateLimit;

      const existingEnrollment = await this.emailOtpEnrollments.readEnrollment(walletId);
      if (existingEnrollment && existingEnrollment.orgId !== orgId) {
        return {
          ok: false,
          code: 'tenant_scope_mismatch',
          message: 'Email OTP enrollment does not match the requested orgId',
        };
      }
      const authState = existingEnrollment
        ? await this.emailOtpEnrollments.readAuthStateForEnrollment(existingEnrollment)
        : { ok: true as const, state: null };
      if (!authState.ok) return authState;
      if (authState.state?.otpLockedUntilMs && authState.state.otpLockedUntilMs > Date.now()) {
        return {
          ok: false,
          code: 'otp_locked_out',
          message: 'Email OTP is temporarily locked for this wallet',
          lockedUntilMs: authState.state.otpLockedUntilMs,
        };
      }

      const nowMs = Date.now();
      await this.emailOtpChallenges.pruneExpired(nowMs);
      const record = await this.emailOtpChallenges.read(challengeId);
      if (!record) return emailOtpChallengeInvalidOrExpired();
      if (nowMs > record.expiresAtMs) {
        await this.emailOtpChallenges.delete(record.challengeId);
        return emailOtpChallengeInvalidOrExpired();
      }
      const resolvedProviderSubject = providerSubject || record.challengeSubjectId;

      const bindingMismatch = emailOtpRegistrationChallengeBindingMismatchCode({
        record,
        providerSubject: resolvedProviderSubject,
        walletId,
        orgId,
        ownerProofBindingDigest,
        proofEmail,
      });
      if (bindingMismatch) {
        return {
          ok: false,
          code: bindingMismatch,
          message: 'Email OTP challenge is not valid for the current owner proof binding',
        };
      }

      if (record.otpCode !== otpCode) {
        return await this.recordInvalidRegistrationAttempt({
          enrollment: existingEnrollment,
          authState: authState.state,
          record,
        });
      }

      let consumed = record;
      if (consumption.kind === 'resumable_registration_start' && requestFingerprint) {
        const receipt: EmailOtpRegistrationVerificationReceiptV1 = {
          version: 'email_otp_registration_verification_receipt_v1',
          requestFingerprint,
          verified: {
            challengeId: record.challengeId,
            challengeSubjectId: record.challengeSubjectId,
            walletId,
            orgId,
            email: record.email,
            otpChannel: EMAIL_OTP_CHANNEL,
          },
          verifiedAtMs: nowMs,
          expiresAtMs: consumption.receiptExpiresAtMs,
        };
        const receiptResult = await this.emailOtpChallenges.consumeRegistrationWithReceipt({
          challenge: record,
          receipt,
        });
        switch (receiptResult.kind) {
          case 'stored':
          case 'exact_replay':
            consumed = record;
            break;
          case 'conflict':
            return {
              ok: false,
              code: 'verification_receipt_conflict',
              message: 'Email OTP verification receipt belongs to another registration start',
            };
          case 'challenge_missing':
            return emailOtpChallengeInvalidOrExpired();
        }
      } else {
        const singleUseConsumed = await this.emailOtpChallenges.consume(record.challengeId);
        if (!singleUseConsumed) return emailOtpChallengeInvalidOrExpired();
        consumed = singleUseConsumed;
      }
      if (existingEnrollment) {
        await this.emailOtpEnrollments.resetFailureState({
          enrollment: existingEnrollment,
          authState: authState.state,
        });
      }
      return {
        ok: true,
        challengeId: consumed.challengeId,
        challengeSubjectId: resolvedProviderSubject,
        walletId,
        orgId,
        email: consumed.email,
        otpChannel: EMAIL_OTP_CHANNEL,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to verify Email OTP enrollment challenge',
      };
    }
  }

  private async resetRegistrationFailureStateForReceipt(
    receipt: EmailOtpRegistrationVerificationReceiptV1,
  ): Promise<void> {
    const enrollment = await this.emailOtpEnrollments.readEnrollment(receipt.verified.walletId);
    if (!enrollment) return;
    if (enrollment.orgId !== receipt.verified.orgId) {
      throw new Error('Email OTP verification receipt enrollment tenant changed');
    }
    const authState = await this.emailOtpEnrollments.readAuthStateForEnrollment(enrollment);
    if (!authState.ok) throw new Error(authState.message);
    await this.emailOtpEnrollments.resetFailureState({
      enrollment,
      authState: authState.state,
    });
  }

  private async readActiveEnrollment(input: {
    readonly walletId: string;
    readonly orgId: string;
    readonly providerUserId: string;
  }): Promise<ActiveEmailOtpEnrollmentResult> {
    const enrollment = await this.emailOtpEnrollments.readEnrollment(input.walletId);
    if (!enrollment) {
      return { ok: false, code: 'not_found', message: 'Email OTP enrollment not found' };
    }
    if (enrollment.orgId !== input.orgId) return emailOtpEnrollmentTenantMismatch();
    if (enrollment.providerUserId !== input.providerUserId) {
      return emailOtpProviderIdentityMismatch();
    }
    return { ok: true, enrollment };
  }

  private async recordInvalidAttempt(input: {
    readonly enrollment: EmailOtpWalletEnrollmentRecord;
    readonly authState: EmailOtpAuthStateRecord | null;
    readonly record: EmailOtpChallengeRecord;
  }): Promise<Extract<EmailOtpExistingChallengeVerifyResult, { ok: false }>> {
    const nextAttemptCount = input.record.attemptCount + 1;
    const nextFailureCount = Number(input.authState?.otpFailureCount || 0) + 1;
    const exhausted = nextAttemptCount >= input.record.maxAttempts;
    const nowMs = Date.now();
    const lockedUntilMs = exhausted ? nowMs + this.lockoutTtlMs : undefined;
    await this.emailOtpEnrollments.putAuthStateForEnrollment(input.enrollment, {
      otpFailureCount: nextFailureCount,
      lastOtpFailureAtMs: nowMs,
      ...(lockedUntilMs ? { otpLockedUntilMs: lockedUntilMs } : {}),
    });
    if (exhausted) {
      await this.emailOtpChallenges.delete(input.record.challengeId);
      return {
        ok: false,
        code: 'otp_attempts_exhausted',
        message: 'Email OTP challenge exceeded the maximum number of attempts',
        attemptsRemaining: 0,
        ...(lockedUntilMs ? { lockedUntilMs } : {}),
      };
    }
    await this.emailOtpChallenges.updateAttemptCount(input.record, nextAttemptCount);
    return {
      ok: false,
      code: 'invalid_otp',
      message: 'OTP code is invalid',
      attemptsRemaining: input.record.maxAttempts - nextAttemptCount,
    };
  }

  private async recordInvalidRegistrationAttempt(input: {
    readonly enrollment: EmailOtpWalletEnrollmentRecord | null;
    readonly authState: EmailOtpAuthStateRecord | null;
    readonly record: EmailOtpChallengeRecord;
  }): Promise<Extract<EmailOtpRegistrationChallengeVerifyResult, { ok: false }>> {
    if (input.enrollment) {
      return await this.recordInvalidAttempt({
        enrollment: input.enrollment,
        authState: input.authState,
        record: input.record,
      });
    }
    const nextAttemptCount = input.record.attemptCount + 1;
    const exhausted = nextAttemptCount >= input.record.maxAttempts;
    const lockedUntilMs = exhausted ? Date.now() + this.lockoutTtlMs : undefined;
    if (exhausted) {
      await this.emailOtpChallenges.delete(input.record.challengeId);
      return {
        ok: false,
        code: 'otp_attempts_exhausted',
        message: 'Email OTP challenge exceeded the maximum number of attempts',
        attemptsRemaining: 0,
        ...(lockedUntilMs ? { lockedUntilMs } : {}),
      };
    }
    await this.emailOtpChallenges.updateAttemptCount(input.record, nextAttemptCount);
    return {
      ok: false,
      code: 'invalid_otp',
      message: 'OTP code is invalid',
      attemptsRemaining: input.record.maxAttempts - nextAttemptCount,
    };
  }
}
