import {
  EMAIL_OTP_CHANNEL,
  WALLET_EMAIL_OTP_ACTIONS,
  WALLET_EMAIL_OTP_UNLOCK_OPERATION,
} from '@shared/utils/emailOtpDomain';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import type {
  EmailOtpAuthStateRecord,
  EmailOtpChallengeRecord,
  EmailOtpLoginChallengeOperation,
  EmailOtpWalletEnrollmentRecord,
} from '../../core/EmailOtpStores';
import type { CloudflareD1EmailOtpChallengeStore } from './d1EmailOtpChallengeStore';
import type { CloudflareD1EmailOtpEnrollmentStore } from './d1EmailOtpEnrollmentStore';
import type { CloudflareD1EmailOtpRateLimitStore } from './d1EmailOtpRateLimitStore';
import {
  emailOtpChallengeBindingMismatchCode,
  emailOtpChallengeInvalidOrExpired,
  emailOtpRegistrationChallengeBindingMismatchCode,
} from './d1EmailOtpRecords';

export type EmailOtpExistingChallengeVerifyBaseInput = {
  readonly userId?: unknown;
  readonly walletId?: unknown;
  readonly orgId?: unknown;
  readonly challengeId?: unknown;
  readonly otpCode?: unknown;
  readonly otpChannel?: unknown;
  readonly sessionHash?: unknown;
  readonly appSessionVersion?: unknown;
  readonly clientIp?: unknown;
};

export type EmailOtpExistingChallengeVerifyInput =
  | (EmailOtpExistingChallengeVerifyBaseInput & {
      readonly action: typeof WALLET_EMAIL_OTP_ACTIONS.login;
      readonly operation: EmailOtpLoginChallengeOperation;
    })
  | (EmailOtpExistingChallengeVerifyBaseInput & {
      readonly action: typeof WALLET_EMAIL_OTP_ACTIONS.deviceRecovery;
      readonly operation: typeof WALLET_EMAIL_OTP_UNLOCK_OPERATION;
    });

export type EmailOtpExistingChallengeVerifyResult =
  | {
      ok: true;
      readonly challengeId: string;
      readonly userId: string;
      readonly walletId: string;
      readonly orgId: string;
      readonly otpChannel: typeof EMAIL_OTP_CHANNEL;
      readonly sessionHash: string;
      readonly appSessionVersion: string;
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
  readonly sessionHash?: unknown;
  readonly appSessionVersion?: unknown;
  readonly proofEmail?: unknown;
  readonly clientIp?: unknown;
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

type ActiveEmailOtpEnrollmentResult =
  | { readonly ok: true; readonly enrollment: EmailOtpWalletEnrollmentRecord }
  | { readonly ok: false; readonly code: string; readonly message: string };

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
      const sessionHash = toOptionalTrimmedString(input.sessionHash);
      const appSessionVersion = toOptionalTrimmedString(input.appSessionVersion);
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
      if (!sessionHash) return { ok: false, code: 'invalid_body', message: 'Missing sessionHash' };
      if (!appSessionVersion) {
        return { ok: false, code: 'invalid_body', message: 'Missing appSessionVersion' };
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

      const enrollment = await this.readActiveEnrollment({ walletId, orgId, providerUserId: userId });
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
        sessionHash,
        appSessionVersion,
        action,
        operation,
      });
      if (bindingMismatch) {
        return {
          ok: false,
          code: bindingMismatch,
          message: 'Email OTP challenge is not valid for the current app session',
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
        sessionHash,
        appSessionVersion,
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
    try {
      const providerSubject = toOptionalTrimmedString(input.providerSubject);
      const walletId = toOptionalTrimmedString(input.walletId);
      const orgId = toOptionalTrimmedString(input.orgId);
      const challengeId = toOptionalTrimmedString(input.challengeId);
      const otpCode = toOptionalTrimmedString(input.otpCode);
      const otpChannel = toOptionalTrimmedString(input.otpChannel);
      const sessionHash = toOptionalTrimmedString(input.sessionHash);
      const appSessionVersion = toOptionalTrimmedString(input.appSessionVersion);
      const proofEmail = toOptionalTrimmedString(input.proofEmail)?.toLowerCase() || '';
      const clientIp = toOptionalTrimmedString(input.clientIp);
      if (!providerSubject) {
        return { ok: false, code: 'invalid_body', message: 'Missing providerSubject' };
      }
      if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
      if (!orgId) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };
      if (!challengeId) {
        return { ok: false, code: 'invalid_body', message: 'Missing challengeId' };
      }
      if (!otpCode) return { ok: false, code: 'invalid_body', message: 'Missing otpCode' };
      if (otpChannel !== EMAIL_OTP_CHANNEL) {
        return { ok: false, code: 'invalid_body', message: 'otpChannel must be email_otp' };
      }
      if (!sessionHash) return { ok: false, code: 'invalid_body', message: 'Missing sessionHash' };
      if (!appSessionVersion) {
        return { ok: false, code: 'invalid_body', message: 'Missing appSessionVersion' };
      }
      if (!proofEmail) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Email OTP registration requires proofEmail',
        };
      }

      const rateLimit = await this.emailOtpRateLimits.consume({
        scope: 'verify',
        action: WALLET_EMAIL_OTP_ACTIONS.registration,
        userId: providerSubject,
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

      const bindingMismatch = emailOtpRegistrationChallengeBindingMismatchCode({
        record,
        providerSubject,
        walletId,
        orgId,
        sessionHash,
        appSessionVersion,
        proofEmail,
      });
      if (bindingMismatch) {
        return {
          ok: false,
          code: bindingMismatch,
          message: 'Email OTP challenge is not valid for the current app session',
        };
      }

      if (record.otpCode !== otpCode) {
        return await this.recordInvalidRegistrationAttempt({
          enrollment: existingEnrollment,
          authState: authState.state,
          record,
        });
      }

      const consumed = await this.emailOtpChallenges.consume(record.challengeId);
      if (!consumed) return emailOtpChallengeInvalidOrExpired();
      if (existingEnrollment) {
        await this.emailOtpEnrollments.resetFailureState({
          enrollment: existingEnrollment,
          authState: authState.state,
        });
      }
      return {
        ok: true,
        challengeId: consumed.challengeId,
        challengeSubjectId: providerSubject,
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
