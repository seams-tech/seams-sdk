import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import {
  EMAIL_OTP_CHANNEL,
  WALLET_EMAIL_OTP_ACTIONS,
  WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
  WALLET_EMAIL_OTP_UNLOCK_OPERATION,
} from '@shared/utils/emailOtpDomain';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import type {
  EmailOtpChallengeOperation,
  EmailOtpLoginChallengeOperation,
  EmailOtpWalletEnrollmentRecord,
} from '../../core/EmailOtpStores';
import type { CloudflareD1EmailOtpChallengeStore } from './d1EmailOtpChallengeStore';
import type { CloudflareD1EmailOtpDeliveryRuntime } from './d1EmailOtpDeliveryRuntime';
import type { CloudflareD1EmailOtpEnrollmentStore } from './d1EmailOtpEnrollmentStore';
import type { CloudflareD1EmailOtpRateLimitStore } from './d1EmailOtpRateLimitStore';
import type { EmailOtpDeliveryMode } from './d1RouterApiAuthConfig';
import {
  emailOtpChallengePurposeIsValid,
  emailOtpChallengeRecord,
  generateNumericOtp,
  maskEmail,
  type EmailOtpChallengeIssueAction,
} from './d1EmailOtpRecords';

type EmailOtpChallengeIssueBaseInput = {
  readonly userId?: unknown;
  readonly walletId?: unknown;
  readonly orgId?: unknown;
  readonly email?: unknown;
  readonly otpChannel?: unknown;
  readonly sessionHash?: unknown;
  readonly appSessionVersion?: unknown;
  readonly clientIp?: unknown;
  readonly reuseActiveChallenge?: unknown;
};

export type EmailOtpChallengeIssueInput =
  | (EmailOtpChallengeIssueBaseInput & {
      readonly action: typeof WALLET_EMAIL_OTP_ACTIONS.login;
      readonly operation: EmailOtpLoginChallengeOperation;
    })
  | (EmailOtpChallengeIssueBaseInput & {
      readonly action: typeof WALLET_EMAIL_OTP_ACTIONS.registration;
      readonly operation: typeof WALLET_EMAIL_OTP_REGISTRATION_OPERATION;
    })
  | (EmailOtpChallengeIssueBaseInput & {
      readonly action: typeof WALLET_EMAIL_OTP_ACTIONS.deviceRecovery;
      readonly operation: typeof WALLET_EMAIL_OTP_UNLOCK_OPERATION;
    });

export type EmailOtpChallengeIssueResult =
  | {
      ok: true;
      challenge: {
        readonly challengeId: string;
        readonly issuedAtMs: number;
        readonly expiresAtMs: number;
        readonly challengeSubjectId: string;
        readonly walletId: string;
        readonly orgId: string;
        readonly otpChannel: typeof EMAIL_OTP_CHANNEL;
        readonly sessionHash: string;
        readonly appSessionVersion: string;
        readonly action: EmailOtpChallengeIssueAction;
        readonly operation: EmailOtpChallengeOperation;
      };
      delivery: {
        readonly status: 'sent' | 'reused';
        readonly mode: EmailOtpDeliveryMode;
        readonly emailHint: string;
      };
    }
  | {
      ok: false;
      code: string;
      message: string;
      lockedUntilMs?: number;
      retryAfterMs?: number;
      resetAtMs?: number;
    };

type ActiveEmailOtpEnrollmentResult =
  | { readonly ok: true; readonly enrollment: EmailOtpWalletEnrollmentRecord }
  | { readonly ok: false; readonly code: string; readonly message: string };

type EmailOtpChallengeIssuerConfig = {
  readonly challengeTtlMs: number;
  readonly codeLength: number;
  readonly deliveryMode: EmailOtpDeliveryMode;
  readonly maxActiveChallengesPerContext: number;
  readonly maxAttempts: number;
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

function emailOtpProviderIdentityMismatch(): ActiveEmailOtpEnrollmentResult {
  return {
    ok: false,
    code: 'provider_identity_mismatch',
    message: 'Email OTP enrollment does not match the requested provider user',
  };
}

export class CloudflareD1EmailOtpChallengeIssuer {
  private readonly config: EmailOtpChallengeIssuerConfig;
  private readonly emailOtpChallenges: CloudflareD1EmailOtpChallengeStore;
  private readonly emailOtpDelivery: CloudflareD1EmailOtpDeliveryRuntime;
  private readonly emailOtpEnrollments: CloudflareD1EmailOtpEnrollmentStore;
  private readonly emailOtpRateLimits: CloudflareD1EmailOtpRateLimitStore;

  constructor(input: {
    readonly config: EmailOtpChallengeIssuerConfig;
    readonly emailOtpChallenges: CloudflareD1EmailOtpChallengeStore;
    readonly emailOtpDelivery: CloudflareD1EmailOtpDeliveryRuntime;
    readonly emailOtpEnrollments: CloudflareD1EmailOtpEnrollmentStore;
    readonly emailOtpRateLimits: CloudflareD1EmailOtpRateLimitStore;
  }) {
    this.config = input.config;
    this.emailOtpChallenges = input.emailOtpChallenges;
    this.emailOtpDelivery = input.emailOtpDelivery;
    this.emailOtpEnrollments = input.emailOtpEnrollments;
    this.emailOtpRateLimits = input.emailOtpRateLimits;
  }

  async create(input: EmailOtpChallengeIssueInput): Promise<EmailOtpChallengeIssueResult> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      const walletId = toOptionalTrimmedString(input.walletId);
      const orgId = toOptionalTrimmedString(input.orgId);
      const email = toOptionalTrimmedString(input.email)?.toLowerCase() || '';
      const otpChannel = toOptionalTrimmedString(input.otpChannel);
      const sessionHash = toOptionalTrimmedString(input.sessionHash);
      const appSessionVersion = toOptionalTrimmedString(input.appSessionVersion);
      const clientIp = toOptionalTrimmedString(input.clientIp);
      const action = input.action;
      const operation = input.operation;
      if (!userId) return { ok: false, code: 'invalid_body', message: 'Missing userId' };
      if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
      if (!orgId) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };
      if (otpChannel !== EMAIL_OTP_CHANNEL) {
        return { ok: false, code: 'invalid_body', message: 'otpChannel must be email_otp' };
      }
      if (!sessionHash) return { ok: false, code: 'invalid_body', message: 'Missing sessionHash' };
      if (!appSessionVersion) {
        return { ok: false, code: 'invalid_body', message: 'Missing appSessionVersion' };
      }
      if (!emailOtpChallengePurposeIsValid({ action, operation })) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Email OTP challenge action does not match operation',
        };
      }

      let challengeEmail = email;
      if (action !== WALLET_EMAIL_OTP_ACTIONS.registration) {
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
        challengeEmail = enrollment.enrollment.verifiedEmail;
      }
      if (!challengeEmail) {
        return {
          ok: false,
          code: 'recovery_email_missing',
          message: 'Current app session does not include a recovery email',
        };
      }

      const nowMs = Date.now();
      await this.emailOtpChallenges.pruneExpired(nowMs);
      if (input.reuseActiveChallenge === true) {
        const existing = await this.emailOtpChallenges.findLatestActive({
          challengeSubjectId: userId,
          walletId,
          orgId,
          action,
          sessionHash,
          appSessionVersion,
          operation,
          nowMs,
        });
        if (existing) {
          this.emailOtpDelivery.reportReusedDevelopmentOtpCode(existing);
          return {
            ok: true,
            challenge: {
              challengeId: existing.challengeId,
              issuedAtMs: existing.createdAtMs,
              expiresAtMs: existing.expiresAtMs,
              challengeSubjectId: userId,
              walletId,
              orgId,
              otpChannel: EMAIL_OTP_CHANNEL,
              sessionHash,
              appSessionVersion,
              action,
              operation,
            },
            delivery: {
              status: 'reused',
              mode: this.config.deliveryMode,
              emailHint: maskEmail(existing.email),
            },
          };
        }
      }

      const rateLimit = await this.emailOtpRateLimits.consume({
        scope: 'challenge',
        action,
        userId,
        walletId,
        orgId,
        clientIp,
      });
      if (!rateLimit.ok) return rateLimit;

      await this.emailOtpChallenges.deleteActiveOverflow({
        challengeSubjectId: userId,
        walletId,
        orgId,
        action,
        sessionHash,
        appSessionVersion,
        operation,
        nowMs,
        maxActiveChallenges: this.config.maxActiveChallengesPerContext,
      });

      const challengeId = secureRandomBase64Url(16, 'email otp challenge ids');
      const otpCode = generateNumericOtp(this.config.codeLength);
      const expiresAtMs = nowMs + this.config.challengeTtlMs;
      const record = emailOtpChallengeRecord({
        challengeId,
        challengeSubjectId: userId,
        walletId,
        orgId,
        email: challengeEmail,
        otpCode,
        sessionHash,
        appSessionVersion,
        action,
        operation,
        createdAtMs: nowMs,
        expiresAtMs,
        maxAttempts: this.config.maxAttempts,
      });
      await this.emailOtpChallenges.put(record);
      const delivery = await this.emailOtpDelivery.deliverEmailOtpCode(record);
      if (!delivery.ok) {
        await this.emailOtpChallenges.delete(challengeId);
        return delivery;
      }

      return {
        ok: true,
        challenge: {
          challengeId,
          issuedAtMs: nowMs,
          expiresAtMs,
          challengeSubjectId: userId,
          walletId,
          orgId,
          otpChannel: EMAIL_OTP_CHANNEL,
          sessionHash,
          appSessionVersion,
          action,
          operation,
        },
        delivery: {
          status: 'sent',
          mode: delivery.deliveryMode,
          emailHint: delivery.emailHint,
        },
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to create Email OTP challenge',
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
}
