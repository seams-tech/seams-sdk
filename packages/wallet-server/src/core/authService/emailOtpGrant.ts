import {
  EMAIL_OTP_CHANNEL,
  WALLET_EMAIL_OTP_ACTIONS,
} from '@shared/utils/emailOtpDomain';
import { errorMessage } from '@shared/utils/errors';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import type {
  EmailOtpChannel,
  EmailOtpGrantStore,
} from '../EmailOtpStores';

export type EmailOtpGrantConsumeRequest = {
  loginGrant?: unknown;
  userId?: unknown;
  walletId?: unknown;
  orgId?: unknown;
  otpChannel?: unknown;
  clientIp?: unknown;
};

export type EmailOtpGrantConsumeResult =
  | {
      ok: true;
      challengeId: string;
      otpChannel: EmailOtpChannel;
    }
  | { ok: false; code: string; message: string };

export type EmailOtpGrantRateLimitInput = {
  scope: 'grant';
  userId: string;
  walletId: string;
  orgId: string;
  clientIp?: string;
};

export type EmailOtpGrantRateLimitResult =
  | { ok: true }
  | { ok: false; code: string; message: string; retryAfterMs?: number; resetAtMs?: number };

export type EmailOtpGrantRateLimitConsumer = (
  input: EmailOtpGrantRateLimitInput,
) => Promise<EmailOtpGrantRateLimitResult>;

export async function consumeEmailOtpGrantWithStore(input: {
  readonly request: EmailOtpGrantConsumeRequest;
  readonly grantStore: EmailOtpGrantStore;
  readonly consumeRateLimit: EmailOtpGrantRateLimitConsumer;
  readonly nowMs: number;
}): Promise<EmailOtpGrantConsumeResult> {
  try {
    const loginGrant = toOptionalTrimmedString(input.request.loginGrant);
    const userId = toOptionalTrimmedString(input.request.userId);
    const walletId = toOptionalTrimmedString(input.request.walletId);
    const orgId = toOptionalTrimmedString(input.request.orgId) || '';
    const otpChannel = toOptionalTrimmedString(input.request.otpChannel);
    const clientIp = toOptionalTrimmedString(input.request.clientIp) || undefined;
    if (!loginGrant) return { ok: false, code: 'invalid_body', message: 'Missing loginGrant' };
    if (!userId) return { ok: false, code: 'invalid_body', message: 'Missing userId' };
    if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
    if (!orgId) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };
    if (otpChannel !== EMAIL_OTP_CHANNEL) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'otpChannel must be email_otp',
      };
    }

    const rateLimit = await input.consumeRateLimit({
      scope: 'grant',
      userId,
      walletId,
      orgId,
      clientIp,
    });
    if (!rateLimit.ok) return rateLimit;

    const record = await input.grantStore.consume(loginGrant);
    const invalidGrant =
      !record ||
      input.nowMs > record.expiresAtMs ||
      record.action !== WALLET_EMAIL_OTP_ACTIONS.unseal;
    if (invalidGrant) {
      return {
        ok: false,
        code: 'login_grant_invalid_or_expired',
        message: 'Login grant is invalid or expired',
      };
    }

    const bindingMismatch =
      record.userId !== userId ||
      record.walletId !== walletId ||
      record.otpChannel !== EMAIL_OTP_CHANNEL ||
      record.orgId !== orgId;
    if (bindingMismatch) {
      return {
        ok: false,
        code: 'recovery_grant_binding_mismatch',
        message: 'Recovery grant is not valid for the current Email OTP authority',
      };
    }

    return {
      ok: true,
      challengeId: record.challengeId,
      otpChannel: EMAIL_OTP_CHANNEL,
    };
  } catch (error: unknown) {
    return {
      ok: false,
      code: 'internal',
      message: errorMessage(error) || 'Failed to consume Email OTP grant',
    };
  }
}
