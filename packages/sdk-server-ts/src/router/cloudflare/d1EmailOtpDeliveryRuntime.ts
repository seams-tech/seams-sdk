import { EMAIL_OTP_CHANNEL } from '@shared/utils/emailOtpDomain';
import type { EmailOtpChallengeRecord } from '../../core/EmailOtpStores';
import { maskEmail } from './d1EmailOtpRecords';
import type { EmailOtpDeliveryMode, EmailOtpRuntimeConfig } from './d1RouterApiAuthConfig';

type EmailOtpDeliveryRuntimeResult =
  | { readonly ok: true; readonly deliveryMode: EmailOtpDeliveryMode; readonly emailHint: string }
  | { readonly ok: false; readonly code: string; readonly message: string };

function logDevelopmentEmailOtpCode(
  record: EmailOtpChallengeRecord,
  deliveryMode: EmailOtpDeliveryMode,
  deliveryStatus: 'sent' | 'reused',
): void {
  console.warn('[email-otp] development OTP code', {
    challengeId: record.challengeId,
    walletId: record.walletId,
    userId: record.challengeSubjectId,
    otpChannel: EMAIL_OTP_CHANNEL,
    action: record.action,
    operation: record.operation,
    deliveryMode,
    deliveryStatus,
    emailHint: maskEmail(record.email),
    devOtpCode: record.otpCode,
    expiresAtMs: record.expiresAtMs,
  });
}

export class CloudflareD1EmailOtpDeliveryRuntime {
  constructor(private readonly config: EmailOtpRuntimeConfig) {}

  reportReusedDevelopmentOtpCode(record: EmailOtpChallengeRecord): void {
    if (this.config.production || this.config.deliveryMode === 'email_provider') return;
    logDevelopmentEmailOtpCode(record, this.config.deliveryMode, 'reused');
  }

  async deliverEmailOtpCode(
    record: EmailOtpChallengeRecord,
  ): Promise<EmailOtpDeliveryRuntimeResult> {
    if (this.config.production && this.config.deliveryMode !== 'email_provider') {
      return {
        ok: false,
        code: 'email_otp_delivery_not_allowed',
        message: `Email OTP delivery mode ${this.config.deliveryMode} is disabled in production`,
      };
    }
    const emailHint = maskEmail(record.email);
    if (this.config.deliveryMode === 'email_provider') {
      const provider = this.config.deliveryProvider;
      if (!provider) {
        return {
          ok: false,
          code: 'email_otp_delivery_not_configured',
          message: 'Email OTP email_provider delivery is not configured',
        };
      }
      const delivered = await provider.deliver({
        challengeId: record.challengeId,
        walletId: record.walletId,
        userId: record.challengeSubjectId,
        ...(record.orgId ? { orgId: record.orgId } : {}),
        email: record.email,
        emailHint,
        otpCode: record.otpCode,
        otpChannel: EMAIL_OTP_CHANNEL,
        action: record.action,
        operation: record.operation,
        expiresAtMs: record.expiresAtMs,
      });
      if (!delivered.ok) return delivered;
      return { ok: true, deliveryMode: 'email_provider', emailHint };
    }
    logDevelopmentEmailOtpCode(record, this.config.deliveryMode, 'sent');
    return { ok: true, deliveryMode: this.config.deliveryMode, emailHint };
  }
}
