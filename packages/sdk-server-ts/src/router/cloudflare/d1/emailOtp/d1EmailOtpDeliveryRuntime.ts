import { EMAIL_OTP_CHANNEL } from '@shared/utils/emailOtpDomain';
import type { EmailOtpChallengeRecord } from '../../core/EmailOtpStores';
import { maskEmail } from './d1EmailOtpRecords';
import type { EmailOtpDeliveryMode, EmailOtpRuntimeConfig } from './d1RouterApiAuthConfig';
import type { EmailOtpChallengeDelivery } from '../authServicePort';

type EmailOtpDeliveryRuntimeResult =
  | { readonly ok: true; readonly delivery: EmailOtpChallengeDelivery }
  | { readonly ok: false; readonly code: string; readonly message: string };

type EmailOtpProviderDispatchResult =
  | { readonly ok: true }
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

  resolveReusedEmailOtpDelivery(
    record: EmailOtpChallengeRecord,
    requestOrigin: unknown,
  ): EmailOtpDeliveryRuntimeResult {
    return this.resolveDelivery(record, requestOrigin, 'reused');
  }

  async deliverEmailOtpCode(
    record: EmailOtpChallengeRecord,
    requestOrigin: unknown,
  ): Promise<EmailOtpDeliveryRuntimeResult> {
    if (
      this.config.production &&
      this.config.deliveryMode !== 'email_provider' &&
      this.config.deliveryMode !== 'provider_and_demo_code' &&
      this.config.deliveryMode !== 'demo_code_response'
    ) {
      return {
        ok: false,
        code: 'email_otp_delivery_not_allowed',
        message: `Email OTP delivery mode ${this.config.deliveryMode} is disabled in production`,
      };
    }
    const emailHint = maskEmail(record.email);
    switch (this.config.deliveryMode) {
      case 'provider_and_demo_code': {
        const demoDelivery = this.resolveDemoCodeDelivery(record, requestOrigin, 'sent', emailHint);
        if (!demoDelivery.ok) return demoDelivery;
        const providerDelivery = await this.dispatchProviderEmail(record, emailHint);
        if (!providerDelivery.ok) return providerDelivery;
        return demoDelivery;
      }
      case 'email_provider': {
        const providerDelivery = await this.dispatchProviderEmail(record, emailHint);
        if (!providerDelivery.ok) return providerDelivery;
        return {
          ok: true,
          delivery: { kind: 'provider', status: 'sent', mode: 'email_provider', emailHint },
        };
      }
      case 'log':
      case 'dev_d1_outbox':
      case 'demo_code_response':
        return this.resolveDelivery(record, requestOrigin, 'sent');
    }
  }

  private async dispatchProviderEmail(
    record: EmailOtpChallengeRecord,
    emailHint: string,
  ): Promise<EmailOtpProviderDispatchResult> {
    const provider = this.config.deliveryProvider;
    if (!provider) {
      return {
        ok: false,
        code: 'email_otp_delivery_not_configured',
        message: 'Email OTP email_provider delivery is not configured',
      };
    }
    return provider.deliver({
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
  }

  private resolveDelivery(
    record: EmailOtpChallengeRecord,
    requestOrigin: unknown,
    status: 'sent' | 'reused',
  ): EmailOtpDeliveryRuntimeResult {
    const emailHint = maskEmail(record.email);
    switch (this.config.deliveryMode) {
      case 'email_provider':
        if (!this.config.deliveryProvider) {
          return {
            ok: false,
            code: 'email_otp_delivery_not_configured',
            message: 'Email OTP email_provider delivery is not configured',
          };
        }
        return {
          ok: true,
          delivery: { kind: 'provider', status, mode: 'email_provider', emailHint },
        };
      case 'provider_and_demo_code':
        if (!this.config.deliveryProvider) {
          return {
            ok: false,
            code: 'email_otp_delivery_not_configured',
            message: 'Email OTP email_provider delivery is not configured',
          };
        }
        return this.resolveDemoCodeDelivery(record, requestOrigin, status, emailHint);
      case 'log':
      case 'dev_d1_outbox':
        logDevelopmentEmailOtpCode(record, this.config.deliveryMode, status);
        return {
          ok: true,
          delivery: {
            kind: 'development',
            status,
            mode: this.config.deliveryMode,
            emailHint,
          },
        };
      case 'demo_code_response': {
        return this.resolveDemoCodeDelivery(record, requestOrigin, status, emailHint);
      }
    }
  }

  private resolveDemoCodeDelivery(
    record: EmailOtpChallengeRecord,
    requestOrigin: unknown,
    status: 'sent' | 'reused',
    emailHint: string,
  ): EmailOtpDeliveryRuntimeResult {
    const origin = typeof requestOrigin === 'string' ? requestOrigin.trim() : '';
    if (!this.config.demoAllowedOrigins.includes(origin)) {
      return {
        ok: false,
        code: 'email_otp_demo_origin_not_allowed',
        message: 'Email OTP demo code delivery is not allowed for this origin',
      };
    }
    if (this.config.deliveryMode === 'provider_and_demo_code') {
      return {
        ok: true,
        delivery: {
          kind: 'provider_and_demo_code',
          status,
          mode: 'provider_and_demo_code',
          emailHint,
          otpCode: record.otpCode,
        },
      };
    }
    return {
      ok: true,
      delivery: {
        kind: 'demo_code_response',
        status,
        mode: 'demo_code_response',
        emailHint,
        otpCode: record.otpCode,
      },
    };
  }
}
