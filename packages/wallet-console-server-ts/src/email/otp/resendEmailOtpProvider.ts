import type { CloudflareD1EmailOtpDeliveryProviderResult } from '@seams/sdk-server/cloud-host';
import { createResendConsoleEmailProvider } from '@seams-internal/console-server/email/providers';
import type { ConsoleEmailProvider, ConsoleEmailProviderSendResult } from '@seams-internal/console-server/email/types';
import type { EmailOtpMessage, EmailOtpMessageProvider } from './emailOtpDeliveryAdapter';

const EMAIL_ADDRESS_PATTERN = /^[^\s<>@]+@[^\s<>@]+\.[^\s<>@]+$/;

export interface ResendEmailOtpProviderEnv {
  readonly EMAIL_OTP_FROM_ADDRESS?: string;
  readonly RESEND_API_KEY?: string;
}

export interface ResendEmailOtpProviderConfig {
  readonly apiKey: string;
  readonly fromAddress: string;
}

export function parseResendEmailOtpProviderConfig(
  env: ResendEmailOtpProviderEnv,
): ResendEmailOtpProviderConfig {
  const fromAddress = requiredEnvString(env.EMAIL_OTP_FROM_ADDRESS, 'EMAIL_OTP_FROM_ADDRESS');
  if (!EMAIL_ADDRESS_PATTERN.test(fromAddress)) {
    throw new Error('EMAIL_OTP_FROM_ADDRESS must be an email address');
  }
  return {
    apiKey: requiredEnvString(env.RESEND_API_KEY, 'RESEND_API_KEY'),
    fromAddress: fromAddress.toLowerCase(),
  };
}

export function createResendEmailOtpMessageProvider(
  config: ResendEmailOtpProviderConfig,
  provider?: ConsoleEmailProvider,
): EmailOtpMessageProvider {
  const resendProvider =
    provider ||
    createResendConsoleEmailProvider({
      apiKey: config.apiKey,
      from: `Seams <${config.fromAddress}>`,
    });
  return new ResendEmailOtpMessageProvider(resendProvider);
}

class ResendEmailOtpMessageProvider implements EmailOtpMessageProvider {
  constructor(private readonly provider: ConsoleEmailProvider) {}

  async send(message: EmailOtpMessage): Promise<CloudflareD1EmailOtpDeliveryProviderResult> {
    const result = await this.provider.send({
      outboxId: `email-otp/${message.deliveryId}`,
      recipient: {
        email: message.recipientEmail,
        displayName: '',
      },
      subject: message.subject,
      text: message.text,
      html: message.html,
    });
    return mapResendResult(result);
  }
}

function mapResendResult(
  result: ConsoleEmailProviderSendResult,
): CloudflareD1EmailOtpDeliveryProviderResult {
  switch (result.kind) {
    case 'SENT':
      return { ok: true, providerMessageId: result.providerMessageId };
    case 'RETRYABLE_FAILURE':
    case 'FINAL_FAILURE':
      return {
        ok: false,
        code: `email_otp_${result.errorCode}`,
        message: 'Resend Email OTP delivery failed',
      };
    default:
      return assertNever(result);
  }
}

function requiredEnvString(value: unknown, field: string): string {
  const normalized = typeof value === 'string' ? value.trim() : '';
  if (!normalized) throw new Error(`${field} is required for Resend Email OTP delivery`);
  return normalized;
}

function assertNever(value: never): never {
  throw new Error(`Unsupported Resend Email OTP result: ${JSON.stringify(value)}`);
}
