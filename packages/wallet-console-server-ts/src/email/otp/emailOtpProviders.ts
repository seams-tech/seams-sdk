import type { CloudflareD1EmailOtpDeliveryProvider } from '@seams/wallet-server/cloud-host';
import {
  createAmazonSesEmailOtpDeliveryProvider,
  parseAmazonSesEmailOtpProviderConfig,
  type AmazonSesEmailOtpProviderEnv,
} from './amazonSesEmailOtpProvider';
import { createEmailOtpDeliveryAdapter } from './emailOtpDeliveryAdapter';
import {
  createResendEmailOtpMessageProvider,
  parseResendEmailOtpProviderConfig,
  type ResendEmailOtpProviderEnv,
} from './resendEmailOtpProvider';

const EMAIL_OTP_PROVIDER_MODES = new Set(['email_provider', 'provider_and_demo_code']);

export interface EmailOtpProviderEnv
  extends AmazonSesEmailOtpProviderEnv, ResendEmailOtpProviderEnv {
  readonly EMAIL_OTP_DELIVERY_MODE?: string;
  readonly EMAIL_OTP_PROVIDER?: string;
}

export function resolveEmailOtpDeliveryProviderFromEnv(
  env: EmailOtpProviderEnv,
): CloudflareD1EmailOtpDeliveryProvider | undefined {
  const deliveryMode = optionalTrimmedString(env.EMAIL_OTP_DELIVERY_MODE);
  if (!deliveryMode || !EMAIL_OTP_PROVIDER_MODES.has(deliveryMode)) return undefined;

  const provider = requiredProvider(env.EMAIL_OTP_PROVIDER);
  switch (provider) {
    case 'resend':
      return createEmailOtpDeliveryAdapter(
        createResendEmailOtpMessageProvider(parseResendEmailOtpProviderConfig(env)),
      );
    case 'amazon_ses':
      return createAmazonSesEmailOtpDeliveryProvider(parseAmazonSesEmailOtpProviderConfig(env));
    default:
      return assertNever(provider);
  }
}

function requiredProvider(value: unknown): 'resend' | 'amazon_ses' {
  const provider = optionalTrimmedString(value)?.toLowerCase();
  if (provider === 'resend' || provider === 'amazon_ses') return provider;
  throw new Error('EMAIL_OTP_PROVIDER must be resend or amazon_ses for provider delivery');
}

function optionalTrimmedString(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() ? value.trim() : undefined;
}

function assertNever(value: never): never {
  throw new Error(`Unsupported Email OTP provider: ${String(value)}`);
}
