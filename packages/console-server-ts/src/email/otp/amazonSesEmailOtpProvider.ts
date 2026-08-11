import { SESv2Client, SendEmailCommand, type SendEmailCommandOutput } from '@aws-sdk/client-sesv2';
import type {
  CloudflareD1EmailOtpDeliveryProvider,
  CloudflareD1EmailOtpDeliveryProviderResult,
} from '@seams/sdk-server/cloud-host';
import {
  createEmailOtpDeliveryAdapter,
  type EmailOtpMessage,
  type EmailOtpMessageProvider,
} from './emailOtpDeliveryAdapter';

const EMAIL_OTP_SES_FROM_DISPLAY_NAME = 'Seams';
const EMAIL_ADDRESS_PATTERN = /^[^\s<>@]+@[^\s<>@]+\.[^\s<>@]+$/;
const AWS_REGION_PATTERN = /^[a-z]{2}(?:-gov)?-[a-z]+-\d+$/;

export interface AmazonSesEmailOtpProviderEnv {
  readonly EMAIL_OTP_SES_REGION?: string;
  readonly EMAIL_OTP_FROM_ADDRESS?: string;
  readonly EMAIL_OTP_SES_ACCESS_KEY_ID?: string;
  readonly EMAIL_OTP_SES_SECRET_ACCESS_KEY?: string;
}

export interface AmazonSesEmailOtpProviderConfig {
  readonly region: string;
  readonly fromAddress: string;
  readonly accessKeyId: string;
  readonly secretAccessKey: string;
}

export interface AmazonSesEmailOtpClient {
  send(command: SendEmailCommand): Promise<SendEmailCommandOutput>;
}

export function parseAmazonSesEmailOtpProviderConfig(
  env: AmazonSesEmailOtpProviderEnv,
): AmazonSesEmailOtpProviderConfig {
  const region = requiredEnvString(env.EMAIL_OTP_SES_REGION, 'EMAIL_OTP_SES_REGION');
  if (!AWS_REGION_PATTERN.test(region)) {
    throw new Error('EMAIL_OTP_SES_REGION must be an AWS region');
  }
  const fromAddress = requiredEnvString(
    env.EMAIL_OTP_FROM_ADDRESS,
    'EMAIL_OTP_FROM_ADDRESS',
  ).toLowerCase();
  if (!EMAIL_ADDRESS_PATTERN.test(fromAddress)) {
    throw new Error('EMAIL_OTP_FROM_ADDRESS must be an email address');
  }
  return {
    region,
    fromAddress,
    accessKeyId: requiredEnvString(env.EMAIL_OTP_SES_ACCESS_KEY_ID, 'EMAIL_OTP_SES_ACCESS_KEY_ID'),
    secretAccessKey: requiredEnvString(
      env.EMAIL_OTP_SES_SECRET_ACCESS_KEY,
      'EMAIL_OTP_SES_SECRET_ACCESS_KEY',
    ),
  };
}

export function createAmazonSesEmailOtpDeliveryProvider(
  config: AmazonSesEmailOtpProviderConfig,
  client?: AmazonSesEmailOtpClient,
): CloudflareD1EmailOtpDeliveryProvider {
  return createEmailOtpDeliveryAdapter(createAmazonSesEmailOtpMessageProvider(config, client));
}

export function createAmazonSesEmailOtpMessageProvider(
  config: AmazonSesEmailOtpProviderConfig,
  client?: AmazonSesEmailOtpClient,
): EmailOtpMessageProvider {
  return new AmazonSesEmailOtpMessageProvider(
    config,
    client || createAmazonSesEmailOtpClient(config),
  );
}

class AmazonSesEmailOtpMessageProvider implements EmailOtpMessageProvider {
  constructor(
    private readonly config: AmazonSesEmailOtpProviderConfig,
    private readonly client: AmazonSesEmailOtpClient,
  ) {}

  async send(message: EmailOtpMessage): Promise<CloudflareD1EmailOtpDeliveryProviderResult> {
    try {
      const output = await this.client.send(
        new SendEmailCommand({
          FromEmailAddress: `${EMAIL_OTP_SES_FROM_DISPLAY_NAME} <${this.config.fromAddress}>`,
          Destination: {
            ToAddresses: [message.recipientEmail],
          },
          Content: {
            Simple: {
              Subject: {
                Charset: 'UTF-8',
                Data: message.subject,
              },
              Body: {
                Text: {
                  Charset: 'UTF-8',
                  Data: message.text,
                },
                Html: {
                  Charset: 'UTF-8',
                  Data: message.html,
                },
              },
            },
          },
        }),
      );
      const providerMessageId = optionalTrimmedString(output.MessageId);
      if (!providerMessageId) {
        return providerFailure(
          'email_otp_ses_missing_message_id',
          'Amazon SES accepted the request without a message identifier',
        );
      }
      return { ok: true, providerMessageId };
    } catch (error) {
      return amazonSesFailure(error);
    }
  }
}

function createAmazonSesEmailOtpClient(
  config: AmazonSesEmailOtpProviderConfig,
): AmazonSesEmailOtpClient {
  return new SESv2Client({
    region: config.region,
    credentials: {
      accessKeyId: config.accessKeyId,
      secretAccessKey: config.secretAccessKey,
    },
  });
}

function amazonSesFailure(error: unknown): CloudflareD1EmailOtpDeliveryProviderResult {
  switch (errorName(error)) {
    case 'TooManyRequestsException':
    case 'ThrottlingException':
      return providerFailure(
        'email_otp_ses_throttled',
        'Amazon SES temporarily throttled Email OTP delivery',
      );
    case 'AccountSuspendedException':
    case 'BadRequestException':
    case 'MailFromDomainNotVerifiedException':
    case 'MessageRejected':
    case 'NotFoundException':
    case 'SendingPausedException':
      return providerFailure('email_otp_ses_rejected', 'Amazon SES rejected Email OTP delivery');
    default:
      return providerFailure(
        'email_otp_ses_transport_failed',
        'Amazon SES Email OTP delivery failed',
      );
  }
}

function errorName(error: unknown): string {
  if (!error || typeof error !== 'object' || !('name' in error)) return '';
  return optionalTrimmedString(error.name) || '';
}

function providerFailure(
  code: string,
  message: string,
): CloudflareD1EmailOtpDeliveryProviderResult {
  return { ok: false, code, message };
}

function requiredEnvString(value: unknown, field: string): string {
  const normalized = optionalTrimmedString(value);
  if (!normalized) throw new Error(`${field} is required for Amazon SES Email OTP delivery`);
  return normalized;
}

function optionalTrimmedString(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() ? value.trim() : undefined;
}
