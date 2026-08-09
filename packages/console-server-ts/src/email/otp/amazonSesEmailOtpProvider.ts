import { SESv2Client, SendEmailCommand, type SendEmailCommandOutput } from '@aws-sdk/client-sesv2';
import type {
  CloudflareD1EmailOtpDeliveryProvider,
  CloudflareD1EmailOtpDeliveryProviderInput,
  CloudflareD1EmailOtpDeliveryProviderResult,
} from '@seams/sdk-server/cloud-host';

const EMAIL_OTP_SES_FROM_DISPLAY_NAME = 'Seams';
const EMAIL_OTP_PROVIDER_MODES = new Set(['email_provider', 'provider_and_demo_code']);
const EMAIL_ADDRESS_PATTERN = /^[^\s<>@]+@[^\s<>@]+\.[^\s<>@]+$/;
const AWS_REGION_PATTERN = /^[a-z]{2}(?:-gov)?-[a-z]+-\d+$/;

export interface AmazonSesEmailOtpProviderEnv {
  readonly EMAIL_OTP_DELIVERY_MODE?: string;
  readonly EMAIL_OTP_SES_REGION?: string;
  readonly EMAIL_OTP_SES_FROM_ADDRESS?: string;
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

export interface RenderedEmailOtpMessage {
  readonly subject: string;
  readonly text: string;
  readonly html: string;
}

type EmailOtpOperationCopy = {
  readonly subject: string;
  readonly heading: string;
  readonly introduction: string;
  readonly caution: string;
};

export function resolveAmazonSesEmailOtpDeliveryProviderFromEnv(
  env: AmazonSesEmailOtpProviderEnv,
): CloudflareD1EmailOtpDeliveryProvider | undefined {
  const deliveryMode = optionalTrimmedString(env.EMAIL_OTP_DELIVERY_MODE);
  if (!deliveryMode || !EMAIL_OTP_PROVIDER_MODES.has(deliveryMode)) return undefined;
  return createAmazonSesEmailOtpDeliveryProvider(parseAmazonSesEmailOtpProviderConfig(env));
}

export function parseAmazonSesEmailOtpProviderConfig(
  env: AmazonSesEmailOtpProviderEnv,
): AmazonSesEmailOtpProviderConfig {
  const region = requiredEnvString(env.EMAIL_OTP_SES_REGION, 'EMAIL_OTP_SES_REGION');
  if (!AWS_REGION_PATTERN.test(region)) {
    throw new Error('EMAIL_OTP_SES_REGION must be an AWS region');
  }
  const fromAddress = requiredEnvString(
    env.EMAIL_OTP_SES_FROM_ADDRESS,
    'EMAIL_OTP_SES_FROM_ADDRESS',
  ).toLowerCase();
  if (!EMAIL_ADDRESS_PATTERN.test(fromAddress)) {
    throw new Error('EMAIL_OTP_SES_FROM_ADDRESS must be an email address');
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
  const sesClient = client || createAmazonSesEmailOtpClient(config);
  return new AmazonSesEmailOtpDeliveryProvider(config, sesClient);
}

export function renderEmailOtpMessage(
  input: Pick<
    CloudflareD1EmailOtpDeliveryProviderInput,
    'operation' | 'otpCode' | 'expiresAtMs'
  > & { readonly nowMs: number },
): RenderedEmailOtpMessage {
  const copy = emailOtpOperationCopy(input.operation);
  const expiry = expiryText(input.expiresAtMs, input.nowMs);
  const text = [
    copy.heading,
    copy.introduction,
    `Your one-time code is: ${input.otpCode}`,
    `This code expires ${expiry}.`,
    copy.caution,
    'Seams staff will never ask for this code. If you did not request this action, ignore this email.',
  ].join('\n\n');
  const htmlCode = escapeHtml(input.otpCode);
  return {
    subject: copy.subject,
    text,
    html: `<!doctype html>
<html lang="en">
  <body style="margin:0;background:#f4f4f5;color:#18181b;font-family:Arial,sans-serif;">
    <div style="display:none;max-height:0;overflow:hidden;opacity:0;">${escapeHtml(copy.introduction)}</div>
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#f4f4f5;padding:32px 16px;">
      <tr>
        <td align="center">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:520px;background:#ffffff;border:1px solid #e4e4e7;border-radius:12px;">
            <tr>
              <td style="padding:32px;">
                <p style="margin:0 0 20px;color:#52525b;font-size:15px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;">Seams</p>
                <h1 style="margin:0 0 16px;font-size:24px;line-height:1.25;">${escapeHtml(copy.heading)}</h1>
                <p style="margin:0 0 24px;color:#3f3f46;font-size:16px;line-height:1.6;">${escapeHtml(copy.introduction)}</p>
                <div aria-label="One-time code" style="margin:0 0 24px;padding:18px 16px;border-radius:10px;background:#18181b;color:#ffffff;font-family:monospace;font-size:32px;font-weight:700;letter-spacing:0.2em;text-align:center;">${htmlCode}</div>
                <p style="margin:0 0 16px;color:#3f3f46;font-size:15px;line-height:1.6;">This code expires ${escapeHtml(expiry)}.</p>
                <p style="margin:0 0 16px;color:#3f3f46;font-size:15px;line-height:1.6;">${escapeHtml(copy.caution)}</p>
                <p style="margin:0;color:#71717a;font-size:14px;line-height:1.6;">Seams staff will never ask for this code. If you did not request this action, ignore this email.</p>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>`,
  };
}

class AmazonSesEmailOtpDeliveryProvider implements CloudflareD1EmailOtpDeliveryProvider {
  constructor(
    private readonly config: AmazonSesEmailOtpProviderConfig,
    private readonly client: AmazonSesEmailOtpClient,
  ) {}

  async deliver(
    input: CloudflareD1EmailOtpDeliveryProviderInput,
  ): Promise<CloudflareD1EmailOtpDeliveryProviderResult> {
    const message = renderEmailOtpMessage({
      operation: input.operation,
      otpCode: input.otpCode,
      expiresAtMs: input.expiresAtMs,
      nowMs: Date.now(),
    });
    try {
      const output = await this.client.send(
        new SendEmailCommand({
          FromEmailAddress: `${EMAIL_OTP_SES_FROM_DISPLAY_NAME} <${this.config.fromAddress}>`,
          Destination: {
            ToAddresses: [input.email],
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

function emailOtpOperationCopy(
  operation: CloudflareD1EmailOtpDeliveryProviderInput['operation'],
): EmailOtpOperationCopy {
  switch (operation) {
    case 'registration':
      return {
        subject: 'Your Seams registration code',
        heading: 'Confirm your wallet registration',
        introduction: 'Enter this code to finish creating your Seams wallet.',
        caution: 'Continue only if you started this wallet registration.',
      };
    case 'wallet_unlock':
      return {
        subject: 'Your Seams wallet unlock code',
        heading: 'Confirm your wallet unlock',
        introduction: 'Enter this code to unlock your Seams wallet.',
        caution: 'Continue only if you requested access to this wallet.',
      };
    case 'transaction_sign':
      return {
        subject: 'Confirm your Seams transaction',
        heading: 'Confirm transaction signing',
        introduction: 'Enter this code to authorize signing a transaction with your Seams wallet.',
        caution: 'Review the transaction details in your wallet before entering the code.',
      };
    case 'export_key':
      return {
        subject: 'Confirm your Seams key export',
        heading: 'Confirm key export',
        introduction: 'Enter this code to authorize exporting your Seams wallet key material.',
        caution:
          'Exported key material grants full control of your wallet. Continue only if you requested it.',
      };
    default:
      return assertNever(operation);
  }
}

function expiryText(expiresAtMs: number, nowMs: number): string {
  const remainingMinutes = Math.max(1, Math.ceil((expiresAtMs - nowMs) / 60_000));
  return remainingMinutes === 1 ? 'in 1 minute' : `in ${remainingMinutes} minutes`;
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

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function assertNever(value: never): never {
  throw new Error(`Unsupported Email OTP operation: ${String(value)}`);
}
