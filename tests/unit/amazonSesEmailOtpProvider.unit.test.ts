import { expect, test } from '@playwright/test';
import type { SendEmailCommand, SendEmailCommandOutput } from '@aws-sdk/client-sesv2';
import type { CloudflareD1EmailOtpDeliveryProviderInput } from '../../packages/sdk-server-ts/src/router/cloudflare/d1/auth/d1RouterApiAuthConfig';
import {
  createAmazonSesEmailOtpDeliveryProvider,
  parseAmazonSesEmailOtpProviderConfig,
  renderEmailOtpMessage,
  resolveAmazonSesEmailOtpDeliveryProviderFromEnv,
  type AmazonSesEmailOtpClient,
} from '../../packages/console-server-ts/src/email/otp/amazonSesEmailOtpProvider';

const SES_CONFIG = {
  region: 'ap-southeast-2',
  fromAddress: 'confirm@seams.sh',
  accessKeyId: 'test-access-key-id',
  secretAccessKey: 'test-secret-access-key',
} as const;

const DELIVERY_INPUT = {
  challengeId: 'challenge-1',
  walletId: 'wallet-1',
  userId: 'user-1',
  orgId: 'org-1',
  email: 'alice@example.test',
  emailHint: 'a***@example.test',
  otpCode: '123456',
  otpChannel: 'email_otp',
  action: 'wallet_email_otp_login',
  operation: 'wallet_unlock',
  expiresAtMs: Date.now() + 5 * 60_000,
} satisfies CloudflareD1EmailOtpDeliveryProviderInput;

class RecordingSesEmailOtpClient implements AmazonSesEmailOtpClient {
  readonly commands: SendEmailCommand[] = [];

  constructor(private readonly output: SendEmailCommandOutput) {}

  async send(command: SendEmailCommand): Promise<SendEmailCommandOutput> {
    this.commands.push(command);
    return this.output;
  }
}

class FailingSesEmailOtpClient implements AmazonSesEmailOtpClient {
  constructor(private readonly failureName: string) {}

  async send(_command: SendEmailCommand): Promise<SendEmailCommandOutput> {
    const error = new Error('sensitive provider detail');
    error.name = this.failureName;
    throw error;
  }
}

test('Amazon SES Email OTP configuration parses required Worker environment values', () => {
  expect(
    parseAmazonSesEmailOtpProviderConfig({
      EMAIL_OTP_SES_REGION: ' ap-southeast-2 ',
      EMAIL_OTP_SES_FROM_ADDRESS: ' CONFIRM@SEAMS.SH ',
      EMAIL_OTP_SES_ACCESS_KEY_ID: ' access-key ',
      EMAIL_OTP_SES_SECRET_ACCESS_KEY: ' secret-key ',
    }),
  ).toEqual({
    region: 'ap-southeast-2',
    fromAddress: 'confirm@seams.sh',
    accessKeyId: 'access-key',
    secretAccessKey: 'secret-key',
  });
});

test('Amazon SES Email OTP provider is required only by provider delivery modes', () => {
  expect(
    resolveAmazonSesEmailOtpDeliveryProviderFromEnv({
      EMAIL_OTP_DELIVERY_MODE: 'demo_code_response',
    }),
  ).toBeUndefined();

  expect(() =>
    resolveAmazonSesEmailOtpDeliveryProviderFromEnv({
      EMAIL_OTP_DELIVERY_MODE: 'email_provider',
    }),
  ).toThrow('EMAIL_OTP_SES_REGION is required for Amazon SES Email OTP delivery');
});

test('Email OTP renderer produces operation-specific HTML and plain text without remote content', () => {
  const registration = renderEmailOtpMessage({
    operation: 'registration',
    otpCode: '123456',
    expiresAtMs: 400_000,
    nowMs: 100_000,
  });
  const unlock = renderEmailOtpMessage({
    operation: 'wallet_unlock',
    otpCode: '123456',
    expiresAtMs: 400_000,
    nowMs: 100_000,
  });
  const transaction = renderEmailOtpMessage({
    operation: 'transaction_sign',
    otpCode: '123456',
    expiresAtMs: 400_000,
    nowMs: 100_000,
  });
  const keyExport = renderEmailOtpMessage({
    operation: 'export_key',
    otpCode: '<123&',
    expiresAtMs: 400_000,
    nowMs: 100_000,
  });

  expect(registration.subject).toBe('Your Seams registration code');
  expect(unlock.subject).toBe('Your Seams wallet unlock code');
  expect(transaction.subject).toBe('Confirm your Seams transaction');
  expect(keyExport.subject).toBe('Confirm your Seams key export');
  expect(registration.text).toContain('This code expires in 5 minutes.');
  expect(registration.html).toContain('123456');
  expect(keyExport.html).toContain('&lt;123&amp;');
  expect(keyExport.html).not.toContain('<123&');
  expect(registration.html).not.toMatch(/https?:\/\//);
  expect(registration.html).not.toMatch(/<(?:img|script|form)\b/i);
});

test('Amazon SES Email OTP provider sends one UTF-8 simple message', async () => {
  const client = new RecordingSesEmailOtpClient({
    MessageId: ' ses-message-1 ',
    $metadata: {},
  });
  const provider = createAmazonSesEmailOtpDeliveryProvider(SES_CONFIG, client);

  await expect(provider.deliver(DELIVERY_INPUT)).resolves.toEqual({
    ok: true,
    providerMessageId: 'ses-message-1',
  });
  expect(client.commands).toHaveLength(1);
  expect(client.commands[0].input.FromEmailAddress).toBe('Seams <confirm@seams.sh>');
  expect(client.commands[0].input.Destination).toEqual({
    ToAddresses: ['alice@example.test'],
  });
  expect(client.commands[0].input.Content?.Simple?.Subject).toEqual({
    Charset: 'UTF-8',
    Data: 'Your Seams wallet unlock code',
  });
  expect(client.commands[0].input.Content?.Simple?.Body?.Text?.Data).toContain('123456');
  expect(client.commands[0].input.Content?.Simple?.Body?.Html?.Data).toContain('123456');
  expect(client.commands[0].input).not.toHaveProperty('ReplyToAddresses');
  expect(client.commands[0].input).not.toHaveProperty('EmailTags');
  expect(client.commands[0].input).not.toHaveProperty('ConfigurationSetName');
});

test('Amazon SES Email OTP provider fails when SES omits its message identifier', async () => {
  const client = new RecordingSesEmailOtpClient({ $metadata: {} });
  const provider = createAmazonSesEmailOtpDeliveryProvider(SES_CONFIG, client);

  await expect(provider.deliver(DELIVERY_INPUT)).resolves.toEqual({
    ok: false,
    code: 'email_otp_ses_missing_message_id',
    message: 'Amazon SES accepted the request without a message identifier',
  });
});

test('Amazon SES Email OTP provider maps throttling without exposing provider details', async () => {
  const provider = createAmazonSesEmailOtpDeliveryProvider(
    SES_CONFIG,
    new FailingSesEmailOtpClient('TooManyRequestsException'),
  );

  await expect(provider.deliver(DELIVERY_INPUT)).resolves.toEqual({
    ok: false,
    code: 'email_otp_ses_throttled',
    message: 'Amazon SES temporarily throttled Email OTP delivery',
  });
});

test('Amazon SES Email OTP provider maps rejected and transport failures', async () => {
  const rejectedProvider = createAmazonSesEmailOtpDeliveryProvider(
    SES_CONFIG,
    new FailingSesEmailOtpClient('MessageRejected'),
  );
  const transportProvider = createAmazonSesEmailOtpDeliveryProvider(
    SES_CONFIG,
    new FailingSesEmailOtpClient('NetworkFailure'),
  );

  await expect(rejectedProvider.deliver(DELIVERY_INPUT)).resolves.toEqual({
    ok: false,
    code: 'email_otp_ses_rejected',
    message: 'Amazon SES rejected Email OTP delivery',
  });
  await expect(transportProvider.deliver(DELIVERY_INPUT)).resolves.toEqual({
    ok: false,
    code: 'email_otp_ses_transport_failed',
    message: 'Amazon SES Email OTP delivery failed',
  });
});
