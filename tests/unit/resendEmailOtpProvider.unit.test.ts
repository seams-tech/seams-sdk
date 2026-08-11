import { expect, test } from '@playwright/test';
import type {
  ConsoleEmailProvider,
  ConsoleEmailProviderSendRequest,
  ConsoleEmailProviderSendResult,
} from '../../packages/console-server-ts/src/email/types';
import { createEmailOtpDeliveryAdapter } from '../../packages/console-server-ts/src/email/otp/emailOtpDeliveryAdapter';
import { resolveEmailOtpDeliveryProviderFromEnv } from '../../packages/console-server-ts/src/email/otp/emailOtpProviders';
import {
  createResendEmailOtpMessageProvider,
  parseResendEmailOtpProviderConfig,
} from '../../packages/console-server-ts/src/email/otp/resendEmailOtpProvider';
import type { CloudflareD1EmailOtpDeliveryProviderInput } from '../../packages/sdk-server-ts/src/router/cloudflare/d1/auth/d1RouterApiAuthConfig';

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
  expiresAtMs: 400_000,
} satisfies CloudflareD1EmailOtpDeliveryProviderInput;

class RecordingResendProvider implements ConsoleEmailProvider {
  readonly provider = 'resend' as const;
  readonly requests: ConsoleEmailProviderSendRequest[] = [];

  constructor(private readonly result: ConsoleEmailProviderSendResult) {}

  async send(request: ConsoleEmailProviderSendRequest): Promise<ConsoleEmailProviderSendResult> {
    this.requests.push(request);
    return this.result;
  }
}

test('Resend Email OTP configuration parses the shared sender and API key', () => {
  expect(
    parseResendEmailOtpProviderConfig({
      EMAIL_OTP_FROM_ADDRESS: ' CONFIRM@SEAMS.SH ',
      RESEND_API_KEY: ' re_test ',
    }),
  ).toEqual({
    fromAddress: 'confirm@seams.sh',
    apiKey: 're_test',
  });
});

test('provider resolver selects Resend for provider delivery', () => {
  expect(
    resolveEmailOtpDeliveryProviderFromEnv({
      EMAIL_OTP_DELIVERY_MODE: 'email_provider',
      EMAIL_OTP_PROVIDER: 'resend',
      EMAIL_OTP_FROM_ADDRESS: 'confirm@seams.sh',
      RESEND_API_KEY: 're_test',
    }),
  ).toBeDefined();
});

test('Resend adapter sends rendered OTP messages with challenge idempotency', async () => {
  const provider = new RecordingResendProvider({
    kind: 'SENT',
    providerMessageId: 'resend-message-1',
    statusCode: 200,
  });
  const delivery = createEmailOtpDeliveryAdapter(
    createResendEmailOtpMessageProvider(
      { apiKey: 're_test', fromAddress: 'confirm@seams.sh' },
      provider,
    ),
    () => 100_000,
  );

  await expect(delivery.deliver(DELIVERY_INPUT)).resolves.toEqual({
    ok: true,
    providerMessageId: 'resend-message-1',
  });
  expect(provider.requests).toHaveLength(1);
  expect(provider.requests[0]).toMatchObject({
    outboxId: 'email-otp/challenge-1',
    recipient: { email: 'alice@example.test' },
    subject: 'Your Seams wallet unlock code',
  });
  expect(provider.requests[0].text).toContain('123456');
  expect(provider.requests[0].html).toContain('123456');
});

test('Resend adapter maps provider failures without exposing provider details', async () => {
  const provider = new RecordingResendProvider({
    kind: 'RETRYABLE_FAILURE',
    errorCode: 'resend_transport_error',
    statusCode: null,
  });
  const delivery = createEmailOtpDeliveryAdapter(
    createResendEmailOtpMessageProvider(
      { apiKey: 're_test', fromAddress: 'confirm@seams.sh' },
      provider,
    ),
  );

  await expect(delivery.deliver(DELIVERY_INPUT)).resolves.toEqual({
    ok: false,
    code: 'email_otp_resend_transport_error',
    message: 'Resend Email OTP delivery failed',
  });
});
