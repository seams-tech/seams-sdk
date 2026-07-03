import { expect, test } from '@playwright/test';
import {
  EMAIL_OTP_CHANNEL,
  WALLET_EMAIL_OTP_ACTIONS,
} from '@shared/utils/emailOtpDomain';
import { createEmailOtpGrantStore } from '@server/core/EmailOtpStores';
import { consumeEmailOtpGrantWithStore } from '@server/core/authService/emailOtpGrant';

function makeGrantRecord(input: { grantToken: string; userId?: string }) {
  return {
    version: 'email_otp_grant_v1' as const,
    grantToken: input.grantToken,
    userId: input.userId || 'google:provider-user',
    walletId: 'wallet-a',
    orgId: 'org-a',
    challengeId: `challenge-${input.grantToken}`,
    otpChannel: EMAIL_OTP_CHANNEL,
    sessionHash: 'issued-session-hash',
    appSessionVersion: 'issued-session-version',
    action: WALLET_EMAIL_OTP_ACTIONS.unseal,
    issuedAtMs: 100,
    expiresAtMs: 10_000,
  };
}

test('Email OTP login grants survive app-session rotation when stable authority matches', async () => {
  const grantStore = createEmailOtpGrantStore();
  await grantStore.put(makeGrantRecord({ grantToken: 'login-grant-1' }));
  const rotatedSessionRequest = {
    loginGrant: 'login-grant-1',
    userId: 'google:provider-user',
    walletId: 'wallet-a',
    orgId: 'org-a',
    otpChannel: EMAIL_OTP_CHANNEL,
    sessionHash: 'rotated-session-hash',
    appSessionVersion: 'rotated-session-version',
  };

  const result = await consumeEmailOtpGrantWithStore({
    request: rotatedSessionRequest,
    grantStore,
    consumeRateLimit: async () => ({ ok: true }),
    nowMs: 1_000,
  });

  expect(result).toEqual({
    ok: true,
    challengeId: 'challenge-login-grant-1',
    otpChannel: EMAIL_OTP_CHANNEL,
  });
});

test('Email OTP login grants still reject mismatched stable authority', async () => {
  const grantStore = createEmailOtpGrantStore();
  await grantStore.put(makeGrantRecord({ grantToken: 'login-grant-2' }));

  const result = await consumeEmailOtpGrantWithStore({
    request: {
      loginGrant: 'login-grant-2',
      userId: 'google:other-provider-user',
      walletId: 'wallet-a',
      orgId: 'org-a',
      otpChannel: EMAIL_OTP_CHANNEL,
    },
    grantStore,
    consumeRateLimit: async () => ({ ok: true }),
    nowMs: 1_000,
  });

  expect(result).toEqual({
    ok: false,
    code: 'recovery_grant_binding_mismatch',
    message: 'Recovery grant is not valid for the current Email OTP authority',
  });
});
