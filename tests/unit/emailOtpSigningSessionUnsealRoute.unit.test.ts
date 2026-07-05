import { expect, test } from '@playwright/test';
import { EMAIL_OTP_CHANNEL } from '@shared/utils/emailOtpDomain';
import {
  handleEmailOtpSigningSessionChallengeRoute,
  handleEmailOtpSigningSessionUnsealRoute,
} from '@server/router/emailOtpRouteHandlers';

type CapturedSigningSessionUnsealCalls = {
  readActiveEnrollmentInput: Record<string, unknown> | null;
  createChallengeInput: Record<string, unknown> | null;
  consumeGrantInput: Record<string, unknown> | null;
  readEnrollmentInput: Record<string, unknown> | null;
};

class SigningSessionUnsealRouteService {
  constructor(private readonly captured: CapturedSigningSessionUnsealCalls) {}

  async readActiveEmailOtpEnrollment(input: Record<string, unknown>) {
    this.captured.readActiveEnrollmentInput = input;
    return {
      ok: true,
      enrollment: {
        walletId: 'wallet-a',
        orgId: 'org-a',
        providerUserId: 'google:provider-user',
        verifiedEmail: 'user@example.com',
      },
    };
  }

  async consumeEmailOtpGrant(input: Record<string, unknown>) {
    this.captured.consumeGrantInput = input;
    return {
      ok: true,
      challengeId: 'challenge-1',
      otpChannel: EMAIL_OTP_CHANNEL,
    };
  }

  async createEmailOtpChallenge(input: Record<string, unknown>) {
    this.captured.createChallengeInput = input;
    return {
      ok: true,
      challenge: {
        challengeId: 'challenge-1',
        issuedAtMs: 1,
        expiresAtMs: 2,
        userId: input.userId,
        walletId: input.walletId,
        orgId: input.orgId,
        sessionHash: input.sessionHash,
        appSessionVersion: input.appSessionVersion,
        otpChannel: EMAIL_OTP_CHANNEL,
        action: 'login',
        operation: input.operation,
      },
      delivery: { ok: true },
    };
  }

  async removeEmailOtpServerSeal() {
    return {
      ok: true,
      ciphertext: 'server-unsealed-client-secret',
      enrollmentSealKeyVersion: 'seal-v1',
    };
  }

  async readEmailOtpEnrollment(input: Record<string, unknown>) {
    this.captured.readEnrollmentInput = input;
    return {
      ok: true,
      enrollment: {
        walletId: 'wallet-a',
        orgId: 'org-a',
      },
    };
  }
}

async function ignoreEmailOtpWebhook(): Promise<void> {}

test('Email OTP signing-session unseal consumes grants with the enrollment authority', async () => {
  const captured: CapturedSigningSessionUnsealCalls = {
    readActiveEnrollmentInput: null,
    createChallengeInput: null,
    consumeGrantInput: null,
    readEnrollmentInput: null,
  };
  const service = new SigningSessionUnsealRouteService(captured);

  const response = await handleEmailOtpSigningSessionUnsealRoute({
    body: {
      walletId: 'wallet-a',
      loginGrant: 'login-grant-1',
      wrappedCiphertext: 'client-wrapped-secret',
    },
    claims: { orgId: 'org-a' },
    userId: 'wallet-a',
    appSessionVersion: 'wallet-session-v1',
    sessionHash: 'wallet-session-hash',
    service: service as any,
    emitWebhook: ignoreEmailOtpWebhook,
  });

  expect(response.status).toBe(200);
  expect(captured.readActiveEnrollmentInput).toMatchObject({
    walletId: 'wallet-a',
    orgId: 'org-a',
  });
  expect(captured.consumeGrantInput).toMatchObject({
    loginGrant: 'login-grant-1',
    userId: 'google:provider-user',
    walletId: 'wallet-a',
    orgId: 'org-a',
    otpChannel: EMAIL_OTP_CHANNEL,
  });
  expect(captured.consumeGrantInput).not.toMatchObject({
    userId: 'wallet-a',
  });
  expect(captured.readEnrollmentInput).toEqual({
    walletId: 'wallet-a',
    orgId: 'org-a',
  });
});

test('Email OTP signing-session challenge resolves wallet identity from wallet-session claims', async () => {
  const captured: CapturedSigningSessionUnsealCalls = {
    readActiveEnrollmentInput: null,
    createChallengeInput: null,
    consumeGrantInput: null,
    readEnrollmentInput: null,
  };
  const service = new SigningSessionUnsealRouteService(captured);

  const response = await handleEmailOtpSigningSessionChallengeRoute({
    body: {
      walletId: 'wallet-a',
      otpChannel: EMAIL_OTP_CHANNEL,
      operation: 'wallet_unlock',
    },
    claims: { walletId: 'wallet-a', orgId: 'org-a' },
    userId: 'near-account-subject',
    appSessionVersion: 'wallet-session-v1',
    sessionHash: 'wallet-session-hash',
    clientIp: '203.0.113.42',
    service: service as any,
    opts: {} as any,
    emitWebhook: ignoreEmailOtpWebhook,
  });

  expect(response.status).toBe(200);
  expect(captured.readActiveEnrollmentInput).toMatchObject({
    walletId: 'wallet-a',
    orgId: 'org-a',
  });
  expect(captured.createChallengeInput).toMatchObject({
    userId: 'google:provider-user',
    walletId: 'wallet-a',
    orgId: 'org-a',
    sessionHash: 'wallet-session-hash',
    appSessionVersion: 'wallet-session-v1',
    clientIp: '203.0.113.42',
    operation: 'wallet_unlock',
  });
});
