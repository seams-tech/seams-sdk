import { expect, test } from '@playwright/test';
import { handleEmailOtpRegistrationChallengeRoute, handleEmailOtpRegistrationFinalizeRoute } from '@server/router/emailOtpRouteHandlers';

test.describe('Email OTP registration routes', () => {
  test('registration challenge binds Google sessions to provider subject', async () => {
    let request: Record<string, unknown> | null = null;
    const response = await handleEmailOtpRegistrationChallengeRoute({
      body: {
        walletId: 'cobalt-meadow-35whhdqoua.w3a-relayer.testnet',
        otpChannel: 'email_otp',
      },
      claims: {
        kind: 'app_session_v1',
        sub: 'cobalt-meadow-35whhdqoua.w3a-relayer.testnet',
        walletId: 'cobalt-meadow-35whhdqoua.w3a-relayer.testnet',
        provider: 'oidc',
        oidcProvider: 'google',
        providerSubject: 'google:117142622123955425762',
        email: 'Name6@Gmail.com',
        appSessionVersion: 'google-app-session-v1',
      },
      userId: 'cobalt-meadow-35whhdqoua.w3a-relayer.testnet',
      appSessionVersion: 'google-app-session-v1',
      service: {
        createEmailOtpEnrollmentChallenge: async (value: Record<string, unknown>) => {
          request = value;
          return {
            ok: true,
            challenge: {
              challengeId: 'challenge-1',
              issuedAtMs: 1,
              expiresAtMs: 2,
              userId: value.userId,
              walletId: value.walletId,
              orgId: value.orgId,
              sessionHash: value.sessionHash,
              appSessionVersion: value.appSessionVersion,
              otpChannel: 'email_otp',
              action: 'wallet_email_otp_registration',
              operation: 'registration',
            },
            delivery: { mode: 'memory', emailHint: 'n***6@g***l.com' },
          };
        },
      } as any,
    });

    expect(response.status).toBe(200);
    expect(request).toMatchObject({
      userId: 'google:117142622123955425762',
      walletId: 'cobalt-meadow-35whhdqoua.w3a-relayer.testnet',
      email: 'name6@gmail.com',
      otpChannel: 'email_otp',
      appSessionVersion: 'google-app-session-v1',
    });
  });

  test('registration finalize enables reroll verification for Google registration attempts', async () => {
    let request: Record<string, unknown> | null = null;
    const response = await handleEmailOtpRegistrationFinalizeRoute({
      body: {
        walletId: 'cobalt-meadow-35whhdqoua.w3a-relayer.testnet',
        challengeId: 'challenge-1',
        otpCode: '852681',
        otpChannel: 'email_otp',
        googleEmailOtpRegistrationAttemptId: 'attempt-reroll-1',
      },
      claims: {
        kind: 'app_session_v1',
        sub: 'cobalt-meadow-35whhdqoua.w3a-relayer.testnet',
        walletId: 'cobalt-meadow-35whhdqoua.w3a-relayer.testnet',
        provider: 'oidc',
        oidcProvider: 'google',
        providerSubject: 'google:117142622123955425762',
        appSessionVersion: 'google-app-session-v2',
      },
      userId: 'cobalt-meadow-35whhdqoua.w3a-relayer.testnet',
      appSessionVersion: 'google-app-session-v2',
      service: {
        verifyEmailOtpEnrollment: async (value: Record<string, unknown>) => {
          request = value;
          return {
            ok: true,
            walletId: value.walletId,
            otpChannel: 'email_otp',
            enrollment: {
              createdAtMs: 1,
              updatedAtMs: 2,
              enrollmentSealKeyVersion: 'seal-v1',
              unlockKeyVersion: 'unlock-v1',
            },
          };
        },
      } as any,
      emitWebhook: async () => {},
    });

    expect(response.status).toBe(200);
    expect(request).toMatchObject({
      providerSubject: 'google:117142622123955425762',
      walletId: 'cobalt-meadow-35whhdqoua.w3a-relayer.testnet',
      challengeId: 'challenge-1',
      otpCode: '852681',
      otpChannel: 'email_otp',
      appSessionVersion: 'google-app-session-v2',
      googleEmailOtpRegistrationAttemptId: 'attempt-reroll-1',
    });
  });
});
