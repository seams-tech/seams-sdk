import { test, expect } from '@playwright/test';
import {
  emailOtpChallengeResponseBody,
  emailOtpEnrollmentFinalizeResponseBody,
  emailOtpEnrolledWebhookEventDescriptor,
  emailOtpFailureAuditPayload,
  emailOtpFailureWebhookEventDescriptors,
  emailOtpLoginVerifyResponseBody,
  emailOtpLoggedInWebhookEventDescriptor,
  emailOtpNewDeviceWebhookEventDescriptor,
  emailOtpServerSealResponseBody,
  shouldEmitEmailOtpLockedWebhook,
  validateEmailOtpChannel,
  validateEmailOtpJsonObjectBody,
  validateEmailOtpRequiredString,
  validateEmailOtpWalletId,
} from '@server/router/emailOtpSessionRouteHelpers';
import {
  emailOtpExportDeniedDecisionFromResult,
  emailOtpExportPolicyWebhookEventDescriptor,
} from '@server/router/emailOtpExportPolicy';

test.describe('Email OTP route helpers', () => {
  test('validates shared request body fields without transport-specific code', () => {
    expect(validateEmailOtpJsonObjectBody(null)).toEqual({
      ok: false,
      status: 400,
      body: { ok: false, code: 'invalid_body', message: 'Expected JSON object body' },
    });
    expect(validateEmailOtpJsonObjectBody({ walletId: 'wallet.testnet' })).toEqual({
      ok: true,
      body: { walletId: 'wallet.testnet' },
    });

    expect(
      validateEmailOtpWalletId({
        body: {},
        claims: { walletId: 'wallet.testnet' },
        userId: 'user.testnet',
      }),
    ).toEqual({
      ok: false,
      status: 400,
      body: { ok: false, code: 'invalid_body', message: 'walletId is required' },
    });
    expect(
      validateEmailOtpWalletId({
        body: { walletId: 'other.testnet' },
        claims: { walletId: 'wallet.testnet' },
        userId: 'user.testnet',
      }),
    ).toEqual({
      ok: false,
      status: 403,
      body: {
        ok: false,
        code: 'wallet_identity_mismatch',
        message: 'walletId must match the current app session wallet',
      },
    });
    expect(
      validateEmailOtpWalletId({
        body: { walletId: 'wallet.testnet' },
        claims: { walletId: 'wallet.testnet' },
        userId: 'user.testnet',
      }),
    ).toEqual({ ok: true, walletId: 'wallet.testnet' });

    expect(validateEmailOtpChannel({ otpChannel: 'email_otp' })).toEqual({
      ok: true,
      otpChannel: 'email_otp',
    });
    expect(validateEmailOtpChannel({ otpChannel: 'sms' })).toEqual({
      ok: false,
      status: 400,
      body: { ok: false, code: 'invalid_body', message: 'otpChannel must be email_otp' },
    });

    expect(validateEmailOtpRequiredString({ challengeId: ' ch_1 ' }, 'challengeId')).toEqual({
      ok: true,
      value: 'ch_1',
    });
    expect(validateEmailOtpRequiredString({}, 'challengeId')).toEqual({
      ok: false,
      status: 400,
      body: { ok: false, code: 'invalid_body', message: 'challengeId is required' },
    });
  });

  test('shapes shared Email OTP response bodies', () => {
    expect(
      emailOtpChallengeResponseBody({
        ok: true,
        challenge: {
          challengeId: 'ch_1',
          issuedAtMs: 1_700_000_000_000,
          expiresAtMs: 1_700_000_060_000,
          userId: 'user.testnet',
          walletId: 'wallet.testnet',
          sessionHash: 'hash',
          appSessionVersion: 'v1',
          otpChannel: 'email_otp',
          action: 'login',
          operation: 'wallet_unlock',
        },
        delivery: { channel: 'dev_outbox' },
      }),
    ).toEqual({
      ok: true,
      challenge: {
        challengeId: 'ch_1',
        issuedAt: '2023-11-14T22:13:20.000Z',
        issuedAtMs: 1_700_000_000_000,
        expiresAt: '2023-11-14T22:14:20.000Z',
        expiresAtMs: 1_700_000_060_000,
        userId: 'user.testnet',
        walletId: 'wallet.testnet',
        sessionHash: 'hash',
        appSessionVersion: 'v1',
        otpChannel: 'email_otp',
        action: 'login',
        operation: 'wallet_unlock',
      },
      delivery: { channel: 'dev_outbox' },
      retryAfterMs: 10_000,
    });

    expect(
      emailOtpServerSealResponseBody(
        { ok: true, ciphertext: 'ciphertext', emailOtpKeyVersion: 'k1' },
        'wallet.testnet',
      ),
    ).toEqual({
      ok: true,
      walletId: 'wallet.testnet',
      ciphertext: 'ciphertext',
      emailOtpKeyVersion: 'k1',
    });

    expect(
      emailOtpEnrollmentFinalizeResponseBody({
        ok: true,
        walletId: 'wallet.testnet',
        otpChannel: 'email_otp',
        enrollment: {
          createdAtMs: 1_700_000_000_000,
          updatedAtMs: 1_700_000_060_000,
          emailOtpKeyVersion: 'k1',
          unlockKeyVersion: 'u1',
        },
      }),
    ).toEqual({
      ok: true,
      walletId: 'wallet.testnet',
      otpChannel: 'email_otp',
      enrollment: {
        createdAt: '2023-11-14T22:13:20.000Z',
        updatedAt: '2023-11-14T22:14:20.000Z',
        emailOtpKeyVersion: 'k1',
        unlockKeyVersion: 'u1',
      },
    });

    expect(
      emailOtpLoginVerifyResponseBody({
        result: {
          ok: true,
          challengeId: 'ch_1',
          loginGrant: 'grant',
          grantExpiresAtMs: 1_700_000_060_000,
          otpChannel: 'email_otp',
        },
        enrollment: { enrollment: { emailOtpEscrowBlob: { v: 1 } } },
      }),
    ).toEqual({
      ok: true,
      challengeId: 'ch_1',
      loginGrant: 'grant',
      grantExpiresAt: '2023-11-14T22:14:20.000Z',
      otpChannel: 'email_otp',
      emailOtpEscrowBlob: { v: 1 },
    });
  });

  test('builds shared failure and lockout audit decisions', () => {
    expect(
      emailOtpFailureAuditPayload({
        source: 'login_verify',
        code: 'otp_locked_out',
        message: 'locked',
        challengeId: 'ch_1',
        otpChannel: 'email_otp',
        operation: 'wallet_unlock',
        lockedUntilMs: 123,
      }),
    ).toEqual({
      source: 'login_verify',
      code: 'otp_locked_out',
      message: 'locked',
      challengeId: 'ch_1',
      otpChannel: 'email_otp',
      operation: 'wallet_unlock',
      lockedUntilMs: 123,
    });
    expect(shouldEmitEmailOtpLockedWebhook('otp_locked_out')).toBe(true);
    expect(shouldEmitEmailOtpLockedWebhook('otp_attempts_exhausted')).toBe(true);
    expect(shouldEmitEmailOtpLockedWebhook('invalid_otp')).toBe(false);
    expect(
      emailOtpFailureWebhookEventDescriptors({
        source: 'login_verify',
        code: 'otp_locked_out',
        message: 'locked',
        challengeId: 'ch_1',
      }),
    ).toEqual([
      {
        eventType: 'wallet.email_otp.failed',
        eventId: 'ch_1',
        payload: {
          source: 'login_verify',
          code: 'otp_locked_out',
          message: 'locked',
          challengeId: 'ch_1',
        },
      },
      {
        eventType: 'wallet.email_otp.locked',
        eventId: 'ch_1',
        payload: {
          source: 'login_verify',
          code: 'otp_locked_out',
          message: 'locked',
          challengeId: 'ch_1',
        },
      },
    ]);
  });

  test('builds shared lifecycle audit webhook descriptors', () => {
    expect(
      emailOtpLoggedInWebhookEventDescriptor({
        challengeId: 'ch_1',
        otpChannel: 'email_otp',
        unlockBackend: 'email_otp',
      }),
    ).toEqual({
      eventType: 'wallet.email_otp.logged_in',
      eventId: 'ch_1',
      payload: {
        otpChannel: 'email_otp',
        unlockBackend: 'email_otp',
        challengeId: 'ch_1',
      },
    });
    expect(
      emailOtpEnrolledWebhookEventDescriptor({
        challengeId: 'ch_1',
        otpChannel: 'email_otp',
        emailOtpKeyVersion: 'k1',
        unlockKeyVersion: 'u1',
      }),
    ).toEqual({
      eventType: 'wallet.email_otp.enrolled',
      eventId: 'ch_1',
      payload: {
        otpChannel: 'email_otp',
        emailOtpKeyVersion: 'k1',
        unlockKeyVersion: 'u1',
      },
    });
    expect(
      emailOtpNewDeviceWebhookEventDescriptor({
        challengeId: 'ch_1',
        otpChannel: 'email_otp',
        enrolledDeviceId: 'device_a',
        currentDeviceId: 'device_b',
      }),
    ).toEqual({
      eventType: 'wallet.email_otp.new_device',
      eventId: 'ch_1',
      payload: {
        otpChannel: 'email_otp',
        challengeId: 'ch_1',
        enrolledDeviceId: 'device_a',
        currentDeviceId: 'device_b',
      },
    });
  });

  test('builds shared export audit webhook descriptors', () => {
    const decision = {
      ok: true as const,
      decision: 'ALLOW' as const,
      policyId: 'policy_1',
      reason: 'allowed',
      policySource: 'adapter' as const,
    };
    expect(
      emailOtpExportPolicyWebhookEventDescriptor({
        eventType: 'wallet.email_otp.export_challenge_issued',
        source: 'login_challenge',
        decision,
        challengeId: 'ch_1',
        otpChannel: 'email_otp',
      }),
    ).toEqual({
      eventType: 'wallet.email_otp.export_challenge_issued',
      eventId: 'ch_1',
      payload: {
        source: 'login_challenge',
        operation: 'export_key',
        policyDecision: 'ALLOW',
        policySource: 'adapter',
        policyId: 'policy_1',
        reason: 'allowed',
        challengeId: 'ch_1',
        otpChannel: 'email_otp',
      },
    });

    expect(
      emailOtpExportDeniedDecisionFromResult({
        code: 'otp_locked_out',
        message: 'locked',
        policySource: 'adapter',
        policyId: 'policy_1',
      }),
    ).toEqual({
      ok: false,
      decision: 'DENY',
      code: 'otp_locked_out',
      message: 'locked',
      policySource: 'adapter',
      policyId: 'policy_1',
    });
  });
});
