import { expect, test } from '@playwright/test';
import {
  EmailOtpRouteError,
  enrollEmailOtpWallet,
  exchangeGoogleEmailOtpSession,
  requestEmailOtpDeviceRecoveryChallenge,
  requestEmailOtpChallenge,
  requestEmailOtpEnrollmentChallenge,
  removeEmailOtpDeviceEnrollmentEscrowFromDevice,
  restoreEmailOtpDeviceEnrollmentEscrow,
  verifyEmailOtpCode,
} from '@/core/SeamsPasskey/emailOtp';

test.describe('SeamsPasskey Email OTP runtime', () => {
  test('Email OTP pre-unseal routes dispatch through the dedicated Email OTP worker when no fetch override is provided', async () => {
    const workerCalls: Array<{ kind: string; type: string; payload: Record<string, unknown> }> = [];
    const workerCtx = {
      requestWorkerOperation: async ({ kind, request }: any) => {
        workerCalls.push({ kind, type: request.type, payload: request.payload });
        if (request.type === 'requestEmailOtpChallenge') {
          return { challengeId: 'challenge-1', otpChannel: 'email_otp' };
        }
        if (request.type === 'requestEmailOtpEnrollmentChallenge') {
          return { challengeId: 'enroll-challenge-1', otpChannel: 'email_otp' };
        }
        if (request.type === 'verifyEmailOtpCode') {
          return {
            loginGrant: 'grant-1',
            otpChannel: 'email_otp',
            enrollmentSealKeyVersion: 'seal-v1',
          };
        }
        throw new Error(`Unexpected worker operation: ${request.type}`);
      },
    };

    await expect(
      requestEmailOtpChallenge({
        relayUrl: 'https://relay.example',
        walletId: 'alice.testnet',
        appSessionJwt: 'app-session-jwt',
        workerCtx,
      }),
    ).resolves.toEqual({
      challengeId: 'challenge-1',
      otpChannel: 'email_otp',
    });

    await expect(
      requestEmailOtpEnrollmentChallenge({
        relayUrl: 'https://relay.example',
        walletId: 'alice.testnet',
        appSessionJwt: 'app-session-jwt',
        workerCtx,
      }),
    ).resolves.toEqual({
      challengeId: 'enroll-challenge-1',
      otpChannel: 'email_otp',
    });

    await expect(
      verifyEmailOtpCode({
        relayUrl: 'https://relay.example',
        walletId: 'alice.testnet',
        challengeId: 'challenge-1',
        otpCode: '123456',
        appSessionJwt: 'app-session-jwt',
        workerCtx,
      }),
    ).resolves.toEqual({
      loginGrant: 'grant-1',
      otpChannel: 'email_otp',
      enrollmentSealKeyVersion: 'seal-v1',
    });

    expect(workerCalls).toEqual([
      {
        kind: 'emailOtp',
        type: 'requestEmailOtpChallenge',
        payload: {
          relayUrl: 'https://relay.example',
          walletId: 'alice.testnet',
          routePlan: {
            routeFamily: 'login',
            authLane: { kind: 'app_session', jwt: 'app-session-jwt' },
            operation: 'wallet_unlock',
          },
          otpChannel: 'email_otp',
        },
      },
      {
        kind: 'emailOtp',
        type: 'requestEmailOtpEnrollmentChallenge',
        payload: {
          relayUrl: 'https://relay.example',
          walletId: 'alice.testnet',
          routePlan: {
            routeFamily: 'registration',
            authLane: { kind: 'app_session', jwt: 'app-session-jwt' },
            operation: 'wallet_unlock',
          },
          otpChannel: 'email_otp',
        },
      },
      {
        kind: 'emailOtp',
        type: 'verifyEmailOtpCode',
        payload: {
          relayUrl: 'https://relay.example',
          walletId: 'alice.testnet',
          challengeId: 'challenge-1',
          otpCode: '123456',
          routePlan: {
            routeFamily: 'login',
            authLane: { kind: 'app_session', jwt: 'app-session-jwt' },
            operation: 'wallet_unlock',
          },
          otpChannel: 'email_otp',
        },
      },
    ]);
  });

  test('non-secret Email OTP route helpers still support explicit fetch overrides', async () => {
    const fetchCalls: Array<{ url: string; body: Record<string, unknown> }> = [];
    const fetchImpl: typeof fetch = async (input, init) => {
      const url = String(input);
      const body = JSON.parse(String(init?.body || '{}'));
      fetchCalls.push({ url, body });
      if (url.endsWith('/wallet/email-otp/login/challenge')) {
        return new Response(
          JSON.stringify({ ok: true, challenge: { challengeId: 'challenge-1' } }),
          {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          },
        );
      }
      if (url.endsWith('/wallet/email-otp/registration/challenge')) {
        return new Response(JSON.stringify({ ok: true, challenge: { challengeId: 'enroll-1' } }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      if (url.endsWith('/wallet/email-otp/recovery-challenge')) {
        return new Response(
          JSON.stringify({ ok: true, challenge: { challengeId: 'recovery-1' } }),
          {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          },
        );
      }
      if (url.endsWith('/wallet/email-otp/login/verify')) {
        return new Response(
          JSON.stringify({
            ok: true,
            loginGrant: 'grant-1',
            enrollmentSealKeyVersion: 'seal-v1',
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      if (url.endsWith('/session/exchange')) {
        return new Response(
          JSON.stringify({
            ok: true,
            session: {
              userId: 'google:subject-1',
              walletId: 'alice.testnet',
              email: 'alice@example.com',
              runtimePolicyScope: {
                orgId: 'org_test',
                projectId: 'project_test',
                envId: 'env_test',
                signingRootVersion: 'root-v1',
              },
            },
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      throw new Error(`Unexpected fetch URL: ${url}`);
    };

    await expect(
      requestEmailOtpChallenge({
        relayUrl: 'https://relay.example',
        walletId: 'alice.testnet',
        fetchImpl,
      }),
    ).resolves.toEqual({ challengeId: 'challenge-1', otpChannel: 'email_otp' });
    await expect(
      requestEmailOtpEnrollmentChallenge({
        relayUrl: 'https://relay.example',
        walletId: 'alice.testnet',
        fetchImpl,
      }),
    ).resolves.toEqual({ challengeId: 'enroll-1', otpChannel: 'email_otp' });
    await expect(
      requestEmailOtpDeviceRecoveryChallenge({
        relayUrl: 'https://relay.example',
        walletId: 'alice.testnet',
        fetchImpl,
      }),
    ).resolves.toEqual({ challengeId: 'recovery-1', otpChannel: 'email_otp' });
    await expect(
      verifyEmailOtpCode({
        relayUrl: 'https://relay.example',
        walletId: 'alice.testnet',
        challengeId: 'challenge-1',
        otpCode: '123456',
        fetchImpl,
      }),
    ).resolves.toEqual({
      loginGrant: 'grant-1',
      otpChannel: 'email_otp',
      enrollmentSealKeyVersion: 'seal-v1',
    });
    await expect(
      exchangeGoogleEmailOtpSession({
        relayUrl: 'https://relay.example',
        idToken: 'google-id-token-1',
        accountMode: 'register',
        sessionKind: 'cookie',
        runtimeEnvironmentId: 'env_test',
        fetchImpl,
      }),
    ).resolves.toEqual({
      session: {
        userId: 'google:subject-1',
        walletId: 'alice.testnet',
        email: 'alice@example.com',
        runtimePolicyScope: {
          orgId: 'org_test',
          projectId: 'project_test',
          envId: 'env_test',
          signingRootVersion: 'root-v1',
        },
      },
    });

    expect(fetchCalls.map((call) => call.url)).toEqual([
      'https://relay.example/wallet/email-otp/login/challenge',
      'https://relay.example/wallet/email-otp/registration/challenge',
      'https://relay.example/wallet/email-otp/recovery-challenge',
      'https://relay.example/wallet/email-otp/login/verify',
      'https://relay.example/session/exchange',
    ]);
    expect(fetchCalls[4]?.body).toEqual({
      session_kind: 'cookie',
      runtimeEnvironmentId: 'env_test',
      exchange: {
        type: 'oidc_jwt',
        provider: 'google',
        account_mode: 'register',
        token: 'google-id-token-1',
      },
    });
  });

  test('Email OTP route helpers preserve rate-limit metadata', async () => {
    const fetchImpl: typeof fetch = async () =>
      new Response(
        JSON.stringify({
          ok: false,
          code: 'rate_limited',
          message: 'Email OTP rate limit exceeded',
          retryAfterMs: 123_000,
          resetAtMs: 1_712_345_678_901,
        }),
        { status: 429, headers: { 'Content-Type': 'application/json' } },
      );

    let caught: unknown;
    try {
      await requestEmailOtpEnrollmentChallenge({
        relayUrl: 'https://relay.example',
        walletId: 'alice.testnet',
        fetchImpl,
      });
    } catch (error: unknown) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(EmailOtpRouteError);
    expect((caught as EmailOtpRouteError).message).toBe('Email OTP rate limit exceeded');
    expect((caught as EmailOtpRouteError).status).toBe(429);
    expect((caught as EmailOtpRouteError).code).toBe('rate_limited');
    expect((caught as EmailOtpRouteError).retryAfterMs).toBe(123_000);
    expect((caught as EmailOtpRouteError).resetAtMs).toBe(1_712_345_678_901);
  });

  test('Email OTP enrollment dispatches secret-bearing enrollment through the dedicated worker', async () => {
    const clientSecret32 = Uint8Array.from(Array.from({ length: 32 }, (_, index) => 255 - index));
    const workerCalls: Array<{ kind: string; type: string; payload: Record<string, unknown> }> = [];
    const result = await enrollEmailOtpWallet({
      relayUrl: 'https://relay.example',
      walletId: 'alice.testnet',
      userId: 'alice.testnet',
      challengeId: 'enroll-1',
      otpCode: '123456',
      shamirPrimeB64u: 'prime-b64u',
      appSessionJwt: 'app-session-jwt',
      clientSecret32,
      workerCtx: {
        requestWorkerOperation: async ({ kind, request }: any) => {
          workerCalls.push({ kind, type: request.type, payload: request.payload });
          expect(request.type).toBe('enrollEmailOtpWallet');
          expect(request.payload.clientSecret32).toBeInstanceOf(ArrayBuffer);
          expect(Array.from(new Uint8Array(request.payload.clientSecret32))).toEqual(
            Array.from(clientSecret32),
          );
          return {
            thresholdEcdsaClientVerifyingShareB64u: 'threshold-verifier-b64u',
            recoveryKeys: [],
            challengeId: 'enroll-1',
            otpChannel: 'email_otp',
            enrollmentSealKeyVersion: 'email-otp-kv-1',
            clientUnlockPublicKeyB64u: 'unlock-public-key-b64u',
            unlockKeyVersion: 'email-otp-unlock-v1',
          };
        },
      },
    });

    expect(result.challengeId).toBe('enroll-1');
    expect(result.thresholdEcdsaClientVerifyingShareB64u).toBe('threshold-verifier-b64u');
    expect(workerCalls).toHaveLength(1);
    expect(workerCalls[0]).toMatchObject({
      kind: 'emailOtp',
      type: 'enrollEmailOtpWallet',
      payload: {
        relayUrl: 'https://relay.example',
        walletId: 'alice.testnet',
        userId: 'alice.testnet',
        challengeId: 'enroll-1',
        otpCode: '123456',
        shamirPrimeB64u: 'prime-b64u',
        routePlan: {
          routeFamily: 'registration',
          authLane: { kind: 'app_session', jwt: 'app-session-jwt' },
          operation: 'wallet_unlock',
        },
        otpChannel: 'email_otp',
      },
    });
  });

  test('Email OTP recovery restore dispatches recovery key handling through the dedicated worker', async () => {
    const workerCalls: Array<{ kind: string; type: string; payload: Record<string, unknown> }> = [];
    const result = await restoreEmailOtpDeviceEnrollmentEscrow({
      relayUrl: 'https://relay.example',
      walletId: 'alice.testnet',
      userId: 'google:alice',
      challengeId: 'recovery-1',
      otpCode: '123456',
      recoveryKey: 'J7KD-9VQF-2MHT-R6ZX-NP4C-8Y12-ABCD-EFGH',
      shamirPrimeB64u: 'prime-b64u',
      appSessionJwt: 'app-session-jwt',
      workerCtx: {
        requestWorkerOperation: async ({ kind, request }: any) => {
          workerCalls.push({ kind, type: request.type, payload: request.payload });
          expect(request.type).toBe('restoreEmailOtpDeviceEnrollmentEscrow');
          return {
            walletId: 'alice.testnet',
            userId: 'google:alice',
            authSubjectId: 'google:alice',
            enrollmentId: 'email-otp-device-enrollment-v1:alice.testnet:google:alice',
            enrollmentVersion: '1',
            enrollmentSealKeyVersion: 'seal-v1',
            signingRootId: 'email_otp_default_signing_root',
            signingRootVersion: 'default',
            recoveryKeyId: 'recovery-key-1',
            activeRecoveryWrappedEnrollmentEscrowCount: 9,
          };
        },
      },
    });

    expect(result.recoveryKeyId).toBe('recovery-key-1');
    expect(result.activeRecoveryWrappedEnrollmentEscrowCount).toBe(9);
    expect(workerCalls).toHaveLength(1);
    expect(workerCalls[0]).toMatchObject({
      kind: 'emailOtp',
      type: 'restoreEmailOtpDeviceEnrollmentEscrow',
      payload: {
        relayUrl: 'https://relay.example',
        walletId: 'alice.testnet',
        userId: 'google:alice',
        challengeId: 'recovery-1',
        otpCode: '123456',
        recoveryKey: 'J7KD-9VQF-2MHT-R6ZX-NP4C-8Y12-ABCD-EFGH',
        shamirPrimeB64u: 'prime-b64u',
        routePlan: {
          routeFamily: 'login',
          authLane: { kind: 'app_session', jwt: 'app-session-jwt' },
          operation: 'wallet_unlock',
        },
        otpChannel: 'email_otp',
      },
    });
  });

  test('Email OTP device escrow removal dispatches only the explicit remove-device worker action', async () => {
    const workerCalls: Array<{ kind: string; type: string; payload: Record<string, unknown> }> = [];
    const result = await removeEmailOtpDeviceEnrollmentEscrowFromDevice({
      walletId: 'alice.testnet',
      userId: 'google:alice',
      workerCtx: {
        requestWorkerOperation: async ({ kind, request }: any) => {
          workerCalls.push({ kind, type: request.type, payload: request.payload });
          expect(request.type).toBe('removeEmailOtpDeviceEnrollmentEscrowFromDevice');
          return {
            walletId: 'alice.testnet',
            authSubjectId: 'google:alice',
            enrollmentId: 'email-otp-device-enrollment-v1:alice.testnet:google:alice',
            removed: true,
          };
        },
      },
    });

    expect(result).toMatchObject({
      walletId: 'alice.testnet',
      authSubjectId: 'google:alice',
      enrollmentId: 'email-otp-device-enrollment-v1:alice.testnet:google:alice',
      removed: true,
    });
    expect(workerCalls).toEqual([
      {
        kind: 'emailOtp',
        type: 'removeEmailOtpDeviceEnrollmentEscrowFromDevice',
        payload: {
          walletId: 'alice.testnet',
          userId: 'google:alice',
        },
      },
    ]);
  });
});
