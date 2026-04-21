import { test, expect } from '@playwright/test';

test.describe('signer worker runtime boundary', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/', { waitUntil: 'domcontentloaded' });
  });

  test('accepts requests without version fields and preserves typed signer errors', async ({
    page,
  }) => {
    const result = await page.evaluate(async () => {
      const { requestWorkerOperation } =
        await import('/sdk/esm/core/signingEngine/workerManager/workerTransport.js');

      try {
        await requestWorkerOperation({
          kind: 'tempoSigner',
          request: {
            type: 'computeTempoSenderHash',
            payload: { tx: {} },
          },
        } as any);
        return { ok: true as const };
      } catch (error: any) {
        return {
          ok: false as const,
          name: error?.name || '',
          code: error?.code || '',
          coreCode: error?.coreCode || '',
          message: error?.message || String(error),
        };
      }
    });

    expect(result.ok).toBe(false);
    expect((result as any).name).toBe('SignerWorkerOperationError');
    expect((result as any).code).toBe('SIGNER_INVALID_INPUT');
    expect((result as any).coreCode).toBe('InvalidInput');
  });

  test('Email OTP worker keeps app-session auth on login routes and threshold-session auth on signing-session routes', async ({
    page,
  }) => {
    const routes: Array<{ path: string; authorization: string; body: unknown }> = [];
    await page.route('**/wallet/email-otp/**', async (route) => {
      const request = route.request();
      const path = new URL(request.url()).pathname;
      routes.push({
        path,
        authorization: request.headers().authorization || '',
        body: request.postDataJSON(),
      });
      const response =
        path.endsWith('/challenge')
          ? { ok: true, challenge: { challengeId: `challenge-${routes.length}` } }
          : {
              ok: true,
              loginGrant: `grant-${routes.length}`,
              enrollmentEscrowCiphertextB64u: `escrow-${routes.length}`,
            };
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(response),
      });
    });

    const result = await page.evaluate(async () => {
      const { requestWorkerOperation } =
        await import('/sdk/esm/core/signingEngine/workerManager/workerTransport.js');
      const relayUrl = window.location.origin;
      const callWorker = async (request: any) =>
        await requestWorkerOperation({ kind: 'emailOtp', request } as any);

      await callWorker({
        type: 'requestEmailOtpChallenge',
        payload: {
          relayUrl,
          walletId: 'alice.testnet',
          routePlan: {
            routeFamily: 'login',
            authLane: { kind: 'app_session', jwt: 'app-session-jwt' },
            operation: 'transaction_sign',
          },
        },
      });
      await callWorker({
        type: 'verifyEmailOtpCode',
        payload: {
          relayUrl,
          walletId: 'alice.testnet',
          challengeId: 'challenge-1',
          otpCode: '123456',
          routePlan: {
            routeFamily: 'login',
            authLane: { kind: 'app_session', jwt: 'app-session-jwt' },
            operation: 'transaction_sign',
          },
        },
      });
      await callWorker({
        type: 'requestEmailOtpChallenge',
        payload: {
          relayUrl,
          walletId: 'alice.testnet',
          routePlan: {
            routeFamily: 'signing_session',
            authLane: {
              kind: 'signing_session',
              jwt: 'threshold-session-jwt',
              thresholdSessionId: 'threshold-session',
              curve: 'ed25519',
            },
            operation: 'export_key',
          },
        },
      });
      await callWorker({
        type: 'verifyEmailOtpCode',
        payload: {
          relayUrl,
          walletId: 'alice.testnet',
          challengeId: 'challenge-3',
          otpCode: '123456',
          routePlan: {
            routeFamily: 'signing_session',
            authLane: {
              kind: 'signing_session',
              jwt: 'threshold-session-jwt',
              thresholdSessionId: 'threshold-session',
              curve: 'ed25519',
            },
            operation: 'export_key',
          },
        },
      });
      return { ok: true };
    });

    expect(result).toEqual({ ok: true });
    expect(routes.map((entry) => entry.path)).toEqual([
      '/wallet/email-otp/login/challenge',
      '/wallet/email-otp/login/verify',
      '/wallet/email-otp/signing-session/challenge',
      '/wallet/email-otp/signing-session/verify',
    ]);
    expect(routes.map((entry) => entry.authorization)).toEqual([
      'Bearer app-session-jwt',
      'Bearer app-session-jwt',
      'Bearer threshold-session-jwt',
      'Bearer threshold-session-jwt',
    ]);
  });
});
