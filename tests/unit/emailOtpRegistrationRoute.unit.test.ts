import { expect, test } from '@playwright/test';
import { handleEmailOtpRegistrationSealRoute } from '@server/router/domains/emailOtp/emailOtpRouteHandlers';

/*
 * Only the seal route survives here. The registration challenge and finalize
 * handlers this file also covered no longer exist, and their tests are deleted
 * rather than repaired: they asserted the shape of routes the server retired,
 * and a stale import aborts collection for the whole unit suite.
 *
 * The seal test is rewritten to the route as it is now. It used to pass
 * `claims` and `userId` and assert a Google registration-candidate validation;
 * the handler takes neither and performs no such validation, so those
 * assertions went with the behaviour.
 */
test.describe('Email OTP registration seal route', () => {
  test('forwards the wrapped ciphertext and echoes the wallet it sealed for', async () => {
    let sealRequest: Record<string, unknown> | null = null;
    const response = await handleEmailOtpRegistrationSealRoute({
      body: {
        walletId: 'silver-solstice-q4s2yq',
        wrappedCiphertext: 'wrapped-client-secret',
      },
      service: {
        applyEmailOtpServerSeal: async (value: Record<string, unknown>) => {
          sealRequest = value;
          return {
            ok: true,
            ciphertext: 'server-sealed-client-secret',
            enrollmentSealKeyVersion: 'seal-v1',
          };
        },
      } as never,
    });

    expect(response.status).toBe(200);
    expect(sealRequest).toEqual({ wrappedCiphertext: 'wrapped-client-secret' });
    expect(response.body).toMatchObject({
      ok: true,
      walletId: 'silver-solstice-q4s2yq',
      ciphertext: 'server-sealed-client-secret',
      enrollmentSealKeyVersion: 'seal-v1',
    });
  });

  test('refuses a field the seal route does not define', async () => {
    const response = await handleEmailOtpRegistrationSealRoute({
      body: {
        walletId: 'silver-solstice-q4s2yq',
        wrappedCiphertext: 'wrapped-client-secret',
        providerSubject: 'google:117142622123955425762',
      },
      service: {
        applyEmailOtpServerSeal: async () => {
          throw new Error('the seal route must reject an unsupported field before sealing');
        },
      } as never,
    });

    expect(response.status).toBe(400);
    expect(response.body).toMatchObject({ ok: false, code: 'invalid_body' });
  });
});
