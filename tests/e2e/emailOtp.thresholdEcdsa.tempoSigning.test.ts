import { expect, test } from '@playwright/test';
import {
  runEmailOtpEcdsaTempoFlow,
  setupEmailOtpEcdsaTempoHarness,
} from '../helpers/emailOtpEcdsaTempoFlow';

test.describe('Email OTP threshold-ecdsa tempo signing', () => {
  test.setTimeout(180_000);

  test('session-mode Email OTP login bootstraps warm ECDSA capability and signs twice', async ({
    page,
  }) => {
    const harness = await setupEmailOtpEcdsaTempoHarness(page);
    const accountId = `emailotpsession${Date.now()}.w3a-v1.testnet`;
    try {
      const appSessionJwt = await harness.mintAppSessionJwt({
        userId: accountId,
        deviceId: 'email-otp-enroll-device',
      });

      const result = await runEmailOtpEcdsaTempoFlow(page, {
        relayerUrl: harness.baseUrl,
        shamirPrimeB64u: harness.shamirPrimeB64u,
        accountId,
        enrollAppSessionJwt: appSessionJwt,
        loginAppSessionJwt: appSessionJwt,
        clientSecretB64u: harness.defaultClientSecretB64u,
        emailOtpAuthPolicy: 'session',
        signTwice: true,
        signNearAfterLogin: true,
      });

      const failureContext = result.ok
        ? result
          : {
              result,
              enrollment: await harness.readEmailOtpEnrollment(accountId),
            };
      expect(result.ok, `${result.error || ''}\n${JSON.stringify(failureContext)}`).toBe(true);
      expect(result.registration?.success).toBe(true);
      expect(result.ecdsaKeyBinding?.ecdsaThresholdKeyId).toBeTruthy();
      expect(result.ecdsaKeyBinding?.participantIds).toEqual([1, 2]);
      expect(result.emailOtpEnrollment?.challengeId).toBeTruthy();
      expect(result.emailOtpEnrollment?.emailOtpKeyVersion).toBeTruthy();
      expect(result.emailOtpLogin?.policy).toBe('session');
      expect(result.emailOtpLogin?.retention).toBe('session');
      expect(result.emailOtpLogin?.warmState).toBe('ready');
      expect(result.otpCounters?.enrollChallengeCount).toBe(1);
      expect(result.otpCounters?.loginChallengeCount).toBe(1);
      expect(result.webauthnCounters?.createCount).toBe(0);
      expect(result.webauthnCounters?.getCount).toBe(0);
      expect(result.firstSign?.ok, result.firstSign?.error || '').toBe(true);
      expect(result.firstSign?.chain).toBe('tempo');
      expect(result.firstSign?.kind).toBe('tempoTransaction');
      expect(result.firstSign?.rawTxHex?.startsWith('0x')).toBe(true);
      expect(result.secondSign?.ok, result.secondSign?.error || '').toBe(true);
      expect(result.secondSign?.chain).toBe('tempo');
      expect(result.secondSign?.kind).toBe('tempoTransaction');
      expect(result.secondSign?.rawTxHex?.startsWith('0x')).toBe(true);
      expect(result.nearSign?.ok, result.nearSign?.error || '').toBe(true);
      expect(result.nearSign?.signedCount).toBe(1);
      expect(result.nearSign?.signerId).toBe(accountId);
      expect(result.nearSign?.receiverId).toBe('w3a-v1.testnet');
    } finally {
      await harness.close();
    }
  });

  test('session-mode Email OTP login accepts a resent unlock code before signing', async ({
    page,
  }) => {
    const harness = await setupEmailOtpEcdsaTempoHarness(page);
    const accountId = `emailotpresend${Date.now()}.w3a-v1.testnet`;
    try {
      const appSessionJwt = await harness.mintAppSessionJwt({
        userId: accountId,
        deviceId: 'email-otp-resend-device',
      });

      const result = await runEmailOtpEcdsaTempoFlow(page, {
        relayerUrl: harness.baseUrl,
        shamirPrimeB64u: harness.shamirPrimeB64u,
        accountId,
        enrollAppSessionJwt: appSessionJwt,
        loginAppSessionJwt: appSessionJwt,
        clientSecretB64u: harness.defaultClientSecretB64u,
        emailOtpAuthPolicy: 'session',
        signTwice: false,
        resendLoginOtpBeforeSubmit: true,
      });

      const failureContext = result.ok
        ? result
        : {
            result,
            enrollment: await harness.readEmailOtpEnrollment(accountId),
          };
      expect(result.ok, `${result.error || ''}\n${JSON.stringify(failureContext)}`).toBe(true);
      expect(result.emailOtpLogin?.policy).toBe('session');
      expect(result.emailOtpLogin?.retention).toBe('session');
      expect(result.emailOtpLogin?.warmState).toBe('ready');
      expect(result.otpCounters?.enrollChallengeCount).toBe(1);
      expect(result.otpCounters?.loginChallengeCount).toBe(2);
      expect(result.webauthnCounters?.createCount).toBe(0);
      expect(result.webauthnCounters?.getCount).toBe(0);
      expect(result.firstSign?.ok, result.firstSign?.error || '').toBe(true);
      expect(result.firstSign?.chain).toBe('tempo');
    } finally {
      await harness.close();
    }
  });

  test('Google SSO Email OTP lifecycle signs and exports Ed25519/ECDSA with resend', async ({
    page,
  }) => {
    const harness = await setupEmailOtpEcdsaTempoHarness(page);
    const nonce = Date.now();
    const accountId = `googlessootp${nonce}.w3a-v1.testnet`;
    const googleSubject = `google:e2e-email-otp-${nonce}`;
    try {
      const appSessionJwt = await harness.mintAppSessionJwt({
        userId: googleSubject,
        walletId: accountId,
        email: `email-otp-e2e-${nonce}@example.com`,
        deviceId: 'google-sso-email-otp-device',
        jwtShape: true,
      });

      const result = await runEmailOtpEcdsaTempoFlow(page, {
        relayerUrl: harness.baseUrl,
        shamirPrimeB64u: harness.shamirPrimeB64u,
        accountId,
        enrollAppSessionJwt: appSessionJwt,
        loginAppSessionJwt: appSessionJwt,
        clientSecretB64u: harness.defaultClientSecretB64u,
        emailOtpAuthPolicy: 'session',
        signingKind: 'eip1559',
        signTwice: true,
        signNearAfterLogin: true,
        exportNearWithResend: true,
        exportEcdsaWithResend: true,
      });

      const failureContext = result.ok
        ? result
        : {
            result,
            enrollment: await harness.readEmailOtpEnrollment(accountId),
          };
      expect(result.ok, `${result.error || ''}\n${JSON.stringify(failureContext)}`).toBe(true);
      expect(result.registration?.success).toBe(true);
      expect(result.emailOtpLogin?.policy).toBe('session');
      expect(result.emailOtpLogin?.retention).toBe('session');
      expect(result.emailOtpLogin?.warmState).toBe('ready');
      expect(result.otpCounters?.enrollChallengeCount).toBe(1);
      expect(result.otpCounters?.loginChallengeCount).toBe(1);
      expect(result.otpCounters?.exportChallengeCount).toBe(4);
      expect(result.webauthnCounters?.createCount).toBe(0);
      expect(result.webauthnCounters?.getCount).toBe(0);
      expect(result.firstSign?.ok, result.firstSign?.error || '').toBe(true);
      expect(result.firstSign?.chain).toBe('evm');
      expect(result.firstSign?.kind).toBe('eip1559');
      expect(result.secondSign?.ok, result.secondSign?.error || '').toBe(true);
      expect(result.secondSign?.chain).toBe('evm');
      expect(result.nearSign?.ok, result.nearSign?.error || '').toBe(true);
      expect(result.nearSign?.signerId).toBe(accountId);
      expect(result.exports?.near?.ok, result.exports?.near?.error || '').toBe(true);
      expect(result.exports?.near?.exportedSchemes).toEqual(['ed25519']);
      expect(result.exports?.ecdsa?.ok, result.exports?.ecdsa?.error || '').toBe(true);
      expect(result.exports?.ecdsa?.exportedSchemes).toEqual(['secp256k1']);
    } finally {
      await harness.close();
    }
  });

  test('Google SSO Email OTP lifecycle signs Tempo transactions', async ({ page }) => {
    const harness = await setupEmailOtpEcdsaTempoHarness(page);
    const nonce = Date.now();
    const accountId = `googlessotempo${nonce}.w3a-v1.testnet`;
    const googleSubject = `google:e2e-email-otp-tempo-${nonce}`;
    try {
      const appSessionJwt = await harness.mintAppSessionJwt({
        userId: googleSubject,
        walletId: accountId,
        email: `email-otp-tempo-e2e-${nonce}@example.com`,
        deviceId: 'google-sso-email-otp-tempo-device',
        jwtShape: true,
      });

      const result = await runEmailOtpEcdsaTempoFlow(page, {
        relayerUrl: harness.baseUrl,
        shamirPrimeB64u: harness.shamirPrimeB64u,
        accountId,
        enrollAppSessionJwt: appSessionJwt,
        loginAppSessionJwt: appSessionJwt,
        clientSecretB64u: harness.defaultClientSecretB64u,
        emailOtpAuthPolicy: 'session',
        signTwice: false,
      });

      const failureContext = result.ok
        ? result
        : {
            result,
            enrollment: await harness.readEmailOtpEnrollment(accountId),
          };
      expect(result.ok, `${result.error || ''}\n${JSON.stringify(failureContext)}`).toBe(true);
      expect(result.registration?.success).toBe(true);
      expect(result.emailOtpLogin?.policy).toBe('session');
      expect(result.emailOtpLogin?.retention).toBe('session');
      expect(result.webauthnCounters?.createCount).toBe(0);
      expect(result.webauthnCounters?.getCount).toBe(0);
      expect(result.firstSign?.ok, result.firstSign?.error || '').toBe(true);
      expect(result.firstSign?.chain).toBe('tempo');
      expect(result.firstSign?.kind).toBe('tempoTransaction');
    } finally {
      await harness.close();
    }
  });

  test('per_operation Email OTP login signs once and then requires fresh OTP before the next sign', async ({
    page,
  }) => {
    const harness = await setupEmailOtpEcdsaTempoHarness(page);
    const accountId = `emailotpperop${Date.now()}.w3a-v1.testnet`;
    try {
      const appSessionJwt = await harness.mintAppSessionJwt({
        userId: accountId,
        deviceId: 'email-otp-enroll-device',
        jwtShape: true,
      });

      const result = await runEmailOtpEcdsaTempoFlow(page, {
        relayerUrl: harness.baseUrl,
        shamirPrimeB64u: harness.shamirPrimeB64u,
        accountId,
        enrollAppSessionJwt: appSessionJwt,
        loginAppSessionJwt: appSessionJwt,
        clientSecretB64u: harness.defaultClientSecretB64u,
        emailOtpAuthPolicy: 'per_operation',
        signTwice: true,
      });

      const failureContext = result.ok
        ? result
          : {
              result,
              enrollment: await harness.readEmailOtpEnrollment(accountId),
            };
      expect(result.ok, `${result.error || ''}\n${JSON.stringify(failureContext)}`).toBe(true);
      expect(result.emailOtpLogin?.policy).toBe('per_operation');
      expect(result.emailOtpLogin?.retention).toBe('single_use');
      expect(result.emailOtpLogin?.warmState).toBe('ready');
      expect(result.otpCounters?.enrollChallengeCount).toBe(1);
      expect(result.otpCounters?.loginChallengeCount).toBe(1);
      expect(result.webauthnCounters?.createCount).toBe(0);
      expect(result.webauthnCounters?.getCount).toBe(0);
      expect(result.firstSign?.ok, result.firstSign?.error || '').toBe(true);
      expect(result.firstSign?.chain).toBe('tempo');
      expect(result.firstSign?.kind).toBe('tempoTransaction');
      expect(result.secondSign?.ok, JSON.stringify(result)).toBe(false);
      expect(String(result.secondSign?.error || '')).toContain(
        'requires fresh Email OTP verification with per_operation policy',
      );
    } finally {
      await harness.close();
    }
  });

  test('session-mode Email OTP login also signs normal EVM eip1559 transactions', async ({
    page,
  }) => {
    const harness = await setupEmailOtpEcdsaTempoHarness(page);
    const accountId = `emailotpevm${Date.now()}.w3a-v1.testnet`;
    try {
      const appSessionJwt = await harness.mintAppSessionJwt({
        userId: accountId,
        deviceId: 'email-otp-evm-device',
      });

      const result = await runEmailOtpEcdsaTempoFlow(page, {
        relayerUrl: harness.baseUrl,
        shamirPrimeB64u: harness.shamirPrimeB64u,
        accountId,
        enrollAppSessionJwt: appSessionJwt,
        loginAppSessionJwt: appSessionJwt,
        clientSecretB64u: harness.defaultClientSecretB64u,
        emailOtpAuthPolicy: 'session',
        signingKind: 'eip1559',
        signTwice: true,
      });

      const failureContext = result.ok
        ? result
          : {
              result,
              enrollment: await harness.readEmailOtpEnrollment(accountId),
            };
      expect(result.ok, `${result.error || ''}\n${JSON.stringify(failureContext)}`).toBe(true);
      expect(result.emailOtpLogin?.policy).toBe('session');
      expect(result.emailOtpLogin?.retention).toBe('session');
      expect(result.webauthnCounters?.createCount).toBe(0);
      expect(result.webauthnCounters?.getCount).toBe(0);
      expect(result.firstSign?.ok, result.firstSign?.error || '').toBe(true);
      expect(result.firstSign?.chain).toBe('evm');
      expect(result.firstSign?.kind).toBe('eip1559');
      expect(result.firstSign?.rawTxHex?.startsWith('0x')).toBe(true);
      expect(result.secondSign?.ok, result.secondSign?.error || '').toBe(true);
      expect(result.secondSign?.chain).toBe('evm');
      expect(result.secondSign?.kind).toBe('eip1559');
      expect(result.secondSign?.rawTxHex?.startsWith('0x')).toBe(true);
    } finally {
      await harness.close();
    }
  });

  test('per_operation Email OTP also forces a fresh OTP before a second EVM eip1559 sign', async ({
    page,
  }) => {
    const harness = await setupEmailOtpEcdsaTempoHarness(page);
    const accountId = `emailotpevmpop${Date.now()}.w3a-v1.testnet`;
    try {
      const appSessionJwt = await harness.mintAppSessionJwt({
        userId: accountId,
        deviceId: 'email-otp-evm-perop-device',
        jwtShape: true,
      });

      const result = await runEmailOtpEcdsaTempoFlow(page, {
        relayerUrl: harness.baseUrl,
        shamirPrimeB64u: harness.shamirPrimeB64u,
        accountId,
        enrollAppSessionJwt: appSessionJwt,
        loginAppSessionJwt: appSessionJwt,
        clientSecretB64u: harness.defaultClientSecretB64u,
        emailOtpAuthPolicy: 'per_operation',
        signingKind: 'eip1559',
        signTwice: true,
      });

      const failureContext = result.ok
        ? result
          : {
              result,
              enrollment: await harness.readEmailOtpEnrollment(accountId),
            };
      expect(result.ok, `${result.error || ''}\n${JSON.stringify(failureContext)}`).toBe(true);
      expect(result.emailOtpLogin?.policy).toBe('per_operation');
      expect(result.emailOtpLogin?.retention).toBe('single_use');
      expect(result.webauthnCounters?.createCount).toBe(0);
      expect(result.webauthnCounters?.getCount).toBe(0);
      expect(result.firstSign?.ok, result.firstSign?.error || '').toBe(true);
      expect(result.firstSign?.chain).toBe('evm');
      expect(result.firstSign?.kind).toBe('eip1559');
      expect(result.secondSign?.ok).toBe(false);
      expect(String(result.secondSign?.error || '')).toContain(
        'requires fresh Email OTP verification with per_operation policy',
      );
    } finally {
      await harness.close();
    }
  });
});
