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
      const bootstrappedKey = await harness.bootstrapEmailOtpEcdsaKey({
        userId: accountId,
        clientSecretB64u: harness.defaultClientSecretB64u,
      });
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
        ecdsaThresholdKeyId: bootstrappedKey.ecdsaThresholdKeyId,
        participantIds: bootstrappedKey.participantIds,
        clientSecretB64u: harness.defaultClientSecretB64u,
        emailOtpAuthPolicy: 'session',
        signTwice: true,
      });

      const failureContext = result.ok
        ? result
        : {
            result,
            bootstrappedKey,
            enrollment: await harness.readEmailOtpEnrollment(accountId),
            integratedKey: await harness.readIntegratedEcdsaKey(
              bootstrappedKey.ecdsaThresholdKeyId,
            ),
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
      expect(result.firstSign?.ok, result.firstSign?.error || '').toBe(true);
      expect(result.firstSign?.chain).toBe('tempo');
      expect(result.firstSign?.kind).toBe('tempoTransaction');
      expect(result.firstSign?.rawTxHex?.startsWith('0x')).toBe(true);
      expect(result.secondSign?.ok, result.secondSign?.error || '').toBe(true);
      expect(result.secondSign?.chain).toBe('tempo');
      expect(result.secondSign?.kind).toBe('tempoTransaction');
      expect(result.secondSign?.rawTxHex?.startsWith('0x')).toBe(true);
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
      const bootstrappedKey = await harness.bootstrapEmailOtpEcdsaKey({
        userId: accountId,
        clientSecretB64u: harness.defaultClientSecretB64u,
      });
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
        ecdsaThresholdKeyId: bootstrappedKey.ecdsaThresholdKeyId,
        participantIds: bootstrappedKey.participantIds,
        clientSecretB64u: harness.defaultClientSecretB64u,
        emailOtpAuthPolicy: 'per_operation',
        signTwice: true,
      });

      const failureContext = result.ok
        ? result
        : {
            result,
            bootstrappedKey,
            enrollment: await harness.readEmailOtpEnrollment(accountId),
            integratedKey: await harness.readIntegratedEcdsaKey(
              bootstrappedKey.ecdsaThresholdKeyId,
            ),
          };
      expect(result.ok, `${result.error || ''}\n${JSON.stringify(failureContext)}`).toBe(true);
      expect(result.emailOtpLogin?.policy).toBe('per_operation');
      expect(result.emailOtpLogin?.retention).toBe('single_use');
      expect(result.emailOtpLogin?.warmState).toBe('ready');
      expect(result.otpCounters?.enrollChallengeCount).toBe(1);
      expect(result.otpCounters?.loginChallengeCount).toBe(1);
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
      const bootstrappedKey = await harness.bootstrapEmailOtpEcdsaKey({
        userId: accountId,
        clientSecretB64u: harness.defaultClientSecretB64u,
      });
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
        ecdsaThresholdKeyId: bootstrappedKey.ecdsaThresholdKeyId,
        participantIds: bootstrappedKey.participantIds,
        clientSecretB64u: harness.defaultClientSecretB64u,
        emailOtpAuthPolicy: 'session',
        signingKind: 'eip1559',
        signTwice: true,
      });

      const failureContext = result.ok
        ? result
        : {
            result,
            bootstrappedKey,
            enrollment: await harness.readEmailOtpEnrollment(accountId),
            integratedKey: await harness.readIntegratedEcdsaKey(
              bootstrappedKey.ecdsaThresholdKeyId,
            ),
          };
      expect(result.ok, `${result.error || ''}\n${JSON.stringify(failureContext)}`).toBe(true);
      expect(result.emailOtpLogin?.policy).toBe('session');
      expect(result.emailOtpLogin?.retention).toBe('session');
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
      const bootstrappedKey = await harness.bootstrapEmailOtpEcdsaKey({
        userId: accountId,
        clientSecretB64u: harness.defaultClientSecretB64u,
      });
      const appSessionJwt = await harness.mintAppSessionJwt({
        userId: accountId,
        deviceId: 'email-otp-evm-perop-device',
      });

      const result = await runEmailOtpEcdsaTempoFlow(page, {
        relayerUrl: harness.baseUrl,
        shamirPrimeB64u: harness.shamirPrimeB64u,
        accountId,
        enrollAppSessionJwt: appSessionJwt,
        loginAppSessionJwt: appSessionJwt,
        ecdsaThresholdKeyId: bootstrappedKey.ecdsaThresholdKeyId,
        participantIds: bootstrappedKey.participantIds,
        clientSecretB64u: harness.defaultClientSecretB64u,
        emailOtpAuthPolicy: 'per_operation',
        signingKind: 'eip1559',
        signTwice: true,
      });

      const failureContext = result.ok
        ? result
        : {
            result,
            bootstrappedKey,
            enrollment: await harness.readEmailOtpEnrollment(accountId),
            integratedKey: await harness.readIntegratedEcdsaKey(
              bootstrappedKey.ecdsaThresholdKeyId,
            ),
          };
      expect(result.ok, `${result.error || ''}\n${JSON.stringify(failureContext)}`).toBe(true);
      expect(result.emailOtpLogin?.policy).toBe('per_operation');
      expect(result.emailOtpLogin?.retention).toBe('single_use');
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
