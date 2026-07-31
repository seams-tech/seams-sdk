import { expect, test } from '@playwright/test';
import { recoverEd25519OperationStepUpMaterial } from '../../packages/sdk-server-ts/src/router/cloudflare/routes/thresholdEd25519';

test('Passkey operation step-up never invokes Email OTP material unseal', async () => {
  let unsealCalls = 0;
  const result = await recoverEd25519OperationStepUpMaterial({
    request: { kind: 'not_requested' },
    removeEmailOtpServerSeal: async () => {
      unsealCalls += 1;
      return {
        ok: true,
        ciphertext: 'unexpected-ciphertext',
        enrollmentSealKeyVersion: 'unexpected-version',
      };
    },
  });

  expect(result).toEqual({
    ok: true,
    recovery: { kind: 'not_requested' },
  });
  expect(unsealCalls).toBe(0);
});

test('Email OTP operation step-up returns material unsealed under the requested key version', async () => {
  const requests: Array<{ wrappedCiphertext: string }> = [];
  const result = await recoverEd25519OperationStepUpMaterial({
    request: {
      kind: 'email_otp_local_material_v1',
      wrappedCiphertext: 'wrapped-local-material',
      enrollmentSealKeyVersion: 'enrollment-seal-v1',
    },
    removeEmailOtpServerSeal: async (request) => {
      requests.push(request);
      return {
        ok: true,
        ciphertext: 'client-encrypted-local-material',
        enrollmentSealKeyVersion: 'enrollment-seal-v1',
      };
    },
  });

  expect(requests).toEqual([{ wrappedCiphertext: 'wrapped-local-material' }]);
  expect(result).toEqual({
    ok: true,
    recovery: {
      kind: 'email_otp_local_material_v1',
      ciphertext: 'client-encrypted-local-material',
      enrollmentSealKeyVersion: 'enrollment-seal-v1',
    },
  });
});

test('Email OTP operation step-up rejects enrollment key substitution', async () => {
  const result = await recoverEd25519OperationStepUpMaterial({
    request: {
      kind: 'email_otp_local_material_v1',
      wrappedCiphertext: 'wrapped-local-material',
      enrollmentSealKeyVersion: 'enrollment-seal-v1',
    },
    removeEmailOtpServerSeal: async () => ({
      ok: true,
      ciphertext: 'client-encrypted-local-material',
      enrollmentSealKeyVersion: 'substituted-version',
    }),
  });

  expect(result).toEqual({
    ok: false,
    code: 'scope_mismatch',
    message: 'Email OTP operation step-up enrollment seal key version changed',
  });
});

test('Email OTP operation step-up preserves a typed server-unseal failure', async () => {
  const result = await recoverEd25519OperationStepUpMaterial({
    request: {
      kind: 'email_otp_local_material_v1',
      wrappedCiphertext: 'wrapped-local-material',
      enrollmentSealKeyVersion: 'enrollment-seal-v1',
    },
    removeEmailOtpServerSeal: async () => ({
      ok: false,
      code: 'not_configured',
      message: 'Email OTP server seal is unavailable',
    }),
  });

  expect(result).toEqual({
    ok: false,
    code: 'not_configured',
    message: 'Email OTP server seal is unavailable',
  });
});
