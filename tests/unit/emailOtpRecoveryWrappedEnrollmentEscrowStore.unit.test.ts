import { expect, test } from '@playwright/test';
import {
  createEmailOtpRecoveryWrappedEnrollmentEscrowStore,
  normalizeEmailOtpRecoveryWrappedEnrollmentEscrowRecord,
  type EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
} from '@server/core/EmailOtpStores';
import {
  EMAIL_OTP_RECOVERY_WRAP_ALG,
  EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND,
  EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND,
} from '@shared/utils/emailOtpRecoveryKey';

const baseRecord: EmailOtpRecoveryWrappedEnrollmentEscrowRecord = {
  version: 'email_otp_recovery_wrapped_enrollment_escrow_v1',
  alg: EMAIL_OTP_RECOVERY_WRAP_ALG,
  secretKind: EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND,
  escrowKind: EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND,
  walletId: 'alice.testnet',
  userId: 'user-1',
  authSubjectId: 'google-sub-1',
  authMethod: 'google_sso_email_otp',
  enrollmentId: 'enrollment-1',
  enrollmentVersion: '1',
  enrollmentSealKeyVersion: 'seal-v1',
  signingRootId: 'root-1',
  signingRootVersion: 'root-v1',
  recoveryKeyId: 'recovery-key-1',
  recoveryKeyStatus: 'active',
  nonceB64u: 'AQIDBAUGBwgJCgsM',
  wrappedDeviceEnrollmentEscrowB64u: 'AQIDBAUGBwg',
  aadHashB64u: 'CQoLDA0ODxA',
  issuedAtMs: 1000,
  updatedAtMs: 2000,
};

test.describe('Email OTP recovery-wrapped enrollment escrow store specs', () => {
  test('normalizes the server-side C_i schema without direct enc_s(S)', () => {
    const parsed = normalizeEmailOtpRecoveryWrappedEnrollmentEscrowRecord({
      ...baseRecord,
      walletId: ' alice.testnet ',
      recoveryKeyLabel: ' Backup 1 ',
      updatedAtMs: 2000.9,
    });

    expect(parsed).toEqual({
      ...baseRecord,
      walletId: 'alice.testnet',
      recoveryKeyLabel: 'Backup 1',
      updatedAtMs: 2000,
    });
  });

  test('rejects direct enrollment escrow, plaintext S, recovery keys, and session secret fields', () => {
    for (const forbiddenField of [
      'enrollmentEscrowCiphertextB64u',
      'encSB64u',
      'encS',
      'S',
      'secretS',
      'plaintextS',
      'emailOtpSecretS',
      'clientSecret',
      'clientSecret32',
      'clientSecretB64u',
      'clientSecret32B64u',
      'signingSessionSecretB64u',
      'sealedSecretB64u',
      'thresholdSessionJwt',
      'recoveryKey',
      'recoveryKeys',
      'recoveryKek',
      'K_recovery_i',
    ]) {
      expect(
        normalizeEmailOtpRecoveryWrappedEnrollmentEscrowRecord({
          ...baseRecord,
          [forbiddenField]: 'must-not-persist',
        }),
      ).toBeNull();
    }
  });

  test('enforces single-use recovery key states', () => {
    expect(
      normalizeEmailOtpRecoveryWrappedEnrollmentEscrowRecord({
        ...baseRecord,
        recoveryKeyStatus: 'active',
        consumedAtMs: 3000,
      }),
    ).toBeNull();
    expect(
      normalizeEmailOtpRecoveryWrappedEnrollmentEscrowRecord({
        ...baseRecord,
        recoveryKeyStatus: 'consumed',
      }),
    ).toBeNull();
    expect(
      normalizeEmailOtpRecoveryWrappedEnrollmentEscrowRecord({
        ...baseRecord,
        recoveryKeyStatus: 'revoked',
      }),
    ).toBeNull();

    expect(
      normalizeEmailOtpRecoveryWrappedEnrollmentEscrowRecord({
        ...baseRecord,
        recoveryKeyStatus: 'consumed',
        consumedAtMs: 3000,
      }),
    ).toMatchObject({ recoveryKeyStatus: 'consumed', consumedAtMs: 3000 });
    expect(
      normalizeEmailOtpRecoveryWrappedEnrollmentEscrowRecord({
        ...baseRecord,
        recoveryKeyStatus: 'revoked',
        revokedAtMs: 3000,
      }),
    ).toMatchObject({ recoveryKeyStatus: 'revoked', revokedAtMs: 3000 });
  });

  test('stores and lists active recovery-wrapped escrows without mutating callers', async () => {
    const store = createEmailOtpRecoveryWrappedEnrollmentEscrowStore();
    await store.put(baseRecord);
    await store.put({
      ...baseRecord,
      recoveryKeyId: 'recovery-key-2',
      recoveryKeyStatus: 'consumed',
      consumedAtMs: 3000,
    });

    const fetched = await store.get({ walletId: 'alice.testnet', recoveryKeyId: 'recovery-key-1' });
    expect(fetched).toEqual(baseRecord);
    if (fetched) fetched.wrappedDeviceEnrollmentEscrowB64u = 'mutated';

    await expect(
      store.get({ walletId: 'alice.testnet', recoveryKeyId: 'recovery-key-1' }),
    ).resolves.toEqual(baseRecord);
    await expect(store.listActiveByWallet('alice.testnet')).resolves.toEqual([baseRecord]);

    await store.del({ walletId: 'alice.testnet', recoveryKeyId: 'recovery-key-1' });
    await expect(
      store.get({ walletId: 'alice.testnet', recoveryKeyId: 'recovery-key-1' }),
    ).resolves.toBeNull();
  });
});
