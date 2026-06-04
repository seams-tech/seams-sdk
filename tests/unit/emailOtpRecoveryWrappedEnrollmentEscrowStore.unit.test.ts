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
  recoveryKeyStatus: 'pending_backup',
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
      'thresholdSessionAuthToken',
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
        recoveryKeyStatus: 'pending_backup',
        acknowledgedAtMs: 3000,
      }),
    ).toBeNull();
    expect(
      normalizeEmailOtpRecoveryWrappedEnrollmentEscrowRecord({
        ...baseRecord,
        recoveryKeyStatus: 'active',
      }),
    ).toBeNull();
    expect(
      normalizeEmailOtpRecoveryWrappedEnrollmentEscrowRecord({
        ...baseRecord,
        recoveryKeyStatus: 'consumed',
        acknowledgedAtMs: 2500,
      }),
    ).toBeNull();
    expect(
      normalizeEmailOtpRecoveryWrappedEnrollmentEscrowRecord({
        ...baseRecord,
        recoveryKeyStatus: 'revoked',
        acknowledgedAtMs: 2500,
      }),
    ).toBeNull();

    expect(
      normalizeEmailOtpRecoveryWrappedEnrollmentEscrowRecord({
        ...baseRecord,
        recoveryKeyStatus: 'active',
        acknowledgedAtMs: 2500,
      }),
    ).toMatchObject({ recoveryKeyStatus: 'active', acknowledgedAtMs: 2500 });
    expect(
      normalizeEmailOtpRecoveryWrappedEnrollmentEscrowRecord({
        ...baseRecord,
        recoveryKeyStatus: 'consumed',
        acknowledgedAtMs: 2500,
        consumedAtMs: 3000,
      }),
    ).toMatchObject({ recoveryKeyStatus: 'consumed', acknowledgedAtMs: 2500, consumedAtMs: 3000 });
    expect(
      normalizeEmailOtpRecoveryWrappedEnrollmentEscrowRecord({
        ...baseRecord,
        recoveryKeyStatus: 'revoked',
        acknowledgedAtMs: 2500,
        revokedAtMs: 3000,
      }),
    ).toMatchObject({ recoveryKeyStatus: 'revoked', acknowledgedAtMs: 2500, revokedAtMs: 3000 });
    expect(
      normalizeEmailOtpRecoveryWrappedEnrollmentEscrowRecord({
        ...baseRecord,
        recoveryKeyStatus: 'abandoned',
        abandonedAtMs: 3000,
        cleanupReason: 'pending_backup_expired',
      }),
    ).toMatchObject({
      recoveryKeyStatus: 'abandoned',
      abandonedAtMs: 3000,
      cleanupReason: 'pending_backup_expired',
    });
  });

  test('stores and lists active recovery-wrapped escrows without mutating callers', async () => {
    const store = createEmailOtpRecoveryWrappedEnrollmentEscrowStore();
    const activeRecord: EmailOtpRecoveryWrappedEnrollmentEscrowRecord = {
      ...baseRecord,
      recoveryKeyStatus: 'active',
      acknowledgedAtMs: 2500,
    };
    const consumedRecord: EmailOtpRecoveryWrappedEnrollmentEscrowRecord = {
      ...baseRecord,
      recoveryKeyId: 'recovery-key-2',
      recoveryKeyStatus: 'consumed',
      acknowledgedAtMs: 2500,
      consumedAtMs: 3000,
    };
    await store.put(baseRecord);
    await store.put(activeRecord);
    await store.put(consumedRecord);

    const fetched = await store.get({ walletId: 'alice.testnet', recoveryKeyId: 'recovery-key-1' });
    expect(fetched).toEqual(activeRecord);
    if (fetched) fetched.wrappedDeviceEnrollmentEscrowB64u = 'mutated';

    await expect(
      store.get({ walletId: 'alice.testnet', recoveryKeyId: 'recovery-key-1' }),
    ).resolves.toEqual(activeRecord);
    await expect(store.listActiveByWallet('alice.testnet')).resolves.toEqual([activeRecord]);
    await expect(store.listByWallet('alice.testnet')).resolves.toEqual([
      activeRecord,
      consumedRecord,
    ]);

    await store.del({ walletId: 'alice.testnet', recoveryKeyId: 'recovery-key-1' });
    await expect(
      store.get({ walletId: 'alice.testnet', recoveryKeyId: 'recovery-key-1' }),
    ).resolves.toBeNull();
  });
});
