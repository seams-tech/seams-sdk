import { expect, test } from '@playwright/test';
import {
  createEmailOtpRecoveryWrappedEnrollmentEscrowStore,
  parseEmailOtpRecoveryWrappedEnrollmentEscrowBoundary,
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
  authSubjectId: 'google-sub-1',
  userId: 'google-sub-1',
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

function parseRecoveryWrappedEscrowRecord(
  raw: unknown,
): EmailOtpRecoveryWrappedEnrollmentEscrowRecord | null {
  return parseEmailOtpRecoveryWrappedEnrollmentEscrowBoundary(raw)?.record ?? null;
}

test.describe('Email OTP recovery-wrapped enrollment escrow store specs', () => {
  test('normalizes the server-side C_i schema without direct enc_s(S)', () => {
    const parsed = parseRecoveryWrappedEscrowRecord({
      ...baseRecord,
      walletId: ' alice.testnet ',
      recoveryKeyLabel: ' Backup 1 ',
      updatedAtMs: '2000',
    });

    expect(parsed).toEqual({
      ...baseRecord,
      walletId: 'alice.testnet',
      recoveryKeyLabel: 'Backup 1',
      updatedAtMs: 2000,
    });
  });

  test('parses raw server records into a recovery-wrap binding and lifecycle branch', () => {
    const parsed = parseEmailOtpRecoveryWrappedEnrollmentEscrowBoundary({
      ...baseRecord,
      walletId: ' alice.testnet ',
      updatedAtMs: '2000',
    });

    expect(parsed).toMatchObject({
      record: {
        ...baseRecord,
        walletId: 'alice.testnet',
        updatedAtMs: 2000,
      },
      binding: {
        auth: {
          authMethod: 'google_sso_email_otp',
          walletId: 'alice.testnet',
          userId: 'google-sub-1',
          authSubjectId: 'google-sub-1',
        },
        enrollment: {
          enrollmentId: 'enrollment-1',
          enrollmentVersion: '1',
          enrollmentSealKeyVersion: 'seal-v1',
        },
        signingRoot: {
          signingRootId: 'root-1',
          signingRootVersion: 'root-v1',
        },
        recoveryKeyId: 'recovery-key-1',
      },
      lifecycle: {
        status: 'active',
      },
    });

    expect(
      parseEmailOtpRecoveryWrappedEnrollmentEscrowBoundary({
        ...baseRecord,
        recoveryKeyStatus: 'consumed',
        consumedAtMs: 3000,
      }),
    ).toMatchObject({
      lifecycle: {
        status: 'consumed',
        consumedAtMs: 3000,
      },
    });
    expect(
      parseEmailOtpRecoveryWrappedEnrollmentEscrowBoundary({
        ...baseRecord,
        enrollmentSealKeyVersion: '',
      }),
    ).toBeNull();
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
      'walletSessionJwt',
      'recoveryKey',
      'recoveryKeys',
      'recoveryKek',
      'K_recovery_i',
    ]) {
      expect(
        parseRecoveryWrappedEscrowRecord({
          ...baseRecord,
          [forbiddenField]: 'must-not-persist',
        }),
      ).toBeNull();
    }
  });

  test('enforces single-use recovery key states', () => {
    expect(
      parseRecoveryWrappedEscrowRecord({
        ...baseRecord,
        recoveryKeyStatus: 'active',
        consumedAtMs: 3000,
      }),
    ).toBeNull();
    expect(
      parseRecoveryWrappedEscrowRecord({
        ...baseRecord,
        recoveryKeyStatus: 'consumed',
        acknowledgedAtMs: 2500,
      }),
    ).toBeNull();
    expect(
      parseRecoveryWrappedEscrowRecord({
        ...baseRecord,
        recoveryKeyStatus: 'revoked',
        acknowledgedAtMs: 2500,
      }),
    ).toBeNull();

    expect(
      parseRecoveryWrappedEscrowRecord({
        ...baseRecord,
        recoveryKeyStatus: 'active',
      }),
    ).toMatchObject({ recoveryKeyStatus: 'active' });
    expect(
      parseRecoveryWrappedEscrowRecord({
        ...baseRecord,
        recoveryKeyStatus: 'consumed',
        consumedAtMs: 3000,
      }),
    ).toMatchObject({ recoveryKeyStatus: 'consumed', consumedAtMs: 3000 });
    expect(
      parseRecoveryWrappedEscrowRecord({
        ...baseRecord,
        recoveryKeyStatus: 'revoked',
        revokedAtMs: 3000,
      }),
    ).toMatchObject({ recoveryKeyStatus: 'revoked', revokedAtMs: 3000 });
  });

  test('stores active, consumed, and revoked recovery-wrapped escrows without mutating callers', async () => {
    const store = createEmailOtpRecoveryWrappedEnrollmentEscrowStore();
    const activeRecord: EmailOtpRecoveryWrappedEnrollmentEscrowRecord = {
      ...baseRecord,
      recoveryKeyStatus: 'active',
    };
    const consumedRecord: EmailOtpRecoveryWrappedEnrollmentEscrowRecord = {
      ...baseRecord,
      recoveryKeyId: 'recovery-key-2',
      recoveryKeyStatus: 'consumed',
      consumedAtMs: 3000,
    };
    const revokedRecord: EmailOtpRecoveryWrappedEnrollmentEscrowRecord = {
      ...baseRecord,
      recoveryKeyId: 'recovery-key-3',
      recoveryKeyStatus: 'revoked',
      revokedAtMs: 3500,
    };
    await store.put(activeRecord);
    await store.put(consumedRecord);
    await store.put(revokedRecord);

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
      revokedRecord,
    ]);

    await store.del({ walletId: 'alice.testnet', recoveryKeyId: 'recovery-key-1' });
    await expect(
      store.get({ walletId: 'alice.testnet', recoveryKeyId: 'recovery-key-1' }),
    ).resolves.toBeNull();
  });
});
