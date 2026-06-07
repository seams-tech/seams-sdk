import { expect, test } from '@playwright/test';
import {
  EMAIL_OTP_RECOVERY_KEY_ALPHABET,
  EMAIL_OTP_RECOVERY_KEY_BYTE_LENGTH,
  EMAIL_OTP_RECOVERY_KEY_CHAR_LENGTH,
  EMAIL_OTP_RECOVERY_KEY_COUNT,
  EMAIL_OTP_RECOVERY_KEY_ID_CONTEXT,
  EMAIL_OTP_RECOVERY_KEY_GROUP_COUNT,
  EMAIL_OTP_RECOVERY_KEY_GROUP_LENGTH,
  EMAIL_OTP_RECOVERY_WRAP_ALG,
  EMAIL_OTP_RECOVERY_WRAP_HKDF_SALT,
  EMAIL_OTP_RECOVERY_WRAP_KEY_LENGTH,
  EMAIL_OTP_RECOVERY_WRAP_NONCE_LENGTH,
  EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND,
  EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_AAD_CONTEXT,
  EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND,
  buildEmailOtpRecoveryWrapBinding,
  decodeEmailOtpRecoveryKey,
  deriveEmailOtpRecoveryKeyId,
  deriveEmailOtpRecoveryKek32,
  emailOtpRecoveryKeyIdFields,
  encodeEmailOtpRecoveryKeyBytes,
  encodeEmailOtpRecoveryKekInfo,
  encodeEmailOtpRecoveryWrappedEnrollmentAad,
  formatEmailOtpRecoveryKey,
  generateEmailOtpRecoveryKeySet,
  normalizeEmailOtpRecoveryKey,
  unwrapEmailOtpDeviceEnrollmentEscrow,
  wrapEmailOtpDeviceEnrollmentEscrow,
  type EmailOtpRecoveryWrapBinding,
} from '@shared/utils/emailOtpRecoveryKey';
import { encodeSigningSessionHkdfTuple } from '@shared/utils/signingSessionSeal';
import { hkdfSync } from 'node:crypto';
import {
  chacha20poly1305Decrypt,
  chacha20poly1305Encrypt,
} from '../../server/src/email-recovery/nearSignerWasm';

const recoveryKey = '008J-4CT4-ANK7-F24S-NAXW-SQFE-ZW83-4N3P';

const binding: EmailOtpRecoveryWrapBinding = buildEmailOtpRecoveryWrapBinding({
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
});

const chacha20poly1305 = {
  encrypt: chacha20poly1305Encrypt,
  decrypt: chacha20poly1305Decrypt,
};

test.describe('shared Email OTP recovery key specs', () => {
  test('freezes recovery-key constants and recovery wrapper identifiers', () => {
    expect(EMAIL_OTP_RECOVERY_KEY_COUNT).toBe(10);
    expect(EMAIL_OTP_RECOVERY_KEY_BYTE_LENGTH).toBe(20);
    expect(EMAIL_OTP_RECOVERY_KEY_CHAR_LENGTH).toBe(32);
    expect(EMAIL_OTP_RECOVERY_KEY_GROUP_COUNT).toBe(8);
    expect(EMAIL_OTP_RECOVERY_KEY_GROUP_LENGTH).toBe(4);
    expect(EMAIL_OTP_RECOVERY_KEY_ALPHABET).toBe('0123456789ABCDEFGHJKMNPQRSTVWXYZ');
    expect(EMAIL_OTP_RECOVERY_WRAP_KEY_LENGTH).toBe(32);
    expect(EMAIL_OTP_RECOVERY_WRAP_NONCE_LENGTH).toBe(12);
    expect(EMAIL_OTP_RECOVERY_WRAP_ALG).toBe('chacha20poly1305-hkdf-sha256-v1');
    expect(EMAIL_OTP_RECOVERY_WRAP_HKDF_SALT).toBe('seams/email-otp/recovery-wrap/v1');
    expect(EMAIL_OTP_RECOVERY_KEY_ID_CONTEXT).toBe('seams/email-otp/recovery-key-id/v1');
    expect(EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_AAD_CONTEXT).toBe(
      'seams/email-otp/recovery-wrapped-enrollment/v1',
    );
    expect(EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND).toBe(
      'email_otp_device_enrollment_escrow',
    );
    expect(EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND).toBe(
      'recovery_wrapped_enrollment_escrow',
    );
  });

  test('generates exactly 10 formatted recovery keys', () => {
    const keys = generateEmailOtpRecoveryKeySet();
    expect(keys).toHaveLength(10);
    expect(new Set(keys).size).toBe(10);
    for (const key of keys) {
      expect(key).toMatch(/^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){7}$/);
      expect(normalizeEmailOtpRecoveryKey(key)).toHaveLength(32);
    }
  });

  test('round-trips 20-byte recovery-key entropy through Crockford Base32', () => {
    const bytes = Uint8Array.from([
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
      0xff, 0x10, 0x32, 0x54, 0x76,
    ]);
    const normalized = encodeEmailOtpRecoveryKeyBytes(bytes);
    expect(normalized).toBe('008J4CT4ANK7F24SNAXWSQFEZW834N3P');
    expect(formatEmailOtpRecoveryKey(normalized)).toBe('008J-4CT4-ANK7-F24S-NAXW-SQFE-ZW83-4N3P');
    expect(Array.from(decodeEmailOtpRecoveryKey(formatEmailOtpRecoveryKey(normalized)))).toEqual(
      Array.from(bytes),
    );
  });

  test('normalizes pasted keys but rejects unsupported recovery-key shapes', () => {
    expect(normalizeEmailOtpRecoveryKey('008j 4ct4 ank7 f24s naxw sqfe zw83 4n3p')).toBe(
      '008J4CT4ANK7F24SNAXWSQFEZW834N3P',
    );

    expect(() => normalizeEmailOtpRecoveryKey('1234-5678-9012-3456')).toThrow(
      /32 Crockford Base32/,
    );
    expect(() => normalizeEmailOtpRecoveryKey('1234-5678-9012-3456-7890-1234-5678-9012')).toThrow(
      /decimal-only/,
    );
    expect(() => normalizeEmailOtpRecoveryKey('008J-4CT4-ANK7-F24S-NAXW-SQFE-ZW83-4N3O')).toThrow(
      /unsupported/,
    );
  });

  test('derives recovery KEK with fixed HKDF metadata binding', async () => {
    const expectedInfo = encodeSigningSessionHkdfTuple([
      'alice.testnet',
      'user-1',
      'google-sub-1',
      'enrollment-1',
      '1',
      'recovery-key-1',
    ]);
    expect(Array.from(encodeEmailOtpRecoveryKekInfo(binding))).toEqual(Array.from(expectedInfo));
    expect(Array.from(encodeEmailOtpRecoveryWrappedEnrollmentAad(binding))).toEqual(
      Array.from(
        encodeSigningSessionHkdfTuple([
          'seams/email-otp/recovery-wrapped-enrollment/v1',
          'alice.testnet',
          'user-1',
          'google-sub-1',
          'google_sso_email_otp',
          'enrollment-1',
          '1',
          'seal-v1',
          'root-1',
          'root-v1',
          'recovery-key-1',
        ]),
      ),
    );

    const expected = new Uint8Array(
      hkdfSync(
        'sha256',
        decodeEmailOtpRecoveryKey(recoveryKey),
        new TextEncoder().encode(EMAIL_OTP_RECOVERY_WRAP_HKDF_SALT),
        expectedInfo,
        32,
      ),
    );
    expect(Array.from(await deriveEmailOtpRecoveryKek32({ recoveryKey, binding }))).toEqual(
      Array.from(expected),
    );
  });

  test('derives stable recovery-key ids from normalized code and enrollment binding', async () => {
    const keyIdBinding = {
      auth: binding.auth,
      enrollment: binding.enrollment,
      signingRoot: binding.signingRoot,
    };
    const keyId = await deriveEmailOtpRecoveryKeyId({
      recoveryKey,
      binding: keyIdBinding,
    });
    const sameKeyId = await deriveEmailOtpRecoveryKeyId({
      recoveryKey: '008j 4ct4 ank7 f24s naxw sqfe zw83 4n3p',
      binding: keyIdBinding,
    });
    const otherEnrollmentKeyId = await deriveEmailOtpRecoveryKeyId({
      recoveryKey,
      binding: {
        ...keyIdBinding,
        enrollment: {
          ...keyIdBinding.enrollment,
          enrollmentId: 'enrollment-2',
        },
      },
    });

    expect(keyId).toMatch(/^email-otp-rkid-v1-[A-Za-z0-9_-]+$/);
    expect(sameKeyId).toBe(keyId);
    expect(otherEnrollmentKeyId).not.toBe(keyId);
    expect(
      emailOtpRecoveryKeyIdFields({
        recoveryKeyBytesB64u: 'test-key-bytes',
        binding: keyIdBinding,
      }),
    ).toEqual([
      EMAIL_OTP_RECOVERY_KEY_ID_CONTEXT,
      'test-key-bytes',
      'alice.testnet',
      'user-1',
      'google-sub-1',
      'google_sso_email_otp',
      'enrollment-1',
      '1',
      'seal-v1',
      'root-1',
      'root-v1',
    ]);
  });

  test('wraps and unwraps enc_s(S) with ChaCha20-Poly1305 and bound AAD', async () => {
    const encS = Uint8Array.from(Array.from({ length: 48 }, (_, index) => index + 7));
    const nonce12 = Uint8Array.from([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);

    const wrapped = await wrapEmailOtpDeviceEnrollmentEscrow({
      recoveryKey,
      binding,
      encS,
      nonce12,
      chacha20poly1305,
    });

    expect(wrapped.alg).toBe(EMAIL_OTP_RECOVERY_WRAP_ALG);
    expect(Array.from(wrapped.nonce12)).toEqual(Array.from(nonce12));
    expect(wrapped.ciphertext).toHaveLength(encS.length + 16);
    await expect(
      unwrapEmailOtpDeviceEnrollmentEscrow({
        recoveryKey,
        binding,
        wrapped,
        chacha20poly1305,
      }),
    ).resolves.toEqual(encS);

    await expect(
      unwrapEmailOtpDeviceEnrollmentEscrow({
        recoveryKey: '00GJ-4CT4-ANK7-F24S-NAXW-SQFE-ZW83-4N3P',
        binding,
        wrapped,
        chacha20poly1305,
      }),
    ).rejects.toThrow(/unwrap failed/i);

    await expect(
      unwrapEmailOtpDeviceEnrollmentEscrow({
        recoveryKey,
        binding: {
          ...binding,
          enrollment: { ...binding.enrollment, enrollmentVersion: '2' },
        },
        wrapped,
        chacha20poly1305,
      }),
    ).rejects.toThrow(/unwrap failed/i);
  });
});
