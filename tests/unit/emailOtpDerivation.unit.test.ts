import { test, expect } from '@playwright/test';
import { hkdfSync } from 'node:crypto';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import {
  EMAIL_OTP_ECDSA_CLIENT_SHARE_SALT_V1,
  EMAIL_OTP_ECDSA_DERIVATION_PATH_V1,
  EMAIL_OTP_THRESHOLD_ROOT_SALT_V1,
  EMAIL_OTP_UNLOCK_AUTH_SALT_V1,
  deriveEmailOtpEcdsaClientRootShare32B64u,
  deriveEmailOtpThresholdRootB64u,
  deriveEmailOtpUnlockAuthSeedB64u,
  encodeEmailOtpTuple,
} from '@shared/utils/emailOtpDerivation';

function utf8Bytes(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

test.describe('Email OTP derivation', () => {
  test('encodes length-prefixed tuples canonically', async () => {
    const encoded = encodeEmailOtpTuple(['alice.testnet', 'evm-signing']);
    expect(Array.from(encoded)).toEqual([
      0x00,
      0x0d,
      ...Array.from(utf8Bytes('alice.testnet')),
      0x00,
      0x0b,
      ...Array.from(utf8Bytes('evm-signing')),
    ]);
  });

  test('matches threshold_root HKDF-SHA-256 reference output', async () => {
    const clientSecretB64u = base64UrlEncode(
      Uint8Array.from(Array.from({ length: 32 }, (_, index) => index + 1)),
    );
    const walletId = 'alice.testnet';
    const info = Buffer.from(encodeEmailOtpTuple([walletId]));
    const expected = base64UrlEncode(
      hkdfSync(
        'sha256',
        Buffer.from(base64UrlDecode(clientSecretB64u)),
        Buffer.from(EMAIL_OTP_THRESHOLD_ROOT_SALT_V1, 'utf8'),
        info,
        32,
      ),
    );

    expect(await deriveEmailOtpThresholdRootB64u({ clientSecretB64u, walletId })).toBe(expected);
  });

  test('derives stable ECDSA and unlock branches with label separation', async () => {
    const clientSecretB64u = base64UrlEncode(
      Uint8Array.from(Array.from({ length: 32 }, (_, index) => 255 - index)),
    );
    const walletId = 'alice.testnet';
    const userId = 'alice.testnet';
    const ecdsaInfo = Buffer.from(encodeEmailOtpTuple([userId, EMAIL_OTP_ECDSA_DERIVATION_PATH_V1]));
    const unlockInfo = Buffer.from(encodeEmailOtpTuple([walletId]));
    const expectedEcdsa = base64UrlEncode(
      hkdfSync(
        'sha256',
        Buffer.from(
          hkdfSync(
            'sha256',
            Buffer.from(base64UrlDecode(clientSecretB64u)),
            Buffer.from(EMAIL_OTP_THRESHOLD_ROOT_SALT_V1, 'utf8'),
            Buffer.from(encodeEmailOtpTuple([walletId])),
            32,
          ),
        ),
        Buffer.from(EMAIL_OTP_ECDSA_CLIENT_SHARE_SALT_V1, 'utf8'),
        ecdsaInfo,
        32,
      ),
    );
    const expectedUnlock = base64UrlEncode(
      hkdfSync(
        'sha256',
        Buffer.from(
          hkdfSync(
            'sha256',
            Buffer.from(base64UrlDecode(clientSecretB64u)),
            Buffer.from(EMAIL_OTP_THRESHOLD_ROOT_SALT_V1, 'utf8'),
            Buffer.from(encodeEmailOtpTuple([walletId])),
            32,
          ),
        ),
        Buffer.from(EMAIL_OTP_UNLOCK_AUTH_SALT_V1, 'utf8'),
        unlockInfo,
        32,
      ),
    );

    const actualEcdsa = await deriveEmailOtpEcdsaClientRootShare32B64u({
      clientSecretB64u,
      walletId,
      userId,
    });
    const actualUnlock = await deriveEmailOtpUnlockAuthSeedB64u({
      clientSecretB64u,
      walletId,
    });

    expect(actualEcdsa).toBe(expectedEcdsa);
    expect(actualUnlock).toBe(expectedUnlock);
    expect(actualEcdsa).not.toBe(actualUnlock);
    expect(base64UrlDecode(actualEcdsa)).toHaveLength(32);
    expect(base64UrlDecode(actualUnlock)).toHaveLength(32);
  });
});
