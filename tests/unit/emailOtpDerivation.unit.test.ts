import { test, expect } from '@playwright/test';
import { hkdfSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import {
  EMAIL_OTP_ECDSA_CLIENT_SHARE_SALT_V1,
  EMAIL_OTP_ECDSA_DERIVATION_PATH,
  EMAIL_OTP_THRESHOLD_ROOT_SALT_V1,
  EMAIL_OTP_UNLOCK_AUTH_SALT_V1,
  deriveEmailOtpEcdsaClientRootShare32FromSecret32,
  deriveEmailOtpEcdsaClientRootShare32B64u,
  deriveEmailOtpThresholdRootFromSecret32,
  deriveEmailOtpThresholdRootB64u,
  deriveEmailOtpUnlockAuthSeedFromSecret32,
  deriveEmailOtpUnlockAuthSeedB64u,
  encodeEmailOtpTuple,
} from '../helpers/emailOtpDerivation';
import {
  derive_email_otp_ecdsa_client_root_share32_from_secret32,
  derive_email_otp_threshold_root_from_secret32,
  derive_email_otp_unlock_auth_seed_from_secret32,
  initSync as initEmailOtpRuntimeWasmSync,
  init_email_otp_runtime,
} from '../../wasm/email_otp_runtime/pkg/email_otp_runtime.js';

const EMAIL_OTP_RUNTIME_WASM_URL = new URL(
  '../../wasm/email_otp_runtime/pkg/email_otp_runtime_bg.wasm',
  import.meta.url,
);
let emailOtpRuntimeWasmInitialized = false;

function ensureEmailOtpRuntimeWasm(): void {
  if (emailOtpRuntimeWasmInitialized) return;
  initEmailOtpRuntimeWasmSync({ module: readFileSync(EMAIL_OTP_RUNTIME_WASM_URL) });
  init_email_otp_runtime();
  emailOtpRuntimeWasmInitialized = true;
}

function utf8Bytes(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function zeroize(bytes: Uint8Array): void {
  bytes.fill(0);
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
    const ecdsaInfo = Buffer.from(encodeEmailOtpTuple([userId, EMAIL_OTP_ECDSA_DERIVATION_PATH]));
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

  test('WASM runtime matches canonical JS byte-oriented derivation', async () => {
    ensureEmailOtpRuntimeWasm();
    const clientSecret32 = Uint8Array.from(Array.from({ length: 32 }, (_, index) => index + 31));
    const walletId = ' alice.testnet ';
    const userId = ' alice.testnet ';
    const derivationPath = 'evm-signing/test-path';

    const expectedThresholdRoot = await deriveEmailOtpThresholdRootFromSecret32({
      clientSecret32,
      walletId,
    });
    const expectedEcdsaShare = await deriveEmailOtpEcdsaClientRootShare32FromSecret32({
      clientSecret32,
      walletId,
      userId,
      derivationPath,
    });
    const expectedUnlockSeed = await deriveEmailOtpUnlockAuthSeedFromSecret32({
      clientSecret32,
      walletId,
    });
    try {
      const wasmThresholdRoot = derive_email_otp_threshold_root_from_secret32(
        clientSecret32,
        walletId,
      );
      const wasmEcdsaShare = derive_email_otp_ecdsa_client_root_share32_from_secret32(
        clientSecret32,
        walletId,
        userId,
        derivationPath,
      );
      const wasmUnlockSeed = derive_email_otp_unlock_auth_seed_from_secret32(
        clientSecret32,
        walletId,
      );
      try {
        expect(Array.from(wasmThresholdRoot)).toEqual(Array.from(expectedThresholdRoot));
        expect(Array.from(wasmEcdsaShare)).toEqual(Array.from(expectedEcdsaShare));
        expect(Array.from(wasmUnlockSeed)).toEqual(Array.from(expectedUnlockSeed));
        expect(wasmThresholdRoot).toHaveLength(32);
        expect(wasmEcdsaShare).toHaveLength(32);
        expect(wasmUnlockSeed).toHaveLength(32);
      } finally {
        zeroize(wasmThresholdRoot);
        zeroize(wasmEcdsaShare);
        zeroize(wasmUnlockSeed);
      }
    } finally {
      zeroize(expectedThresholdRoot);
      zeroize(expectedEcdsaShare);
      zeroize(expectedUnlockSeed);
      zeroize(clientSecret32);
    }
  });

  test('WASM runtime returns owned derivation buffers that can be zeroized by the caller', async () => {
    ensureEmailOtpRuntimeWasm();
    const clientSecret32 = Uint8Array.from(Array.from({ length: 32 }, (_, index) => 255 - index));
    const walletId = 'alice.testnet';
    const userId = 'alice.testnet';
    const first = derive_email_otp_ecdsa_client_root_share32_from_secret32(
      clientSecret32,
      walletId,
      userId,
    );
    const firstSnapshot = Array.from(first);
    zeroize(first);

    const second = derive_email_otp_ecdsa_client_root_share32_from_secret32(
      clientSecret32,
      walletId,
      userId,
    );
    try {
      expect(Array.from(first)).toEqual(Array.from(new Uint8Array(32)));
      expect(Array.from(second)).toEqual(firstSnapshot);
      expect(second).not.toBe(first);
    } finally {
      zeroize(second);
      zeroize(clientSecret32);
    }
  });

  test('WASM runtime rejects non-32-byte Email OTP client secrets', async () => {
    ensureEmailOtpRuntimeWasm();
    expect(() =>
      derive_email_otp_threshold_root_from_secret32(new Uint8Array(31), 'alice.testnet'),
    ).toThrow('Email OTP client secret must be 32 bytes');
    expect(() =>
      derive_email_otp_ecdsa_client_root_share32_from_secret32(
        new Uint8Array(33),
        'alice.testnet',
        'alice.testnet',
      ),
    ).toThrow('Email OTP client secret must be 32 bytes');
    expect(() =>
      derive_email_otp_unlock_auth_seed_from_secret32(new Uint8Array(0), 'alice.testnet'),
    ).toThrow('Email OTP client secret must be 32 bytes');
  });
});
