import { test, expect } from '@playwright/test';
import { hkdfSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import {
  EMAIL_OTP_UNLOCK_AUTH_SALT_V2,
  deriveEmailOtpUnlockAuthSeedFromSecret32,
  deriveEmailOtpUnlockAuthSeedB64u,
  encodeEmailOtpTuple,
} from '../helpers/emailOtpDerivation';
import {
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

  test('derives a stable unlock branch', async () => {
    const clientSecretB64u = base64UrlEncode(
      Uint8Array.from(Array.from({ length: 32 }, (_, index) => 255 - index)),
    );
    const walletId = 'alice.testnet';
    const unlockInfo = Buffer.from(encodeEmailOtpTuple([walletId]));
    const expectedUnlock = base64UrlEncode(
      hkdfSync(
        'sha256',
        Buffer.from(base64UrlDecode(clientSecretB64u)),
        Buffer.from(EMAIL_OTP_UNLOCK_AUTH_SALT_V2, 'utf8'),
        unlockInfo,
        32,
      ),
    );

    const actualUnlock = await deriveEmailOtpUnlockAuthSeedB64u({
      clientSecretB64u,
      walletId,
    });

    expect(actualUnlock).toBe(expectedUnlock);
    expect(base64UrlDecode(actualUnlock)).toHaveLength(32);
  });

  test('WASM runtime matches canonical JS byte-oriented derivation', async () => {
    ensureEmailOtpRuntimeWasm();
    const clientSecret32 = Uint8Array.from(Array.from({ length: 32 }, (_, index) => index + 31));
    const walletId = ' alice.testnet ';
    const expectedUnlockSeed = await deriveEmailOtpUnlockAuthSeedFromSecret32({
      clientSecret32,
      walletId,
    });
    try {
      const wasmUnlockSeed = derive_email_otp_unlock_auth_seed_from_secret32(
        clientSecret32,
        walletId,
      );
      try {
        expect(Array.from(wasmUnlockSeed)).toEqual(Array.from(expectedUnlockSeed));
        expect(wasmUnlockSeed).toHaveLength(32);
      } finally {
        zeroize(wasmUnlockSeed);
      }
    } finally {
      zeroize(expectedUnlockSeed);
      zeroize(clientSecret32);
    }
  });

  test('WASM runtime returns owned derivation buffers that can be zeroized by the caller', async () => {
    ensureEmailOtpRuntimeWasm();
    const clientSecret32 = Uint8Array.from(Array.from({ length: 32 }, (_, index) => 255 - index));
    const walletId = 'alice.testnet';
    const first = derive_email_otp_unlock_auth_seed_from_secret32(clientSecret32, walletId);
    const firstSnapshot = Array.from(first);
    zeroize(first);

    const second = derive_email_otp_unlock_auth_seed_from_secret32(clientSecret32, walletId);
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
      derive_email_otp_unlock_auth_seed_from_secret32(new Uint8Array(31), 'alice.testnet'),
    ).toThrow('Email OTP client secret must be 32 bytes');
    expect(() =>
      derive_email_otp_unlock_auth_seed_from_secret32(new Uint8Array(0), 'alice.testnet'),
    ).toThrow('Email OTP client secret must be 32 bytes');
  });
});
