import { test, expect } from '@playwright/test';
import { hkdfSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import {
  EMAIL_OTP_ECDSA_CLIENT_SHARE_SALT_V2,
  EMAIL_OTP_ECDSA_DERIVATION_PATH,
  EMAIL_OTP_UNLOCK_AUTH_SALT_V2,
  deriveEmailOtpEcdsaClientRootShare32FromSecret32,
  deriveEmailOtpEcdsaClientRootShare32B64u,
  deriveEmailOtpUnlockAuthSeedFromSecret32,
  deriveEmailOtpUnlockAuthSeedB64u,
  encodeEmailOtpTuple,
} from '../helpers/emailOtpDerivation';
import {
  derive_email_otp_ecdsa_client_root_share32_from_secret32,
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

  test('derives stable ECDSA and unlock branches with label separation', async () => {
    const clientSecretB64u = base64UrlEncode(
      Uint8Array.from(Array.from({ length: 32 }, (_, index) => 255 - index)),
    );
    const walletId = 'alice.testnet';
    const userId = 'alice.testnet';
    const ecdsaInfo = Buffer.from(
      encodeEmailOtpTuple([walletId, userId, EMAIL_OTP_ECDSA_DERIVATION_PATH]),
    );
    const unlockInfo = Buffer.from(encodeEmailOtpTuple([walletId]));
    // Parallel derivation: both branches take the client secret as IKM
    // directly. Neither is a function of the retired root intermediate.
    const expectedEcdsa = base64UrlEncode(
      hkdfSync(
        'sha256',
        Buffer.from(base64UrlDecode(clientSecretB64u)),
        Buffer.from(EMAIL_OTP_ECDSA_CLIENT_SHARE_SALT_V2, 'utf8'),
        ecdsaInfo,
        32,
      ),
    );
    const expectedUnlock = base64UrlEncode(
      hkdfSync(
        'sha256',
        Buffer.from(base64UrlDecode(clientSecretB64u)),
        Buffer.from(EMAIL_OTP_UNLOCK_AUTH_SALT_V2, 'utf8'),
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

  test('the retired email-otp/root intermediate cannot compute the ECDSA share or unlock seed', async () => {
    const clientSecretB64u = base64UrlEncode(
      Uint8Array.from(Array.from({ length: 32 }, (_, index) => index * 3 + 1)),
    );
    const walletId = 'alice.testnet';
    const userId = 'alice.testnet';
    // Recompute the retired v1 chain parent locally. No production code
    // derives it any more, so the test owns the computation it is disproving.
    const retiredChainParent = base64UrlEncode(
      hkdfSync(
        'sha256',
        Buffer.from(base64UrlDecode(clientSecretB64u)),
        Buffer.from('seams/email-otp/root/v1', 'utf8'),
        Buffer.from(encodeEmailOtpTuple([walletId])),
        32,
      ),
    );

    // The retired v1 scheme derived both values from this intermediate plus
    // public info. It is a sibling of the Ed25519 Yao Client root, not its
    // parent. Reconstruct the chained computation with the intermediate as IKM
    // and assert it matches neither live output, under old or new labels.
    const chainedCandidates = [
      {
        salt: 'seams/email-otp/threshold-client-share/v1',
        info: [userId, EMAIL_OTP_ECDSA_DERIVATION_PATH],
      },
      {
        salt: EMAIL_OTP_ECDSA_CLIENT_SHARE_SALT_V2,
        info: [walletId, userId, EMAIL_OTP_ECDSA_DERIVATION_PATH],
      },
      { salt: 'seams/email-otp/unlock-auth/v1', info: [walletId] },
      { salt: EMAIL_OTP_UNLOCK_AUTH_SALT_V2, info: [walletId] },
    ];
    const ecdsaShare = await deriveEmailOtpEcdsaClientRootShare32B64u({
      clientSecretB64u,
      walletId,
      userId,
    });
    const unlockSeed = await deriveEmailOtpUnlockAuthSeedB64u({ clientSecretB64u, walletId });
    for (const candidate of chainedCandidates) {
      const fromRoot = base64UrlEncode(
        hkdfSync(
          'sha256',
          Buffer.from(base64UrlDecode(retiredChainParent)),
          Buffer.from(candidate.salt, 'utf8'),
          Buffer.from(encodeEmailOtpTuple(candidate.info)),
          32,
        ),
      );
      expect(fromRoot).not.toBe(ecdsaShare);
      expect(fromRoot).not.toBe(unlockSeed);
    }
  });

  test('WASM runtime matches canonical JS byte-oriented derivation', async () => {
    ensureEmailOtpRuntimeWasm();
    const clientSecret32 = Uint8Array.from(Array.from({ length: 32 }, (_, index) => index + 31));
    const walletId = ' alice.testnet ';
    const userId = ' alice.testnet ';
    const derivationPath = 'evm-signing/test-path';

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
        expect(Array.from(wasmEcdsaShare)).toEqual(Array.from(expectedEcdsaShare));
        expect(Array.from(wasmUnlockSeed)).toEqual(Array.from(expectedUnlockSeed));
        expect(wasmEcdsaShare).toHaveLength(32);
        expect(wasmUnlockSeed).toHaveLength(32);
      } finally {
        zeroize(wasmEcdsaShare);
        zeroize(wasmUnlockSeed);
      }
    } finally {
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
      derive_email_otp_unlock_auth_seed_from_secret32(new Uint8Array(31), 'alice.testnet'),
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
