import {
  email_recovery_chacha20poly1305_decrypt,
  email_recovery_chacha20poly1305_encrypt,
  email_recovery_hkdf_sha256_32,
  email_recovery_sha256,
  email_recovery_x25519_public_key_from_secret,
  email_recovery_x25519_shared_secret,
} from '../../../../wasm/near_signer/pkg/wasm_signer_worker.js';
import { ensureNearSignerWasm, isNearSignerWasmReady } from '../core/nearSignerWasmRuntime';

export async function ensureEmailRecoverySignerWasm(): Promise<void> {
  await ensureNearSignerWasm();
}

function requireReady(): void {
  if (!isNearSignerWasmReady()) {
    throw new Error('[email-recovery] signer WASM is not initialized');
  }
}

function checkedBytes(label: string, value: Uint8Array, expectedLength: number): Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new Error(`${label} must return Uint8Array`);
  }
  if (value.length !== expectedLength) {
    throw new Error(`${label} must be ${expectedLength} bytes (got ${value.length})`);
  }
  return value;
}

export async function x25519PublicKeyFromSecret(secretKey32: Uint8Array): Promise<Uint8Array> {
  await ensureEmailRecoverySignerWasm();
  const out = email_recovery_x25519_public_key_from_secret(secretKey32) as Uint8Array;
  return checkedBytes('email_recovery_x25519_public_key_from_secret', out, 32);
}

export async function x25519SharedSecret(input: {
  secretKey32: Uint8Array;
  peerPublicKey32: Uint8Array;
}): Promise<Uint8Array> {
  await ensureEmailRecoverySignerWasm();
  const out = email_recovery_x25519_shared_secret(
    input.secretKey32,
    input.peerPublicKey32,
  ) as Uint8Array;
  return checkedBytes('email_recovery_x25519_shared_secret', out, 32);
}

export async function hkdfSha25632(input: {
  ikm: Uint8Array;
  info: Uint8Array;
}): Promise<Uint8Array> {
  await ensureEmailRecoverySignerWasm();
  const out = email_recovery_hkdf_sha256_32(input.ikm, input.info) as Uint8Array;
  return checkedBytes('email_recovery_hkdf_sha256_32', out, 32);
}

export async function chacha20poly1305Encrypt(input: {
  key32: Uint8Array;
  nonce12: Uint8Array;
  aad: Uint8Array;
  plaintext: Uint8Array;
}): Promise<Uint8Array> {
  await ensureEmailRecoverySignerWasm();
  const out = email_recovery_chacha20poly1305_encrypt(
    input.key32,
    input.nonce12,
    input.aad,
    input.plaintext,
  ) as Uint8Array;
  if (!(out instanceof Uint8Array) || out.length === 0) {
    throw new Error('email_recovery_chacha20poly1305_encrypt returned empty ciphertext');
  }
  return out;
}

export async function chacha20poly1305Decrypt(input: {
  key32: Uint8Array;
  nonce12: Uint8Array;
  aad: Uint8Array;
  ciphertext: Uint8Array;
}): Promise<Uint8Array> {
  await ensureEmailRecoverySignerWasm();
  const out = email_recovery_chacha20poly1305_decrypt(
    input.key32,
    input.nonce12,
    input.aad,
    input.ciphertext,
  ) as Uint8Array;
  if (!(out instanceof Uint8Array)) {
    throw new Error('email_recovery_chacha20poly1305_decrypt must return Uint8Array');
  }
  return out;
}

export async function sha256Bytes(input: Uint8Array): Promise<Uint8Array> {
  await ensureEmailRecoverySignerWasm();
  requireReady();
  const out = email_recovery_sha256(input) as Uint8Array;
  return checkedBytes('email_recovery_sha256', out, 32);
}
