import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import { decodeNearSecretKey, toPublicKeyStringFromSecretKey } from '../nearKeys';

export type NearTxUnsignedBorshOutput = {
  unsignedTransactionBorshB64u: string;
  signingDigestB64u: string;
};

export type FinalizeNearTxFromSignatureOutput = {
  signedTransactionBorshB64u: string;
  transactionHash: string;
};

const ED25519_PKCS8_SEED_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object') {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function requireNonEmptyString(value: unknown, label: string): string {
  const text = String(value || '').trim();
  if (!text) throw new Error(`${label} is required`);
  return text;
}

export function requireSingleUnsignedNearTxBorshOutput(
  value: unknown,
): NearTxUnsignedBorshOutput {
  if (!Array.isArray(value) || value.length !== 1) {
    throw new Error('Expected exactly one unsigned NEAR transaction from signer WASM');
  }
  const record = requireRecord(value[0], 'unsigned NEAR transaction output');
  return {
    unsignedTransactionBorshB64u: requireNonEmptyString(
      record.unsignedTransactionBorshB64u,
      'unsignedTransactionBorshB64u',
    ),
    signingDigestB64u: requireNonEmptyString(record.signingDigestB64u, 'signingDigestB64u'),
  };
}

export function requireFinalizeNearTxFromSignatureOutput(
  value: unknown,
): FinalizeNearTxFromSignatureOutput {
  const record = requireRecord(value, 'finalized NEAR transaction output');
  return {
    signedTransactionBorshB64u: requireNonEmptyString(
      record.signedTransactionBorshB64u,
      'signedTransactionBorshB64u',
    ),
    transactionHash: requireNonEmptyString(record.transactionHash, 'transactionHash'),
  };
}

function createEd25519Pkcs8FromSeed(seed32: Uint8Array): Uint8Array {
  if (seed32.length !== 32) {
    throw new Error(`Ed25519 seed must be 32 bytes, got ${seed32.length}`);
  }
  const pkcs8 = new Uint8Array(ED25519_PKCS8_SEED_PREFIX.length + seed32.length);
  pkcs8.set(ED25519_PKCS8_SEED_PREFIX, 0);
  pkcs8.set(seed32, ED25519_PKCS8_SEED_PREFIX.length);
  return pkcs8;
}

export async function signNearDigestWithSecretKey(args: {
  nearPrivateKey: string;
  signingDigestB64u: string;
  expectedSignerPublicKey: string;
}): Promise<string> {
  const actualPublicKey = toPublicKeyStringFromSecretKey(args.nearPrivateKey);
  if (actualPublicKey !== args.expectedSignerPublicKey) {
    throw new Error('NEAR private key does not match expected signer public key');
  }
  const digest = base64UrlDecode(args.signingDigestB64u);
  if (digest.length !== 32) {
    throw new Error(`NEAR signing digest must be 32 bytes, got ${digest.length}`);
  }

  const secretKeyBytes = decodeNearSecretKey(args.nearPrivateKey);
  const seed32 = new Uint8Array(secretKeyBytes.subarray(0, 32));
  const pkcs8 = createEd25519Pkcs8FromSeed(seed32);
  try {
    const signature = await signEd25519MessageWithPkcs8(pkcs8, digest);
    if (signature.length !== 64) {
      throw new Error(`Ed25519 signature must be 64 bytes, got ${signature.length}`);
    }
    return base64UrlEncode(signature);
  } finally {
    secretKeyBytes.fill(0);
    seed32.fill(0);
    pkcs8.fill(0);
  }
}

async function signEd25519MessageWithPkcs8(
  pkcs8: Uint8Array,
  message: Uint8Array,
): Promise<Uint8Array> {
  const nodeSignature = await signEd25519MessageWithNodeCrypto(pkcs8, message);
  if (nodeSignature) return nodeSignature;
  const webCryptoSignature = await signEd25519MessageWithWebCrypto(pkcs8, message);
  if (webCryptoSignature) return webCryptoSignature;
  throw new Error('Ed25519 private-key signing is unavailable in this runtime');
}

async function signEd25519MessageWithNodeCrypto(
  pkcs8: Uint8Array,
  message: Uint8Array,
): Promise<Uint8Array | null> {
  try {
    const nodeCrypto = await import('node:crypto');
    const { Buffer } = await import('node:buffer');
    const key = nodeCrypto.createPrivateKey({
      key: Buffer.from(pkcs8),
      format: 'der',
      type: 'pkcs8',
    });
    return new Uint8Array(nodeCrypto.sign(null, message, key));
  } catch {
    return null;
  }
}

async function signEd25519MessageWithWebCrypto(
  pkcs8: Uint8Array,
  message: Uint8Array,
): Promise<Uint8Array | null> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) return null;
  try {
    const key = await subtle.importKey('pkcs8', copyToArrayBuffer(pkcs8), 'Ed25519', false, [
      'sign',
    ]);
    return new Uint8Array(await subtle.sign('Ed25519', key, copyToArrayBuffer(message)));
  } catch {
    return null;
  }
}

function copyToArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(bytes.length);
  new Uint8Array(buffer).set(bytes);
  return buffer;
}
