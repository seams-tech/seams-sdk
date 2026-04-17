import { toOptionalTrimmedString } from '@shared/utils/validation';
import type {
  SigningRootSecretShareId,
  SigningRootSecretShareWireV1,
  SealedSigningRootSecretShare,
} from './signingRootSecretShareWires';
import { parseSigningRootSecretShareWireV1, zeroizeBytes } from './signingRootSecretShareWires';
import type { SigningRootSecretDecryptAdapter } from './signingRootSecretResolverAdapters';

const AES_GCM_NONCE_LENGTH = 12;
const AES_GCM_KEY_LENGTH_BITS = 256;
const AES_GCM_KEY_LENGTH_BYTES = AES_GCM_KEY_LENGTH_BITS / 8;
const SIGNING_ROOT_SECRET_SHARE_SEAL_MAGIC = new Uint8Array([0x74, 0x70, 0x72, 0x73, 0x01]); // "tprs" + v1
const SIGNING_ROOT_SECRET_SHARE_SEAL_AAD_DOMAIN = 'tatchi/signing-root-share/aes-gcm/v1';

export type SigningRootSecretShareKekResolutionInput = {
  readonly signingRootId: string;
  readonly shareId: SigningRootSecretShareId;
  readonly signingRootVersion?: string;
  readonly kekId: string;
};

export type SigningRootSecretShareKekResolver = (
  input: SigningRootSecretShareKekResolutionInput,
) => CryptoKey | Uint8Array | Promise<CryptoKey | Uint8Array>;

export type SealSigningRootSecretShareWireInput = SigningRootSecretShareKekResolutionInput & {
  readonly plaintextShareWire: SigningRootSecretShareWireV1 | Uint8Array;
  readonly resolveKek: SigningRootSecretShareKekResolver;
};

function requireCrypto(): Crypto {
  if (
    typeof globalThis.crypto === 'undefined' ||
    typeof globalThis.crypto.getRandomValues !== 'function' ||
    !globalThis.crypto.subtle
  ) {
    throw new Error('WebCrypto getRandomValues and subtle are required for signing-root sealing');
  }
  return globalThis.crypto;
}

function toArrayBufferCopy(bytes: Uint8Array): ArrayBuffer {
  const ab = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(ab).set(bytes);
  return ab;
}

function concatBytes(parts: readonly Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.byteLength, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.byteLength;
  }
  return out;
}

function u8(value: number): Uint8Array {
  return new Uint8Array([value & 0xff]);
}

function u16be(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) {
    throw new Error('length-prefixed signing-root seal field is too large');
  }
  return new Uint8Array([(value >>> 8) & 0xff, value & 0xff]);
}

function lengthPrefixedUtf8(label: string, value: string): Uint8Array {
  const encoded = new TextEncoder().encode(value);
  if (encoded.byteLength > 0xffff) {
    throw new Error(`${label} is too large for signing-root seal AAD`);
  }
  return concatBytes([u16be(encoded.byteLength), encoded]);
}

function normalizeResolutionInput(input: {
  readonly signingRootId: unknown;
  readonly shareId: unknown;
  readonly signingRootVersion?: unknown;
  readonly kekId: unknown;
}): SigningRootSecretShareKekResolutionInput {
  const signingRootId = toOptionalTrimmedString(input.signingRootId);
  const kekId = toOptionalTrimmedString(input.kekId);
  if (!signingRootId) throw new Error('signingRootId is required');
  if (!kekId) throw new Error('kekId is required');
  if (input.shareId !== 1 && input.shareId !== 2 && input.shareId !== 3) {
    throw new Error('shareId must be 1, 2, or 3');
  }
  const signingRootVersion = toOptionalTrimmedString(input.signingRootVersion);
  return {
    signingRootId,
    shareId: input.shareId,
    ...(signingRootVersion ? { signingRootVersion } : {}),
    kekId,
  };
}

function aadForSigningRootSecretShare(input: SigningRootSecretShareKekResolutionInput): Uint8Array {
  return concatBytes([
    lengthPrefixedUtf8('domain', SIGNING_ROOT_SECRET_SHARE_SEAL_AAD_DOMAIN),
    lengthPrefixedUtf8('signingRootId', input.signingRootId),
    lengthPrefixedUtf8('signingRootVersion', input.signingRootVersion || ''),
    u8(input.shareId),
    lengthPrefixedUtf8('kekId', input.kekId),
  ]);
}

function parseSealedEnvelope(sealedShare: Uint8Array): {
  readonly nonce: Uint8Array;
  readonly ciphertext: Uint8Array;
} {
  const minLength = SIGNING_ROOT_SECRET_SHARE_SEAL_MAGIC.byteLength + AES_GCM_NONCE_LENGTH + 16;
  if (sealedShare.byteLength < minLength) {
    throw new Error('sealed signing-root share envelope is too short');
  }
  for (let i = 0; i < SIGNING_ROOT_SECRET_SHARE_SEAL_MAGIC.byteLength; i++) {
    if (sealedShare[i] !== SIGNING_ROOT_SECRET_SHARE_SEAL_MAGIC[i]) {
      throw new Error('sealed signing-root share envelope has invalid magic');
    }
  }
  const nonceStart = SIGNING_ROOT_SECRET_SHARE_SEAL_MAGIC.byteLength;
  const ciphertextStart = nonceStart + AES_GCM_NONCE_LENGTH;
  return {
    nonce: sealedShare.slice(nonceStart, ciphertextStart),
    ciphertext: sealedShare.slice(ciphertextStart),
  };
}

function assertAes256GcmCryptoKey(key: CryptoKey, usages: readonly KeyUsage[]): CryptoKey {
  const algorithm = key.algorithm as AesKeyAlgorithm;
  if (algorithm.name !== 'AES-GCM' || algorithm.length !== AES_GCM_KEY_LENGTH_BITS) {
    throw new Error('signing-root KEK CryptoKey must be AES-256-GCM');
  }
  for (const usage of usages) {
    if (!key.usages.includes(usage)) {
      throw new Error(`signing-root KEK CryptoKey is missing ${usage} usage`);
    }
  }
  return key;
}

async function importAesGcmKek(raw: Uint8Array, usages: KeyUsage[]): Promise<CryptoKey> {
  if (raw.byteLength !== AES_GCM_KEY_LENGTH_BYTES) {
    throw new Error(`signing-root KEK must be ${AES_GCM_KEY_LENGTH_BYTES} bytes`);
  }
  const keyBytes = new Uint8Array(raw);
  try {
    return await requireCrypto().subtle.importKey(
      'raw',
      toArrayBufferCopy(keyBytes),
      { name: 'AES-GCM' },
      false,
      usages,
    );
  } finally {
    zeroizeBytes(keyBytes);
  }
}

async function resolveAesGcmKek(
  input: SigningRootSecretShareKekResolutionInput & { readonly resolveKek: SigningRootSecretShareKekResolver },
  usages: KeyUsage[],
): Promise<CryptoKey> {
  const request: SigningRootSecretShareKekResolutionInput = {
    signingRootId: input.signingRootId,
    shareId: input.shareId,
    ...(input.signingRootVersion ? { signingRootVersion: input.signingRootVersion } : {}),
    kekId: input.kekId,
  };
  const kek = await input.resolveKek(request);
  if (typeof CryptoKey !== 'undefined' && kek instanceof CryptoKey) {
    return assertAes256GcmCryptoKey(kek, usages);
  }
  if (kek instanceof Uint8Array) return await importAesGcmKek(kek, usages);
  throw new Error('signing-root KEK resolver returned an unsupported key type');
}

export async function sealSigningRootSecretShareWireV1(
  input: SealSigningRootSecretShareWireInput,
): Promise<Uint8Array> {
  const metadata = normalizeResolutionInput(input);
  const parsed = parseSigningRootSecretShareWireV1(input.plaintextShareWire);
  if (!parsed.ok) throw new Error(parsed.message);
  if (parsed.value[0] !== metadata.shareId) {
    zeroizeBytes(parsed.value);
    throw new Error('plaintext signing-root share id does not match seal metadata');
  }

  const crypto = requireCrypto();
  const nonce = crypto.getRandomValues(new Uint8Array(AES_GCM_NONCE_LENGTH));
  const aad = aadForSigningRootSecretShare(metadata);
  const key = await resolveAesGcmKek({ ...metadata, resolveKek: input.resolveKek }, ['encrypt']);
  try {
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 },
        key,
        toArrayBufferCopy(parsed.value),
      ),
    );
    return concatBytes([SIGNING_ROOT_SECRET_SHARE_SEAL_MAGIC, nonce, ciphertext]);
  } finally {
    zeroizeBytes(parsed.value);
  }
}

export async function openSigningRootSecretShareWireV1(input: {
  readonly record: SealedSigningRootSecretShare;
  readonly resolveKek: SigningRootSecretShareKekResolver;
}): Promise<Uint8Array> {
  const metadata = normalizeResolutionInput({
    signingRootId: input.record.signingRootId,
    shareId: input.record.shareId,
    signingRootVersion: input.record.signingRootVersion,
    kekId: input.record.kekId,
  });
  const envelope = parseSealedEnvelope(input.record.sealedShare);
  const aad = aadForSigningRootSecretShare(metadata);
  const key = await resolveAesGcmKek({ ...metadata, resolveKek: input.resolveKek }, ['decrypt']);
  try {
    const plaintext = new Uint8Array(
      await requireCrypto().subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: envelope.nonce,
          additionalData: aad,
          tagLength: 128,
        },
        key,
        toArrayBufferCopy(envelope.ciphertext),
      ),
    );

    const parsed = parseSigningRootSecretShareWireV1(plaintext);
    if (!parsed.ok) {
      zeroizeBytes(plaintext);
      throw new Error(parsed.message);
    }
    zeroizeBytes(parsed.value);
    if (plaintext[0] !== input.record.shareId) {
      zeroizeBytes(plaintext);
      throw new Error('decrypted signing-root share id does not match its record');
    }
    return plaintext;
  } finally {
    zeroizeBytes(envelope.nonce);
    zeroizeBytes(envelope.ciphertext);
    zeroizeBytes(aad);
  }
}

export function createSigningRootSecretAesGcmDecryptAdapter(input: {
  readonly resolveKek: SigningRootSecretShareKekResolver;
}): SigningRootSecretDecryptAdapter {
  return {
    adapterKind: 'local-aes-gcm-kek',
    decryptSigningRootSecretShare: (record) =>
      openSigningRootSecretShareWireV1({ record, resolveKek: input.resolveKek }),
  };
}
