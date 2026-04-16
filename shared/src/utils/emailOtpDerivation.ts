import { base64UrlDecode, base64UrlEncode } from './encoders';

export const EMAIL_OTP_THRESHOLD_ROOT_SALT_V1 = 'tatchi/email-otp/root/v1';
export const EMAIL_OTP_ECDSA_CLIENT_SHARE_SALT_V1 =
  'tatchi/email-otp/threshold-client-share/v1';
export const EMAIL_OTP_UNLOCK_AUTH_SALT_V1 = 'tatchi/email-otp/unlock-auth/v1';
export const EMAIL_OTP_ECDSA_DERIVATION_PATH_V1 = 'evm-signing';

const HKDF_SHA256_LENGTH = 32;
const textEncoder = new TextEncoder();

function zeroizeBytes(bytes?: Uint8Array | null): void {
  if (!(bytes instanceof Uint8Array)) return;
  bytes.fill(0);
}

function requireSubtleCrypto(): SubtleCrypto {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new Error('WebCrypto subtle API is unavailable in this runtime');
  }
  return subtle;
}

function utf8Bytes(value: string): Uint8Array {
  return textEncoder.encode(String(value));
}

function concatBytes(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function normalizeFieldBytes(value: string | Uint8Array): Uint8Array {
  if (typeof value === 'string') return utf8Bytes(value);
  if (value instanceof Uint8Array) return value;
  throw new Error('Email OTP tuple fields must be UTF-8 strings or Uint8Array values');
}

function encodeU16Be(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) {
    throw new Error('Email OTP tuple field length must fit in u16');
  }
  return Uint8Array.from([(value >>> 8) & 0xff, value & 0xff]);
}

export function encodeEmailOtpTuple(fields: Array<string | Uint8Array>): Uint8Array {
  return concatBytes(
    fields.map((field) => {
      const bytes = normalizeFieldBytes(field);
      return concatBytes([encodeU16Be(bytes.length), bytes]);
    }),
  );
}

async function hmacSha256(keyBytes: Uint8Array, dataBytes: Uint8Array): Promise<Uint8Array> {
  const subtle = requireSubtleCrypto();
  const key = await subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const mac = await subtle.sign('HMAC', key, dataBytes);
  return new Uint8Array(mac);
}

async function hkdfExtractSha256(args: {
  ikm: Uint8Array;
  salt: Uint8Array;
}): Promise<Uint8Array> {
  const salt = args.salt.length > 0 ? args.salt : new Uint8Array(HKDF_SHA256_LENGTH);
  return hmacSha256(salt, args.ikm);
}

async function hkdfExpandSha256(args: {
  prk: Uint8Array;
  info: Uint8Array;
  length: number;
}): Promise<Uint8Array> {
  if (!Number.isInteger(args.length) || args.length <= 0) {
    throw new Error('HKDF output length must be a positive integer');
  }
  const blocksNeeded = Math.ceil(args.length / HKDF_SHA256_LENGTH);
  if (blocksNeeded > 255) {
    throw new Error('HKDF output length exceeds SHA-256 single-expand limit');
  }

  const out = new Uint8Array(args.length);
  let offset = 0;
  let previous = new Uint8Array(0);
  try {
    for (let counter = 1; counter <= blocksNeeded; counter += 1) {
      const blockInput = concatBytes([previous, args.info, Uint8Array.from([counter])]);
      try {
        const next = await hmacSha256(args.prk, blockInput);
        zeroizeBytes(previous);
        previous = next;
      } finally {
        zeroizeBytes(blockInput);
      }
      const bytesToCopy = Math.min(previous.length, args.length - offset);
      out.set(previous.subarray(0, bytesToCopy), offset);
      offset += bytesToCopy;
    }
    return out;
  } finally {
    zeroizeBytes(previous);
  }
}

export async function hkdfSha256(args: {
  ikm: Uint8Array;
  salt: string | Uint8Array;
  info: Uint8Array;
  length?: number;
}): Promise<Uint8Array> {
  const salt = normalizeFieldBytes(args.salt);
  const prk = await hkdfExtractSha256({
    ikm: args.ikm,
    salt,
  });
  try {
    return await hkdfExpandSha256({
      prk,
      info: args.info,
      length: args.length ?? HKDF_SHA256_LENGTH,
    });
  } finally {
    zeroizeBytes(prk);
    if (typeof args.salt === 'string') {
      zeroizeBytes(salt);
    }
  }
}

export function decodeEmailOtpClientSecret32B64u(clientSecretB64u: string): Uint8Array {
  const secret = base64UrlDecode(String(clientSecretB64u || '').trim());
  if (secret.length !== 32) {
    throw new Error('Email OTP client secret must decode to 32 bytes');
  }
  return secret;
}

export async function deriveEmailOtpThresholdRootFromSecret32(args: {
  clientSecret32: Uint8Array;
  walletId: string;
}): Promise<Uint8Array> {
  if (!(args.clientSecret32 instanceof Uint8Array) || args.clientSecret32.length !== 32) {
    throw new Error('Email OTP client secret must be 32 bytes');
  }
  const info = encodeEmailOtpTuple([String(args.walletId || '').trim()]);
  try {
    return await hkdfSha256({
      ikm: args.clientSecret32,
      salt: EMAIL_OTP_THRESHOLD_ROOT_SALT_V1,
      info,
    });
  } finally {
    zeroizeBytes(info);
  }
}

export async function deriveEmailOtpThresholdRoot(args: {
  clientSecretB64u: string;
  walletId: string;
}): Promise<Uint8Array> {
  const clientSecret32 = decodeEmailOtpClientSecret32B64u(args.clientSecretB64u);
  try {
    return await deriveEmailOtpThresholdRootFromSecret32({
      clientSecret32,
      walletId: args.walletId,
    });
  } finally {
    zeroizeBytes(clientSecret32);
  }
}

export async function deriveEmailOtpThresholdRootB64u(args: {
  clientSecretB64u: string;
  walletId: string;
}): Promise<string> {
  const thresholdRoot = await deriveEmailOtpThresholdRoot(args);
  try {
    return base64UrlEncode(thresholdRoot);
  } finally {
    zeroizeBytes(thresholdRoot);
  }
}

export async function deriveEmailOtpEcdsaClientRootShare32FromSecret32(args: {
  clientSecret32: Uint8Array;
  walletId: string;
  userId: string;
  derivationPath?: string;
}): Promise<Uint8Array> {
  const thresholdRoot = await deriveEmailOtpThresholdRootFromSecret32({
    clientSecret32: args.clientSecret32,
    walletId: args.walletId,
  });
  const info = encodeEmailOtpTuple([
    String(args.userId || '').trim(),
    String(args.derivationPath || EMAIL_OTP_ECDSA_DERIVATION_PATH_V1).trim(),
  ]);
  try {
    return await hkdfSha256({
      ikm: thresholdRoot,
      salt: EMAIL_OTP_ECDSA_CLIENT_SHARE_SALT_V1,
      info,
    });
  } finally {
    zeroizeBytes(info);
    zeroizeBytes(thresholdRoot);
  }
}

export async function deriveEmailOtpEcdsaClientRootShare32(args: {
  clientSecretB64u: string;
  walletId: string;
  userId: string;
  derivationPath?: string;
}): Promise<Uint8Array> {
  const clientSecret32 = decodeEmailOtpClientSecret32B64u(args.clientSecretB64u);
  try {
    return await deriveEmailOtpEcdsaClientRootShare32FromSecret32({
      clientSecret32,
      walletId: args.walletId,
      userId: args.userId,
      derivationPath: args.derivationPath,
    });
  } finally {
    zeroizeBytes(clientSecret32);
  }
}

export async function deriveEmailOtpEcdsaClientRootShare32B64u(args: {
  clientSecretB64u: string;
  walletId: string;
  userId: string;
  derivationPath?: string;
}): Promise<string> {
  const clientRootShare32 = await deriveEmailOtpEcdsaClientRootShare32(args);
  try {
    return base64UrlEncode(clientRootShare32);
  } finally {
    zeroizeBytes(clientRootShare32);
  }
}

export async function deriveEmailOtpUnlockAuthSeedFromSecret32(args: {
  clientSecret32: Uint8Array;
  walletId: string;
}): Promise<Uint8Array> {
  const thresholdRoot = await deriveEmailOtpThresholdRootFromSecret32({
    clientSecret32: args.clientSecret32,
    walletId: args.walletId,
  });
  const info = encodeEmailOtpTuple([String(args.walletId || '').trim()]);
  try {
    return await hkdfSha256({
      ikm: thresholdRoot,
      salt: EMAIL_OTP_UNLOCK_AUTH_SALT_V1,
      info,
    });
  } finally {
    zeroizeBytes(info);
    zeroizeBytes(thresholdRoot);
  }
}

export async function deriveEmailOtpUnlockAuthSeed(args: {
  clientSecretB64u: string;
  walletId: string;
}): Promise<Uint8Array> {
  const clientSecret32 = decodeEmailOtpClientSecret32B64u(args.clientSecretB64u);
  try {
    return await deriveEmailOtpUnlockAuthSeedFromSecret32({
      clientSecret32,
      walletId: args.walletId,
    });
  } finally {
    zeroizeBytes(clientSecret32);
  }
}

export async function deriveEmailOtpUnlockAuthSeedB64u(args: {
  clientSecretB64u: string;
  walletId: string;
}): Promise<string> {
  const unlockAuthSeed = await deriveEmailOtpUnlockAuthSeed(args);
  try {
    return base64UrlEncode(unlockAuthSeed);
  } finally {
    zeroizeBytes(unlockAuthSeed);
  }
}
