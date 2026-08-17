import { base64UrlEncode } from './encoding';

const DEFAULT_SECURE_RANDOM_ID_BYTES = 32;
const BASE36_ALPHABET = '0123456789abcdefghijklmnopqrstuvwxyz';

type CryptoRandomSource = {
  getRandomValues?: (array: Uint8Array) => Uint8Array;
};

export function secureRandomBytes(
  length = DEFAULT_SECURE_RANDOM_ID_BYTES,
  label = 'secure random bytes',
): Uint8Array {
  const byteLength = Math.max(1, Math.floor(Number(length) || 0));
  const cryptoApi = (globalThis as { crypto?: CryptoRandomSource }).crypto;
  if (typeof cryptoApi?.getRandomValues !== 'function') {
    throw new Error(`WebCrypto getRandomValues is required for ${label}`);
  }
  return cryptoApi.getRandomValues(new Uint8Array(byteLength));
}

export function secureRandomBase64Url(
  byteLength = DEFAULT_SECURE_RANDOM_ID_BYTES,
  label = 'secure random id',
): string {
  return base64UrlEncode(secureRandomBytes(byteLength, label));
}

function secureRandomUintBelow(maxExclusive: number, label: string): number {
  const max = Math.floor(Number(maxExclusive) || 0);
  if (max <= 0 || max > 256) {
    throw new Error(`Invalid upper bound for ${label}`);
  }
  const rejectionLimit = Math.floor(256 / max) * max;
  for (;;) {
    const candidate = secureRandomBytes(1, label)[0] ?? 0;
    if (candidate < rejectionLimit) return candidate % max;
  }
}

export function secureRandomBase36(length: number, label = 'base36 random id'): string {
  const outputLength = Math.max(1, Math.floor(Number(length) || 0));
  let value = '';
  for (let i = 0; i < outputLength; i++) {
    value += BASE36_ALPHABET[secureRandomUintBelow(BASE36_ALPHABET.length, label)] || '0';
  }
  return value;
}
