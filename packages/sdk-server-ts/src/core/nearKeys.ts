import bs58 from 'bs58';

import { ensureEd25519Prefix } from '@shared/utils/validation';

function stripEd25519Prefix(value: string): string {
  return String(value || '')
    .trim()
    .replace(/^ed25519:/i, '');
}

export function decodeNearSecretKey(secretKey: string): Uint8Array {
  const bytes = bs58.decode(stripEd25519Prefix(secretKey));
  if (bytes.length !== 64) {
    throw new Error(`Invalid NEAR secret key length: ${bytes.length}`);
  }
  return bytes;
}

export function toPublicKeyStringFromSecretKey(secretKey: string): string {
  const bytes = decodeNearSecretKey(secretKey);
  return ensureEd25519Prefix(bs58.encode(bytes.subarray(32, 64)));
}
