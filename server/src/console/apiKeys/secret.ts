import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';

const SECRET_PREFIX = 'tsk_v1_';
const LOOKUP_PREFIX_LENGTH = 48;

function requireCrypto(): Crypto {
  if (!globalThis.crypto?.getRandomValues) {
    throw new Error('WebCrypto getRandomValues is required for API key secret generation');
  }
  return globalThis.crypto;
}

export function makeSecretPreview(secret: string): string {
  return `${secret.slice(0, 10)}...`;
}

export function makeApiKeyLookupPrefix(secret: string): string {
  return String(secret || '').trim().slice(0, LOOKUP_PREFIX_LENGTH);
}

export function makeId(prefix: string, now: Date): string {
  const ts = now.getTime().toString(36);
  const random = new Uint8Array(8);
  requireCrypto().getRandomValues(random);
  const suffix = base64UrlEncode(random).slice(0, 10);
  return `${prefix}_${ts}_${suffix}`;
}

function encodeText(value: string): string {
  return base64UrlEncode(new TextEncoder().encode(value));
}

function decodeText(value: string): string {
  const bytes = base64UrlDecode(value);
  return new TextDecoder().decode(bytes);
}

function randomNonceB64u(): string {
  const bytes = new Uint8Array(24);
  requireCrypto().getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

export function makeApiKeySecret(input: { orgId: string; apiKeyId: string }): string {
  const orgId = String(input.orgId || '').trim();
  const apiKeyId = String(input.apiKeyId || '').trim();
  if (!orgId) throw new Error('orgId is required to generate API key secret');
  if (!apiKeyId) throw new Error('apiKeyId is required to generate API key secret');
  return `${SECRET_PREFIX}${encodeText(orgId)}.${encodeText(apiKeyId)}.${randomNonceB64u()}`;
}

export function parseApiKeySecret(
  rawSecret: string,
): {
  orgId: string;
  apiKeyId: string;
} | null {
  const secret = String(rawSecret || '').trim();
  if (!secret.startsWith(SECRET_PREFIX)) return null;
  const encodedParts = secret.slice(SECRET_PREFIX.length).split('.');
  if (encodedParts.length !== 3) return null;
  const orgIdPart = String(encodedParts[0] || '').trim();
  const apiKeyIdPart = String(encodedParts[1] || '').trim();
  if (!orgIdPart || !apiKeyIdPart) return null;
  try {
    const orgId = decodeText(orgIdPart).trim();
    const apiKeyId = decodeText(apiKeyIdPart).trim();
    if (!orgId || !apiKeyId) return null;
    return { orgId, apiKeyId };
  } catch {
    return null;
  }
}

export async function hashApiKeySecret(secret: string): Promise<string> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new Error('WebCrypto subtle API is required for API key hashing');
  }
  const bytes = await subtle.digest('SHA-256', new TextEncoder().encode(secret));
  const hex = Array.from(new Uint8Array(bytes))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return `sha256:${hex}`;
}
