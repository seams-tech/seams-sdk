import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';

const SECRET_PREFIX_BY_KIND = {
  secret_key: 'tsk_v1_',
  publishable_key: 'tpk_v1_',
} as const;
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

export function makeApiKeySecret(input: {
  orgId: string;
  apiKeyId: string;
  kind?: 'secret_key' | 'publishable_key';
}): string {
  const orgId = String(input.orgId || '').trim();
  const apiKeyId = String(input.apiKeyId || '').trim();
  const kind = input.kind === 'publishable_key' ? 'publishable_key' : 'secret_key';
  if (!orgId) throw new Error('orgId is required to generate API key secret');
  if (!apiKeyId) throw new Error('apiKeyId is required to generate API key secret');
  return `${SECRET_PREFIX_BY_KIND[kind]}${encodeText(orgId)}.${encodeText(apiKeyId)}.${randomNonceB64u()}`;
}

export function parseApiKeySecret(
  rawSecret: string,
): {
  orgId: string;
  apiKeyId: string;
  kind: 'secret_key' | 'publishable_key';
} | null {
  const secret = String(rawSecret || '').trim();
  const kind = secret.startsWith(SECRET_PREFIX_BY_KIND.publishable_key)
    ? 'publishable_key'
    : secret.startsWith(SECRET_PREFIX_BY_KIND.secret_key)
      ? 'secret_key'
      : null;
  if (!kind) return null;
  const encodedParts = secret.slice(SECRET_PREFIX_BY_KIND[kind].length).split('.');
  if (encodedParts.length !== 3) return null;
  const orgIdPart = String(encodedParts[0] || '').trim();
  const apiKeyIdPart = String(encodedParts[1] || '').trim();
  if (!orgIdPart || !apiKeyIdPart) return null;
  try {
    const orgId = decodeText(orgIdPart).trim();
    const apiKeyId = decodeText(apiKeyIdPart).trim();
    if (!orgId || !apiKeyId) return null;
    return { orgId, apiKeyId, kind };
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
