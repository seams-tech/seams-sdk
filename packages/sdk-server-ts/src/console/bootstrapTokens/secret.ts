import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';

const BOOTSTRAP_TOKEN_PREFIX = 'tbt_v1_';
const LOOKUP_PREFIX_LENGTH = 48;

function requireCrypto(): Crypto {
  if (!globalThis.crypto?.getRandomValues) {
    throw new Error('WebCrypto getRandomValues is required for bootstrap token generation');
  }
  return globalThis.crypto;
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

export function makeBootstrapToken(input: { orgId: string; tokenId: string }): string {
  const orgId = String(input.orgId || '').trim();
  const tokenId = String(input.tokenId || '').trim();
  if (!orgId) throw new Error('orgId is required to generate bootstrap token');
  if (!tokenId) throw new Error('tokenId is required to generate bootstrap token');
  return `${BOOTSTRAP_TOKEN_PREFIX}${encodeText(orgId)}.${encodeText(tokenId)}.${randomNonceB64u()}`;
}

export function parseBootstrapToken(
  rawToken: string,
): {
  orgId: string;
  tokenId: string;
} | null {
  const token = String(rawToken || '').trim();
  if (!token.startsWith(BOOTSTRAP_TOKEN_PREFIX)) return null;
  const encodedParts = token.slice(BOOTSTRAP_TOKEN_PREFIX.length).split('.');
  if (encodedParts.length !== 3) return null;
  const orgIdPart = String(encodedParts[0] || '').trim();
  const tokenIdPart = String(encodedParts[1] || '').trim();
  if (!orgIdPart || !tokenIdPart) return null;
  try {
    const orgId = decodeText(orgIdPart).trim();
    const tokenId = decodeText(tokenIdPart).trim();
    if (!orgId || !tokenId) return null;
    return { orgId, tokenId };
  } catch {
    return null;
  }
}

export function makeBootstrapTokenLookupPrefix(token: string): string {
  return String(token || '').trim().slice(0, LOOKUP_PREFIX_LENGTH);
}

export async function hashBootstrapToken(token: string): Promise<string> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new Error('WebCrypto subtle API is required for bootstrap token hashing');
  }
  const bytes = await subtle.digest('SHA-256', new TextEncoder().encode(token));
  const hex = Array.from(new Uint8Array(bytes))
    .map((entry) => entry.toString(16).padStart(2, '0'))
    .join('');
  return `sha256:${hex}`;
}

