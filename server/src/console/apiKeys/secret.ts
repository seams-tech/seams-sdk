const SECRET_PREFIX_BY_KIND = {
  secret_key: 'sk_',
  publishable_key: 'pk_',
} as const;
const LOOKUP_PREFIX_LENGTH = 24;
const SECRET_BODY_ALPHABET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
const SECRET_BODY_LENGTH = 32;

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
  const suffix = Array.from(random)
    .map((value) => value.toString(16).padStart(2, '0'))
    .join('');
  return `${prefix}_${ts}${suffix}`;
}

export function makeApiKeyId(now: Date): string {
  const random = new Uint8Array(8);
  requireCrypto().getRandomValues(random);
  const suffix = Array.from(random)
    .map((value) => value.toString(16).padStart(2, '0'))
    .join('');
  return `ak_${suffix}`;
}

function randomAlphaNumeric(length: number): string {
  const crypto = requireCrypto();
  const out: string[] = [];
  const maxAcceptedValue =
    Math.floor(256 / SECRET_BODY_ALPHABET.length) * SECRET_BODY_ALPHABET.length;

  while (out.length < length) {
    const bytes = new Uint8Array(Math.max(16, (length - out.length) * 2));
    crypto.getRandomValues(bytes);
    for (const value of bytes) {
      if (value >= maxAcceptedValue) continue;
      out.push(SECRET_BODY_ALPHABET[value % SECRET_BODY_ALPHABET.length] || 'a');
      if (out.length >= length) break;
    }
  }

  return out.join('');
}

export function makeApiKeySecret(input: {
  kind?: 'secret_key' | 'publishable_key';
}): string {
  const kind = input.kind === 'publishable_key' ? 'publishable_key' : 'secret_key';
  return `${SECRET_PREFIX_BY_KIND[kind]}${randomAlphaNumeric(SECRET_BODY_LENGTH)}`;
}

export function parseApiKeySecret(
  rawSecret: string,
): {
  kind: 'secret_key' | 'publishable_key';
} | null {
  const secret = String(rawSecret || '').trim();
  const kind = secret.startsWith(SECRET_PREFIX_BY_KIND.publishable_key)
    ? 'publishable_key'
    : secret.startsWith(SECRET_PREFIX_BY_KIND.secret_key)
      ? 'secret_key'
      : null;
  if (!kind) return null;
  const body = secret.slice(SECRET_PREFIX_BY_KIND[kind].length).trim();
  if (!body) return null;
  if (body.includes('.')) return null;
  if (!/^[A-Za-z0-9]+$/.test(body)) return null;
  return { kind };
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
