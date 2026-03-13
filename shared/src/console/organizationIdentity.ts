const CONSOLE_ORGANIZATION_ID_PREFIX = 'org_';
const CONSOLE_ORGANIZATION_ID_RANDOM_LENGTH = 12;
const CONSOLE_ORGANIZATION_ID_ALPHABET = 'abcdefghijklmnopqrstuvwxyz0123456789';

export const CONSOLE_ORGANIZATION_ID_PATTERN = /^org_[a-z0-9]{12}$/;

export function deriveConsoleOrganizationSlug(value: string): string {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

function fillRandomBytes(length: number): Uint8Array | null {
  if (typeof globalThis.crypto?.getRandomValues !== 'function') return null;
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}

function randomOrganizationIdSuffix(): string {
  const randomBytes = fillRandomBytes(CONSOLE_ORGANIZATION_ID_RANDOM_LENGTH);
  if (randomBytes) {
    let out = '';
    for (const value of randomBytes) {
      out += CONSOLE_ORGANIZATION_ID_ALPHABET[value % CONSOLE_ORGANIZATION_ID_ALPHABET.length];
    }
    return out;
  }

  let out = '';
  for (let index = 0; index < CONSOLE_ORGANIZATION_ID_RANDOM_LENGTH; index += 1) {
    const randomIndex = Math.floor(Math.random() * CONSOLE_ORGANIZATION_ID_ALPHABET.length);
    out += CONSOLE_ORGANIZATION_ID_ALPHABET[randomIndex] || '0';
  }
  return out;
}

export function generateConsoleOrganizationId(): string {
  return `${CONSOLE_ORGANIZATION_ID_PREFIX}${randomOrganizationIdSuffix()}`;
}
