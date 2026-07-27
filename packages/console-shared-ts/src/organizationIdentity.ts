const CONSOLE_ORGANIZATION_ID_PREFIX = 'org_';
const CONSOLE_ORGANIZATION_ID_RANDOM_LENGTH = 12;
const CONSOLE_ORGANIZATION_ID_ALPHABET = 'abcdefghijklmnopqrstuvwxyz0123456789';
const UINT32_RANGE = 0x1_0000_0000;

export const CONSOLE_ORGANIZATION_ID_PATTERN = /^org_[a-z0-9]{12}$/;

export function deriveConsoleOrganizationSlug(value: string): string {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

function secureRandomUintBelow(upperBound: number): number {
  if (!Number.isSafeInteger(upperBound) || upperBound <= 0 || upperBound > UINT32_RANGE) {
    throw new Error('Organization ID alphabet size is invalid');
  }
  const rejectionLimit = Math.floor(UINT32_RANGE / upperBound) * upperBound;
  const sample = new Uint32Array(1);
  for (;;) {
    crypto.getRandomValues(sample);
    const value = sample[0];
    if (value !== undefined && value < rejectionLimit) return value % upperBound;
  }
}

function randomOrganizationIdSuffix(): string {
  let out = '';
  for (let index = 0; index < CONSOLE_ORGANIZATION_ID_RANDOM_LENGTH; index += 1) {
    const randomIndex = secureRandomUintBelow(CONSOLE_ORGANIZATION_ID_ALPHABET.length);
    out += CONSOLE_ORGANIZATION_ID_ALPHABET[randomIndex] || '0';
  }
  return out;
}

export function generateConsoleOrganizationId(): string {
  return `${CONSOLE_ORGANIZATION_ID_PREFIX}${randomOrganizationIdSuffix()}`;
}
