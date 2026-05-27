import { secureRandomUintBelow } from '../utils/secureRandomId';

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

function randomOrganizationIdSuffix(): string {
  let out = '';
  for (let index = 0; index < CONSOLE_ORGANIZATION_ID_RANDOM_LENGTH; index += 1) {
    const randomIndex = secureRandomUintBelow(
      CONSOLE_ORGANIZATION_ID_ALPHABET.length,
      'console organization IDs',
    );
    out += CONSOLE_ORGANIZATION_ID_ALPHABET[randomIndex] || '0';
  }
  return out;
}

export function generateConsoleOrganizationId(): string {
  return `${CONSOLE_ORGANIZATION_ID_PREFIX}${randomOrganizationIdSuffix()}`;
}
