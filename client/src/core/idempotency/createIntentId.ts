import { secureRandomBase64Url } from '@shared/utils/secureRandomId';

export function createIntentId(prefix: string): string {
  const normalizedPrefix = String(prefix || '').trim() || 'intent';
  return `${normalizedPrefix}:${secureRandomBase64Url(32, 'intent IDs')}`;
}
