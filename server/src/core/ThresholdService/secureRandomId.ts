import { secureRandomBase64Url } from '@shared/utils/secureRandomId';

export function secureRandomIdFragment(): string {
  return secureRandomBase64Url(32, 'threshold session IDs');
}
