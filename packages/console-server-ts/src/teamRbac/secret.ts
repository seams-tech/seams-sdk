import { secureRandomBase64Url } from '../boundary';

const ORGANIZATION_INVITATION_TOKEN_PREFIX = 'org_inv_v1_';

export function createOrganizationInvitationToken(): string {
  return `${ORGANIZATION_INVITATION_TOKEN_PREFIX}${secureRandomBase64Url(
    32,
    'organization invitation tokens',
  )}`;
}

export async function hashOrganizationInvitationToken(token: string): Promise<string> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new Error('WebCrypto subtle API is required for organization invitation token hashing');
  }
  const digest = await subtle.digest('SHA-256', new TextEncoder().encode(token));
  const hex = Array.from(new Uint8Array(digest))
    .map((entry) => entry.toString(16).padStart(2, '0'))
    .join('');
  return `sha256:${hex}`;
}
