import {
  parseWebAuthnRpId,
  type WebAuthnRpId,
} from '@shared/utils/domainIds';
import type { ThresholdEd25519AuthorityScope } from '../types';

export function requireWebAuthnRpId(value: unknown, fieldName: string): WebAuthnRpId {
  const parsed = parseWebAuthnRpId(value);
  if (!parsed.ok) {
    throw new Error(`${fieldName}: ${parsed.error.message}`);
  }
  return parsed.value;
}

export function passkeyThresholdEd25519AuthorityScope(
  rpId: WebAuthnRpId,
): ThresholdEd25519AuthorityScope {
  return {
    kind: 'passkey_rp',
    rpId,
  };
}
