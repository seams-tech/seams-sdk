import {
  isPlainObject,
  toOptionalTrimmedString,
} from '@shared/utils/validation';
import type { WebAuthnAuthenticationCredential } from '../core/types';

export function findUnexpectedRouteKey(
  record: Record<string, unknown>,
  allowedKeys: readonly string[],
): string | null {
  for (const key of Object.keys(record)) {
    if (!allowedKeys.includes(key)) return key;
  }
  return null;
}

export function optionalRouteTrimmedString(
  record: Record<string, unknown>,
  field: string,
): string | undefined {
  return toOptionalTrimmedString(record[field]) || undefined;
}

export function parseWebAuthnAuthenticationCredential(
  raw: unknown,
): WebAuthnAuthenticationCredential | null {
  if (!isPlainObject(raw)) return null;
  const response = isPlainObject(raw.response) ? raw.response : null;
  if (
    typeof raw.id !== 'string' ||
    typeof raw.rawId !== 'string' ||
    typeof raw.type !== 'string' ||
    (typeof raw.authenticatorAttachment !== 'string' && raw.authenticatorAttachment !== null) ||
    !response ||
    typeof response.clientDataJSON !== 'string' ||
    typeof response.authenticatorData !== 'string' ||
    typeof response.signature !== 'string' ||
    (typeof response.userHandle !== 'string' && response.userHandle !== null)
  ) {
    return null;
  }
  return {
    id: raw.id,
    rawId: raw.rawId,
    type: raw.type,
    authenticatorAttachment: raw.authenticatorAttachment,
    response: {
      clientDataJSON: response.clientDataJSON,
      authenticatorData: response.authenticatorData,
      signature: response.signature,
      userHandle: response.userHandle,
    },
    clientExtensionResults: isPlainObject(raw.clientExtensionResults)
      ? raw.clientExtensionResults
      : null,
  };
}
