import { errorMessage } from '@shared/utils/errors';
import { base64Decode, base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import type { WebAuthnAuthenticationCredential } from '../../core/types';

export type WebAuthnCredentialIdParseResult =
  | { readonly ok: true; readonly credentialIdB64u: string }
  | { readonly ok: false; readonly code: string; readonly message: string };

export type WebAuthnClientDataJson = {
  readonly challenge: string;
  readonly origin: string;
  readonly type: string;
};

function toRecordValue(value: unknown): Record<string, unknown> | null {
  return isRecordValue(value) ? value : null;
}

function parseJsonObject(input: unknown): Record<string, unknown> | null {
  if (isRecordValue(input)) return input;
  if (typeof input !== 'string') return null;
  try {
    const parsed: unknown = JSON.parse(input);
    return isRecordValue(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function isRecordValue(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

export function decodeWebAuthnBase64UrlOrBase64(input: string, fieldName: string): Uint8Array {
  try {
    return base64UrlDecode(input);
  } catch {
    try {
      return base64Decode(input);
    } catch (error: unknown) {
      throw new Error(
        `Invalid ${fieldName}: expected base64url/base64 string (${errorMessage(error) || 'decode failed'})`,
      );
    }
  }
}

export function parseWebAuthnClientDataJsonBase64url(
  clientDataJSONB64u: string,
): WebAuthnClientDataJson {
  const bytes = decodeWebAuthnBase64UrlOrBase64(
    clientDataJSONB64u,
    'webauthn_authentication.response.clientDataJSON',
  );
  const json = new TextDecoder().decode(bytes);
  const record = parseJsonObject(json);
  if (!record) throw new Error('Invalid clientDataJSON: expected object');
  const challenge = toOptionalTrimmedString(record.challenge);
  const origin = toOptionalTrimmedString(record.origin);
  const type = toOptionalTrimmedString(record.type);
  if (!challenge) throw new Error('Invalid clientDataJSON.challenge');
  if (!origin) throw new Error('Invalid clientDataJSON.origin');
  if (!type) throw new Error('Invalid clientDataJSON.type');
  return { challenge, origin, type };
}

export function webAuthnOriginHostnameOrEmpty(origin: string): string {
  try {
    return new URL(origin).hostname.toLowerCase();
  } catch {
    return '';
  }
}

export function webAuthnCredentialIdB64uFromCredential(
  input: unknown,
): WebAuthnCredentialIdParseResult {
  const credential = toRecordValue(input) || {};
  const rawId = toOptionalTrimmedString(credential.rawId);
  const id = toOptionalTrimmedString(credential.id);
  const selected = rawId || id;
  if (!selected) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'Missing webauthn_authentication.id/rawId',
    };
  }
  try {
    return {
      ok: true,
      credentialIdB64u: base64UrlEncode(
        decodeWebAuthnBase64UrlOrBase64(selected, 'webauthn_authentication.rawId'),
      ),
    };
  } catch (error: unknown) {
    return {
      ok: false,
      code: 'invalid_body',
      message: errorMessage(error) || 'Invalid credential rawId',
    };
  }
}

export function parseWebAuthnAuthenticationCredential(
  input: unknown,
): WebAuthnAuthenticationCredential | null {
  const credential = toRecordValue(input);
  const response = toRecordValue(credential?.response);
  const id = toOptionalTrimmedString(credential?.id);
  const rawId = toOptionalTrimmedString(credential?.rawId);
  const type = toOptionalTrimmedString(credential?.type);
  const clientDataJSON = toOptionalTrimmedString(response?.clientDataJSON);
  const authenticatorData = toOptionalTrimmedString(response?.authenticatorData);
  const signature = toOptionalTrimmedString(response?.signature);
  const userHandle =
    response?.userHandle === null ? null : toOptionalTrimmedString(response?.userHandle) || null;
  const authenticatorAttachment =
    credential?.authenticatorAttachment === null
      ? null
      : toOptionalTrimmedString(credential?.authenticatorAttachment) || null;
  if (!id || !rawId || type !== 'public-key') return null;
  if (!clientDataJSON || !authenticatorData || !signature) return null;
  return {
    id,
    rawId,
    type,
    authenticatorAttachment,
    response: {
      clientDataJSON,
      authenticatorData,
      signature,
      userHandle,
    },
    clientExtensionResults: credential?.clientExtensionResults ?? null,
  };
}
