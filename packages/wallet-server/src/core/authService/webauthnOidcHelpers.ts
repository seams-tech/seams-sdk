import { base64Decode, base64UrlDecode } from '@shared/utils/encoders';
import { errorMessage } from '@shared/utils/errors';
import type { WebAuthnRpId } from '@shared/utils/domainIds';

export type SimpleWebAuthnRegistrationVerification = {
  verified?: boolean;
  registrationInfo?: {
    credential?: {
      id?: string;
      publicKey?: Uint8Array;
      counter?: number;
    };
  };
};

export type SimpleWebAuthnAuthenticationVerification = {
  verified?: boolean;
  authenticationInfo?: {
    newCounter?: number;
  };
};

export type SimpleWebAuthnRegistrationVerifier = (
  args: SimpleWebAuthnRegistrationVerificationInput,
) => Promise<SimpleWebAuthnRegistrationVerification>;

export type SimpleWebAuthnAuthenticationVerifier = (
  args: SimpleWebAuthnAuthenticationVerificationInput,
) => Promise<SimpleWebAuthnAuthenticationVerification>;

export type SimpleWebAuthnRegistrationVerificationInput = {
  response: unknown;
  expectedChallenge: string;
  expectedOrigin: string;
  expectedRPID: string;
  requireUserVerification: boolean;
};

export type SimpleWebAuthnAuthenticationVerificationInput = {
  response: unknown;
  expectedChallenge: string;
  expectedOrigin: string;
  expectedRPID: string;
  credential: unknown;
  requireUserVerification: boolean;
};

export type SimpleWebAuthnServerModule = {
  verifyRegistrationResponse?: SimpleWebAuthnRegistrationVerifier;
  verifyAuthenticationResponse?: SimpleWebAuthnAuthenticationVerifier;
};

export async function loadSimpleWebAuthnServer(): Promise<SimpleWebAuthnServerModule> {
  try {
    const mod = await import('@simplewebauthn/server');
    return {
      verifyRegistrationResponse:
        typeof mod.verifyRegistrationResponse === 'function'
          ? async (args) =>
              (await mod.verifyRegistrationResponse(
                args as Parameters<typeof mod.verifyRegistrationResponse>[0],
              )) as SimpleWebAuthnRegistrationVerification
          : undefined,
      verifyAuthenticationResponse:
        typeof mod.verifyAuthenticationResponse === 'function'
          ? async (args) =>
              (await mod.verifyAuthenticationResponse(
                args as Parameters<typeof mod.verifyAuthenticationResponse>[0],
              )) as SimpleWebAuthnAuthenticationVerification
          : undefined,
    };
  } catch (error) {
    const message = errorMessage(error);
    throw new Error(
      `Server WebAuthn route selected but '@simplewebauthn/server' dependency is not available${
        message ? `: ${message}` : ''
      }`,
    );
  }
}

export function decodeBase64UrlOrBase64(input: string, fieldName: string): Uint8Array {
  try {
    return base64UrlDecode(input);
  } catch {
    try {
      return base64Decode(input);
    } catch (err) {
      throw new Error(
        `Invalid ${fieldName}: expected base64url/base64 string (${errorMessage(err) || 'decode failed'})`,
      );
    }
  }
}

export function parseClientDataJsonBase64url(clientDataJSONB64u: string): {
  challenge: string;
  origin: string;
  type: string;
} {
  const bytes = decodeBase64UrlOrBase64(
    clientDataJSONB64u,
    'webauthn_authentication.response.clientDataJSON',
  );
  const json = new TextDecoder().decode(bytes);
  const obj = JSON.parse(json) as unknown;
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
    throw new Error('Invalid clientDataJSON: expected object');
  }
  const record = obj as Record<string, unknown>;
  const challenge = typeof record.challenge === 'string' ? record.challenge : '';
  const origin = typeof record.origin === 'string' ? record.origin : '';
  const type = typeof record.type === 'string' ? record.type : '';
  if (!challenge) throw new Error('Invalid clientDataJSON.challenge');
  if (!origin) throw new Error('Invalid clientDataJSON.origin');
  if (!type) throw new Error('Invalid clientDataJSON.type');
  return { challenge, origin, type };
}

export function originHostnameOrEmpty(origin: string): string {
  try {
    return new URL(origin).hostname.toLowerCase();
  } catch {
    return '';
  }
}

export function isHostWithinRpId(host: string, rpId: WebAuthnRpId): boolean {
  const h = (host || '').toLowerCase();
  const r = String(rpId).toLowerCase();
  if (!h || !r) return false;
  if (
    (process.env.NO_CADDY === '1' || process.env.VITE_NO_CADDY === '1') &&
    (h === 'localhost' || h === '127.0.0.1') &&
    r.endsWith('.localhost')
  ) {
    return true;
  }
  return h === r || h.endsWith(`.${r}`);
}

export function parseCacheControlMaxAgeSec(cacheControl: string | null): number | null {
  const s = String(cacheControl || '').trim();
  if (!s) return null;
  const m = s.match(/(?:^|,)\s*max-age=(\d+)\s*(?:,|$)/i);
  if (!m) return null;
  const n = Number(m[1]);
  if (!Number.isFinite(n) || n <= 0) return null;
  return Math.floor(n);
}

export function normalizeOidcIssuer(input: string): string {
  const trimmed = String(input || '').trim();
  if (!trimmed) return '';
  return trimmed.endsWith('/') ? trimmed.slice(0, -1) : trimmed;
}

export function parseJwtSegmentJson(input: string): Record<string, unknown> | null {
  try {
    const raw = new TextDecoder().decode(base64UrlDecode(input));
    const parsed = raw ? JSON.parse(raw) : null;
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

export function parseJwtAud(input: unknown): string[] {
  if (Array.isArray(input)) {
    return input.map((v) => (typeof v === 'string' ? v.trim() : '')).filter(Boolean);
  }
  const single = String(input || '').trim();
  return single ? [single] : [];
}
