import { ensureLeadingSlash } from '@shared/utils/validation';
import { WALLET_SESSION_SEAL_BASE_PATH } from '@shared/utils/signingSessionSeal';
import { parseThresholdSessionId } from '@shared/utils/domainIds';
import type {
  SigningSessionSealApplyServerSealRequest,
  SigningSessionSealAuthorizeResult,
  SigningSessionSealRemoveServerSealRequest,
  SigningSessionSealRouteHeaders,
  SigningSessionSealRouteResult,
  SigningSessionSealRoutesOptions,
} from '../signingSessionSeal.types';

const DEFAULT_BASE_PATH = WALLET_SESSION_SEAL_BASE_PATH;

type ParseResult<T> = { ok: true; value: T } | { ok: false; code: 'invalid_body'; message: string };

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

function readRequiredString(obj: Record<string, unknown>, key: string): string {
  return typeof obj[key] === 'string' ? String(obj[key] || '').trim() : '';
}

function readOptionalString(obj: Record<string, unknown>, key: string): string | undefined {
  const value = typeof obj[key] === 'string' ? String(obj[key] || '').trim() : '';
  return value || undefined;
}

function readOptionalMetadata(value: unknown): Record<string, unknown> | undefined {
  const obj = asRecord(value);
  return obj || undefined;
}

export function resolveSigningSessionSealBasePath(input: string | undefined): string {
  const withLeadingSlash = ensureLeadingSlash(String(input || '').trim());
  const normalized = withLeadingSlash.replace(/\/+$/g, '');
  return normalized || DEFAULT_BASE_PATH;
}

export function buildSigningSessionSealApplyPath(basePath: string): string {
  return `${basePath}/apply-server-seal`;
}

export function buildSigningSessionSealRemovePath(basePath: string): string {
  return `${basePath}/remove-server-seal`;
}

export function parseSigningSessionSealApplyBody(
  body: unknown,
): ParseResult<SigningSessionSealApplyServerSealRequest> {
  const obj = asRecord(body);
  if (!obj)
    return { ok: false, code: 'invalid_body', message: 'Request body must be a JSON object' };

  const thresholdSessionId = readRequiredString(obj, 'thresholdSessionId');
  const ciphertext = readRequiredString(obj, 'ciphertext');
  if (!thresholdSessionId || !ciphertext) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'thresholdSessionId and ciphertext are required',
    };
  }
  const parsedThresholdSessionId = parseThresholdSessionId(thresholdSessionId);
  if (!parsedThresholdSessionId.ok) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'thresholdSessionId is invalid',
    };
  }

  return {
    ok: true,
    value: {
      thresholdSessionId: parsedThresholdSessionId.value,
      ciphertext,
      keyVersion: readOptionalString(obj, 'keyVersion'),
      metadata: readOptionalMetadata(obj.metadata),
    },
  };
}

export function parseSigningSessionSealRemoveBody(
  body: unknown,
): ParseResult<SigningSessionSealRemoveServerSealRequest> {
  const obj = asRecord(body);
  if (!obj)
    return { ok: false, code: 'invalid_body', message: 'Request body must be a JSON object' };

  const thresholdSessionId = readRequiredString(obj, 'thresholdSessionId');
  const ciphertext = readRequiredString(obj, 'ciphertext');
  if (!thresholdSessionId || !ciphertext) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'thresholdSessionId and ciphertext are required',
    };
  }
  const parsedThresholdSessionId = parseThresholdSessionId(thresholdSessionId);
  if (!parsedThresholdSessionId.ok) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'thresholdSessionId is invalid',
    };
  }

  return {
    ok: true,
    value: {
      thresholdSessionId: parsedThresholdSessionId.value,
      ciphertext,
      keyVersion: readOptionalString(obj, 'keyVersion'),
      metadata: readOptionalMetadata(obj.metadata),
    },
  };
}

export async function authorizeSigningSessionSealRequest(args: {
  options: SigningSessionSealRoutesOptions;
  headers: SigningSessionSealRouteHeaders;
  authorize?: SigningSessionSealRoutesOptions['authorize'];
  thresholdSessionId: string;
}): Promise<SigningSessionSealAuthorizeResult> {
  const authorize = args.authorize ?? args.options.authorize;
  if (authorize) {
    try {
      return await authorize({
        headers: args.headers,
        thresholdSessionId: args.thresholdSessionId,
      });
    } catch (error: unknown) {
      const message =
        error instanceof Error ? error.message : String(error || 'Authorization failed');
      return { ok: false, code: 'internal', message };
    }
  }

  return {
    ok: false,
    code: 'sessions_disabled',
    message: 'Opaque Wallet Session authorization is not configured for seal routes',
    status: 501,
  };
}

export function signingSessionSealStatusCode(result: SigningSessionSealRouteResult): number {
  if (result.ok) return 200;
  switch (result.code) {
    case 'unauthorized':
    case 'wallet_session_missing':
    case 'wallet_session_signature_invalid':
    case 'wallet_session_claims_invalid':
    case 'wallet_session_expired':
      return 401;
    case 'forbidden':
    case 'wallet_session_scope_mismatch':
      return 403;
    case 'wallet_budget_exhausted':
      return 409;
    case 'wallet_session_unavailable':
      return 503;
    case 'not_found':
      return 404;
    case 'rate_limited':
      return 429;
    case 'expired':
    case 'exhausted':
    case 'stale_session_state':
    case 'conflict':
      return 409;
    case 'not_configured':
      return 503;
    case 'sessions_disabled':
    case 'not_implemented':
      return 501;
    case 'internal':
      return 500;
    default:
      return 400;
  }
}

export function signingSessionSealAuthorizeStatusCode(
  result: SigningSessionSealAuthorizeResult,
): number {
  if (result.ok) return 200;
  if (Number.isFinite(Number(result.status))) {
    return Math.max(100, Math.floor(Number(result.status)));
  }
  switch (result.code) {
    case 'unauthorized':
    case 'wallet_session_missing':
    case 'wallet_session_signature_invalid':
    case 'wallet_session_claims_invalid':
    case 'wallet_session_expired':
      return 401;
    case 'forbidden':
    case 'wallet_session_scope_mismatch':
      return 403;
    case 'wallet_budget_exhausted':
      return 409;
    case 'wallet_session_unavailable':
      return 503;
    case 'rate_limited':
      return 429;
    case 'sessions_disabled':
      return 501;
    case 'internal':
      return 500;
    default:
      return 400;
  }
}
