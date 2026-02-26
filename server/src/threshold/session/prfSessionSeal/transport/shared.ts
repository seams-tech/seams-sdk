import { ensureLeadingSlash } from '@shared/utils/validation';
import type {
  PrfSessionSealApplyServerSealRequest,
  PrfSessionSealAuthorizeResult,
  PrfSessionSealRemoveServerSealRequest,
  PrfSessionSealRouteHeaders,
  PrfSessionSealRouteResult,
  PrfSessionSealRoutesOptions,
  PrfSessionSealSessionAdapter,
  PrfSessionSealSessionClaims,
} from '../types';

const DEFAULT_BASE_PATH = '/threshold-ecdsa/prf-seal';
const THRESHOLD_SESSION_ID_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{7,127}$/;

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

export function resolvePrfSessionSealBasePath(input: string | undefined): string {
  const withLeadingSlash = ensureLeadingSlash(String(input || '').trim());
  const normalized = withLeadingSlash.replace(/\/+$/g, '');
  return normalized || DEFAULT_BASE_PATH;
}

export function buildPrfSessionSealApplyPath(basePath: string): string {
  return `${basePath}/apply-server-seal`;
}

export function buildPrfSessionSealRemovePath(basePath: string): string {
  return `${basePath}/remove-server-seal`;
}

export function parsePrfSessionSealApplyBody(
  body: unknown,
): ParseResult<PrfSessionSealApplyServerSealRequest> {
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
  if (!THRESHOLD_SESSION_ID_RE.test(thresholdSessionId)) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'thresholdSessionId is invalid',
    };
  }

  return {
    ok: true,
    value: {
      thresholdSessionId,
      ciphertext,
      keyVersion: readOptionalString(obj, 'keyVersion'),
      metadata: readOptionalMetadata(obj.metadata),
    },
  };
}

export function parsePrfSessionSealRemoveBody(
  body: unknown,
): ParseResult<PrfSessionSealRemoveServerSealRequest> {
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
  if (!THRESHOLD_SESSION_ID_RE.test(thresholdSessionId)) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'thresholdSessionId is invalid',
    };
  }

  return {
    ok: true,
    value: {
      thresholdSessionId,
      ciphertext,
      keyVersion: readOptionalString(obj, 'keyVersion'),
      metadata: readOptionalMetadata(obj.metadata),
    },
  };
}

function claimsFromUnknown(value: unknown): PrfSessionSealSessionClaims {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
  return value as PrfSessionSealSessionClaims;
}

function userIdFromClaims(claims: PrfSessionSealSessionClaims): string {
  const raw = (claims as { sub?: unknown }).sub;
  return typeof raw === 'string' ? raw.trim() : '';
}

export async function authorizePrfSessionSealRequest(args: {
  options: PrfSessionSealRoutesOptions;
  headers: PrfSessionSealRouteHeaders;
  session: PrfSessionSealSessionAdapter | null | undefined;
}): Promise<PrfSessionSealAuthorizeResult> {
  if (args.options.authorize) {
    try {
      return await args.options.authorize({
        headers: args.headers,
        session: args.session,
      });
    } catch (error: unknown) {
      const message =
        error instanceof Error ? error.message : String(error || 'Authorization failed');
      return { ok: false, code: 'internal', message };
    }
  }

  if (!args.session) {
    return {
      ok: false,
      code: 'sessions_disabled',
      message: 'Sessions are not configured for PRF session seal routes',
      status: 501,
    };
  }

  const parsed = await args.session.parse(args.headers);
  if (!parsed.ok) {
    return {
      ok: false,
      code: 'unauthorized',
      message: 'No valid session',
      status: 401,
    };
  }

  const claims = claimsFromUnknown(parsed.claims);
  const userId = userIdFromClaims(claims);
  if (!userId) {
    return {
      ok: false,
      code: 'unauthorized',
      message: 'Invalid session subject',
      status: 401,
    };
  }

  return { ok: true, auth: { userId, claims } };
}

export function prfSessionSealStatusCode(result: PrfSessionSealRouteResult): number {
  if (result.ok) return 200;
  switch (result.code) {
    case 'unauthorized':
      return 401;
    case 'forbidden':
      return 403;
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

export function prfSessionSealAuthorizeStatusCode(result: PrfSessionSealAuthorizeResult): number {
  if (result.ok) return 200;
  if (Number.isFinite(Number(result.status))) {
    return Math.max(100, Math.floor(Number(result.status)));
  }
  switch (result.code) {
    case 'unauthorized':
      return 401;
    case 'forbidden':
      return 403;
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
