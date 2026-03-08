import { ConsoleSettingsError } from './errors';
import {
  readOptionalQueryStringField as readOptionalQueryString,
  readOptionalStringField as readOptionalString,
  requireBodyObject as requireObject,
  requireQueryObject,
} from '../shared/requestParse';
import type {
  ConsoleCookieSameSite,
  ConsoleSecurityApprovalPolicy,
  GetConsoleSettingsRequest,
  UpdateConsoleAppSettingsRequest,
  UpdateConsoleSecuritySettingsRequest,
} from './types';

const COOKIE_SAMESITE_VALUES = new Set<ConsoleCookieSameSite>(['LAX', 'STRICT', 'NONE']);

function createError(code: string, status: number, message: string): ConsoleSettingsError {
  return new ConsoleSettingsError(code, status, message);
}

function parseRequiredEnvironmentId(source: Record<string, unknown>, sourceKind: 'query' | 'body'): string {
  const value =
    sourceKind === 'query'
      ? readOptionalQueryString(source, 'environmentId')
      : readOptionalString(source, 'environmentId');
  if (!value) {
    throw createError(
      sourceKind === 'query' ? 'invalid_query' : 'invalid_body',
      400,
      'Missing required field: environmentId',
    );
  }
  return value;
}

function parseOptionalBoolean(raw: unknown, field: string): boolean | undefined {
  if (raw === undefined || raw === null || raw === '') return undefined;
  if (typeof raw === 'boolean') return raw;
  const text = String(raw).trim().toLowerCase();
  if (text === 'true' || text === '1') return true;
  if (text === 'false' || text === '0') return false;
  throw createError('invalid_body', 400, `Field ${field} must be a boolean`);
}

function parsePositiveInteger(raw: unknown, field: string): number {
  const value = typeof raw === 'number' ? raw : Number(raw);
  if (!Number.isInteger(value) || value <= 0) {
    throw createError('invalid_body', 400, `Field ${field} must be a positive integer`);
  }
  return value;
}

function parseStringArray(raw: unknown, field: string): string[] {
  if (!Array.isArray(raw)) {
    throw createError('invalid_body', 400, `Field ${field} must be an array`);
  }
  const out: string[] = [];
  const seen = new Set<string>();
  for (const entry of raw) {
    const value = String(entry || '').trim();
    if (!value) continue;
    const key = value.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(value);
  }
  return out;
}

function parseOptionalCookie(raw: unknown): UpdateConsoleAppSettingsRequest['cookie'] {
  if (raw === undefined || raw === null) return undefined;
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw createError('invalid_body', 400, 'Field cookie must be an object');
  }
  const row = raw as Record<string, unknown>;
  const next: UpdateConsoleAppSettingsRequest['cookie'] = {};
  const httpOnly = parseOptionalBoolean(row.httpOnly, 'cookie.httpOnly');
  if (httpOnly !== undefined) next.httpOnly = httpOnly;
  const secure = parseOptionalBoolean(row.secure, 'cookie.secure');
  if (secure !== undefined) next.secure = secure;
  if (row.sameSite !== undefined && row.sameSite !== null) {
    const sameSite = String(row.sameSite || '').trim().toUpperCase() as ConsoleCookieSameSite;
    if (!COOKIE_SAMESITE_VALUES.has(sameSite)) {
      throw createError(
        'invalid_body',
        400,
        `Field cookie.sameSite must be one of: ${Array.from(COOKIE_SAMESITE_VALUES).join(', ')}`,
      );
    }
    next.sameSite = sameSite;
  }
  if (row.domain !== undefined) {
    next.domain = row.domain == null ? null : String(row.domain || '').trim() || null;
  }
  if (row.path !== undefined && row.path !== null) {
    const path = String(row.path || '').trim();
    if (!path) {
      throw createError('invalid_body', 400, 'Field cookie.path cannot be empty');
    }
    next.path = path;
  }
  if (row.maxAgeSeconds !== undefined && row.maxAgeSeconds !== null) {
    next.maxAgeSeconds = parsePositiveInteger(row.maxAgeSeconds, 'cookie.maxAgeSeconds');
  }
  return Object.keys(next).length > 0 ? next : {};
}

function parseOptionalJwt(raw: unknown): UpdateConsoleAppSettingsRequest['jwt'] {
  if (raw === undefined || raw === null) return undefined;
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw createError('invalid_body', 400, 'Field jwt must be an object');
  }
  const row = raw as Record<string, unknown>;
  const next: UpdateConsoleAppSettingsRequest['jwt'] = {};
  if (row.issuer !== undefined && row.issuer !== null) {
    const issuer = String(row.issuer || '').trim();
    if (!issuer) {
      throw createError('invalid_body', 400, 'Field jwt.issuer cannot be empty');
    }
    next.issuer = issuer;
  }
  if (row.audience !== undefined) next.audience = parseStringArray(row.audience, 'jwt.audience');
  if (row.keyIds !== undefined) next.keyIds = parseStringArray(row.keyIds, 'jwt.keyIds');
  if (row.accessTokenTtlSeconds !== undefined && row.accessTokenTtlSeconds !== null) {
    next.accessTokenTtlSeconds = parsePositiveInteger(
      row.accessTokenTtlSeconds,
      'jwt.accessTokenTtlSeconds',
    );
  }
  if (row.refreshTokenTtlSeconds !== undefined && row.refreshTokenTtlSeconds !== null) {
    next.refreshTokenTtlSeconds = parsePositiveInteger(
      row.refreshTokenTtlSeconds,
      'jwt.refreshTokenTtlSeconds',
    );
  }
  return Object.keys(next).length > 0 ? next : {};
}

function parseOptionalApprovalPolicy(
  raw: unknown,
): Partial<ConsoleSecurityApprovalPolicy> | undefined {
  if (raw === undefined || raw === null) return undefined;
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw createError('invalid_body', 400, 'Field riskyChangeApproval must be an object');
  }
  const row = raw as Record<string, unknown>;
  const next: Partial<ConsoleSecurityApprovalPolicy> = {};
  if (row.approvalsRequired !== undefined && row.approvalsRequired !== null) {
    next.approvalsRequired = parsePositiveInteger(
      row.approvalsRequired,
      'riskyChangeApproval.approvalsRequired',
    );
  }
  const requireAdmin = parseOptionalBoolean(row.requireAdmin, 'riskyChangeApproval.requireAdmin');
  if (requireAdmin !== undefined) next.requireAdmin = requireAdmin;
  const requireMfa = parseOptionalBoolean(row.requireMfa, 'riskyChangeApproval.requireMfa');
  if (requireMfa !== undefined) next.requireMfa = requireMfa;
  return Object.keys(next).length > 0 ? next : {};
}

export function parseGetConsoleSettingsRequest(query: unknown): GetConsoleSettingsRequest {
  const obj = requireQueryObject(query, createError);
  return {
    environmentId: parseRequiredEnvironmentId(obj, 'query'),
  };
}

export function parseUpdateConsoleAppSettingsRequest(body: unknown): UpdateConsoleAppSettingsRequest {
  const obj = requireObject(body, createError);
  const allowedOrigins = obj.allowedOrigins === undefined ? undefined : parseStringArray(obj.allowedOrigins, 'allowedOrigins');
  const ssoMetadataUrl =
    obj.ssoMetadataUrl === undefined
      ? undefined
      : obj.ssoMetadataUrl == null
        ? null
        : String(obj.ssoMetadataUrl || '').trim() || null;
  return {
    environmentId: parseRequiredEnvironmentId(obj, 'body'),
    ...(allowedOrigins !== undefined ? { allowedOrigins } : {}),
    ...(parseOptionalCookie(obj.cookie) !== undefined ? { cookie: parseOptionalCookie(obj.cookie) } : {}),
    ...(parseOptionalJwt(obj.jwt) !== undefined ? { jwt: parseOptionalJwt(obj.jwt) } : {}),
    ...(ssoMetadataUrl !== undefined ? { ssoMetadataUrl } : {}),
  };
}

export function parseUpdateConsoleSecuritySettingsRequest(
  body: unknown,
): UpdateConsoleSecuritySettingsRequest {
  const obj = requireObject(body, createError);
  const ipAllowlist = obj.ipAllowlist === undefined ? undefined : parseStringArray(obj.ipAllowlist, 'ipAllowlist');
  return {
    environmentId: parseRequiredEnvironmentId(obj, 'body'),
    ...(ipAllowlist !== undefined ? { ipAllowlist } : {}),
    ...(parseOptionalBoolean(obj.enforceIpAllowlist, 'enforceIpAllowlist') !== undefined
      ? { enforceIpAllowlist: parseOptionalBoolean(obj.enforceIpAllowlist, 'enforceIpAllowlist') }
      : {}),
    ...(parseOptionalBoolean(obj.requireMfaForRiskyChanges, 'requireMfaForRiskyChanges') !== undefined
      ? {
          requireMfaForRiskyChanges: parseOptionalBoolean(
            obj.requireMfaForRiskyChanges,
            'requireMfaForRiskyChanges',
          ),
        }
      : {}),
    ...(parseOptionalApprovalPolicy(obj.riskyChangeApproval) !== undefined
      ? { riskyChangeApproval: parseOptionalApprovalPolicy(obj.riskyChangeApproval) }
      : {}),
  };
}
