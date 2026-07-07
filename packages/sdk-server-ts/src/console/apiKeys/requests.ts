import { ConsoleApiKeyError } from './errors';
import {
  API_CREDENTIAL_SCOPES,
  isApiCredentialScope,
  type ApiCredentialScope,
} from "../../../../console-shared-ts/src/apiKeyScopes";
import {
  readOptionalStringField as readOptionalString,
  readRequiredStringField as readRequiredString,
  requireBodyObject as requireObject,
} from '../shared/requestParse';
import type {
  CreateConsoleApiKeyRequest,
  RevokeConsoleApiKeyRequest,
  RotateConsoleApiKeyRequest,
  UpdateConsoleApiKeyRequest,
} from './types';

function parseScopesOrThrow(raw: unknown): ApiCredentialScope[] {
  if (!Array.isArray(raw) || raw.length === 0) {
    throw new ConsoleApiKeyError('invalid_body', 400, 'Field scopes must be a non-empty array');
  }

  const out: ApiCredentialScope[] = [];
  const seen = new Set<string>();
  for (const valueRaw of raw) {
    const value = String(valueRaw || '').trim();
    if (!value) {
      throw new ConsoleApiKeyError(
        'invalid_body',
        400,
        'Field scopes must contain non-empty strings',
      );
    }
    if (!isApiCredentialScope(value)) {
      throw new ConsoleApiKeyError(
        'invalid_body',
        400,
        `Invalid secret_key scope: ${value}. Allowed scopes: ${API_CREDENTIAL_SCOPES.join(', ')}`,
      );
    }
    const key = value.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(value);
  }
  return out;
}

function parseIpAllowlistOrThrow(raw: unknown): string[] | undefined {
  if (raw === undefined || raw === null) return undefined;
  if (!Array.isArray(raw)) {
    throw new ConsoleApiKeyError('invalid_body', 400, 'Field ipAllowlist must be an array');
  }
  const out: string[] = [];
  const seen = new Set<string>();
  for (const item of raw) {
    const value = String(item || '').trim();
    if (!value) {
      throw new ConsoleApiKeyError(
        'invalid_body',
        400,
        'Field ipAllowlist must contain non-empty values',
      );
    }
    if (!/^[0-9a-fA-F.:/]+$/.test(value)) {
      throw new ConsoleApiKeyError('invalid_body', 400, `Invalid IP/CIDR value: ${value}`);
    }
    const key = value.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(value);
  }
  return out;
}

function parseAllowedOriginsOrThrow(raw: unknown): string[] {
  if (!Array.isArray(raw) || raw.length === 0) {
    throw new ConsoleApiKeyError(
      'invalid_body',
      400,
      'Field allowedOrigins must be a non-empty array',
    );
  }
  const out: string[] = [];
  const seen = new Set<string>();
  for (const entry of raw) {
    const value = String(entry || '').trim();
    if (!value) {
      throw new ConsoleApiKeyError(
        'invalid_body',
        400,
        'Field allowedOrigins must contain non-empty strings',
      );
    }
    let origin: string;
    try {
      const parsed = new URL(value);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        throw new Error('unsupported protocol');
      }
      if (parsed.origin !== value) {
        throw new Error('origin only');
      }
      origin = parsed.origin;
    } catch {
      throw new ConsoleApiKeyError(
        'invalid_body',
        400,
        `Invalid origin value in allowedOrigins: ${value}`,
      );
    }
    const key = origin.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(origin);
  }
  return out;
}

function parseOptionalObjectOrThrow(raw: unknown, fieldName: string): Record<string, unknown> | undefined {
  if (raw === undefined || raw === null) return undefined;
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new ConsoleApiKeyError('invalid_body', 400, `Field ${fieldName} must be an object`);
  }
  return { ...(raw as Record<string, unknown>) };
}

function assertFieldAbsent(
  obj: Record<string, unknown>,
  fieldName: string,
  keyKind: 'secret_key' | 'publishable_key',
): void {
  if (obj[fieldName] !== undefined) {
    throw new ConsoleApiKeyError(
      'invalid_body',
      400,
      `Field ${fieldName} is not valid for ${keyKind}`,
    );
  }
}

function parseOptionalExpiresAtOrThrow(raw: unknown): string | undefined {
  const value = String(raw || '').trim();
  if (!value) return undefined;
  const expiresAtMs = Date.parse(value);
  if (!Number.isFinite(expiresAtMs)) {
    throw new ConsoleApiKeyError('invalid_body', 400, 'Field expiresAt must be a valid ISO timestamp');
  }
  if (expiresAtMs <= Date.now()) {
    throw new ConsoleApiKeyError('invalid_body', 400, 'Field expiresAt must be in the future');
  }
  return new Date(expiresAtMs).toISOString();
}

function parseUpdateExpiresAtOrThrow(raw: unknown): string | null | undefined {
  if (raw === undefined) return undefined;
  if (raw === null || raw === '') return null;
  return parseOptionalExpiresAtOrThrow(raw) || null;
}

export function parseCreateConsoleApiKeyRequest(body: unknown): CreateConsoleApiKeyRequest {
  const obj = requireObject(body, (code, status, message) => new ConsoleApiKeyError(code, status, message));
  const kind = readRequiredString(
    obj,
    'kind',
    (code, status, message) => new ConsoleApiKeyError(code, status, message),
  );
  const name = readRequiredString(
    obj,
    'name',
    (code, status, message) => new ConsoleApiKeyError(code, status, message),
  );
  const environmentId = readRequiredString(
    obj,
    'environmentId',
    (code, status, message) => new ConsoleApiKeyError(code, status, message),
  );
  const expiresAt = parseOptionalExpiresAtOrThrow(obj.expiresAt);
  if (kind === 'secret_key') {
    assertFieldAbsent(obj, 'allowedOrigins', kind);
    assertFieldAbsent(obj, 'rateLimitBucket', kind);
    assertFieldAbsent(obj, 'quotaBucket', kind);
    assertFieldAbsent(obj, 'riskPolicy', kind);
    assertFieldAbsent(obj, 'paymentPolicy', kind);
    const scopes = parseScopesOrThrow(obj.scopes);
    const ipAllowlist = parseIpAllowlistOrThrow(obj.ipAllowlist);
    return {
      kind,
      name,
      environmentId,
      scopes,
      ...(ipAllowlist ? { ipAllowlist } : {}),
      ...(expiresAt ? { expiresAt } : {}),
    };
  }
  if (kind === 'publishable_key') {
    assertFieldAbsent(obj, 'scopes', kind);
    assertFieldAbsent(obj, 'ipAllowlist', kind);
    const allowedOrigins = parseAllowedOriginsOrThrow(obj.allowedOrigins);
    const rateLimitBucket = readRequiredString(
      obj,
      'rateLimitBucket',
      (code, status, message) => new ConsoleApiKeyError(code, status, message),
    );
    const quotaBucket = readRequiredString(
      obj,
      'quotaBucket',
      (code, status, message) => new ConsoleApiKeyError(code, status, message),
    );
    const riskPolicy = parseOptionalObjectOrThrow(obj.riskPolicy, 'riskPolicy');
    const paymentPolicy = parseOptionalObjectOrThrow(obj.paymentPolicy, 'paymentPolicy');
    return {
      kind,
      name,
      environmentId,
      allowedOrigins,
      rateLimitBucket,
      quotaBucket,
      ...(riskPolicy ? { riskPolicy } : {}),
      ...(paymentPolicy ? { paymentPolicy } : {}),
      ...(expiresAt ? { expiresAt } : {}),
    };
  }
  throw new ConsoleApiKeyError(
    'invalid_body',
    400,
    'Field kind must be either secret_key or publishable_key',
  );
}

export function parseRotateConsoleApiKeyRequest(body: unknown): RotateConsoleApiKeyRequest {
  if (body === undefined || body === null) return {};
  const obj = requireObject(body, (code, status, message) => new ConsoleApiKeyError(code, status, message));
  return {
    reason: readOptionalString(obj, 'reason'),
  };
}

export function parseUpdateConsoleApiKeyRequest(body: unknown): UpdateConsoleApiKeyRequest {
  const obj = requireObject(
    body,
    (code, status, message) => new ConsoleApiKeyError(code, status, message),
  );
  const name = obj.name === undefined ? undefined : readOptionalString(obj, 'name');
  const scopes = obj.scopes === undefined ? undefined : parseScopesOrThrow(obj.scopes);
  const ipAllowlist =
    obj.ipAllowlist === undefined ? undefined : parseIpAllowlistOrThrow(obj.ipAllowlist);
  const allowedOrigins =
    obj.allowedOrigins === undefined ? undefined : parseAllowedOriginsOrThrow(obj.allowedOrigins);
  const rateLimitBucket =
    obj.rateLimitBucket === undefined ? undefined : readOptionalString(obj, 'rateLimitBucket');
  const quotaBucket =
    obj.quotaBucket === undefined ? undefined : readOptionalString(obj, 'quotaBucket');
  const riskPolicy =
    obj.riskPolicy === undefined ? undefined : parseOptionalObjectOrThrow(obj.riskPolicy, 'riskPolicy');
  const paymentPolicy =
    obj.paymentPolicy === undefined
      ? undefined
      : parseOptionalObjectOrThrow(obj.paymentPolicy, 'paymentPolicy');
  const expiresAt = parseUpdateExpiresAtOrThrow(obj.expiresAt);
  return {
    ...(name !== undefined ? { name } : {}),
    ...(scopes !== undefined ? { scopes } : {}),
    ...(ipAllowlist !== undefined ? { ipAllowlist } : {}),
    ...(allowedOrigins !== undefined ? { allowedOrigins } : {}),
    ...(rateLimitBucket !== undefined ? { rateLimitBucket } : {}),
    ...(quotaBucket !== undefined ? { quotaBucket } : {}),
    ...(riskPolicy !== undefined ? { riskPolicy } : {}),
    ...(paymentPolicy !== undefined ? { paymentPolicy } : {}),
    ...(expiresAt !== undefined ? { expiresAt } : {}),
  };
}

export function parseRevokeConsoleApiKeyRequest(body: unknown): RevokeConsoleApiKeyRequest {
  if (body === undefined || body === null) return {};
  const obj = requireObject(body, (code, status, message) => new ConsoleApiKeyError(code, status, message));
  return {
    reason: readOptionalString(obj, 'reason'),
  };
}
