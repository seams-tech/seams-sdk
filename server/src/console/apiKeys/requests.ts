import { ConsoleApiKeyError } from './errors';
import {
  readOptionalStringField as readOptionalString,
  readRequiredStringField as readRequiredString,
  requireBodyObject as requireObject,
} from '../shared/requestParse';
import type { CreateConsoleApiKeyRequest, RotateConsoleApiKeyRequest } from './types';

function parseScopesOrThrow(raw: unknown): string[] {
  if (!Array.isArray(raw) || raw.length === 0) {
    throw new ConsoleApiKeyError('invalid_body', 400, 'Field scopes must be a non-empty array');
  }

  const out: string[] = [];
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

export function parseCreateConsoleApiKeyRequest(body: unknown): CreateConsoleApiKeyRequest {
  const obj = requireObject(body, (code, status, message) => new ConsoleApiKeyError(code, status, message));
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
  const scopes = parseScopesOrThrow(obj.scopes);
  const ipAllowlist = parseIpAllowlistOrThrow(obj.ipAllowlist);
  return {
    name,
    environmentId,
    scopes,
    ...(ipAllowlist ? { ipAllowlist } : {}),
  };
}

export function parseRotateConsoleApiKeyRequest(body: unknown): RotateConsoleApiKeyRequest {
  if (body === undefined || body === null) return {};
  const obj = requireObject(body, (code, status, message) => new ConsoleApiKeyError(code, status, message));
  return {
    reason: readOptionalString(obj, 'reason'),
  };
}
