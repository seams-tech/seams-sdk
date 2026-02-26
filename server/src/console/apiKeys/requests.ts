import { ConsoleApiKeyError } from './errors';
import type { CreateConsoleApiKeyRequest, RotateConsoleApiKeyRequest } from './types';

function requireObject(body: unknown): Record<string, unknown> {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new ConsoleApiKeyError('invalid_body', 400, 'Expected JSON object request body');
  }
  return body as Record<string, unknown>;
}

function readRequiredString(body: Record<string, unknown>, key: string): string {
  const value = String(body[key] ?? '').trim();
  if (!value) {
    throw new ConsoleApiKeyError('invalid_body', 400, `Missing required field: ${key}`);
  }
  return value;
}

function readOptionalString(body: Record<string, unknown>, key: string): string | undefined {
  const raw = body[key];
  if (raw === undefined || raw === null) return undefined;
  const value = String(raw).trim();
  return value || undefined;
}

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
  const obj = requireObject(body);
  const name = readRequiredString(obj, 'name');
  const environmentId = readRequiredString(obj, 'environmentId');
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
  const obj = requireObject(body);
  return {
    reason: readOptionalString(obj, 'reason'),
  };
}
