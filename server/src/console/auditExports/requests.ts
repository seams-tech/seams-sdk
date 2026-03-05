import {
  readOptionalQueryPositiveIntegerField as readOptionalPositiveInteger,
  readOptionalQueryStringField as readOptionalQueryString,
  readOptionalStringField as readOptionalString,
  readRequiredStringField as readRequiredString,
  requireBodyObject as requireObject,
  requireQueryObject,
} from '../shared/requestParse';
import { ConsoleAuditExportsError } from './errors';
import type {
  ConsoleAuditExportDomain,
  ConsoleAuditExportFormat,
  ConsoleAuditExportStatus,
  CreateConsoleAuditExportRequest,
  ListConsoleAuditExportsRequest,
} from './types';

const EXPORT_STATUS_SET = new Set<ConsoleAuditExportStatus>([
  'QUEUED',
  'PROCESSING',
  'READY',
  'FAILED',
]);

const EXPORT_DOMAIN_SET = new Set<ConsoleAuditExportDomain>([
  'POLICY',
  'BILLING',
  'KEY_EXPORT',
  'SECURITY',
  'ALL',
]);

const EXPORT_FORMAT_SET = new Set<ConsoleAuditExportFormat>(['JSONL', 'CSV']);

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 200;

function createError(code: string, status: number, message: string): ConsoleAuditExportsError {
  return new ConsoleAuditExportsError(code, status, message);
}

function parseOptionalStatus(raw: unknown): ConsoleAuditExportStatus | undefined {
  if (raw === undefined || raw === null || String(raw).trim() === '') return undefined;
  const value = String(raw).trim().toUpperCase() as ConsoleAuditExportStatus;
  if (!EXPORT_STATUS_SET.has(value)) {
    throw createError(
      'invalid_query',
      400,
      `Query parameter status must be one of: ${Array.from(EXPORT_STATUS_SET).join(', ')}`,
    );
  }
  return value;
}

function parseOptionalDomain(
  raw: unknown,
  field: 'query' | 'body',
): ConsoleAuditExportDomain | undefined {
  if (raw === undefined || raw === null || String(raw).trim() === '') return undefined;
  const value = String(raw).trim().toUpperCase() as ConsoleAuditExportDomain;
  if (!EXPORT_DOMAIN_SET.has(value)) {
    throw createError(
      field === 'query' ? 'invalid_query' : 'invalid_body',
      400,
      `Field domain must be one of: ${Array.from(EXPORT_DOMAIN_SET).join(', ')}`,
    );
  }
  return value;
}

function parseRequiredFormat(raw: unknown): ConsoleAuditExportFormat {
  const value = String(raw || '')
    .trim()
    .toUpperCase() as ConsoleAuditExportFormat;
  if (!EXPORT_FORMAT_SET.has(value)) {
    throw createError(
      'invalid_body',
      400,
      `Field format must be one of: ${Array.from(EXPORT_FORMAT_SET).join(', ')}`,
    );
  }
  return value;
}

function parseOptionalIsoDate(raw: unknown, field: string): string | undefined {
  if (raw === undefined || raw === null || String(raw).trim() === '') return undefined;
  const input = String(raw).trim();
  const parsed = Date.parse(input);
  if (!Number.isFinite(parsed)) {
    throw createError('invalid_body', 400, `Field ${field} must be a valid ISO timestamp`);
  }
  return new Date(parsed).toISOString();
}

function parseLimit(raw: unknown): number {
  const parsed = raw === undefined ? DEFAULT_LIMIT : Number(raw);
  if (!Number.isFinite(parsed) || parsed <= 0) return DEFAULT_LIMIT;
  return Math.min(Math.floor(parsed), MAX_LIMIT);
}

export function parseListConsoleAuditExportsRequest(query: unknown): ListConsoleAuditExportsRequest {
  const obj = requireQueryObject(query, createError);
  const requestedLimit = readOptionalPositiveInteger(obj, 'limit', createError);
  return {
    ...(parseOptionalStatus(readOptionalQueryString(obj, 'status'))
      ? { status: parseOptionalStatus(readOptionalQueryString(obj, 'status')) }
      : {}),
    ...(parseOptionalDomain(readOptionalQueryString(obj, 'domain'), 'query')
      ? { domain: parseOptionalDomain(readOptionalQueryString(obj, 'domain'), 'query') }
      : {}),
    limit: parseLimit(requestedLimit),
  };
}

export function parseCreateConsoleAuditExportRequest(body: unknown): CreateConsoleAuditExportRequest {
  const obj = requireObject(body, createError);
  const from = parseOptionalIsoDate(readOptionalString(obj, 'from'), 'from');
  const to = parseOptionalIsoDate(readOptionalString(obj, 'to'), 'to');
  if (from && to && from > to) {
    throw createError('invalid_body', 400, 'Field from must be earlier than or equal to to');
  }
  const out: CreateConsoleAuditExportRequest = {
    ...(readOptionalString(obj, 'id') ? { id: readOptionalString(obj, 'id') } : {}),
    format: parseRequiredFormat(readRequiredString(obj, 'format', createError)),
    ...(parseOptionalDomain(readOptionalString(obj, 'domain'), 'body')
      ? { domain: parseOptionalDomain(readOptionalString(obj, 'domain'), 'body') }
      : {}),
    ...(readOptionalString(obj, 'projectId') ? { projectId: readOptionalString(obj, 'projectId') } : {}),
    ...(readOptionalString(obj, 'environmentId')
      ? { environmentId: readOptionalString(obj, 'environmentId') }
      : {}),
    ...(from ? { from } : {}),
    ...(to ? { to } : {}),
  };
  return out;
}
