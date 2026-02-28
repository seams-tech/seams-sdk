import { ConsoleKeyExportError } from './errors';
import {
  readOptionalQueryStringField as readOptionalQueryString,
  readOptionalStringField as readOptionalString,
  readRequiredStringField as readRequiredString,
  requireBodyObject as requireObject,
  requireQueryObject,
} from '../shared/requestParse';
import type {
  ApproveConsoleKeyExportRequest,
  ConsoleKeyExportConstraints,
  ConsoleKeyExportMode,
  ConsoleKeyExportStatus,
  CreateConsoleKeyExportRequest,
  ListConsoleKeyExportsRequest,
} from './types';

const KEY_EXPORT_MODES = new Set<ConsoleKeyExportMode>([
  'DISABLED',
  'APPROVAL_REQUIRED',
  'ALLOWED_WITH_CONSTRAINTS',
]);
const KEY_EXPORT_STATUSES = new Set<ConsoleKeyExportStatus>([
  'PENDING_APPROVAL',
  'APPROVED',
  'REJECTED',
  'EXECUTED',
  'CANCELED',
]);

function createError(code: string, status: number, message: string): ConsoleKeyExportError {
  return new ConsoleKeyExportError(code, status, message);
}

function parseMode(raw: unknown): ConsoleKeyExportMode | undefined {
  if (raw === undefined || raw === null || String(raw).trim() === '') return undefined;
  const value = String(raw).trim().toUpperCase() as ConsoleKeyExportMode;
  if (!KEY_EXPORT_MODES.has(value)) {
    throw createError('invalid_body', 400, `Field mode must be one of: ${Array.from(KEY_EXPORT_MODES).join(', ')}`);
  }
  return value;
}

function parseStatus(raw: unknown): ConsoleKeyExportStatus | undefined {
  if (raw === undefined || raw === null || String(raw).trim() === '') return undefined;
  const value = String(raw).trim().toUpperCase() as ConsoleKeyExportStatus;
  if (!KEY_EXPORT_STATUSES.has(value)) {
    throw createError(
      'invalid_query',
      400,
      `Query status must be one of: ${Array.from(KEY_EXPORT_STATUSES).join(', ')}`,
    );
  }
  return value;
}

function parsePositiveInteger(raw: unknown, field: string): number | undefined {
  if (raw === undefined || raw === null || raw === '') return undefined;
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

function parseConstraints(raw: unknown): Partial<ConsoleKeyExportConstraints> | undefined {
  if (raw === undefined || raw === null) return undefined;
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw createError('invalid_body', 400, 'Field constraints must be an object');
  }
  const row = raw as Record<string, unknown>;
  const constraints: Partial<ConsoleKeyExportConstraints> = {};
  if (row.roles !== undefined) constraints.roles = parseStringArray(row.roles, 'constraints.roles');
  if (row.chains !== undefined) constraints.chains = parseStringArray(row.chains, 'constraints.chains');
  if (row.walletTypes !== undefined) {
    constraints.walletTypes = parseStringArray(row.walletTypes, 'constraints.walletTypes');
  }
  if (row.environmentIds !== undefined) {
    constraints.environmentIds = parseStringArray(row.environmentIds, 'constraints.environmentIds');
  }
  return Object.keys(constraints).length > 0 ? constraints : {};
}

function parseMfaVerified(raw: unknown): boolean {
  if (typeof raw === 'boolean') return raw;
  const value = String(raw || '').trim().toLowerCase();
  if (value === 'true' || value === '1') return true;
  if (value === 'false' || value === '0') return false;
  throw createError('invalid_body', 400, 'Field mfaVerified must be a boolean');
}

export function parseListConsoleKeyExportsRequest(query: unknown): ListConsoleKeyExportsRequest {
  const obj = requireQueryObject(query, createError);
  const status = parseStatus(readOptionalQueryString(obj, 'status'));
  return {
    ...(readOptionalQueryString(obj, 'environmentId')
      ? { environmentId: readOptionalQueryString(obj, 'environmentId') }
      : {}),
    ...(status ? { status } : {}),
  };
}

export function parseCreateConsoleKeyExportRequest(body: unknown): CreateConsoleKeyExportRequest {
  const obj = requireObject(body, createError);
  const mode = parseMode(obj.mode);
  return {
    ...(readOptionalString(obj, 'id') ? { id: readOptionalString(obj, 'id') } : {}),
    environmentId: readRequiredString(obj, 'environmentId', createError),
    ...(readOptionalString(obj, 'walletId') ? { walletId: readOptionalString(obj, 'walletId') } : {}),
    ...(mode ? { mode } : {}),
    reason: readRequiredString(obj, 'reason', createError),
    ...(parsePositiveInteger(obj.requiredApprovals, 'requiredApprovals') !== undefined
      ? { requiredApprovals: parsePositiveInteger(obj.requiredApprovals, 'requiredApprovals') }
      : {}),
    ...(parseConstraints(obj.constraints) !== undefined ? { constraints: parseConstraints(obj.constraints) } : {}),
  };
}

export function parseApproveConsoleKeyExportRequest(body: unknown): ApproveConsoleKeyExportRequest {
  const obj = requireObject(body, createError);
  return {
    reason: readRequiredString(obj, 'reason', createError),
    mfaVerified: parseMfaVerified(obj.mfaVerified),
  };
}
