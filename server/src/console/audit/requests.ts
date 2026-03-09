import { ConsoleAuditError } from './errors';
import {
  readOptionalQueryPositiveIntegerField as readOptionalPositiveInteger,
  readOptionalQueryStringField as readOptionalQueryString,
  requireQueryObject,
} from '../shared/requestParse';
import type {
  ConsoleAuditCategory,
  ConsoleAuditEvidenceDomain,
  ConsoleAuditOutcome,
  ListConsoleAuditEventsRequest,
  ListConsoleAuditEvidenceRequest,
} from './types';

const AUDIT_CATEGORY_SET = new Set<ConsoleAuditCategory>([
  'POLICY',
  'SETTINGS',
  'KEY_EXPORT',
  'BILLING',
  'WEBHOOK',
  'API_KEY',
  'TEAM',
  'APPROVAL',
  'ORG_PROJECT_ENV',
  'RUNTIME_SNAPSHOT',
  'SYSTEM',
]);

const AUDIT_OUTCOME_SET = new Set<ConsoleAuditOutcome>(['SUCCESS', 'FAILURE', 'PENDING']);
const AUDIT_EVIDENCE_DOMAIN_SET = new Set<ConsoleAuditEvidenceDomain>([
  'POLICY',
  'BILLING',
  'KEY_EXPORT',
  'SECURITY',
]);

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 200;

function createError(code: string, status: number, message: string): ConsoleAuditError {
  return new ConsoleAuditError(code, status, message);
}

function parseOptionalCategory(raw: unknown): ConsoleAuditCategory | undefined {
  if (!raw) return undefined;
  const category = String(raw).trim().toUpperCase() as ConsoleAuditCategory;
  if (!AUDIT_CATEGORY_SET.has(category)) {
    throw createError(
      'invalid_query',
      400,
      `Query parameter category must be one of: ${Array.from(AUDIT_CATEGORY_SET).join(', ')}`,
    );
  }
  return category;
}

function parseOptionalOutcome(raw: unknown): ConsoleAuditOutcome | undefined {
  if (!raw) return undefined;
  const outcome = String(raw).trim().toUpperCase() as ConsoleAuditOutcome;
  if (!AUDIT_OUTCOME_SET.has(outcome)) {
    throw createError(
      'invalid_query',
      400,
      `Query parameter outcome must be one of: ${Array.from(AUDIT_OUTCOME_SET).join(', ')}`,
    );
  }
  return outcome;
}

function parseOptionalDomain(raw: unknown): ConsoleAuditEvidenceDomain | undefined {
  if (!raw) return undefined;
  const domain = String(raw).trim().toUpperCase() as ConsoleAuditEvidenceDomain;
  if (!AUDIT_EVIDENCE_DOMAIN_SET.has(domain)) {
    throw createError(
      'invalid_query',
      400,
      `Query parameter domain must be one of: ${Array.from(AUDIT_EVIDENCE_DOMAIN_SET).join(', ')}`,
    );
  }
  return domain;
}

function parseOptionalIsoDate(raw: unknown, field: string): string | undefined {
  if (!raw) return undefined;
  const value = String(raw).trim();
  if (!value) return undefined;
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) {
    throw createError('invalid_query', 400, `Query parameter ${field} must be a valid ISO timestamp`);
  }
  return new Date(timestamp).toISOString();
}

function parseOptionalSearchQuery(raw: unknown): string | undefined {
  if (!raw) return undefined;
  const value = String(raw).trim();
  if (!value) return undefined;
  if (value.length > 256) {
    throw createError('invalid_query', 400, 'Query parameter q must be 256 characters or less');
  }
  return value;
}

function parseLimit(raw: unknown): number {
  const parsed = raw === undefined ? DEFAULT_LIMIT : Number(raw);
  if (!Number.isFinite(parsed) || parsed <= 0) return DEFAULT_LIMIT;
  return Math.min(Math.floor(parsed), MAX_LIMIT);
}

export function parseListConsoleAuditEventsRequest(query: unknown): ListConsoleAuditEventsRequest {
  const obj = requireQueryObject(query, createError);
  const projectId = readOptionalQueryString(obj, 'projectId');
  const environmentId = readOptionalQueryString(obj, 'environmentId');
  const category = parseOptionalCategory(readOptionalQueryString(obj, 'category'));
  const actorUserId = readOptionalQueryString(obj, 'actorUserId');
  const outcome = parseOptionalOutcome(readOptionalQueryString(obj, 'outcome'));
  const q = parseOptionalSearchQuery(readOptionalQueryString(obj, 'q'));
  const from = parseOptionalIsoDate(readOptionalQueryString(obj, 'from'), 'from');
  const to = parseOptionalIsoDate(readOptionalQueryString(obj, 'to'), 'to');
  if (from && to && from > to) {
    throw createError('invalid_query', 400, 'Query parameter from must be earlier than or equal to to');
  }
  const requestedLimit = readOptionalPositiveInteger(obj, 'limit', createError);
  return {
    ...(projectId ? { projectId } : {}),
    ...(environmentId ? { environmentId } : {}),
    ...(category ? { category } : {}),
    ...(actorUserId ? { actorUserId } : {}),
    ...(outcome ? { outcome } : {}),
    ...(q ? { q } : {}),
    ...(from ? { from } : {}),
    ...(to ? { to } : {}),
    limit: parseLimit(requestedLimit),
  };
}

export function parseListConsoleAuditEvidenceRequest(
  query: unknown,
): ListConsoleAuditEvidenceRequest {
  const obj = requireQueryObject(query, createError);
  const from = parseOptionalIsoDate(readOptionalQueryString(obj, 'from'), 'from');
  const to = parseOptionalIsoDate(readOptionalQueryString(obj, 'to'), 'to');
  if (from && to && from > to) {
    throw createError('invalid_query', 400, 'Query parameter from must be earlier than or equal to to');
  }
  const requestedLimit = readOptionalPositiveInteger(obj, 'limit', createError);
  return {
    ...(readOptionalQueryString(obj, 'projectId') ? { projectId: readOptionalQueryString(obj, 'projectId') } : {}),
    ...(readOptionalQueryString(obj, 'environmentId')
      ? { environmentId: readOptionalQueryString(obj, 'environmentId') }
      : {}),
    ...(parseOptionalDomain(readOptionalQueryString(obj, 'domain'))
      ? { domain: parseOptionalDomain(readOptionalQueryString(obj, 'domain')) }
      : {}),
    ...(from ? { from } : {}),
    ...(to ? { to } : {}),
    limit: parseLimit(requestedLimit),
  };
}
