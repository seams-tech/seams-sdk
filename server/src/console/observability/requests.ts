import { ConsoleObservabilityError } from './errors';
import {
  readOptionalQueryPositiveIntegerField as readOptionalPositiveInteger,
  readOptionalQueryStringField as readOptionalQueryString,
  requireQueryObject,
} from '../shared/requestParse';
import type {
  ConsoleObservabilityLevel,
  GetConsoleObservabilitySummaryRequest,
  GetConsoleObservabilityTimeseriesRequest,
  ListConsoleObservabilityEventsRequest,
  ListConsoleObservabilityServicesRequest,
} from './types';

const OBSERVABILITY_LEVELS = new Set<ConsoleObservabilityLevel>([
  'DEBUG',
  'INFO',
  'WARN',
  'ERROR',
  'FATAL',
]);

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 200;
const DEFAULT_BUCKET_MINUTES = 5;
const MAX_BUCKET_MINUTES = 60;
const MAX_QUERY_WINDOW_MS = 1000 * 60 * 60 * 24 * 7;

function createError(code: string, status: number, message: string): ConsoleObservabilityError {
  return new ConsoleObservabilityError(code, status, message);
}

function parseOptionalIsoTimestamp(raw: unknown, field: string): string | undefined {
  if (!raw) return undefined;
  const value = String(raw).trim();
  if (!value) return undefined;
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) {
    throw createError('invalid_query', 400, `Query parameter ${field} must be a valid ISO timestamp`);
  }
  return new Date(parsed).toISOString();
}

function parseOptionalLevel(raw: unknown): ConsoleObservabilityLevel | undefined {
  if (!raw) return undefined;
  const value = String(raw).trim().toUpperCase() as ConsoleObservabilityLevel;
  if (!OBSERVABILITY_LEVELS.has(value)) {
    throw createError(
      'invalid_query',
      400,
      `Query parameter level must be one of: ${Array.from(OBSERVABILITY_LEVELS).join(', ')}`,
    );
  }
  return value;
}

function parseLimit(raw: unknown): number {
  const parsed = raw === undefined ? DEFAULT_LIMIT : Number(raw);
  if (!Number.isFinite(parsed) || parsed <= 0) return DEFAULT_LIMIT;
  return Math.min(Math.floor(parsed), MAX_LIMIT);
}

function parseBucketMinutes(raw: unknown): number {
  const parsed = raw === undefined ? DEFAULT_BUCKET_MINUTES : Number(raw);
  if (!Number.isFinite(parsed) || parsed <= 0) return DEFAULT_BUCKET_MINUTES;
  return Math.min(Math.floor(parsed), MAX_BUCKET_MINUTES);
}

function ensureValidWindow(from?: string, to?: string): void {
  if (!from || !to) return;
  const fromMs = Date.parse(from);
  const toMs = Date.parse(to);
  if (!Number.isFinite(fromMs) || !Number.isFinite(toMs)) return;
  if (fromMs > toMs) {
    throw createError(
      'invalid_query',
      400,
      'Query parameter from must be earlier than or equal to to',
    );
  }
  if (toMs - fromMs > MAX_QUERY_WINDOW_MS) {
    throw createError(
      'invalid_query',
      400,
      'Query window must be 7 days or less',
    );
  }
}

export function parseGetConsoleObservabilitySummaryRequest(
  query: unknown,
): GetConsoleObservabilitySummaryRequest {
  const obj = requireQueryObject(query, createError);
  const from = parseOptionalIsoTimestamp(readOptionalQueryString(obj, 'from'), 'from');
  const to = parseOptionalIsoTimestamp(readOptionalQueryString(obj, 'to'), 'to');
  ensureValidWindow(from, to);

  return {
    ...(from ? { from } : {}),
    ...(to ? { to } : {}),
    ...(readOptionalQueryString(obj, 'projectId')
      ? { projectId: readOptionalQueryString(obj, 'projectId') }
      : {}),
    ...(readOptionalQueryString(obj, 'environmentId')
      ? { environmentId: readOptionalQueryString(obj, 'environmentId') }
      : {}),
  };
}

export function parseListConsoleObservabilityEventsRequest(
  query: unknown,
): ListConsoleObservabilityEventsRequest {
  const obj = requireQueryObject(query, createError);
  const from = parseOptionalIsoTimestamp(readOptionalQueryString(obj, 'from'), 'from');
  const to = parseOptionalIsoTimestamp(readOptionalQueryString(obj, 'to'), 'to');
  ensureValidWindow(from, to);
  const requestedLimit = readOptionalPositiveInteger(obj, 'limit', createError);

  return {
    ...(from ? { from } : {}),
    ...(to ? { to } : {}),
    ...(readOptionalQueryString(obj, 'query')
      ? { query: readOptionalQueryString(obj, 'query') }
      : {}),
    ...(parseOptionalLevel(readOptionalQueryString(obj, 'level'))
      ? { level: parseOptionalLevel(readOptionalQueryString(obj, 'level')) }
      : {}),
    ...(readOptionalQueryString(obj, 'service')
      ? { service: readOptionalQueryString(obj, 'service') }
      : {}),
    ...(readOptionalQueryString(obj, 'component')
      ? { component: readOptionalQueryString(obj, 'component') }
      : {}),
    ...(readOptionalQueryString(obj, 'eventType')
      ? { eventType: readOptionalQueryString(obj, 'eventType') }
      : {}),
    ...(readOptionalQueryString(obj, 'projectId')
      ? { projectId: readOptionalQueryString(obj, 'projectId') }
      : {}),
    ...(readOptionalQueryString(obj, 'environmentId')
      ? { environmentId: readOptionalQueryString(obj, 'environmentId') }
      : {}),
    ...(readOptionalQueryString(obj, 'cursor')
      ? { cursor: readOptionalQueryString(obj, 'cursor') }
      : {}),
    limit: parseLimit(requestedLimit),
  };
}

export function parseGetConsoleObservabilityTimeseriesRequest(
  query: unknown,
): GetConsoleObservabilityTimeseriesRequest {
  const obj = requireQueryObject(query, createError);
  const from = parseOptionalIsoTimestamp(readOptionalQueryString(obj, 'from'), 'from');
  const to = parseOptionalIsoTimestamp(readOptionalQueryString(obj, 'to'), 'to');
  ensureValidWindow(from, to);
  const requestedBucketMinutes = readOptionalPositiveInteger(obj, 'bucketMinutes', createError);

  return {
    ...(from ? { from } : {}),
    ...(to ? { to } : {}),
    ...(readOptionalQueryString(obj, 'service')
      ? { service: readOptionalQueryString(obj, 'service') }
      : {}),
    ...(readOptionalQueryString(obj, 'projectId')
      ? { projectId: readOptionalQueryString(obj, 'projectId') }
      : {}),
    ...(readOptionalQueryString(obj, 'environmentId')
      ? { environmentId: readOptionalQueryString(obj, 'environmentId') }
      : {}),
    bucketMinutes: parseBucketMinutes(requestedBucketMinutes),
  };
}

export function parseListConsoleObservabilityServicesRequest(
  query: unknown,
): ListConsoleObservabilityServicesRequest {
  const obj = requireQueryObject(query, createError);
  const from = parseOptionalIsoTimestamp(readOptionalQueryString(obj, 'from'), 'from');
  const to = parseOptionalIsoTimestamp(readOptionalQueryString(obj, 'to'), 'to');
  ensureValidWindow(from, to);
  const requestedLimit = readOptionalPositiveInteger(obj, 'limit', createError);

  return {
    ...(from ? { from } : {}),
    ...(to ? { to } : {}),
    ...(readOptionalQueryString(obj, 'projectId')
      ? { projectId: readOptionalQueryString(obj, 'projectId') }
      : {}),
    ...(readOptionalQueryString(obj, 'environmentId')
      ? { environmentId: readOptionalQueryString(obj, 'environmentId') }
      : {}),
    limit: parseLimit(requestedLimit),
  };
}
