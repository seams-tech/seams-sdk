import {
  buildConsoleAcceptHeaders,
  normalizeConsoleFetchError,
  parseConsoleJson,
  requireConsoleBaseUrl,
} from '../../consoleHttp';

export type DashboardConsoleObservabilityModuleState =
  | 'ok'
  | 'not_configured'
  | 'forbidden'
  | 'error';
export type DashboardConsoleObservabilityLevel = 'DEBUG' | 'INFO' | 'WARN' | 'ERROR' | 'FATAL';
export type DashboardConsoleServiceHealthState = 'HEALTHY' | 'DEGRADED' | 'FAILING' | 'UNKNOWN';

export interface DashboardConsoleObservabilityModuleStatus {
  state: DashboardConsoleObservabilityModuleState;
  code?: string;
  message?: string;
}

export interface DashboardConsoleObservabilitySummary {
  generatedAt: string;
  status: DashboardConsoleObservabilityModuleStatus;
  errorRate: number;
  p95LatencyMs: number;
  failingServices: number;
  deadLetterCount: number;
}

export interface DashboardConsoleObservabilityEvent {
  id: string;
  orgId: string;
  projectId?: string;
  environmentId?: string;
  timestamp: string;
  service: string;
  component: string;
  level: DashboardConsoleObservabilityLevel;
  eventType: string;
  message: string;
  requestId?: string;
  traceId?: string;
  metadata: Record<string, unknown>;
}

export interface DashboardConsoleObservabilityEventsPage {
  status: DashboardConsoleObservabilityModuleStatus;
  events: DashboardConsoleObservabilityEvent[];
  nextCursor?: string;
}

export interface DashboardConsoleObservabilityTimeseriesBucket {
  start: string;
  end: string;
  errorCount: number;
  requestCount: number;
  p50LatencyMs: number;
  p95LatencyMs: number;
}

export interface DashboardConsoleObservabilityTimeseries {
  status: DashboardConsoleObservabilityModuleStatus;
  buckets: DashboardConsoleObservabilityTimeseriesBucket[];
}

export interface DashboardConsoleObservabilityServiceHealth {
  service: string;
  status: DashboardConsoleServiceHealthState;
  recentFailureCount: number;
  latestIncidentAt?: string;
}

export interface DashboardConsoleObservabilityServicesView {
  status: DashboardConsoleObservabilityModuleStatus;
  services: DashboardConsoleObservabilityServiceHealth[];
}

export interface DashboardConsoleObservabilitySnapshot {
  summary: DashboardConsoleObservabilitySummary;
  events: DashboardConsoleObservabilityEventsPage;
  timeseries: DashboardConsoleObservabilityTimeseries;
  services: DashboardConsoleObservabilityServicesView;
}

export class DashboardConsoleObservabilityApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(input: { status: number; code?: string; message: string }) {
    super(input.message);
    this.name = 'DashboardConsoleObservabilityApiError';
    this.status = input.status;
    this.code = String(input.code || '').trim();
  }
}

interface ConsoleObservabilitySummaryResponse {
  ok?: boolean;
  code?: string;
  message?: string;
  summary?: unknown;
}

interface ConsoleObservabilityEventsResponse {
  ok?: boolean;
  code?: string;
  message?: string;
  status?: unknown;
  events?: unknown;
  nextCursor?: unknown;
}

interface ConsoleObservabilityTimeseriesResponse {
  ok?: boolean;
  code?: string;
  message?: string;
  status?: unknown;
  buckets?: unknown;
}

interface ConsoleObservabilityServicesResponse {
  ok?: boolean;
  code?: string;
  message?: string;
  status?: unknown;
  services?: unknown;
}

export interface DashboardConsoleObservabilityScope {
  from?: string;
  to?: string;
  projectId?: string;
  environmentId?: string;
}

export interface ListDashboardConsoleObservabilityEventsRequest
  extends DashboardConsoleObservabilityScope {
  level?: DashboardConsoleObservabilityLevel;
  service?: string;
  eventType?: string;
  cursor?: string;
  limit?: number;
}

export interface GetDashboardConsoleObservabilityTimeseriesRequest
  extends DashboardConsoleObservabilityScope {
  service?: string;
  eventType?: string;
  bucketMinutes?: number;
}

export interface ListDashboardConsoleObservabilityServicesRequest
  extends DashboardConsoleObservabilityScope {
  limit?: number;
}

const OBSERVABILITY_LEVEL_SET = new Set<DashboardConsoleObservabilityLevel>([
  'DEBUG',
  'INFO',
  'WARN',
  'ERROR',
  'FATAL',
]);
const SERVICE_HEALTH_SET = new Set<DashboardConsoleServiceHealthState>([
  'HEALTHY',
  'DEGRADED',
  'FAILING',
  'UNKNOWN',
]);

function toTrimmedString(raw: unknown): string {
  return String(raw || '').trim();
}

function toFiniteNumber(raw: unknown, fallback = 0): number {
  const value = Number(raw);
  return Number.isFinite(value) ? value : fallback;
}

function toNonNegativeInteger(raw: unknown): number {
  const value = toFiniteNumber(raw, 0);
  if (value <= 0) return 0;
  return Math.floor(value);
}

function buildApiError(
  response: Response,
  body: any,
  fallback: string,
): DashboardConsoleObservabilityApiError {
  const code = toTrimmedString(body?.code);
  const apiMessage = toTrimmedString(body?.message);
  return new DashboardConsoleObservabilityApiError({
    status: response.status,
    code,
    message: apiMessage || `${fallback} (${response.status})`,
  });
}

export function isDashboardConsoleObservabilityApiErrorCode(
  error: unknown,
  code: string,
): boolean {
  if (!(error instanceof DashboardConsoleObservabilityApiError)) return false;
  return error.code === code;
}

function decodeStatus(raw: unknown): DashboardConsoleObservabilityModuleStatus {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return {
      state: 'error',
      code: 'invalid_status',
      message: 'Observability status payload was invalid',
    };
  }
  const row = raw as Record<string, unknown>;
  const stateRaw = toTrimmedString(row.state).toLowerCase();
  const state: DashboardConsoleObservabilityModuleState =
    stateRaw === 'ok' ||
    stateRaw === 'not_configured' ||
    stateRaw === 'forbidden' ||
    stateRaw === 'error'
      ? (stateRaw as DashboardConsoleObservabilityModuleState)
      : 'error';
  return {
    state,
    ...(toTrimmedString(row.code) ? { code: toTrimmedString(row.code) } : {}),
    ...(toTrimmedString(row.message) ? { message: toTrimmedString(row.message) } : {}),
  };
}

function decodeSummary(raw: unknown): DashboardConsoleObservabilitySummary | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  return {
    generatedAt: toTrimmedString(row.generatedAt),
    status: decodeStatus(row.status),
    errorRate: Math.max(0, toFiniteNumber(row.errorRate, 0)),
    p95LatencyMs: Math.max(0, toFiniteNumber(row.p95LatencyMs, 0)),
    failingServices: toNonNegativeInteger(row.failingServices),
    deadLetterCount: toNonNegativeInteger(row.deadLetterCount),
  };
}

function decodeEvent(raw: unknown): DashboardConsoleObservabilityEvent | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const id = toTrimmedString(row.id);
  const orgId = toTrimmedString(row.orgId);
  if (!id || !orgId) return null;

  const levelRaw = toTrimmedString(row.level).toUpperCase() as DashboardConsoleObservabilityLevel;
  const level = OBSERVABILITY_LEVEL_SET.has(levelRaw) ? levelRaw : 'INFO';
  const metadata =
    row.metadata && typeof row.metadata === 'object' && !Array.isArray(row.metadata)
      ? { ...(row.metadata as Record<string, unknown>) }
      : {};

  return {
    id,
    orgId,
    ...(toTrimmedString(row.projectId) ? { projectId: toTrimmedString(row.projectId) } : {}),
    ...(toTrimmedString(row.environmentId)
      ? { environmentId: toTrimmedString(row.environmentId) }
      : {}),
    timestamp: toTrimmedString(row.timestamp),
    service: toTrimmedString(row.service),
    component: toTrimmedString(row.component),
    level,
    eventType: toTrimmedString(row.eventType),
    message: toTrimmedString(row.message),
    ...(toTrimmedString(row.requestId) ? { requestId: toTrimmedString(row.requestId) } : {}),
    ...(toTrimmedString(row.traceId) ? { traceId: toTrimmedString(row.traceId) } : {}),
    metadata,
  };
}

function decodeTimeseriesBucket(raw: unknown): DashboardConsoleObservabilityTimeseriesBucket | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const start = toTrimmedString(row.start);
  const end = toTrimmedString(row.end);
  if (!start || !end) return null;
  return {
    start,
    end,
    errorCount: toNonNegativeInteger(row.errorCount),
    requestCount: toNonNegativeInteger(row.requestCount),
    p50LatencyMs: Math.max(0, toFiniteNumber(row.p50LatencyMs, 0)),
    p95LatencyMs: Math.max(0, toFiniteNumber(row.p95LatencyMs, 0)),
  };
}

function decodeServiceHealth(raw: unknown): DashboardConsoleObservabilityServiceHealth | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const service = toTrimmedString(row.service);
  if (!service) return null;
  const statusRaw = toTrimmedString(row.status).toUpperCase() as DashboardConsoleServiceHealthState;
  return {
    service,
    status: SERVICE_HEALTH_SET.has(statusRaw) ? statusRaw : 'UNKNOWN',
    recentFailureCount: toNonNegativeInteger(row.recentFailureCount),
    ...(toTrimmedString(row.latestIncidentAt)
      ? { latestIncidentAt: toTrimmedString(row.latestIncidentAt) }
      : {}),
  };
}

function appendOptionalQuery(url: URL, key: string, value: string | undefined): void {
  const normalized = toTrimmedString(value);
  if (!normalized) return;
  url.searchParams.set(key, normalized);
}

function applyScope(url: URL, scope: DashboardConsoleObservabilityScope | undefined): void {
  appendOptionalQuery(url, 'from', scope?.from);
  appendOptionalQuery(url, 'to', scope?.to);
  appendOptionalQuery(url, 'projectId', scope?.projectId);
  appendOptionalQuery(url, 'environmentId', scope?.environmentId);
}

export async function getDashboardObservabilitySummary(
  input?: DashboardConsoleObservabilityScope,
): Promise<DashboardConsoleObservabilitySummary> {
  const base = requireConsoleBaseUrl();
  const url = new URL('/console/observability/summary', base);
  applyScope(url, input);

  let response: Response;
  try {
    response = await fetch(url.toString(), {
      method: 'GET',
      headers: buildConsoleAcceptHeaders(),
      credentials: 'include',
      cache: 'no-store',
    });
  } catch (error: unknown) {
    throw normalizeConsoleFetchError({
      error,
      baseUrl: base,
      path: '/console/observability/summary',
      operation: 'Observability summary request',
    });
  }

  const body = (await parseConsoleJson(response)) as ConsoleObservabilitySummaryResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw buildApiError(response, body, 'Observability summary request failed');
  }
  const summary = decodeSummary(body.summary);
  if (!summary) throw new Error('Observability summary response was invalid');
  return summary;
}

export async function listDashboardObservabilityEvents(
  input?: ListDashboardConsoleObservabilityEventsRequest,
): Promise<DashboardConsoleObservabilityEventsPage> {
  const base = requireConsoleBaseUrl();
  const url = new URL('/console/observability/events', base);
  applyScope(url, input);
  appendOptionalQuery(url, 'service', input?.service);
  appendOptionalQuery(url, 'eventType', input?.eventType);
  appendOptionalQuery(url, 'cursor', input?.cursor);
  if (input?.level && OBSERVABILITY_LEVEL_SET.has(input.level)) {
    url.searchParams.set('level', input.level);
  }
  if (Number.isFinite(Number(input?.limit)) && Number(input?.limit) > 0) {
    url.searchParams.set('limit', String(Math.floor(Number(input?.limit))));
  }

  let response: Response;
  try {
    response = await fetch(url.toString(), {
      method: 'GET',
      headers: buildConsoleAcceptHeaders(),
      credentials: 'include',
      cache: 'no-store',
    });
  } catch (error: unknown) {
    throw normalizeConsoleFetchError({
      error,
      baseUrl: base,
      path: '/console/observability/events',
      operation: 'Observability events request',
    });
  }

  const body = (await parseConsoleJson(response)) as ConsoleObservabilityEventsResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw buildApiError(response, body, 'Observability events request failed');
  }

  const eventsRaw = Array.isArray(body.events) ? body.events : [];
  return {
    status: decodeStatus(body.status),
    events: eventsRaw
      .map((entry) => decodeEvent(entry))
      .filter((entry): entry is DashboardConsoleObservabilityEvent => entry !== null),
    ...(toTrimmedString(body.nextCursor) ? { nextCursor: toTrimmedString(body.nextCursor) } : {}),
  };
}

export async function getDashboardObservabilityTimeseries(
  input?: GetDashboardConsoleObservabilityTimeseriesRequest,
): Promise<DashboardConsoleObservabilityTimeseries> {
  const base = requireConsoleBaseUrl();
  const url = new URL('/console/observability/timeseries', base);
  applyScope(url, input);
  appendOptionalQuery(url, 'service', input?.service);
  appendOptionalQuery(url, 'eventType', input?.eventType);
  if (Number.isFinite(Number(input?.bucketMinutes)) && Number(input?.bucketMinutes) > 0) {
    url.searchParams.set('bucketMinutes', String(Math.floor(Number(input?.bucketMinutes))));
  }

  let response: Response;
  try {
    response = await fetch(url.toString(), {
      method: 'GET',
      headers: buildConsoleAcceptHeaders(),
      credentials: 'include',
      cache: 'no-store',
    });
  } catch (error: unknown) {
    throw normalizeConsoleFetchError({
      error,
      baseUrl: base,
      path: '/console/observability/timeseries',
      operation: 'Observability timeseries request',
    });
  }

  const body = (await parseConsoleJson(response)) as ConsoleObservabilityTimeseriesResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw buildApiError(response, body, 'Observability timeseries request failed');
  }

  const bucketsRaw = Array.isArray(body.buckets) ? body.buckets : [];
  return {
    status: decodeStatus(body.status),
    buckets: bucketsRaw
      .map((entry) => decodeTimeseriesBucket(entry))
      .filter((entry): entry is DashboardConsoleObservabilityTimeseriesBucket => entry !== null),
  };
}

export async function listDashboardObservabilityServices(
  input?: ListDashboardConsoleObservabilityServicesRequest,
): Promise<DashboardConsoleObservabilityServicesView> {
  const base = requireConsoleBaseUrl();
  const url = new URL('/console/observability/services', base);
  applyScope(url, input);
  if (Number.isFinite(Number(input?.limit)) && Number(input?.limit) > 0) {
    url.searchParams.set('limit', String(Math.floor(Number(input?.limit))));
  }

  let response: Response;
  try {
    response = await fetch(url.toString(), {
      method: 'GET',
      headers: buildConsoleAcceptHeaders(),
      credentials: 'include',
      cache: 'no-store',
    });
  } catch (error: unknown) {
    throw normalizeConsoleFetchError({
      error,
      baseUrl: base,
      path: '/console/observability/services',
      operation: 'Observability services request',
    });
  }

  const body = (await parseConsoleJson(response)) as ConsoleObservabilityServicesResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw buildApiError(response, body, 'Observability services request failed');
  }

  const servicesRaw = Array.isArray(body.services) ? body.services : [];
  return {
    status: decodeStatus(body.status),
    services: servicesRaw
      .map((entry) => decodeServiceHealth(entry))
      .filter((entry): entry is DashboardConsoleObservabilityServiceHealth => entry !== null),
  };
}

export async function getDashboardObservabilitySnapshot(
  input?: DashboardConsoleObservabilityScope,
): Promise<DashboardConsoleObservabilitySnapshot> {
  const [summary, events, timeseries, services] = await Promise.all([
    getDashboardObservabilitySummary(input),
    listDashboardObservabilityEvents({ ...input, limit: 25 }),
    getDashboardObservabilityTimeseries({ ...input, bucketMinutes: 5 }),
    listDashboardObservabilityServices({ ...input, limit: 25 }),
  ]);
  return {
    summary,
    events,
    timeseries,
    services,
  };
}
