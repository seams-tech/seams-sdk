import {
  buildConsoleAcceptHeaders,
  consoleErrorMessage,
  parseConsoleJson,
  requireConsoleBaseUrl,
} from '../../consoleHttp';

export type DashboardConsoleAuditCategory =
  | 'POLICY'
  | 'SETTINGS'
  | 'KEY_EXPORT'
  | 'BILLING'
  | 'WEBHOOK'
  | 'API_KEY'
  | 'TEAM'
  | 'APPROVAL'
  | 'ORG_PROJECT_ENV'
  | 'RUNTIME_SNAPSHOT'
  | 'SYSTEM';

export type DashboardConsoleAuditOutcome = 'SUCCESS' | 'FAILURE' | 'PENDING';
export type DashboardConsoleAuditExportDomain =
  | 'POLICY'
  | 'BILLING'
  | 'KEY_EXPORT'
  | 'SECURITY'
  | 'ALL';
export type DashboardConsoleAuditExportFormat = 'JSONL' | 'CSV';
export type DashboardConsoleAuditExportStatus = 'QUEUED' | 'PROCESSING' | 'READY' | 'FAILED';

export interface DashboardConsoleAuditEvent {
  id: string;
  orgId: string;
  projectId?: string;
  environmentId?: string;
  policyId: string | null;
  policyName: string | null;
  actorUserId: string;
  actorType: 'USER' | 'SYSTEM';
  category: DashboardConsoleAuditCategory;
  action: string;
  outcome: DashboardConsoleAuditOutcome;
  summary: string;
  metadata: Record<string, unknown>;
  createdAt: string;
}

export interface DashboardConsoleAuditExportRecord {
  id: string;
  orgId: string;
  requestedByUserId: string;
  status: DashboardConsoleAuditExportStatus;
  format: DashboardConsoleAuditExportFormat;
  filters: {
    projectId?: string;
    environmentId?: string;
    domain?: DashboardConsoleAuditExportDomain;
    from?: string;
    to?: string;
  };
  createdAt: string;
  updatedAt: string;
  readyAt: string | null;
  expiresAt: string | null;
  downloadUrl: string | null;
  failureCode: string | null;
  failureMessage: string | null;
}

interface ConsoleAuditEventsResponse {
  ok?: boolean;
  code?: string;
  message?: string;
  events?: unknown;
}

interface ConsoleAuditExportsResponse {
  ok?: boolean;
  code?: string;
  message?: string;
  exports?: unknown;
}

interface ConsoleAuditExportMutationResponse {
  ok?: boolean;
  code?: string;
  message?: string;
  export?: unknown;
}

const CATEGORY_SET = new Set<DashboardConsoleAuditCategory>([
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
const OUTCOME_SET = new Set<DashboardConsoleAuditOutcome>(['SUCCESS', 'FAILURE', 'PENDING']);
const EXPORT_DOMAIN_SET = new Set<DashboardConsoleAuditExportDomain>([
  'POLICY',
  'BILLING',
  'KEY_EXPORT',
  'SECURITY',
  'ALL',
]);
const EXPORT_FORMAT_SET = new Set<DashboardConsoleAuditExportFormat>(['JSONL', 'CSV']);
const EXPORT_STATUS_SET = new Set<DashboardConsoleAuditExportStatus>([
  'QUEUED',
  'PROCESSING',
  'READY',
  'FAILED',
]);

function decodeAuditEvent(raw: unknown): DashboardConsoleAuditEvent | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const id = String(row.id || '').trim();
  const orgId = String(row.orgId || '').trim();
  const actorUserId = String(row.actorUserId || '').trim();
  const category = String(row.category || '')
    .trim()
    .toUpperCase() as DashboardConsoleAuditCategory;
  const outcome = String(row.outcome || '')
    .trim()
    .toUpperCase() as DashboardConsoleAuditOutcome;
  if (!id || !orgId || !actorUserId || !CATEGORY_SET.has(category) || !OUTCOME_SET.has(outcome)) {
    return null;
  }
  const actorType = String(row.actorType || '')
    .trim()
    .toUpperCase();
  return {
    id,
    orgId,
    ...(row.projectId ? { projectId: String(row.projectId || '').trim() } : {}),
    ...(row.environmentId ? { environmentId: String(row.environmentId || '').trim() } : {}),
    policyId: String(row.policyId || '').trim() || null,
    policyName: String(row.policyName || '').trim() || null,
    actorUserId,
    actorType: actorType === 'SYSTEM' ? 'SYSTEM' : 'USER',
    category,
    action: String(row.action || '').trim(),
    outcome,
    summary: String(row.summary || '').trim(),
    metadata:
      row.metadata && typeof row.metadata === 'object' && !Array.isArray(row.metadata)
        ? { ...(row.metadata as Record<string, unknown>) }
        : {},
    createdAt: String(row.createdAt || '').trim(),
  };
}

function decodeAuditExport(raw: unknown): DashboardConsoleAuditExportRecord | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const id = String(row.id || '').trim();
  const orgId = String(row.orgId || '').trim();
  const requestedByUserId = String(row.requestedByUserId || '').trim();
  const status = String(row.status || '')
    .trim()
    .toUpperCase() as DashboardConsoleAuditExportStatus;
  const format = String(row.format || '')
    .trim()
    .toUpperCase() as DashboardConsoleAuditExportFormat;
  if (!id || !orgId || !requestedByUserId) return null;
  if (!EXPORT_STATUS_SET.has(status) || !EXPORT_FORMAT_SET.has(format)) return null;

  const filtersRaw =
    row.filters && typeof row.filters === 'object' && !Array.isArray(row.filters)
      ? (row.filters as Record<string, unknown>)
      : {};
  const domainRaw = String(filtersRaw.domain || '')
    .trim()
    .toUpperCase() as DashboardConsoleAuditExportDomain;
  const domain = EXPORT_DOMAIN_SET.has(domainRaw) ? domainRaw : undefined;

  return {
    id,
    orgId,
    requestedByUserId,
    status,
    format,
    filters: {
      ...(filtersRaw.projectId ? { projectId: String(filtersRaw.projectId || '').trim() } : {}),
      ...(filtersRaw.environmentId
        ? { environmentId: String(filtersRaw.environmentId || '').trim() }
        : {}),
      ...(domain ? { domain } : {}),
      ...(filtersRaw.from ? { from: String(filtersRaw.from || '').trim() } : {}),
      ...(filtersRaw.to ? { to: String(filtersRaw.to || '').trim() } : {}),
    },
    createdAt: String(row.createdAt || '').trim(),
    updatedAt: String(row.updatedAt || '').trim(),
    readyAt: String(row.readyAt || '').trim() || null,
    expiresAt: String(row.expiresAt || '').trim() || null,
    downloadUrl: String(row.downloadUrl || '').trim() || null,
    failureCode: String(row.failureCode || '').trim() || null,
    failureMessage: String(row.failureMessage || '').trim() || null,
  };
}

function appendOptionalQuery(url: URL, key: string, value: string | undefined): void {
  const normalized = String(value || '').trim();
  if (!normalized) return;
  url.searchParams.set(key, normalized);
}

export async function listDashboardAuditEvents(input?: {
  projectId?: string;
  environmentId?: string;
  category?: DashboardConsoleAuditCategory;
  actorUserId?: string;
  outcome?: DashboardConsoleAuditOutcome;
  q?: string;
  from?: string;
  to?: string;
  limit?: number;
}): Promise<DashboardConsoleAuditEvent[]> {
  const base = requireConsoleBaseUrl();
  const url = new URL('/console/audit/events', base);
  appendOptionalQuery(url, 'projectId', input?.projectId);
  appendOptionalQuery(url, 'environmentId', input?.environmentId);
  appendOptionalQuery(url, 'category', input?.category);
  appendOptionalQuery(url, 'actorUserId', input?.actorUserId);
  appendOptionalQuery(url, 'outcome', input?.outcome);
  appendOptionalQuery(url, 'q', input?.q);
  appendOptionalQuery(url, 'from', input?.from);
  appendOptionalQuery(url, 'to', input?.to);
  if (Number.isFinite(Number(input?.limit)) && Number(input?.limit) > 0) {
    url.searchParams.set('limit', String(Math.floor(Number(input?.limit))));
  }

  const response = await fetch(url.toString(), {
    method: 'GET',
    headers: buildConsoleAcceptHeaders(),
    credentials: 'include',
    cache: 'no-store',
  });
  const body = (await parseConsoleJson(response)) as ConsoleAuditEventsResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Audit event list request failed'));
  }
  const rows = Array.isArray(body?.events) ? body.events : [];
  return rows
    .map((entry) => decodeAuditEvent(entry))
    .filter((entry): entry is DashboardConsoleAuditEvent => entry !== null);
}

export async function listDashboardAuditExports(input?: {
  status?: DashboardConsoleAuditExportStatus;
  domain?: DashboardConsoleAuditExportDomain;
  limit?: number;
}): Promise<DashboardConsoleAuditExportRecord[]> {
  const base = requireConsoleBaseUrl();
  const url = new URL('/console/audit/exports', base);
  appendOptionalQuery(url, 'status', input?.status);
  appendOptionalQuery(url, 'domain', input?.domain);
  if (Number.isFinite(Number(input?.limit)) && Number(input?.limit) > 0) {
    url.searchParams.set('limit', String(Math.floor(Number(input?.limit))));
  }

  const response = await fetch(url.toString(), {
    method: 'GET',
    headers: buildConsoleAcceptHeaders(),
    credentials: 'include',
    cache: 'no-store',
  });
  const body = (await parseConsoleJson(response)) as ConsoleAuditExportsResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Audit export list request failed'));
  }
  const rows = Array.isArray(body?.exports) ? body.exports : [];
  return rows
    .map((entry) => decodeAuditExport(entry))
    .filter((entry): entry is DashboardConsoleAuditExportRecord => entry !== null);
}

export async function createDashboardAuditExport(input: {
  id?: string;
  format: DashboardConsoleAuditExportFormat;
  domain?: DashboardConsoleAuditExportDomain;
  projectId?: string;
  environmentId?: string;
  from?: string;
  to?: string;
}): Promise<DashboardConsoleAuditExportRecord> {
  const base = requireConsoleBaseUrl();
  const response = await fetch(`${base}/console/audit/exports`, {
    method: 'POST',
    headers: {
      ...buildConsoleAcceptHeaders(),
      'Content-Type': 'application/json',
    },
    credentials: 'include',
    cache: 'no-store',
    body: JSON.stringify(input),
  });
  const body = (await parseConsoleJson(response)) as ConsoleAuditExportMutationResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Audit export create request failed'));
  }
  const auditExport = decodeAuditExport(body?.export);
  if (!auditExport) throw new Error('Audit export response was invalid');
  return auditExport;
}
