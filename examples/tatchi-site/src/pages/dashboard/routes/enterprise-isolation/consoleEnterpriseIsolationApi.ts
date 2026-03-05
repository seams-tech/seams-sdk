import {
  buildConsoleAcceptHeaders,
  buildConsoleJsonHeaders,
  consoleErrorMessage,
  parseConsoleJson,
  requireConsoleBaseUrl,
} from '../../consoleHttp';

export type DashboardEnterpriseIsolationScope = 'ORG' | 'PROJECT' | 'ENVIRONMENT';
export type DashboardEnterpriseIsolationMode = 'SHARED' | 'DEDICATED';
export type DashboardEnterpriseIsolationStatus =
  | 'SHARED'
  | 'REQUESTED'
  | 'MIGRATING'
  | 'ISOLATED'
  | 'FAILED';
export type DashboardEnterpriseIsolationTrigger = 'MANUAL' | 'SLA_BREACH' | 'COMPLIANCE';

export interface DashboardEnterpriseIsolationState {
  orgId: string;
  scope: DashboardEnterpriseIsolationScope;
  projectId: string | null;
  environmentId: string | null;
  mode: DashboardEnterpriseIsolationMode;
  status: DashboardEnterpriseIsolationStatus;
  trigger: DashboardEnterpriseIsolationTrigger | null;
  requestedByUserId: string | null;
  requestedAt: string | null;
  activatedAt: string | null;
  reason: string | null;
  ticketId: string | null;
  sla: {
    availabilityTargetPercent: string;
    rpoMinutes: number;
    rtoHours: number;
  };
  createdAt: string;
  updatedAt: string;
}

interface ConsoleIsolationResponse {
  ok?: boolean;
  code?: string;
  message?: string;
  isolation?: unknown;
}

const SCOPE_SET = new Set<DashboardEnterpriseIsolationScope>(['ORG', 'PROJECT', 'ENVIRONMENT']);
const MODE_SET = new Set<DashboardEnterpriseIsolationMode>(['SHARED', 'DEDICATED']);
const STATUS_SET = new Set<DashboardEnterpriseIsolationStatus>([
  'SHARED',
  'REQUESTED',
  'MIGRATING',
  'ISOLATED',
  'FAILED',
]);
const TRIGGER_SET = new Set<DashboardEnterpriseIsolationTrigger>([
  'MANUAL',
  'SLA_BREACH',
  'COMPLIANCE',
]);

function decodeIsolationState(raw: unknown): DashboardEnterpriseIsolationState | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const orgId = String(row.orgId || '').trim();
  const scope = String(row.scope || '')
    .trim()
    .toUpperCase() as DashboardEnterpriseIsolationScope;
  const mode = String(row.mode || '')
    .trim()
    .toUpperCase() as DashboardEnterpriseIsolationMode;
  const status = String(row.status || '')
    .trim()
    .toUpperCase() as DashboardEnterpriseIsolationStatus;
  const triggerRaw = String(row.trigger || '')
    .trim()
    .toUpperCase() as DashboardEnterpriseIsolationTrigger;
  if (!orgId || !SCOPE_SET.has(scope) || !MODE_SET.has(mode) || !STATUS_SET.has(status)) return null;
  const slaRaw = row.sla && typeof row.sla === 'object' && !Array.isArray(row.sla) ? (row.sla as Record<string, unknown>) : {};
  return {
    orgId,
    scope,
    projectId: String(row.projectId || '').trim() || null,
    environmentId: String(row.environmentId || '').trim() || null,
    mode,
    status,
    trigger: TRIGGER_SET.has(triggerRaw) ? triggerRaw : null,
    requestedByUserId: String(row.requestedByUserId || '').trim() || null,
    requestedAt: String(row.requestedAt || '').trim() || null,
    activatedAt: String(row.activatedAt || '').trim() || null,
    reason: String(row.reason || '').trim() || null,
    ticketId: String(row.ticketId || '').trim() || null,
    sla: {
      availabilityTargetPercent: String(slaRaw.availabilityTargetPercent || '99.95').trim() || '99.95',
      rpoMinutes: Math.max(1, Number(slaRaw.rpoMinutes || 15)),
      rtoHours: Math.max(1, Number(slaRaw.rtoHours || 4)),
    },
    createdAt: String(row.createdAt || '').trim(),
    updatedAt: String(row.updatedAt || '').trim(),
  };
}

export async function getDashboardEnterpriseIsolationStatus(input?: {
  scope?: DashboardEnterpriseIsolationScope;
  projectId?: string;
  environmentId?: string;
}): Promise<DashboardEnterpriseIsolationState> {
  const base = requireConsoleBaseUrl();
  const url = new URL('/console/isolation/status', base);
  if (input?.scope) url.searchParams.set('scope', input.scope);
  if (input?.projectId) url.searchParams.set('projectId', input.projectId);
  if (input?.environmentId) url.searchParams.set('environmentId', input.environmentId);
  const response = await fetch(url.toString(), {
    method: 'GET',
    headers: buildConsoleAcceptHeaders(),
    credentials: 'include',
    cache: 'no-store',
  });
  const body = (await parseConsoleJson(response)) as ConsoleIsolationResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Enterprise isolation status request failed'));
  }
  const isolation = decodeIsolationState(body?.isolation);
  if (!isolation) throw new Error('Enterprise isolation status response was invalid');
  return isolation;
}

export async function triggerDashboardEnterpriseIsolation(input: {
  scope?: DashboardEnterpriseIsolationScope;
  projectId?: string;
  environmentId?: string;
  trigger?: DashboardEnterpriseIsolationTrigger;
  reason: string;
  ticketId?: string;
}): Promise<DashboardEnterpriseIsolationState> {
  const base = requireConsoleBaseUrl();
  const response = await fetch(`${base}/console/isolation/trigger`, {
    method: 'POST',
    headers: buildConsoleJsonHeaders(),
    credentials: 'include',
    cache: 'no-store',
    body: JSON.stringify(input),
  });
  const body = (await parseConsoleJson(response)) as ConsoleIsolationResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Enterprise isolation trigger request failed'));
  }
  const isolation = decodeIsolationState(body?.isolation);
  if (!isolation) throw new Error('Enterprise isolation trigger response was invalid');
  return isolation;
}
