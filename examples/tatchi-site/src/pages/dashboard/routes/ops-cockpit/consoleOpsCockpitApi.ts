import {
  buildConsoleAcceptHeaders,
  consoleErrorMessage,
  parseConsoleJson,
  requireConsoleBaseUrl,
} from '../../consoleHttp';

export type DashboardOpsCockpitSectionState = 'ok' | 'not_configured' | 'forbidden' | 'error';

export interface DashboardOpsCockpitSectionStatus {
  state: DashboardOpsCockpitSectionState;
  code?: string;
  message?: string;
}

export interface DashboardOpsCockpitPendingApproval {
  id: string;
  operationType: string;
  reason: string;
  requestedByUserId: string;
  requiredApprovals: number;
  requireMfa: boolean;
  resourceType: string | null;
  resourceId: string | null;
  createdAt: string;
}

export interface DashboardOpsCockpitFailedInvoice {
  id: string;
  status: string;
  dueAt: string | null;
}

export interface DashboardOpsCockpitDeadLetterEntry {
  endpointId: string;
  endpointUrl: string;
  endpointStatus: string;
  deadLetter: {
    id: string;
    deliveryId: string;
    eventId: string;
    eventType: string;
    failedAttempts: number;
    lastErrorMessage: string | null;
    movedToDlqAt: string;
  };
}

export interface DashboardOpsCockpitQueuedExport {
  id: string;
  status: string;
  format: string;
  createdAt: string;
}

export interface DashboardOpsCockpitIsolationRequest {
  status: string;
  trigger: string | null;
}

export interface DashboardOpsCockpitOnboardingAlert {
  code: string;
  operation: string;
  severity: 'WARN' | 'CRITICAL';
  message: string;
}

export interface DashboardOpsCockpitSummary {
  generatedAt: string;
  approvals: {
    status: DashboardOpsCockpitSectionStatus;
    pendingCount: number;
    pending: DashboardOpsCockpitPendingApproval[];
  };
  billing: {
    status: DashboardOpsCockpitSectionStatus;
    failedInvoiceCount: number;
    failedInvoices: DashboardOpsCockpitFailedInvoice[];
  };
  webhooks: {
    status: DashboardOpsCockpitSectionStatus;
    endpointCount: number;
    scannedEndpointCount: number;
    deadLetterCount: number;
    deadLetters: DashboardOpsCockpitDeadLetterEntry[];
  };
  auditExports: {
    status: DashboardOpsCockpitSectionStatus;
    queuedExportCount: number;
    queuedExports: DashboardOpsCockpitQueuedExport[];
  };
  enterpriseIsolation: {
    status: DashboardOpsCockpitSectionStatus;
    activeRequestCount: number;
    activeRequests: DashboardOpsCockpitIsolationRequest[];
  };
  onboardingTelemetry: {
    status: DashboardOpsCockpitSectionStatus;
    windowMinutes: number;
    alertCount: number;
    alerts: DashboardOpsCockpitOnboardingAlert[];
  };
}

interface ConsoleOpsCockpitSummaryResponse {
  ok?: boolean;
  code?: string;
  message?: string;
  summary?: unknown;
}

function toTrimmedString(raw: unknown): string {
  return String(raw || '').trim();
}

function toFiniteNumber(raw: unknown, fallback = 0): number {
  const value = Number(raw);
  return Number.isFinite(value) ? value : fallback;
}

function decodeStatus(raw: unknown): DashboardOpsCockpitSectionStatus {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return { state: 'error', code: 'invalid_status', message: 'Status payload was invalid' };
  }
  const row = raw as Record<string, unknown>;
  const stateRaw = toTrimmedString(row.state).toLowerCase();
  const state: DashboardOpsCockpitSectionState =
    stateRaw === 'ok' ||
    stateRaw === 'not_configured' ||
    stateRaw === 'forbidden' ||
    stateRaw === 'error'
      ? (stateRaw as DashboardOpsCockpitSectionState)
      : 'error';
  return {
    state,
    ...(toTrimmedString(row.code) ? { code: toTrimmedString(row.code) } : {}),
    ...(toTrimmedString(row.message) ? { message: toTrimmedString(row.message) } : {}),
  };
}

function decodePendingApproval(raw: unknown): DashboardOpsCockpitPendingApproval | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const id = toTrimmedString(row.id);
  if (!id) return null;
  return {
    id,
    operationType: toTrimmedString(row.operationType),
    reason: toTrimmedString(row.reason),
    requestedByUserId: toTrimmedString(row.requestedByUserId),
    requiredApprovals: Math.max(1, Math.floor(toFiniteNumber(row.requiredApprovals, 1))),
    requireMfa: row.requireMfa === true,
    resourceType: toTrimmedString(row.resourceType) || null,
    resourceId: toTrimmedString(row.resourceId) || null,
    createdAt: toTrimmedString(row.createdAt),
  };
}

function decodeFailedInvoice(raw: unknown): DashboardOpsCockpitFailedInvoice | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const id = toTrimmedString(row.id);
  if (!id) return null;
  return {
    id,
    status: toTrimmedString(row.status),
    dueAt: toTrimmedString(row.dueAt) || null,
  };
}

function decodeDeadLetterEntry(raw: unknown): DashboardOpsCockpitDeadLetterEntry | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const deadLetterRaw =
    row.deadLetter && typeof row.deadLetter === 'object' && !Array.isArray(row.deadLetter)
      ? (row.deadLetter as Record<string, unknown>)
      : null;
  if (!deadLetterRaw) return null;
  const deadLetterId = toTrimmedString(deadLetterRaw.id);
  if (!deadLetterId) return null;
  const endpointId = toTrimmedString(row.endpointId);
  if (!endpointId) return null;
  return {
    endpointId,
    endpointUrl: toTrimmedString(row.endpointUrl),
    endpointStatus: toTrimmedString(row.endpointStatus),
    deadLetter: {
      id: deadLetterId,
      deliveryId: toTrimmedString(deadLetterRaw.deliveryId),
      eventId: toTrimmedString(deadLetterRaw.eventId),
      eventType: toTrimmedString(deadLetterRaw.eventType),
      failedAttempts: Math.max(0, Math.floor(toFiniteNumber(deadLetterRaw.failedAttempts))),
      lastErrorMessage: toTrimmedString(deadLetterRaw.lastErrorMessage) || null,
      movedToDlqAt: toTrimmedString(deadLetterRaw.movedToDlqAt),
    },
  };
}

function decodeQueuedExport(raw: unknown): DashboardOpsCockpitQueuedExport | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const id = toTrimmedString(row.id);
  if (!id) return null;
  return {
    id,
    status: toTrimmedString(row.status),
    format: toTrimmedString(row.format),
    createdAt: toTrimmedString(row.createdAt),
  };
}

function decodeIsolationRequest(raw: unknown): DashboardOpsCockpitIsolationRequest | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const status = toTrimmedString(row.status);
  if (!status) return null;
  return {
    status,
    trigger: toTrimmedString(row.trigger) || null,
  };
}

function decodeOnboardingAlert(raw: unknown): DashboardOpsCockpitOnboardingAlert | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const severityRaw = toTrimmedString(row.severity).toUpperCase();
  return {
    code: toTrimmedString(row.code),
    operation: toTrimmedString(row.operation),
    severity: severityRaw === 'CRITICAL' ? 'CRITICAL' : 'WARN',
    message: toTrimmedString(row.message),
  };
}

function decodeSummary(raw: unknown): DashboardOpsCockpitSummary | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const approvalsRaw =
    row.approvals && typeof row.approvals === 'object' && !Array.isArray(row.approvals)
      ? (row.approvals as Record<string, unknown>)
      : {};
  const billingRaw =
    row.billing && typeof row.billing === 'object' && !Array.isArray(row.billing)
      ? (row.billing as Record<string, unknown>)
      : {};
  const webhooksRaw =
    row.webhooks && typeof row.webhooks === 'object' && !Array.isArray(row.webhooks)
      ? (row.webhooks as Record<string, unknown>)
      : {};
  const auditExportsRaw =
    row.auditExports && typeof row.auditExports === 'object' && !Array.isArray(row.auditExports)
      ? (row.auditExports as Record<string, unknown>)
      : {};
  const enterpriseIsolationRaw =
    row.enterpriseIsolation &&
    typeof row.enterpriseIsolation === 'object' &&
    !Array.isArray(row.enterpriseIsolation)
      ? (row.enterpriseIsolation as Record<string, unknown>)
      : {};
  const onboardingTelemetryRaw =
    row.onboardingTelemetry &&
    typeof row.onboardingTelemetry === 'object' &&
    !Array.isArray(row.onboardingTelemetry)
      ? (row.onboardingTelemetry as Record<string, unknown>)
      : {};

  return {
    generatedAt: toTrimmedString(row.generatedAt),
    approvals: {
      status: decodeStatus(approvalsRaw.status),
      pendingCount: Math.max(0, Math.floor(toFiniteNumber(approvalsRaw.pendingCount))),
      pending: Array.isArray(approvalsRaw.pending)
        ? approvalsRaw.pending
            .map((entry) => decodePendingApproval(entry))
            .filter((entry): entry is DashboardOpsCockpitPendingApproval => entry !== null)
        : [],
    },
    billing: {
      status: decodeStatus(billingRaw.status),
      failedInvoiceCount: Math.max(0, Math.floor(toFiniteNumber(billingRaw.failedInvoiceCount))),
      failedInvoices: Array.isArray(billingRaw.failedInvoices)
        ? billingRaw.failedInvoices
            .map((entry) => decodeFailedInvoice(entry))
            .filter((entry): entry is DashboardOpsCockpitFailedInvoice => entry !== null)
        : [],
    },
    webhooks: {
      status: decodeStatus(webhooksRaw.status),
      endpointCount: Math.max(0, Math.floor(toFiniteNumber(webhooksRaw.endpointCount))),
      scannedEndpointCount: Math.max(
        0,
        Math.floor(toFiniteNumber(webhooksRaw.scannedEndpointCount)),
      ),
      deadLetterCount: Math.max(0, Math.floor(toFiniteNumber(webhooksRaw.deadLetterCount))),
      deadLetters: Array.isArray(webhooksRaw.deadLetters)
        ? webhooksRaw.deadLetters
            .map((entry) => decodeDeadLetterEntry(entry))
            .filter((entry): entry is DashboardOpsCockpitDeadLetterEntry => entry !== null)
        : [],
    },
    auditExports: {
      status: decodeStatus(auditExportsRaw.status),
      queuedExportCount: Math.max(0, Math.floor(toFiniteNumber(auditExportsRaw.queuedExportCount))),
      queuedExports: Array.isArray(auditExportsRaw.queuedExports)
        ? auditExportsRaw.queuedExports
            .map((entry) => decodeQueuedExport(entry))
            .filter((entry): entry is DashboardOpsCockpitQueuedExport => entry !== null)
        : [],
    },
    enterpriseIsolation: {
      status: decodeStatus(enterpriseIsolationRaw.status),
      activeRequestCount: Math.max(
        0,
        Math.floor(toFiniteNumber(enterpriseIsolationRaw.activeRequestCount)),
      ),
      activeRequests: Array.isArray(enterpriseIsolationRaw.activeRequests)
        ? enterpriseIsolationRaw.activeRequests
            .map((entry) => decodeIsolationRequest(entry))
            .filter((entry): entry is DashboardOpsCockpitIsolationRequest => entry !== null)
        : [],
    },
    onboardingTelemetry: {
      status: decodeStatus(onboardingTelemetryRaw.status),
      windowMinutes: Math.max(1, Math.floor(toFiniteNumber(onboardingTelemetryRaw.windowMinutes, 60))),
      alertCount: Math.max(0, Math.floor(toFiniteNumber(onboardingTelemetryRaw.alertCount))),
      alerts: Array.isArray(onboardingTelemetryRaw.alerts)
        ? onboardingTelemetryRaw.alerts
            .map((entry) => decodeOnboardingAlert(entry))
            .filter((entry): entry is DashboardOpsCockpitOnboardingAlert => entry !== null)
        : [],
    },
  };
}

export async function getDashboardOpsCockpitSummary(input?: {
  windowMinutes?: number;
}): Promise<DashboardOpsCockpitSummary> {
  const base = requireConsoleBaseUrl();
  const url = new URL('/console/ops-cockpit/summary', base);
  if (Number.isFinite(Number(input?.windowMinutes)) && Number(input?.windowMinutes) > 0) {
    url.searchParams.set('windowMinutes', String(Math.floor(Number(input?.windowMinutes))));
  }
  const response = await fetch(url.toString(), {
    method: 'GET',
    headers: buildConsoleAcceptHeaders(),
    credentials: 'include',
    cache: 'no-store',
  });
  const body = (await parseConsoleJson(response)) as ConsoleOpsCockpitSummaryResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Ops cockpit summary request failed'));
  }
  const summary = decodeSummary(body.summary);
  if (!summary) {
    throw new Error('Ops cockpit summary response was invalid');
  }
  return summary;
}
