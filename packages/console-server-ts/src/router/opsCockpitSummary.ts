import type { ConsoleApprovalService, ConsoleApprovalRequestRecord } from '@seams-internal/console-server/approvals';
import type { ConsoleAuditExportsService, ConsoleAuditExportRecord } from '@seams-internal/console-server/auditExports';
import type { BillingInvoice, ConsoleBillingService } from '@seams-internal/console-server/billing';
import type {
  ConsoleEnterpriseIsolationService,
  ConsoleEnterpriseIsolationState,
} from '@seams-internal/console-server/enterpriseIsolation';
import type {
  ConsoleOnboardingService,
  ConsoleOnboardingTelemetryAlert,
  ConsoleOnboardingTelemetrySnapshot,
} from '@seams-internal/console-server/onboarding';
import type { ConsoleWebhookDeadLetter, ConsoleWebhookService } from '@seams-internal/console-server/webhooks';
import type { ConsoleAuthClaims } from '@seams/sdk-server/internal/router/consoleAuth';
import type { NormalizedRouterLogger } from '@seams/sdk-server/internal/router/logger';

type ConsoleOpsCockpitSectionState = 'ok' | 'not_configured' | 'forbidden' | 'error';

interface ConsoleOpsCockpitSectionStatus {
  state: ConsoleOpsCockpitSectionState;
  code?: string;
  message?: string;
}

export interface ConsoleOpsCockpitWebhookDeadLetterEntry {
  endpointId: string;
  endpointUrl: string;
  endpointStatus: string;
  deadLetter: ConsoleWebhookDeadLetter;
}

interface ConsoleOpsCockpitApprovalsSection {
  status: ConsoleOpsCockpitSectionStatus;
  pendingCount: number;
  pending: ConsoleApprovalRequestRecord[];
}

interface ConsoleOpsCockpitBillingSection {
  status: ConsoleOpsCockpitSectionStatus;
  failedInvoiceCount: number;
  failedInvoices: BillingInvoice[];
}

interface ConsoleOpsCockpitWebhooksSection {
  status: ConsoleOpsCockpitSectionStatus;
  endpointCount: number;
  scannedEndpointCount: number;
  deadLetterCount: number;
  deadLetters: ConsoleOpsCockpitWebhookDeadLetterEntry[];
}

interface ConsoleOpsCockpitAuditExportsSection {
  status: ConsoleOpsCockpitSectionStatus;
  queuedExportCount: number;
  queuedExports: ConsoleAuditExportRecord[];
}

interface ConsoleOpsCockpitEnterpriseIsolationSection {
  status: ConsoleOpsCockpitSectionStatus;
  activeRequestCount: number;
  activeRequests: ConsoleEnterpriseIsolationState[];
}

interface ConsoleOpsCockpitOnboardingTelemetrySection {
  status: ConsoleOpsCockpitSectionStatus;
  windowMinutes: number;
  alertCount: number;
  alerts: ConsoleOnboardingTelemetryAlert[];
  telemetry: ConsoleOnboardingTelemetrySnapshot | null;
}

export interface ConsoleOpsCockpitSummary {
  generatedAt: string;
  approvals: ConsoleOpsCockpitApprovalsSection;
  billing: ConsoleOpsCockpitBillingSection;
  webhooks: ConsoleOpsCockpitWebhooksSection;
  auditExports: ConsoleOpsCockpitAuditExportsSection;
  enterpriseIsolation: ConsoleOpsCockpitEnterpriseIsolationSection;
  onboardingTelemetry: ConsoleOpsCockpitOnboardingTelemetrySection;
}

export interface BuildConsoleOpsCockpitSummaryOptions {
  claims: ConsoleAuthClaims;
  approvals?: ConsoleApprovalService | null;
  billing?: ConsoleBillingService | null;
  webhooks?: ConsoleWebhookService | null;
  auditExports?: ConsoleAuditExportsService | null;
  enterpriseIsolation?: ConsoleEnterpriseIsolationService | null;
  onboarding?: ConsoleOnboardingService | null;
  telemetryWindowMinutes?: number;
  canViewOnboardingTelemetry?: boolean;
  maxWebhookEndpointsScanned?: number;
  maxPreviewItems?: number;
  now?: () => Date;
  logger?: NormalizedRouterLogger | null;
}

const DEFAULT_TELEMETRY_WINDOW_MINUTES = 60;
const DEFAULT_MAX_WEBHOOK_ENDPOINTS_SCANNED = 20;
const DEFAULT_MAX_PREVIEW_ITEMS = 20;

function toStatus(
  state: ConsoleOpsCockpitSectionState,
  input?: { code?: string; message?: string },
): ConsoleOpsCockpitSectionStatus {
  return {
    state,
    ...(input?.code ? { code: input.code } : {}),
    ...(input?.message ? { message: input.message } : {}),
  };
}

function readErrorCode(error: unknown): string {
  if (!error || typeof error !== 'object' || !('code' in error)) return '';
  return String((error as { code?: unknown }).code || '').trim();
}

function readErrorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error || 'Unknown error');
}

function isFailedOrOverdueInvoice(invoice: BillingInvoice, nowMs: number): boolean {
  if (invoice.status === 'UNCOLLECTIBLE') return true;
  if (invoice.status !== 'OPEN') return false;
  if (invoice.amountDueMinor <= invoice.amountPaidMinor) return false;
  const dueMs = invoice.dueAt ? new Date(invoice.dueAt).getTime() : Number.NaN;
  return Number.isFinite(dueMs) && dueMs < nowMs;
}

function toBillingContext(claims: ConsoleAuthClaims): {
  orgId: string;
  actorUserId: string;
  roles: string[];
} {
  return {
    orgId: claims.orgId,
    actorUserId: claims.userId,
    roles: claims.roles,
  };
}

function toScopedContext(claims: ConsoleAuthClaims): {
  orgId: string;
  actorUserId: string;
  roles: string[];
  projectId?: string;
  environmentId?: string;
} {
  return {
    orgId: claims.orgId,
    actorUserId: claims.userId,
    roles: claims.roles,
    ...(claims.projectId ? { projectId: claims.projectId } : {}),
    ...(claims.environmentId ? { environmentId: claims.environmentId } : {}),
  };
}

export async function buildConsoleOpsCockpitSummary(
  opts: BuildConsoleOpsCockpitSummaryOptions,
): Promise<ConsoleOpsCockpitSummary> {
  const now = opts.now || (() => new Date());
  const current = now();
  const nowMs = current.getTime();
  const maxWebhookEndpointsScanned = Math.max(
    1,
    Math.floor(opts.maxWebhookEndpointsScanned || DEFAULT_MAX_WEBHOOK_ENDPOINTS_SCANNED),
  );
  const maxPreviewItems = Math.max(1, Math.floor(opts.maxPreviewItems || DEFAULT_MAX_PREVIEW_ITEMS));
  const telemetryWindowMinutes = Math.max(
    1,
    Math.floor(opts.telemetryWindowMinutes || DEFAULT_TELEMETRY_WINDOW_MINUTES),
  );
  const baseContext = toBillingContext(opts.claims);
  const scopedContext = toScopedContext(opts.claims);

  const summary: ConsoleOpsCockpitSummary = {
    generatedAt: current.toISOString(),
    approvals: {
      status: toStatus('not_configured'),
      pendingCount: 0,
      pending: [],
    },
    billing: {
      status: toStatus('not_configured'),
      failedInvoiceCount: 0,
      failedInvoices: [],
    },
    webhooks: {
      status: toStatus('not_configured'),
      endpointCount: 0,
      scannedEndpointCount: 0,
      deadLetterCount: 0,
      deadLetters: [],
    },
    auditExports: {
      status: toStatus('not_configured'),
      queuedExportCount: 0,
      queuedExports: [],
    },
    enterpriseIsolation: {
      status: toStatus('not_configured'),
      activeRequestCount: 0,
      activeRequests: [],
    },
    onboardingTelemetry: {
      status: toStatus('not_configured'),
      windowMinutes: telemetryWindowMinutes,
      alertCount: 0,
      alerts: [],
      telemetry: null,
    },
  };

  if (opts.approvals) {
    try {
      const rows = await opts.approvals.listApprovalRequests(scopedContext, { status: 'PENDING' });
      summary.approvals = {
        status: toStatus('ok'),
        pendingCount: rows.length,
        pending: rows.slice(0, maxPreviewItems),
      };
    } catch (error: unknown) {
      const code = readErrorCode(error);
      const message = readErrorMessage(error);
      summary.approvals.status = toStatus('error', {
        ...(code ? { code } : {}),
        message,
      });
      opts.logger?.warn('[console][ops-cockpit] approvals summary failed', {
        orgId: opts.claims.orgId,
        code,
        message,
      });
    }
  }

  if (opts.billing) {
    try {
      const invoices = await opts.billing.listInvoices(baseContext);
      const failedInvoices = invoices.filter((entry) => isFailedOrOverdueInvoice(entry, nowMs));
      summary.billing = {
        status: toStatus('ok'),
        failedInvoiceCount: failedInvoices.length,
        failedInvoices: failedInvoices.slice(0, maxPreviewItems),
      };
    } catch (error: unknown) {
      const code = readErrorCode(error);
      const message = readErrorMessage(error);
      summary.billing.status = toStatus('error', {
        ...(code ? { code } : {}),
        message,
      });
      opts.logger?.warn('[console][ops-cockpit] billing summary failed', {
        orgId: opts.claims.orgId,
        code,
        message,
      });
    }
  }

  if (opts.webhooks) {
    try {
      const endpoints = await opts.webhooks.listEndpoints(baseContext);
      const scannedEndpoints = endpoints.slice(0, maxWebhookEndpointsScanned);
      const deadLetterResponses = await Promise.all(
        scannedEndpoints.map(async (endpoint) => {
          const page = await opts.webhooks!.listDeadLetters(baseContext, endpoint.id, {
            includeResolved: false,
            limit: maxPreviewItems,
          });
          return page.items
            .filter((row) => row.resolvedAt === null)
            .map((deadLetter) => ({
              endpointId: endpoint.id,
              endpointUrl: endpoint.url,
              endpointStatus: endpoint.status,
              deadLetter,
            }));
        }),
      );

      const deadLetters = deadLetterResponses
        .flat()
        .sort((a, b) => b.deadLetter.movedToDlqAt.localeCompare(a.deadLetter.movedToDlqAt));

      summary.webhooks = {
        status: toStatus('ok'),
        endpointCount: endpoints.length,
        scannedEndpointCount: scannedEndpoints.length,
        deadLetterCount: deadLetters.length,
        deadLetters: deadLetters.slice(0, maxPreviewItems),
      };
    } catch (error: unknown) {
      const code = readErrorCode(error);
      const message = readErrorMessage(error);
      summary.webhooks.status = toStatus('error', {
        ...(code ? { code } : {}),
        message,
      });
      opts.logger?.warn('[console][ops-cockpit] webhooks summary failed', {
        orgId: opts.claims.orgId,
        code,
        message,
      });
    }
  }

  if (opts.auditExports) {
    try {
      const exports = await opts.auditExports.listExports(scopedContext, { limit: 200 });
      const queuedExports = exports.filter(
        (row) => row.status === 'QUEUED' || row.status === 'PROCESSING',
      );
      summary.auditExports = {
        status: toStatus('ok'),
        queuedExportCount: queuedExports.length,
        queuedExports: queuedExports.slice(0, maxPreviewItems),
      };
    } catch (error: unknown) {
      const code = readErrorCode(error);
      const message = readErrorMessage(error);
      summary.auditExports.status = toStatus('error', {
        ...(code ? { code } : {}),
        message,
      });
      opts.logger?.warn('[console][ops-cockpit] audit exports summary failed', {
        orgId: opts.claims.orgId,
        code,
        message,
      });
    }
  }

  if (opts.enterpriseIsolation) {
    try {
      const state = await opts.enterpriseIsolation.getIsolationState(scopedContext, { scope: 'ORG' });
      const active =
        state.status === 'REQUESTED' || state.status === 'MIGRATING' ? [state] : [];
      summary.enterpriseIsolation = {
        status: toStatus('ok'),
        activeRequestCount: active.length,
        activeRequests: active,
      };
    } catch (error: unknown) {
      const code = readErrorCode(error);
      const message = readErrorMessage(error);
      summary.enterpriseIsolation.status = toStatus('error', {
        ...(code ? { code } : {}),
        message,
      });
      opts.logger?.warn('[console][ops-cockpit] enterprise isolation summary failed', {
        orgId: opts.claims.orgId,
        code,
        message,
      });
    }
  }

  if (opts.onboarding) {
    const canViewOnboardingTelemetry =
      opts.canViewOnboardingTelemetry === undefined ? true : opts.canViewOnboardingTelemetry;
    if (!canViewOnboardingTelemetry) {
      summary.onboardingTelemetry = {
        status: toStatus('forbidden', {
          code: 'forbidden',
          message: 'Only admin or ops can view onboarding telemetry',
        }),
        windowMinutes: telemetryWindowMinutes,
        alertCount: 0,
        alerts: [],
        telemetry: null,
      };
    } else {
      try {
        const telemetry = await opts.onboarding.getOnboardingTelemetry(scopedContext, {
          windowMinutes: telemetryWindowMinutes,
        });
        summary.onboardingTelemetry = {
          status: toStatus('ok'),
          windowMinutes: telemetry.windowMinutes,
          alertCount: telemetry.alerts.length,
          alerts: telemetry.alerts.slice(0, maxPreviewItems),
          telemetry,
        };
      } catch (error: unknown) {
        const code = readErrorCode(error);
        const message = readErrorMessage(error);
        summary.onboardingTelemetry.status = toStatus('error', {
          ...(code ? { code } : {}),
          message,
        });
        opts.logger?.warn('[console][ops-cockpit] onboarding telemetry summary failed', {
          orgId: opts.claims.orgId,
          code,
          message,
        });
      }
    }
  }

  return summary;
}
