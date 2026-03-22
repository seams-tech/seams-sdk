import type { AuthService } from '../core/AuthService';
import type { RecoveryExecutionRecord } from '../core/RecoveryExecutionStore';
import {
  buildRecoveryExecutionFailedObservabilityEvent,
  buildRecoveryExecutionStuckObservabilityEvent,
  type ConsoleObservabilityIngestionService,
} from '../console/observability';
import { SMART_ACCOUNT_RECOVERY_ADD_OWNER_ACTION } from './recoveryExecutionTracking';
import type { NormalizedRouterLogger } from './logger';
import { parseRecoveryAuthoritySponsorshipScope } from './recoveryAuthoritySponsorship';

export interface RecoveryAuthorityMonitoringConfig {
  enabled?: boolean;
  stalePendingAfterMs?: number;
  staleSubmittedAfterMs?: number;
  failedLimit?: number;
  staleLimit?: number;
  nowMs?: number;
}

export interface RecoveryAuthorityMonitoringSummary {
  stalePending: number;
  staleSubmitted: number;
  failed: number;
}

const DEFAULT_STALE_PENDING_AFTER_MS = 15 * 60_000;
const DEFAULT_STALE_SUBMITTED_AFTER_MS = 30 * 60_000;
const DEFAULT_ALERT_LIMIT = 25;
const DEFAULT_ACTOR_USER_ID = 'system-recovery-authority';
const DEFAULT_ACTOR_ROLES = ['ops'];

function asObject(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? ({ ...(value as Record<string, unknown>) } as Record<string, unknown>)
    : {};
}

function buildExecutionRef(input: {
  sessionId: string;
  chainIdKey: string;
  accountAddress: string;
  status: string;
}): string {
  return `${input.sessionId}:${input.chainIdKey}:${input.accountAddress}:${input.status}`;
}

function coercePositiveInteger(value: unknown, fallback: number): number {
  const normalized = Number(value);
  return Number.isFinite(normalized) && normalized > 0 ? Math.floor(normalized) : fallback;
}

function normalizeOptionalString(value: unknown): string | undefined {
  const normalized = String(value || '').trim();
  return normalized || undefined;
}

function normalizeActorRoles(value: unknown): string[] {
  return Array.isArray(value)
    ? value.map((entry) => normalizeOptionalString(entry)).filter(Boolean) as string[]
    : [...DEFAULT_ACTOR_ROLES];
}

function resolveExecutionScope(record: RecoveryExecutionRecord): {
  orgId: string;
  environmentId: string;
  projectId?: string;
} | null {
  const metadata = asObject(record.metadata);
  const linkedAccount = asObject(metadata.linkedAccount);
  return (
    parseRecoveryAuthoritySponsorshipScope(metadata.sponsorshipScope) ||
    parseRecoveryAuthoritySponsorshipScope(linkedAccount.sponsorshipScope)
  );
}

async function appendRecoveryMonitoringObservabilityEvent(input: {
  logger: NormalizedRouterLogger;
  observabilityIngestion: ConsoleObservabilityIngestionService | null;
  actorUserId?: string;
  actorRoles?: string[];
  event: Parameters<ConsoleObservabilityIngestionService['appendEvent']>[1];
}): Promise<void> {
  if (!input.observabilityIngestion) return;
  try {
    await input.observabilityIngestion.appendEvent(
      {
        orgId: input.event.orgId,
        actorUserId: normalizeOptionalString(input.actorUserId) || DEFAULT_ACTOR_USER_ID,
        roles: normalizeActorRoles(input.actorRoles),
      },
      input.event,
    );
  } catch (error: unknown) {
    input.logger.warn('[recovery-authority][monitoring] failed to append observability event', {
      orgId: input.event.orgId,
      eventType: input.event.eventType,
      message: error instanceof Error ? error.message : String(error || 'unknown error'),
    });
  }
}

async function emitGroupedRecoveryMonitoringEvents(input: {
  logger: NormalizedRouterLogger;
  observabilityIngestion: ConsoleObservabilityIngestionService | null;
  actorUserId?: string;
  actorRoles?: string[];
  records: RecoveryExecutionRecord[];
  category: 'failed' | 'pending' | 'submitted';
  nowIso: string;
  staleAfterMs?: number;
}): Promise<void> {
  if (!input.observabilityIngestion || input.records.length === 0) return;

  const grouped = new Map<
    string,
    {
      orgId: string;
      environmentId: string;
      projectId?: string;
      records: RecoveryExecutionRecord[];
    }
  >();

  for (const record of input.records) {
    const scope = resolveExecutionScope(record);
    if (!scope) continue;
    const key = `${scope.orgId}:${scope.environmentId}:${scope.projectId || ''}`;
    const current = grouped.get(key);
    if (current) {
      current.records.push(record);
      continue;
    }
    grouped.set(key, {
      ...scope,
      records: [record],
    });
  }

  for (const group of grouped.values()) {
    const sampleExecutionRefs = group.records.slice(0, 5).map((record) =>
      buildExecutionRef({
        sessionId: record.sessionId,
        chainIdKey: record.chainIdKey,
        accountAddress: record.accountAddress,
        status: record.status,
      }),
    );
    const failureCodes = Array.from(
      new Set(
        group.records
          .map((record) => normalizeOptionalString(record.errorCode))
          .filter((value): value is string => Boolean(value)),
      ),
    );
    const event =
      input.category === 'failed'
        ? buildRecoveryExecutionFailedObservabilityEvent({
            orgId: group.orgId,
            environmentId: group.environmentId,
            ...(group.projectId ? { projectId: group.projectId } : {}),
            count: group.records.length,
            sampleExecutionRefs,
            failureCodes,
            timestamp: input.nowIso,
          })
        : buildRecoveryExecutionStuckObservabilityEvent({
            orgId: group.orgId,
            environmentId: group.environmentId,
            ...(group.projectId ? { projectId: group.projectId } : {}),
            status: input.category,
            count: group.records.length,
            staleAfterMs: coercePositiveInteger(input.staleAfterMs, 1),
            sampleExecutionRefs,
            timestamp: input.nowIso,
          });
    await appendRecoveryMonitoringObservabilityEvent({
      logger: input.logger,
      observabilityIngestion: input.observabilityIngestion,
      actorUserId: input.actorUserId,
      actorRoles: input.actorRoles,
      event,
    });
  }
}

export async function monitorRecoveryAuthorityExecutions(
  service: Pick<AuthService, 'listRecoveryExecutionsByStatus'>,
  input: {
    logger: NormalizedRouterLogger;
    config?: RecoveryAuthorityMonitoringConfig | null;
    observabilityIngestion?: ConsoleObservabilityIngestionService | null;
    actorUserId?: string;
    actorRoles?: string[];
  },
): Promise<
  | { ok: true; summary: RecoveryAuthorityMonitoringSummary }
  | { ok: false; code: 'invalid_args' | 'internal'; message: string }
> {
  if (input.config?.enabled === false) {
    return {
      ok: true,
      summary: {
        stalePending: 0,
        staleSubmitted: 0,
        failed: 0,
      },
    };
  }

  const nowMs = coercePositiveInteger(input.config?.nowMs, Date.now());
  const stalePendingAfterMs = coercePositiveInteger(
    input.config?.stalePendingAfterMs,
    DEFAULT_STALE_PENDING_AFTER_MS,
  );
  const staleSubmittedAfterMs = coercePositiveInteger(
    input.config?.staleSubmittedAfterMs,
    DEFAULT_STALE_SUBMITTED_AFTER_MS,
  );
  const failedLimit = coercePositiveInteger(input.config?.failedLimit, DEFAULT_ALERT_LIMIT);
  const staleLimit = coercePositiveInteger(input.config?.staleLimit, DEFAULT_ALERT_LIMIT);
  const nowIso = new Date(nowMs).toISOString();

  const [failed, stalePending, staleSubmitted] = await Promise.all([
    service.listRecoveryExecutionsByStatus({
      status: 'failed',
      action: SMART_ACCOUNT_RECOVERY_ADD_OWNER_ACTION,
      limit: failedLimit,
    }),
    service.listRecoveryExecutionsByStatus({
      status: 'pending',
      action: SMART_ACCOUNT_RECOVERY_ADD_OWNER_ACTION,
      updatedBeforeMs: nowMs - stalePendingAfterMs,
      limit: staleLimit,
    }),
    service.listRecoveryExecutionsByStatus({
      status: 'submitted',
      action: SMART_ACCOUNT_RECOVERY_ADD_OWNER_ACTION,
      updatedBeforeMs: nowMs - staleSubmittedAfterMs,
      limit: staleLimit,
    }),
  ]);

  if (!failed.ok) return failed;
  if (!stalePending.ok) return stalePending;
  if (!staleSubmitted.ok) return staleSubmitted;

  if (failed.records.length > 0) {
    input.logger.warn('[recovery-authority][monitoring] failed recovery executions detected', {
      count: failed.records.length,
      samples: failed.records.slice(0, 5).map((record) =>
        buildExecutionRef({
          sessionId: record.sessionId,
          chainIdKey: record.chainIdKey,
          accountAddress: record.accountAddress,
          status: record.status,
        }),
      ),
    });
    await emitGroupedRecoveryMonitoringEvents({
      logger: input.logger,
      observabilityIngestion: input.observabilityIngestion || null,
      actorUserId: input.actorUserId,
      actorRoles: input.actorRoles,
      records: failed.records,
      category: 'failed',
      nowIso,
    });
  }

  if (stalePending.records.length > 0) {
    input.logger.warn('[recovery-authority][monitoring] stale pending recovery executions detected', {
      count: stalePending.records.length,
      staleAfterMs: stalePendingAfterMs,
      samples: stalePending.records.slice(0, 5).map((record) =>
        buildExecutionRef({
          sessionId: record.sessionId,
          chainIdKey: record.chainIdKey,
          accountAddress: record.accountAddress,
          status: record.status,
        }),
      ),
    });
    await emitGroupedRecoveryMonitoringEvents({
      logger: input.logger,
      observabilityIngestion: input.observabilityIngestion || null,
      actorUserId: input.actorUserId,
      actorRoles: input.actorRoles,
      records: stalePending.records,
      category: 'pending',
      nowIso,
      staleAfterMs: stalePendingAfterMs,
    });
  }

  if (staleSubmitted.records.length > 0) {
    input.logger.warn('[recovery-authority][monitoring] stale submitted recovery executions detected', {
      count: staleSubmitted.records.length,
      staleAfterMs: staleSubmittedAfterMs,
      samples: staleSubmitted.records.slice(0, 5).map((record) =>
        buildExecutionRef({
          sessionId: record.sessionId,
          chainIdKey: record.chainIdKey,
          accountAddress: record.accountAddress,
          status: record.status,
        }),
      ),
    });
    await emitGroupedRecoveryMonitoringEvents({
      logger: input.logger,
      observabilityIngestion: input.observabilityIngestion || null,
      actorUserId: input.actorUserId,
      actorRoles: input.actorRoles,
      records: staleSubmitted.records,
      category: 'submitted',
      nowIso,
      staleAfterMs: staleSubmittedAfterMs,
    });
  }

  return {
    ok: true,
    summary: {
      failed: failed.records.length,
      stalePending: stalePending.records.length,
      staleSubmitted: staleSubmitted.records.length,
    },
  };
}
