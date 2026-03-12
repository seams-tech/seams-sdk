import {
  buildApprovalFailureObservabilityEvent,
  buildBillingFailureObservabilityEvent,
  type ConsoleObservabilityIngestionService,
} from '../console/observability';
import type { ConsoleAuthClaims } from './console';
import type { NormalizedRouterLogger } from './logger';

type ConsoleObservabilityIngestContext = Parameters<
  ConsoleObservabilityIngestionService['appendEvent']
>[0];
type ConsoleObservabilityEventEnvelope = Parameters<
  ConsoleObservabilityIngestionService['appendEvent']
>[1];
type ConsoleObservabilityRequestMetric = Parameters<
  NonNullable<ConsoleObservabilityIngestionService['observeRequestMetric']>
>[1];

export interface ConsoleObservabilityHookContext {
  logger: NormalizedRouterLogger;
  observabilityIngestion: ConsoleObservabilityIngestionService | null;
}

function normalizeString(raw: unknown): string {
  return String(raw || '').trim();
}

export function toUnknownErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function buildConsoleObservabilityIngestContext(
  claims: ConsoleAuthClaims,
  fallbackActorUserId = 'system-console-router',
): ConsoleObservabilityIngestContext {
  const roles = Array.isArray(claims.roles) ? claims.roles.filter(Boolean) : [];
  return {
    orgId: claims.orgId,
    actorUserId: normalizeString(claims.userId) || fallbackActorUserId,
    roles: roles.length ? roles : ['ops'],
    ...(claims.projectId ? { projectId: claims.projectId } : {}),
    ...(claims.environmentId ? { environmentId: claims.environmentId } : {}),
  };
}

export function readConsoleRequestTraceContext(readHeader: (header: string) => string | undefined): {
  requestId?: string;
  traceId?: string;
} {
  const requestId = readHeader('x-request-id');
  const traceId = readHeader('x-trace-id') || readHeader('traceparent');
  return {
    ...(requestId ? { requestId } : {}),
    ...(traceId ? { traceId } : {}),
  };
}

export async function appendConsoleObservabilityEvent(
  ctx: ConsoleObservabilityHookContext,
  ingestCtx: ConsoleObservabilityIngestContext,
  event: ConsoleObservabilityEventEnvelope,
): Promise<void> {
  if (!ctx.observabilityIngestion) return;
  try {
    await ctx.observabilityIngestion.appendEvent(ingestCtx, event);
  } catch (error: unknown) {
    ctx.logger.warn('[console][observability] failed to append observability event', {
      orgId: ingestCtx.orgId,
      eventType: event.eventType,
      message: toUnknownErrorMessage(error),
    });
  }
}

export async function appendConsoleObservabilityRequestMetric(
  ctx: ConsoleObservabilityHookContext,
  ingestCtx: ConsoleObservabilityIngestContext,
  metric: ConsoleObservabilityRequestMetric,
): Promise<void> {
  if (!ctx.observabilityIngestion?.observeRequestMetric) return;
  try {
    await ctx.observabilityIngestion.observeRequestMetric(ingestCtx, metric);
  } catch (error: unknown) {
    ctx.logger.warn('[console][observability] failed to append request metric', {
      orgId: ingestCtx.orgId,
      route: metric.route,
      method: metric.method,
      statusCode: metric.statusCode,
      message: toUnknownErrorMessage(error),
    });
  }
}

export async function observeConsoleRequestMetric(
  ctx: ConsoleObservabilityHookContext,
  input: {
    claims: ConsoleAuthClaims | null | undefined;
    route: string;
    method: string;
    statusCode: number;
    latencyMs: number;
    timestamp?: string;
  },
): Promise<void> {
  if (!ctx.observabilityIngestion?.observeRequestMetric) return;
  const claims = input.claims;
  const orgId = normalizeString(claims?.orgId);
  if (!orgId || !claims) return;
  await appendConsoleObservabilityRequestMetric(
    ctx,
    buildConsoleObservabilityIngestContext(claims),
    {
      orgId,
      ...(claims.projectId ? { projectId: claims.projectId } : {}),
      ...(claims.environmentId ? { environmentId: claims.environmentId } : {}),
      route: input.route,
      method: input.method,
      statusCode: input.statusCode,
      latencyMs: input.latencyMs,
      timestamp: input.timestamp || new Date().toISOString(),
    },
  );
}

export async function emitConsoleBillingFailureObservabilityEvent(
  ctx: ConsoleObservabilityHookContext,
  input: {
    claims: ConsoleAuthClaims;
    operation: 'INVOICE_FINALIZATION';
    invoiceId?: string;
    providerRef?: string;
    failureCode: string;
    failureMessage: string;
    readHeader: (header: string) => string | undefined;
  },
): Promise<void> {
  const event = buildBillingFailureObservabilityEvent({
    orgId: input.claims.orgId,
    ...(input.claims.projectId ? { projectId: input.claims.projectId } : {}),
    ...(input.claims.environmentId ? { environmentId: input.claims.environmentId } : {}),
    ...(input.invoiceId ? { invoiceId: input.invoiceId } : {}),
    operation: input.operation,
    failureCode: input.failureCode,
    failureMessage: input.failureMessage,
    ...(input.providerRef ? { providerRef: input.providerRef } : {}),
    ...readConsoleRequestTraceContext(input.readHeader),
  });
  await appendConsoleObservabilityEvent(
    ctx,
    buildConsoleObservabilityIngestContext(input.claims, input.claims.userId),
    event,
  );
}

export async function emitConsoleApprovalFailureObservabilityEvent(
  ctx: ConsoleObservabilityHookContext,
  input: {
    claims: ConsoleAuthClaims;
    approvalId?: string;
    operationType: string;
    resourceType?: string;
    resourceId?: string;
    failureCode: string;
    failureMessage: string;
    readHeader: (header: string) => string | undefined;
  },
): Promise<void> {
  const event = buildApprovalFailureObservabilityEvent({
    orgId: input.claims.orgId,
    ...(input.claims.projectId ? { projectId: input.claims.projectId } : {}),
    ...(input.claims.environmentId ? { environmentId: input.claims.environmentId } : {}),
    ...(input.approvalId ? { approvalId: input.approvalId } : {}),
    operationType: input.operationType,
    ...(input.resourceType ? { resourceType: input.resourceType } : {}),
    ...(input.resourceId ? { resourceId: input.resourceId } : {}),
    failureCode: input.failureCode,
    failureMessage: input.failureMessage,
    ...readConsoleRequestTraceContext(input.readHeader),
  });
  await appendConsoleObservabilityEvent(
    ctx,
    buildConsoleObservabilityIngestContext(input.claims, input.claims.userId),
    event,
  );
}
