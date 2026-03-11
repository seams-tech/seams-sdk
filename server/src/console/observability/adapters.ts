import type {
  ConsoleObservabilityApprovalFailureInput,
  ConsoleObservabilityBillingFailureInput,
  ConsoleObservabilityEventEnvelope,
  ConsoleObservabilityWebhookDeadLetterInput,
} from './types';

function normalizeString(raw: unknown): string {
  return String(raw || '').trim();
}

function normalizeIso(raw: unknown, fallback: Date): string {
  const value = normalizeString(raw);
  if (!value) return fallback.toISOString();
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) return fallback.toISOString();
  return new Date(parsed).toISOString();
}

function normalizeNumber(raw: unknown, fallback: number): number {
  const value = Number(raw);
  if (!Number.isFinite(value)) return fallback;
  return value;
}

function makeEventId(prefix: string, now: Date): string {
  return `${prefix}_${now.getTime().toString(36)}_${Math.random().toString(36).slice(2, 10)}`;
}

function baseEnvelope(input: {
  eventIdPrefix: string;
  orgId: string;
  projectId?: string;
  environmentId?: string;
  requestId?: string;
  traceId?: string;
  timestamp?: string;
  schemaVersion?: number;
  redactionVersion?: number;
  source: ConsoleObservabilityEventEnvelope['source'];
  service: string;
  component: string;
  level: ConsoleObservabilityEventEnvelope['level'];
  eventType: string;
  message: string;
  metadata: Record<string, unknown>;
}): ConsoleObservabilityEventEnvelope {
  const now = new Date();
  const ingestedAtMs = now.getTime();
  const eventId = makeEventId(input.eventIdPrefix, now);
  const timestamp = normalizeIso(input.timestamp, now);
  return {
    eventId,
    schemaVersion: Math.max(1, Math.floor(normalizeNumber(input.schemaVersion, 1))),
    source: input.source,
    ingestedAtMs,
    timestamp,
    orgId: normalizeString(input.orgId),
    ...(normalizeString(input.projectId) ? { projectId: normalizeString(input.projectId) } : {}),
    ...(normalizeString(input.environmentId)
      ? { environmentId: normalizeString(input.environmentId) }
      : {}),
    service: normalizeString(input.service),
    component: normalizeString(input.component),
    level: input.level,
    eventType: normalizeString(input.eventType),
    message: normalizeString(input.message),
    ...(normalizeString(input.requestId) ? { requestId: normalizeString(input.requestId) } : {}),
    ...(normalizeString(input.traceId) ? { traceId: normalizeString(input.traceId) } : {}),
    metadata: { ...input.metadata },
    redactionVersion: Math.max(1, Math.floor(normalizeNumber(input.redactionVersion, 1))),
    redactionApplied: false,
  };
}

export function buildWebhookDeadLetterObservabilityEvent(
  input: ConsoleObservabilityWebhookDeadLetterInput,
): ConsoleObservabilityEventEnvelope {
  return baseEnvelope({
    eventIdPrefix: 'obs_webhook_dead_letter',
    orgId: input.orgId,
    projectId: input.projectId,
    environmentId: input.environmentId,
    requestId: input.requestId,
    traceId: input.traceId,
    timestamp: input.movedToDlqAt,
    schemaVersion: input.schemaVersion,
    redactionVersion: input.redactionVersion,
    source: 'WEBHOOK',
    service: 'webhooks',
    component: 'delivery_dispatch',
    level: 'ERROR',
    eventType: 'webhook.delivery.dead_letter',
    message: `Webhook delivery ${input.deliveryId} moved to dead-letter queue`,
    metadata: {
      endpointId: normalizeString(input.endpointId),
      deliveryId: normalizeString(input.deliveryId),
      webhookEventId: normalizeString(input.webhookEventId),
      webhookEventType: normalizeString(input.webhookEventType),
      failedAttempts: Math.max(0, Math.floor(normalizeNumber(input.failedAttempts, 0))),
      ...(Number.isFinite(Number(input.lastResponseStatus))
        ? { lastResponseStatus: Number(input.lastResponseStatus) }
        : {}),
      ...(normalizeString(input.lastErrorMessage)
        ? { lastErrorMessage: normalizeString(input.lastErrorMessage) }
        : {}),
      movedToDlqAt: normalizeIso(input.movedToDlqAt, new Date()),
    },
  });
}

export function buildBillingFailureObservabilityEvent(
  input: ConsoleObservabilityBillingFailureInput,
): ConsoleObservabilityEventEnvelope {
  const invoiceId = normalizeString(input.invoiceId);
  return baseEnvelope({
    eventIdPrefix: 'obs_billing_failure',
    orgId: input.orgId,
    projectId: input.projectId,
    environmentId: input.environmentId,
    requestId: input.requestId,
    traceId: input.traceId,
    timestamp: input.timestamp,
    schemaVersion: input.schemaVersion,
    redactionVersion: input.redactionVersion,
    source: 'BILLING',
    service: 'billing',
    component: 'finalization',
    level: 'ERROR',
    eventType: `billing.${normalizeString(input.operation).toLowerCase()}.failed`,
    message: normalizeString(input.failureMessage),
    metadata: {
      operation: normalizeString(input.operation),
      failureCode: normalizeString(input.failureCode),
      ...(invoiceId ? { invoiceId } : {}),
      ...(normalizeString(input.providerRef) ? { providerRef: normalizeString(input.providerRef) } : {}),
    },
  });
}

export function buildApprovalFailureObservabilityEvent(
  input: ConsoleObservabilityApprovalFailureInput,
): ConsoleObservabilityEventEnvelope {
  const approvalId = normalizeString(input.approvalId);
  return baseEnvelope({
    eventIdPrefix: 'obs_approval_failure',
    orgId: input.orgId,
    projectId: input.projectId,
    environmentId: input.environmentId,
    requestId: input.requestId,
    traceId: input.traceId,
    timestamp: input.timestamp,
    schemaVersion: input.schemaVersion,
    redactionVersion: input.redactionVersion,
    source: 'APPROVAL',
    service: 'approvals',
    component: 'policy_publish',
    level: 'ERROR',
    eventType: 'approval.policy_publish.failed',
    message: normalizeString(input.failureMessage),
    metadata: {
      operationType: normalizeString(input.operationType),
      failureCode: normalizeString(input.failureCode),
      ...(approvalId ? { approvalId } : {}),
      ...(normalizeString(input.resourceType) ? { resourceType: normalizeString(input.resourceType) } : {}),
      ...(normalizeString(input.resourceId) ? { resourceId: normalizeString(input.resourceId) } : {}),
    },
  });
}
