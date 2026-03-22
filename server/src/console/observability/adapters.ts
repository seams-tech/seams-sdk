import type {
  ConsoleObservabilityApprovalFailureInput,
  ConsoleObservabilityBillingBalanceTransitionInput,
  ConsoleObservabilityBillingFailureInput,
  ConsoleObservabilityBillingSponsorshipBlockedInput,
  ConsoleObservabilityBillingStripeWebhookFailureInput,
  ConsoleObservabilityEventEnvelope,
  ConsoleObservabilityRecoveryExecutionFailedInput,
  ConsoleObservabilityRecoveryExecutionStuckInput,
  ConsoleObservabilityWebhookEndpointDegradedInput,
  ConsoleObservabilityWebhookDeadLetterInput,
  ConsoleObservabilityWebhookRetryExhaustedInput,
} from './types';
import { CONSOLE_OBSERVABILITY_EVENT_POLICIES } from './policy';

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

function hashEventIdPart(input: string, seed: number): string {
  let hash = seed >>> 0;
  for (let index = 0; index < input.length; index += 1) {
    hash ^= input.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0).toString(16).padStart(8, '0');
}

function makeDeterministicEventId(input: { eventIdPrefix: string; parts: unknown[] }): string {
  const canonical = input.parts.map((part) => normalizeString(part).toLowerCase()).join('|');
  const forward = hashEventIdPart(canonical, 0x811c9dc5);
  const reverse = hashEventIdPart(Array.from(canonical).reverse().join(''), 0x9e3779b9);
  return `${input.eventIdPrefix}_${forward}${reverse}`;
}

function normalizeWindowStartIso(raw: unknown, fallback: Date, windowMs: number): string {
  const timestamp = normalizeIso(raw, fallback);
  const parsed = Date.parse(timestamp);
  if (!Number.isFinite(parsed)) return fallback.toISOString();
  return new Date(parsed - (parsed % Math.max(1, Math.floor(windowMs)))).toISOString();
}

function normalizeUniqueStrings(raw: unknown): string[] {
  return Array.isArray(raw)
    ? Array.from(new Set(raw.map((entry) => normalizeString(entry)).filter(Boolean))).sort()
    : [];
}

function buildRecoveryAlertScope(input: {
  orgId: string;
  environmentId?: string;
  projectId?: string;
}): string {
  return [
    normalizeString(input.orgId) || 'unknown-org',
    normalizeString(input.environmentId) || 'unknown-environment',
    normalizeString(input.projectId) || 'default-project',
  ].join(':');
}

const RECOVERY_MONITORING_ALERT_WINDOW_MS = 6 * 60 * 60_000;

function baseEnvelope(input: {
  eventIdPrefix: string;
  eventId?: string;
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
  const eventId = normalizeString(input.eventId) || makeEventId(input.eventIdPrefix, now);
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
  const policy = CONSOLE_OBSERVABILITY_EVENT_POLICIES.webhookDeadLetter;
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
    source: policy.source,
    service: policy.service,
    component: policy.component,
    level: policy.level,
    eventType: policy.eventType,
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

export function buildWebhookRetryExhaustedObservabilityEvent(
  input: ConsoleObservabilityWebhookRetryExhaustedInput,
): ConsoleObservabilityEventEnvelope {
  const policy = CONSOLE_OBSERVABILITY_EVENT_POLICIES.webhookDeliveryRetryExhausted;
  return baseEnvelope({
    eventIdPrefix: 'obs_webhook_retry_exhausted',
    orgId: input.orgId,
    requestId: input.requestId,
    traceId: input.traceId,
    timestamp: input.exhaustedAt,
    schemaVersion: input.schemaVersion,
    redactionVersion: input.redactionVersion,
    source: policy.source,
    service: policy.service,
    component: policy.component,
    level: policy.level,
    eventType: policy.eventType,
    message: `Webhook delivery ${input.deliveryId} exhausted retries after ${Math.max(
      0,
      Math.floor(normalizeNumber(input.failedAttempts, 0)),
    )} failed attempts`,
    metadata: {
      endpointId: normalizeString(input.endpointId),
      deliveryId: normalizeString(input.deliveryId),
      webhookEventId: normalizeString(input.webhookEventId),
      webhookEventType: normalizeString(input.webhookEventType),
      failedAttempts: Math.max(0, Math.floor(normalizeNumber(input.failedAttempts, 0))),
      maxAttempts: Math.max(1, Math.floor(normalizeNumber(input.maxAttempts, 1))),
      ...(Number.isFinite(Number(input.lastResponseStatus))
        ? { lastResponseStatus: Number(input.lastResponseStatus) }
        : {}),
      ...(normalizeString(input.lastErrorMessage)
        ? { lastErrorMessage: normalizeString(input.lastErrorMessage) }
        : {}),
      exhaustedAt: normalizeIso(input.exhaustedAt, new Date()),
    },
  });
}

export function buildWebhookEndpointDegradedObservabilityEvent(
  input: ConsoleObservabilityWebhookEndpointDegradedInput,
): ConsoleObservabilityEventEnvelope {
  const policy = CONSOLE_OBSERVABILITY_EVENT_POLICIES.webhookEndpointDegraded;
  return baseEnvelope({
    eventIdPrefix: 'obs_webhook_endpoint_degraded',
    orgId: input.orgId,
    requestId: input.requestId,
    traceId: input.traceId,
    timestamp: input.degradedAt,
    schemaVersion: input.schemaVersion,
    redactionVersion: input.redactionVersion,
    source: policy.source,
    service: policy.service,
    component: policy.component,
    level: policy.level,
    eventType: policy.eventType,
    message: `Webhook endpoint ${input.endpointId} crossed the degraded failure threshold`,
    metadata: {
      endpointId: normalizeString(input.endpointId),
      unresolvedDeadLetterCount: Math.max(
        0,
        Math.floor(normalizeNumber(input.unresolvedDeadLetterCount, 0)),
      ),
      degradationThreshold: Math.max(
        1,
        Math.floor(normalizeNumber(input.degradationThreshold, 1)),
      ),
      ...(normalizeString(input.latestDeliveryId)
        ? { latestDeliveryId: normalizeString(input.latestDeliveryId) }
        : {}),
      ...(normalizeString(input.latestWebhookEventId)
        ? { latestWebhookEventId: normalizeString(input.latestWebhookEventId) }
        : {}),
      ...(normalizeString(input.latestWebhookEventType)
        ? { latestWebhookEventType: normalizeString(input.latestWebhookEventType) }
        : {}),
      ...(Number.isFinite(Number(input.lastResponseStatus))
        ? { lastResponseStatus: Number(input.lastResponseStatus) }
        : {}),
      ...(normalizeString(input.lastErrorMessage)
        ? { lastErrorMessage: normalizeString(input.lastErrorMessage) }
        : {}),
      degradedAt: normalizeIso(input.degradedAt, new Date()),
    },
  });
}

export function buildBillingFailureObservabilityEvent(
  input: ConsoleObservabilityBillingFailureInput,
): ConsoleObservabilityEventEnvelope {
  const invoiceId = normalizeString(input.invoiceId);
  const policy =
    input.operation === 'PAYMENT_RECONCILE'
      ? CONSOLE_OBSERVABILITY_EVENT_POLICIES.billingPaymentReconcileFailure
      : CONSOLE_OBSERVABILITY_EVENT_POLICIES.billingInvoiceFinalizationFailure;
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
    source: policy.source,
    service: policy.service,
    component: policy.component,
    level: policy.level,
    eventType: policy.eventType,
    message: normalizeString(input.failureMessage),
    metadata: {
      operation: normalizeString(input.operation),
      failureCode: normalizeString(input.failureCode),
      ...(invoiceId ? { invoiceId } : {}),
      ...(normalizeString(input.providerRef) ? { providerRef: normalizeString(input.providerRef) } : {}),
    },
  });
}

export function buildBillingStripeWebhookFailureObservabilityEvent(
  input: ConsoleObservabilityBillingStripeWebhookFailureInput,
): ConsoleObservabilityEventEnvelope {
  const policy =
    input.eventType === 'billing.stripe_webhook.invalid_signature'
      ? CONSOLE_OBSERVABILITY_EVENT_POLICIES.billingStripeWebhookInvalidSignature
      : CONSOLE_OBSERVABILITY_EVENT_POLICIES.billingStripeWebhookProcessingFailure;
  return baseEnvelope({
    eventIdPrefix: 'obs_billing_stripe_webhook_failure',
    orgId: input.orgId,
    requestId: input.requestId,
    traceId: input.traceId,
    timestamp: input.timestamp,
    schemaVersion: input.schemaVersion,
    redactionVersion: input.redactionVersion,
    source: policy.source,
    service: policy.service,
    component: policy.component,
    level: policy.level,
    eventType: policy.eventType,
    message: normalizeString(input.failureMessage),
    metadata: {
      failureCode: normalizeString(input.failureCode),
      ...(normalizeString(input.stripeEventId)
        ? { stripeEventId: normalizeString(input.stripeEventId) }
        : {}),
      ...(normalizeString(input.stripeEventType)
        ? { stripeEventType: normalizeString(input.stripeEventType) }
        : {}),
      ...(normalizeString(input.checkoutSessionId)
        ? { checkoutSessionId: normalizeString(input.checkoutSessionId) }
        : {}),
      ...(normalizeString(input.providerRef) ? { providerRef: normalizeString(input.providerRef) } : {}),
      ...(normalizeString(input.providerCustomerRef)
        ? { providerCustomerRef: normalizeString(input.providerCustomerRef) }
        : {}),
    },
  });
}

export function buildBillingBalanceTransitionObservabilityEvent(
  input: ConsoleObservabilityBillingBalanceTransitionInput,
): ConsoleObservabilityEventEnvelope {
  const policy =
    input.eventType === 'billing.balance.low_balance'
      ? CONSOLE_OBSERVABILITY_EVENT_POLICIES.billingBalanceLow
      : input.eventType === 'billing.balance.blocked'
        ? CONSOLE_OBSERVABILITY_EVENT_POLICIES.billingBalanceBlocked
        : CONSOLE_OBSERVABILITY_EVENT_POLICIES.billingBalanceRecovered;
  const message =
    input.eventType === 'billing.balance.low_balance'
      ? 'Sponsored prepaid balance entered low-balance state'
      : input.eventType === 'billing.balance.blocked'
        ? 'Sponsored prepaid balance became blocked'
        : 'Sponsored prepaid balance recovered to healthy state';
  return baseEnvelope({
    eventIdPrefix: 'obs_billing_balance_transition',
    orgId: input.orgId,
    projectId: input.projectId,
    environmentId: input.environmentId,
    requestId: input.requestId,
    traceId: input.traceId,
    timestamp: input.timestamp,
    schemaVersion: input.schemaVersion,
    redactionVersion: input.redactionVersion,
    source: policy.source,
    service: policy.service,
    component: policy.component,
    level: policy.level,
    eventType: policy.eventType,
    message,
    metadata: {
      previousState: normalizeString(input.previousState),
      currentState: normalizeString(input.currentState),
      creditBalanceMinor: Number(input.creditBalanceMinor),
      lowBalanceThresholdMinor: Number(input.lowBalanceThresholdMinor),
      triggerKind: normalizeString(input.triggerKind),
      ...(normalizeString(input.routeId) ? { routeId: normalizeString(input.routeId) } : {}),
      ...(normalizeString(input.ledgerEntryId)
        ? { ledgerEntryId: normalizeString(input.ledgerEntryId) }
        : {}),
      ...(normalizeString(input.adjustmentId)
        ? { adjustmentId: normalizeString(input.adjustmentId) }
        : {}),
      ...(normalizeString(input.purchaseId)
        ? { purchaseId: normalizeString(input.purchaseId) }
        : {}),
      ...(normalizeString(input.sourceEventId)
        ? { sourceEventId: normalizeString(input.sourceEventId) }
        : {}),
    },
  });
}

export function buildApprovalFailureObservabilityEvent(
  input: ConsoleObservabilityApprovalFailureInput,
): ConsoleObservabilityEventEnvelope {
  const approvalId = normalizeString(input.approvalId);
  const policy = CONSOLE_OBSERVABILITY_EVENT_POLICIES.approvalPublishFailure;
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
    source: policy.source,
    service: policy.service,
    component: policy.component,
    level: policy.level,
    eventType: policy.eventType,
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

export function buildBillingSponsorshipBlockedObservabilityEvent(
  input: ConsoleObservabilityBillingSponsorshipBlockedInput,
): ConsoleObservabilityEventEnvelope {
  const policy = CONSOLE_OBSERVABILITY_EVENT_POLICIES.billingSponsorshipBlocked;
  return baseEnvelope({
    eventIdPrefix: 'obs_billing_sponsorship_blocked',
    orgId: input.orgId,
    projectId: input.projectId,
    environmentId: input.environmentId,
    requestId: input.requestId,
    traceId: input.traceId,
    timestamp: input.timestamp,
    schemaVersion: input.schemaVersion,
    redactionVersion: input.redactionVersion,
    source: policy.source,
    service: policy.service,
    component: policy.component,
    level: policy.level,
    eventType: policy.eventType,
    message: normalizeString(input.failureMessage),
    metadata: {
      failureCode: normalizeString(input.failureCode),
      ...(normalizeString(input.policyId) ? { policyId: normalizeString(input.policyId) } : {}),
      ...(normalizeString(input.routeId) ? { routeId: normalizeString(input.routeId) } : {}),
      ...(normalizeString(input.chainFamily)
        ? { chainFamily: normalizeString(input.chainFamily) }
        : {}),
      ...(normalizeString(input.intentKind) ? { intentKind: normalizeString(input.intentKind) } : {}),
      ...(normalizeString(input.executorKind)
        ? { executorKind: normalizeString(input.executorKind) }
        : {}),
      ...(Number.isFinite(Number(input.chainId)) ? { chainId: Number(input.chainId) } : {}),
      ...(normalizeString(input.accountRef) ? { accountRef: normalizeString(input.accountRef) } : {}),
      ...(normalizeString(input.targetRef) ? { targetRef: normalizeString(input.targetRef) } : {}),
      ...(normalizeString(input.idempotencyKey)
        ? { idempotencyKey: normalizeString(input.idempotencyKey) }
        : {}),
      ...(normalizeString(input.sourceEventId)
        ? { sourceEventId: normalizeString(input.sourceEventId) }
        : {}),
      ...(normalizeString(input.balanceState) ? { balanceState: normalizeString(input.balanceState) } : {}),
      ...(Number.isFinite(Number(input.creditBalanceMinor))
        ? { creditBalanceMinor: Number(input.creditBalanceMinor) }
        : {}),
      ...(Number.isFinite(Number(input.lowBalanceThresholdMinor))
        ? { lowBalanceThresholdMinor: Number(input.lowBalanceThresholdMinor) }
        : {}),
      ...(Number.isFinite(Number(input.availableBalanceMinor))
        ? { availableBalanceMinor: Number(input.availableBalanceMinor) }
        : {}),
      ...(Number.isFinite(Number(input.postedBalanceMinor))
        ? { postedBalanceMinor: Number(input.postedBalanceMinor) }
        : {}),
      ...(Number.isFinite(Number(input.reservedMinor))
        ? { reservedMinor: Number(input.reservedMinor) }
        : {}),
      ...(Number.isFinite(Number(input.requestedMinor))
        ? { requestedMinor: Number(input.requestedMinor) }
        : {}),
    },
  });
}

export function buildRecoveryExecutionFailedObservabilityEvent(
  input: ConsoleObservabilityRecoveryExecutionFailedInput,
): ConsoleObservabilityEventEnvelope {
  const policy = CONSOLE_OBSERVABILITY_EVENT_POLICIES.recoveryExecutionFailed;
  const normalizedFailureCodes = normalizeUniqueStrings(input.failureCodes);
  const alertScope = buildRecoveryAlertScope({
    orgId: input.orgId,
    environmentId: input.environmentId,
    projectId: input.projectId,
  });
  const alertWindowStart = normalizeWindowStartIso(
    input.timestamp,
    new Date(),
    RECOVERY_MONITORING_ALERT_WINDOW_MS,
  );
  const alertRoutingKey = [
    'recovery-execution',
    'failed',
    alertScope,
    normalizedFailureCodes.join(',') || 'unknown-failure',
  ].join(':');
  return baseEnvelope({
    eventIdPrefix: 'obs_recovery_execution_failed',
    eventId: makeDeterministicEventId({
      eventIdPrefix: 'obs_recovery_execution_failed',
      parts: [alertRoutingKey, alertWindowStart],
    }),
    orgId: input.orgId,
    projectId: input.projectId,
    environmentId: input.environmentId,
    requestId: input.requestId,
    traceId: input.traceId,
    timestamp: input.timestamp,
    schemaVersion: input.schemaVersion,
    redactionVersion: input.redactionVersion,
    source: policy.source,
    service: policy.service,
    component: policy.component,
    level: policy.level,
    eventType: policy.eventType,
    message: `Detected ${Math.max(
      1,
      Math.floor(normalizeNumber(input.count, 1)),
    )} failed recovery executions during recovery-authority monitoring`,
    metadata: {
      alertScope,
      alertWindowStart,
      alertRoutingKey,
      count: Math.max(1, Math.floor(normalizeNumber(input.count, 1))),
      sampleExecutionRefs: Array.isArray(input.sampleExecutionRefs)
        ? input.sampleExecutionRefs.map((entry) => normalizeString(entry)).filter(Boolean)
        : [],
      ...(normalizedFailureCodes.length ? { failureCodes: normalizedFailureCodes } : {}),
    },
  });
}

export function buildRecoveryExecutionStuckObservabilityEvent(
  input: ConsoleObservabilityRecoveryExecutionStuckInput,
): ConsoleObservabilityEventEnvelope {
  const policy = CONSOLE_OBSERVABILITY_EVENT_POLICIES.recoveryExecutionStuck;
  const normalizedStatus = normalizeString(input.status) || 'pending';
  const alertScope = buildRecoveryAlertScope({
    orgId: input.orgId,
    environmentId: input.environmentId,
    projectId: input.projectId,
  });
  const alertWindowStart = normalizeWindowStartIso(
    input.timestamp,
    new Date(),
    RECOVERY_MONITORING_ALERT_WINDOW_MS,
  );
  const staleAfterMs = Math.max(1, Math.floor(normalizeNumber(input.staleAfterMs, 1)));
  const alertRoutingKey = [
    'recovery-execution',
    'stuck',
    normalizedStatus,
    String(staleAfterMs),
    alertScope,
  ].join(':');
  return baseEnvelope({
    eventIdPrefix: 'obs_recovery_execution_stuck',
    eventId: makeDeterministicEventId({
      eventIdPrefix: 'obs_recovery_execution_stuck',
      parts: [alertRoutingKey, alertWindowStart],
    }),
    orgId: input.orgId,
    projectId: input.projectId,
    environmentId: input.environmentId,
    requestId: input.requestId,
    traceId: input.traceId,
    timestamp: input.timestamp,
    schemaVersion: input.schemaVersion,
    redactionVersion: input.redactionVersion,
    source: policy.source,
    service: policy.service,
    component: policy.component,
    level: policy.level,
    eventType: policy.eventType,
    message: `Detected ${Math.max(
      1,
      Math.floor(normalizeNumber(input.count, 1)),
    )} stale ${normalizedStatus} recovery executions during recovery-authority monitoring`,
    metadata: {
      alertScope,
      alertWindowStart,
      alertRoutingKey,
      status: normalizedStatus,
      count: Math.max(1, Math.floor(normalizeNumber(input.count, 1))),
      staleAfterMs,
      sampleExecutionRefs: Array.isArray(input.sampleExecutionRefs)
        ? input.sampleExecutionRefs.map((entry) => normalizeString(entry)).filter(Boolean)
        : [],
    },
  });
}
