export type ConsoleObservabilityModuleState = 'ok' | 'forbidden' | 'not_configured' | 'error';

export interface ConsoleObservabilityModuleStatus {
  state: ConsoleObservabilityModuleState;
  code?: string;
  message?: string;
}

export type ConsoleObservabilityLevel = 'DEBUG' | 'INFO' | 'WARN' | 'ERROR' | 'FATAL';
export type ConsoleObservabilitySource = 'WEBHOOK' | 'BILLING' | 'APPROVAL' | 'SYSTEM';

export interface ConsoleObservabilitySummary {
  generatedAt: string;
  status: ConsoleObservabilityModuleStatus;
  errorRate: number;
  p95LatencyMs: number;
  failingServices: number;
  deadLetterCount: number;
}

export interface ConsoleObservabilityEvent {
  id: string;
  orgId: string;
  projectId?: string;
  environmentId?: string;
  timestamp: string;
  service: string;
  component: string;
  level: ConsoleObservabilityLevel;
  eventType: string;
  message: string;
  requestId?: string;
  traceId?: string;
  metadata: Record<string, unknown>;
}

export interface ConsoleObservabilityEventEnvelope {
  eventId: string;
  schemaVersion: number;
  source: ConsoleObservabilitySource;
  ingestedAtMs: number;
  timestamp: string;
  orgId: string;
  projectId?: string;
  environmentId?: string;
  service: string;
  component: string;
  level: ConsoleObservabilityLevel;
  eventType: string;
  message: string;
  requestId?: string;
  traceId?: string;
  metadata: Record<string, unknown>;
  redactionVersion: number;
  redactionApplied: boolean;
}

export interface ConsoleObservabilityEventsPage {
  status: ConsoleObservabilityModuleStatus;
  events: ConsoleObservabilityEvent[];
  totalPages: number;
  nextCursor?: string;
}

export interface ConsoleObservabilityTimeseriesBucket {
  start: string;
  end: string;
  errorCount: number;
  requestCount: number;
  p50LatencyMs: number;
  p95LatencyMs: number;
}

export interface ConsoleObservabilityTimeseries {
  status: ConsoleObservabilityModuleStatus;
  buckets: ConsoleObservabilityTimeseriesBucket[];
}

export type ConsoleServiceHealthState = 'HEALTHY' | 'DEGRADED' | 'FAILING' | 'UNKNOWN';

export interface ConsoleObservabilityServiceHealth {
  service: string;
  status: ConsoleServiceHealthState;
  recentFailureCount: number;
  latestIncidentAt?: string;
}

export interface ConsoleObservabilityServicesView {
  status: ConsoleObservabilityModuleStatus;
  services: ConsoleObservabilityServiceHealth[];
}

export interface GetConsoleObservabilitySummaryRequest {
  from?: string;
  to?: string;
  projectId?: string;
  environmentId?: string;
}

export interface ListConsoleObservabilityEventsRequest {
  from?: string;
  to?: string;
  query?: string;
  level?: ConsoleObservabilityLevel;
  service?: string;
  component?: string;
  eventType?: string;
  projectId?: string;
  environmentId?: string;
  cursor?: string;
  limit?: number;
}

export interface GetConsoleObservabilityTimeseriesRequest {
  from?: string;
  to?: string;
  service?: string;
  projectId?: string;
  environmentId?: string;
  bucketMinutes?: number;
}

export interface ListConsoleObservabilityServicesRequest {
  from?: string;
  to?: string;
  projectId?: string;
  environmentId?: string;
  limit?: number;
}

export interface ConsoleObservabilityEventIngestResult {
  accepted: number;
  deduplicated: number;
}

export interface ConsoleObservabilityIngestionContext {
  orgId: string;
  actorUserId: string;
  roles: string[];
}

export interface ConsoleObservabilityRequestMetricInput {
  orgId: string;
  projectId?: string;
  environmentId?: string;
  route: string;
  method: string;
  statusCode: number;
  latencyMs: number;
  timestamp?: string;
}

export interface ConsoleObservabilityMetadataRedactionPolicy {
  denylistKeys?: string[];
  allowlistKeys?: string[];
  maxDepth?: number;
  maxStringLength?: number;
  replacement?: string;
  redactionVersion?: number;
}

export interface ConsoleObservabilityWebhookDeadLetterInput {
  orgId: string;
  projectId?: string;
  environmentId?: string;
  endpointId: string;
  deliveryId: string;
  webhookEventId: string;
  webhookEventType: string;
  failedAttempts: number;
  lastResponseStatus?: number;
  lastErrorMessage?: string;
  movedToDlqAt: string;
  requestId?: string;
  traceId?: string;
  schemaVersion?: number;
  redactionVersion?: number;
}

export interface ConsoleObservabilityWebhookRetryExhaustedInput {
  orgId: string;
  endpointId: string;
  deliveryId: string;
  webhookEventId: string;
  webhookEventType: string;
  failedAttempts: number;
  maxAttempts: number;
  lastResponseStatus?: number;
  lastErrorMessage?: string;
  exhaustedAt: string;
  requestId?: string;
  traceId?: string;
  schemaVersion?: number;
  redactionVersion?: number;
}

export interface ConsoleObservabilityWebhookEndpointDegradedInput {
  orgId: string;
  endpointId: string;
  unresolvedDeadLetterCount: number;
  degradationThreshold: number;
  latestDeliveryId?: string;
  latestWebhookEventId?: string;
  latestWebhookEventType?: string;
  lastResponseStatus?: number;
  lastErrorMessage?: string;
  degradedAt: string;
  requestId?: string;
  traceId?: string;
  schemaVersion?: number;
  redactionVersion?: number;
}

export interface ConsoleObservabilityBillingFailureInput {
  orgId: string;
  projectId?: string;
  environmentId?: string;
  invoiceId?: string;
  operation: 'INVOICE_FINALIZATION' | 'PAYMENT_RECONCILE';
  failureCode: string;
  failureMessage: string;
  providerRef?: string;
  requestId?: string;
  traceId?: string;
  timestamp?: string;
  schemaVersion?: number;
  redactionVersion?: number;
}

export interface ConsoleObservabilityBillingStripeWebhookFailureInput {
  orgId: string;
  stripeEventId?: string;
  stripeEventType?: string;
  checkoutSessionId?: string;
  providerRef?: string;
  providerCustomerRef?: string;
  eventType:
    | 'billing.stripe_webhook.invalid_signature'
    | 'billing.stripe_webhook.processing.failed';
  failureCode: string;
  failureMessage: string;
  requestId?: string;
  traceId?: string;
  timestamp?: string;
  schemaVersion?: number;
  redactionVersion?: number;
}

export interface ConsoleObservabilityApprovalFailureInput {
  orgId: string;
  projectId?: string;
  environmentId?: string;
  approvalId?: string;
  operationType: string;
  resourceType?: string;
  resourceId?: string;
  failureCode: string;
  failureMessage: string;
  requestId?: string;
  traceId?: string;
  timestamp?: string;
  schemaVersion?: number;
  redactionVersion?: number;
}
