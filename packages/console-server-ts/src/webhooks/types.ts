/**
 * Product-supplied webhook category vocabulary. Core delivery stores and
 * matches normalized category strings; the composed product owns the catalog.
 */
export interface WebhookEventCategoryValidation {
  normalizeCategory(value: unknown): string | null;
}

export type ConsoleWebhookEndpointStatus = 'ACTIVE' | 'DISABLED';

export type ConsoleWebhookDeliveryStatus = 'SUCCEEDED' | 'FAILED';

export interface ConsoleWebhooksContext {
  orgId: string;
  actorUserId: string;
}

export interface ConsoleWebhookEndpoint {
  id: string;
  orgId: string;
  url: string;
  eventCategories: string[];
  status: ConsoleWebhookEndpointStatus;
  secretVersion: number;
  secretPreview: string;
  createdAt: string;
  updatedAt: string;
}

/**
 * The plaintext signing secret is sealed at rest and never returned by any
 * read route, so create and rotate are the only moments a customer can capture
 * it. Both carry it out-of-band from the endpoint record for that reason.
 */
export interface CreateConsoleWebhookEndpointResult {
  endpoint: ConsoleWebhookEndpoint;
  signingSecret: string;
}

export interface RotateConsoleWebhookSecretResult {
  endpoint: ConsoleWebhookEndpoint;
  signingSecret: string;
}

export interface ConsoleWebhookDelivery {
  id: string;
  orgId: string;
  endpointId: string;
  eventId: string;
  eventType: string;
  status: ConsoleWebhookDeliveryStatus;
  attemptCount: number;
  replayCount: number;
  responseStatus: number | null;
  responseBody: string | null;
  errorMessage: string | null;
  deliveredAt: string | null;
  lastAttemptAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface ConsoleWebhookDeliveryAttempt {
  id: string;
  orgId: string;
  endpointId: string;
  deliveryId: string;
  attemptNo: number;
  status: ConsoleWebhookDeliveryStatus;
  responseStatus: number | null;
  responseBody: string | null;
  errorMessage: string | null;
  attemptedAt: string;
  isReplay: boolean;
}

export interface ConsoleWebhookDeadLetter {
  id: string;
  orgId: string;
  endpointId: string;
  deliveryId: string;
  eventId: string;
  eventType: string;
  failedAttempts: number;
  lastResponseStatus: number | null;
  lastErrorMessage: string | null;
  movedToDlqAt: string;
  resolvedAt: string | null;
}

export interface ConsoleWebhookPage<T> {
  items: T[];
  nextCursor?: string;
}

export interface CreateConsoleWebhookEndpointRequest {
  url: string;
  eventCategories: string[];
  status?: ConsoleWebhookEndpointStatus;
}

export interface UpdateConsoleWebhookEndpointRequest {
  url?: string;
  eventCategories?: string[];
  status?: ConsoleWebhookEndpointStatus;
}

export interface ReplayConsoleWebhookDeliveryRequest {
  deliveryId?: string;
}

export interface ListConsoleWebhookDeliveriesRequest {
  limit?: number;
  cursor?: string;
}

export interface ListConsoleWebhookAttemptsRequest {
  deliveryId?: string;
  limit?: number;
  cursor?: string;
}

export interface ListConsoleWebhookDeadLettersRequest {
  deliveryId?: string;
  includeResolved?: boolean;
  limit?: number;
  cursor?: string;
}

export interface ReplayConsoleWebhookDeliveryResult {
  replayed: boolean;
  delivery: ConsoleWebhookDelivery | null;
  reason?: 'endpoint_not_found' | 'delivery_not_found' | 'no_replayable_delivery';
}

export interface EmitConsoleWebhookEventRequest {
  eventId?: string;
  eventType: string;
  payload: Record<string, unknown>;
}

export interface EmitConsoleWebhookEventResult {
  eventId: string;
  attempted: number;
  delivered: number;
  failed: number;
}
