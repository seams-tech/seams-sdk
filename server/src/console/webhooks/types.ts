export type ConsoleWebhookSubscription = 'wallet' | 'policy' | 'auth' | 'tx' | 'billing';

export type ConsoleWebhookEndpointStatus = 'ACTIVE' | 'DISABLED';

export type ConsoleWebhookDeliveryStatus = 'SUCCEEDED' | 'FAILED';

export interface ConsoleWebhookEndpoint {
  id: string;
  orgId: string;
  url: string;
  subscriptions: ConsoleWebhookSubscription[];
  status: ConsoleWebhookEndpointStatus;
  secretVersion: number;
  secretPreview: string;
  createdAt: string;
  updatedAt: string;
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
  subscriptions: ConsoleWebhookSubscription[];
  status?: ConsoleWebhookEndpointStatus;
}

export interface UpdateConsoleWebhookEndpointRequest {
  url?: string;
  subscriptions?: ConsoleWebhookSubscription[];
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
