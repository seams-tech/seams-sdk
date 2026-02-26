import { ConsoleWebhookError } from './errors';
import type {
  ConsoleWebhookEndpointStatus,
  ConsoleWebhookSubscription,
  CreateConsoleWebhookEndpointRequest,
  ListConsoleWebhookDeliveriesRequest,
  ListConsoleWebhookAttemptsRequest,
  ListConsoleWebhookDeadLettersRequest,
  ReplayConsoleWebhookDeliveryRequest,
  UpdateConsoleWebhookEndpointRequest,
} from './types';

const WEBHOOK_SUBSCRIPTIONS: Set<ConsoleWebhookSubscription> = new Set([
  'wallet',
  'policy',
  'auth',
  'tx',
  'billing',
]);

const WEBHOOK_ENDPOINT_STATUSES: Set<ConsoleWebhookEndpointStatus> = new Set([
  'ACTIVE',
  'DISABLED',
]);

function requireObject(body: unknown): Record<string, unknown> {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new ConsoleWebhookError('invalid_body', 400, 'Expected JSON object request body');
  }
  return body as Record<string, unknown>;
}

function readRequiredString(body: Record<string, unknown>, key: string): string {
  const value = String(body[key] ?? '').trim();
  if (!value) {
    throw new ConsoleWebhookError('invalid_body', 400, `Missing required field: ${key}`);
  }
  return value;
}

function readOptionalString(body: Record<string, unknown>, key: string): string | undefined {
  const raw = body[key];
  if (raw === undefined || raw === null) return undefined;
  const value = String(raw).trim();
  return value || undefined;
}

function readOptionalQueryString(query: Record<string, unknown>, key: string): string | undefined {
  const raw = query[key];
  if (raw === undefined || raw === null) return undefined;
  const first = Array.isArray(raw) ? raw[0] : raw;
  const value = String(first).trim();
  return value || undefined;
}

function readOptionalQueryBoolean(
  query: Record<string, unknown>,
  key: string,
): boolean | undefined {
  const raw = query[key];
  if (raw === undefined || raw === null) return undefined;
  const first = Array.isArray(raw) ? raw[0] : raw;
  if (typeof first === 'boolean') return first;

  const value = String(first).trim().toLowerCase();
  if (!value) return undefined;
  if (value === 'true' || value === '1') return true;
  if (value === 'false' || value === '0') return false;
  throw new ConsoleWebhookError('invalid_query', 400, `Query parameter ${key} must be true/false`);
}

function readOptionalQueryInteger(query: Record<string, unknown>, key: string): number | undefined {
  const raw = query[key];
  if (raw === undefined || raw === null) return undefined;
  const first = Array.isArray(raw) ? raw[0] : raw;
  const text = String(first).trim();
  if (!text) return undefined;
  if (!/^\d+$/.test(text)) {
    throw new ConsoleWebhookError(
      'invalid_query',
      400,
      `Query parameter ${key} must be a positive integer`,
    );
  }
  const value = Number.parseInt(text, 10);
  if (!Number.isFinite(value) || value <= 0) {
    throw new ConsoleWebhookError(
      'invalid_query',
      400,
      `Query parameter ${key} must be a positive integer`,
    );
  }
  return value;
}

function requireQueryObject(query: unknown): Record<string, unknown> {
  if (query === undefined || query === null) return {};
  if (!query || typeof query !== 'object' || Array.isArray(query)) {
    throw new ConsoleWebhookError('invalid_query', 400, 'Expected query params object');
  }
  return query as Record<string, unknown>;
}

function normalizeWebhookUrlOrThrow(value: string, fieldName: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new ConsoleWebhookError(
      'invalid_body',
      400,
      `Field ${fieldName} must be a valid absolute URL`,
    );
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new ConsoleWebhookError(
      'invalid_body',
      400,
      `Field ${fieldName} must use https:// or http://`,
    );
  }
  return parsed.toString();
}

function parseWebhookSubscriptionsOrThrow(raw: unknown): ConsoleWebhookSubscription[] {
  if (!Array.isArray(raw) || raw.length === 0) {
    throw new ConsoleWebhookError(
      'invalid_body',
      400,
      'Field subscriptions must be a non-empty array',
    );
  }
  const out: ConsoleWebhookSubscription[] = [];
  const seen = new Set<string>();
  for (const item of raw) {
    const value = String(item || '')
      .trim()
      .toLowerCase();
    if (!WEBHOOK_SUBSCRIPTIONS.has(value as ConsoleWebhookSubscription)) {
      throw new ConsoleWebhookError('invalid_body', 400, `Unsupported subscription: ${value}`);
    }
    if (!seen.has(value)) {
      seen.add(value);
      out.push(value as ConsoleWebhookSubscription);
    }
  }
  return out;
}

function parseWebhookStatusOrThrow(
  value: unknown,
  fieldName: string,
): ConsoleWebhookEndpointStatus {
  const normalized = String(value || '')
    .trim()
    .toUpperCase();
  if (!WEBHOOK_ENDPOINT_STATUSES.has(normalized as ConsoleWebhookEndpointStatus)) {
    throw new ConsoleWebhookError('invalid_body', 400, `Unsupported ${fieldName}: ${normalized}`);
  }
  return normalized as ConsoleWebhookEndpointStatus;
}

export function parseCreateConsoleWebhookEndpointRequest(
  body: unknown,
): CreateConsoleWebhookEndpointRequest {
  const obj = requireObject(body);
  const url = normalizeWebhookUrlOrThrow(readRequiredString(obj, 'url'), 'url');
  const subscriptions = parseWebhookSubscriptionsOrThrow(obj.subscriptions);
  const statusRaw = obj.status;
  const status =
    statusRaw === undefined ? undefined : parseWebhookStatusOrThrow(statusRaw, 'status');
  return {
    url,
    subscriptions,
    status,
  };
}

export function parseUpdateConsoleWebhookEndpointRequest(
  body: unknown,
): UpdateConsoleWebhookEndpointRequest {
  const obj = requireObject(body);
  const urlRaw = readOptionalString(obj, 'url');
  const statusRaw = obj.status;
  const subscriptionsRaw = obj.subscriptions;

  const out: UpdateConsoleWebhookEndpointRequest = {};
  if (urlRaw !== undefined) {
    out.url = normalizeWebhookUrlOrThrow(urlRaw, 'url');
  }
  if (subscriptionsRaw !== undefined) {
    out.subscriptions = parseWebhookSubscriptionsOrThrow(subscriptionsRaw);
  }
  if (statusRaw !== undefined) {
    out.status = parseWebhookStatusOrThrow(statusRaw, 'status');
  }
  if (!out.url && !out.subscriptions && !out.status) {
    throw new ConsoleWebhookError(
      'invalid_body',
      400,
      'Update request must include at least one of: url, subscriptions, status',
    );
  }
  return out;
}

export function parseReplayConsoleWebhookDeliveryRequest(
  body: unknown,
): ReplayConsoleWebhookDeliveryRequest {
  if (body === undefined || body === null) return {};
  const obj = requireObject(body);
  return {
    deliveryId: readOptionalString(obj, 'deliveryId'),
  };
}

export function parseListConsoleWebhookDeliveriesRequest(
  query: unknown,
): ListConsoleWebhookDeliveriesRequest {
  const obj = requireQueryObject(query);
  return {
    limit: readOptionalQueryInteger(obj, 'limit'),
    cursor: readOptionalQueryString(obj, 'cursor'),
  };
}

export function parseListConsoleWebhookAttemptsRequest(
  query: unknown,
): ListConsoleWebhookAttemptsRequest {
  const obj = requireQueryObject(query);
  return {
    deliveryId: readOptionalQueryString(obj, 'deliveryId'),
    limit: readOptionalQueryInteger(obj, 'limit'),
    cursor: readOptionalQueryString(obj, 'cursor'),
  };
}

export function parseListConsoleWebhookDeadLettersRequest(
  query: unknown,
): ListConsoleWebhookDeadLettersRequest {
  const obj = requireQueryObject(query);
  return {
    deliveryId: readOptionalQueryString(obj, 'deliveryId'),
    includeResolved: readOptionalQueryBoolean(obj, 'includeResolved'),
    limit: readOptionalQueryInteger(obj, 'limit'),
    cursor: readOptionalQueryString(obj, 'cursor'),
  };
}
