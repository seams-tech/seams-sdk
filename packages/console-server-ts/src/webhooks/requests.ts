import { ConsoleWebhookError } from './errors';

import {
  readOptionalQueryBooleanField as readOptionalQueryBoolean,
  readOptionalQueryPositiveIntegerField as readOptionalQueryInteger,
  readOptionalQueryStringField as readOptionalQueryString,
  readOptionalStringField as readOptionalString,
  readRequiredStringField as readRequiredString,
  requireBodyObject as requireObject,
  requireQueryObject,
} from '../shared/requestParse';
import type {
  WebhookEventCategoryValidation,
  ConsoleWebhookEndpointStatus,
  CreateConsoleWebhookEndpointRequest,
  ListConsoleWebhookDeliveriesRequest,
  ListConsoleWebhookAttemptsRequest,
  ListConsoleWebhookDeadLettersRequest,
  ReplayConsoleWebhookDeliveryRequest,
  UpdateConsoleWebhookEndpointRequest,
} from './types';


const WEBHOOK_ENDPOINT_STATUSES: Set<ConsoleWebhookEndpointStatus> = new Set([
  'ACTIVE',
  'DISABLED',
]);

function createParseError(code: string, status: number, message: string): ConsoleWebhookError {
  return new ConsoleWebhookError(code, status, message);
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

function parseWebhookEventCategoriesOrThrow(
  raw: unknown,
  categoryValidation: WebhookEventCategoryValidation,
): string[] {
  if (!Array.isArray(raw) || raw.length === 0) {
    throw new ConsoleWebhookError(
      'invalid_body',
      400,
      'Field eventCategories must be a non-empty array',
    );
  }
  const out: string[] = [];
  const seen = new Set<string>();
  for (const item of raw) {
    const value = categoryValidation.normalizeCategory(item);
    if (!value) {
      throw new ConsoleWebhookError(
        'invalid_body',
        400,
        `Unsupported event category: ${String(item || '')
          .trim()
          .toLowerCase()}`,
      );
    }
    if (!seen.has(value)) {
      seen.add(value);
      out.push(value);
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
  categoryValidation: WebhookEventCategoryValidation,
): CreateConsoleWebhookEndpointRequest {
  const obj = requireObject(body, createParseError);
  const url = normalizeWebhookUrlOrThrow(readRequiredString(obj, 'url', createParseError), 'url');
  const eventCategories = parseWebhookEventCategoriesOrThrow(obj.eventCategories, categoryValidation);
  const statusRaw = obj.status;
  const status =
    statusRaw === undefined ? undefined : parseWebhookStatusOrThrow(statusRaw, 'status');
  return {
    url,
    eventCategories,
    status,
  };
}

export function parseUpdateConsoleWebhookEndpointRequest(
  body: unknown,
  categoryValidation: WebhookEventCategoryValidation,
): UpdateConsoleWebhookEndpointRequest {
  const obj = requireObject(body, createParseError);
  const urlRaw = readOptionalString(obj, 'url');
  const statusRaw = obj.status;
  const eventCategoriesRaw = obj.eventCategories;

  const out: UpdateConsoleWebhookEndpointRequest = {};
  if (urlRaw !== undefined) {
    out.url = normalizeWebhookUrlOrThrow(urlRaw, 'url');
  }
  if (eventCategoriesRaw !== undefined) {
    out.eventCategories = parseWebhookEventCategoriesOrThrow(eventCategoriesRaw, categoryValidation);
  }
  if (statusRaw !== undefined) {
    out.status = parseWebhookStatusOrThrow(statusRaw, 'status');
  }
  if (!out.url && !out.eventCategories && !out.status) {
    throw new ConsoleWebhookError(
      'invalid_body',
      400,
      'Update request must include at least one of: url, eventCategories, status',
    );
  }
  return out;
}

export function parseReplayConsoleWebhookDeliveryRequest(
  body: unknown,
): ReplayConsoleWebhookDeliveryRequest {
  if (body === undefined || body === null) return {};
  const obj = requireObject(body, createParseError);
  return {
    deliveryId: readOptionalString(obj, 'deliveryId'),
  };
}

export function parseListConsoleWebhookDeliveriesRequest(
  query: unknown,
): ListConsoleWebhookDeliveriesRequest {
  const obj = requireQueryObject(query, createParseError);
  return {
    limit: readOptionalQueryInteger(obj, 'limit', createParseError),
    cursor: readOptionalQueryString(obj, 'cursor'),
  };
}

export function parseListConsoleWebhookAttemptsRequest(
  query: unknown,
): ListConsoleWebhookAttemptsRequest {
  const obj = requireQueryObject(query, createParseError);
  return {
    deliveryId: readOptionalQueryString(obj, 'deliveryId'),
    limit: readOptionalQueryInteger(obj, 'limit', createParseError),
    cursor: readOptionalQueryString(obj, 'cursor'),
  };
}

export function parseListConsoleWebhookDeadLettersRequest(
  query: unknown,
): ListConsoleWebhookDeadLettersRequest {
  const obj = requireQueryObject(query, createParseError);
  return {
    deliveryId: readOptionalQueryString(obj, 'deliveryId'),
    includeResolved: readOptionalQueryBoolean(obj, 'includeResolved', createParseError),
    limit: readOptionalQueryInteger(obj, 'limit', createParseError),
    cursor: readOptionalQueryString(obj, 'cursor'),
  };
}
