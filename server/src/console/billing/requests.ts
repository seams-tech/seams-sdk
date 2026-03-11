import { ConsoleBillingError } from './errors';
import {
  CUSTOM_BILLING_CREDIT_PACK_ID,
  isBillingCreditPackId,
  validateCustomCreditPackAmountMinor,
} from './creditPacks';
import {
  readOptionalQueryBooleanField as readOptionalQueryBoolean,
  readOptionalQueryPositiveIntegerField as readOptionalQueryPositiveInteger,
  readOptionalQueryStringField as readOptionalQueryString,
  readOptionalStringField as readOptionalString,
  readRequiredIntegerField as readRequiredInteger,
  readRequiredStringField as readRequiredString,
  requireBodyObject as requireObject,
  requireQueryObject as requireQuery,
} from '../shared/requestParse';
import type {
  BillingAccountActivityRequest,
  BillingInvoiceListRequest,
  BillingManualAdjustmentRequest,
  BillingUsageEventRequest,
  GenerateMonthlyInvoiceRequest,
  StripeCheckoutSessionRequest,
  StripeWebhookEventRequest,
} from './types';

function createParseError(code: string, status: number, message: string): ConsoleBillingError {
  return new ConsoleBillingError(code, status, message);
}

const BILLING_INVOICE_STATUSES = new Set(['OPEN', 'PAID', 'VOID', 'UNCOLLECTIBLE']);
const BILLING_DOCUMENT_TYPES = new Set(['PURCHASE_RECEIPT', 'USAGE_STATEMENT']);
const DEFAULT_INVOICE_LIST_LIMIT = 25;
const MAX_INVOICE_LIST_LIMIT = 100;
const DEFAULT_ACCOUNT_ACTIVITY_LIMIT = 25;
const MAX_ACCOUNT_ACTIVITY_LIMIT = 100;

function normalizeInvoiceListLimit(limit: number | undefined): number {
  if (!Number.isFinite(Number(limit)) || Number(limit) <= 0) {
    return DEFAULT_INVOICE_LIST_LIMIT;
  }
  return Math.max(1, Math.min(MAX_INVOICE_LIST_LIMIT, Math.floor(Number(limit))));
}

function normalizeAccountActivityLimit(limit: number | undefined): number {
  if (!Number.isFinite(Number(limit)) || Number(limit) <= 0) {
    return DEFAULT_ACCOUNT_ACTIVITY_LIMIT;
  }
  return Math.max(1, Math.min(MAX_ACCOUNT_ACTIVITY_LIMIT, Math.floor(Number(limit))));
}

function parseOptionalMonthUtc(value: string | undefined): string | undefined {
  if (!value) return undefined;
  if (!/^\d{4}-\d{2}$/.test(value)) {
    throw new ConsoleBillingError(
      'invalid_query',
      400,
      'Query parameter periodMonthUtc must be in YYYY-MM format',
    );
  }
  const month = Number(value.slice(5, 7));
  if (!Number.isInteger(month) || month < 1 || month > 12) {
    throw new ConsoleBillingError(
      'invalid_query',
      400,
      'Query parameter periodMonthUtc month must be between 01 and 12',
    );
  }
  return value;
}

export function parseBillingInvoiceListRequest(query: unknown): BillingInvoiceListRequest {
  const obj = requireQuery(query, createParseError);
  const rawStatus = readOptionalQueryString(obj, 'status');
  const rawCursor = readOptionalQueryString(obj, 'cursor');
  const rawPeriodMonthUtc = readOptionalQueryString(obj, 'periodMonthUtc');
  const rawDocumentType = readOptionalQueryString(obj, 'documentType');
  const rawLimit = readOptionalQueryPositiveInteger(obj, 'limit', createParseError);
  const overdueParam = readOptionalQueryBoolean(obj, 'overdue', createParseError);

  let status: BillingInvoiceListRequest['status'];
  let overdueOnly = overdueParam === true;
  if (rawStatus) {
    const normalizedStatus = rawStatus.toUpperCase();
    if (normalizedStatus === 'OVERDUE') {
      status = 'OPEN';
      overdueOnly = true;
    } else if (BILLING_INVOICE_STATUSES.has(normalizedStatus)) {
      status = normalizedStatus as BillingInvoiceListRequest['status'];
    } else {
      throw new ConsoleBillingError(
        'invalid_query',
        400,
        `Query parameter status must be one of: ${Array.from(BILLING_INVOICE_STATUSES).join(', ')}, OVERDUE`,
      );
    }
  }

  const periodMonthUtc = parseOptionalMonthUtc(rawPeriodMonthUtc);
  let documentType: BillingInvoiceListRequest['documentType'];
  if (rawDocumentType) {
    const normalized = rawDocumentType.toUpperCase();
    if (!BILLING_DOCUMENT_TYPES.has(normalized)) {
      throw new ConsoleBillingError(
        'invalid_query',
        400,
        `Query parameter documentType must be one of: ${Array.from(BILLING_DOCUMENT_TYPES).join(', ')}`,
      );
    }
    documentType = normalized as BillingInvoiceListRequest['documentType'];
  }
  return {
    ...(status ? { status } : {}),
    ...(overdueOnly ? { overdueOnly: true } : {}),
    ...(periodMonthUtc ? { periodMonthUtc } : {}),
    ...(documentType ? { documentType } : {}),
    ...(rawCursor ? { cursor: rawCursor } : {}),
    limit: normalizeInvoiceListLimit(rawLimit),
  };
}

export function parseBillingAccountActivityRequest(query: unknown): BillingAccountActivityRequest {
  const obj = requireQuery(query, createParseError);
  const rawLimit = readOptionalQueryPositiveInteger(obj, 'limit', createParseError);
  return {
    limit: normalizeAccountActivityLimit(rawLimit),
  };
}

export function parseBillingManualAdjustmentRequest(body: unknown): BillingManualAdjustmentRequest {
  const obj = requireObject(body, createParseError);
  const amountMinor = readRequiredInteger(obj, 'amountMinor', createParseError);
  const reasonCode = readRequiredString(obj, 'reasonCode', createParseError).trim();
  const note = readRequiredString(obj, 'note', createParseError).trim();
  const idempotencyKey = readRequiredString(obj, 'idempotencyKey', createParseError).trim();
  const relatedInvoiceId = readOptionalString(obj, 'relatedInvoiceId');

  if (amountMinor <= 0) {
    throw new ConsoleBillingError('invalid_body', 400, 'Field amountMinor must be positive');
  }
  if (!reasonCode) {
    throw new ConsoleBillingError('invalid_body', 400, 'Field reasonCode is required');
  }
  if (!note) {
    throw new ConsoleBillingError('invalid_body', 400, 'Field note is required');
  }
  if (!idempotencyKey) {
    throw new ConsoleBillingError('invalid_body', 400, 'Field idempotencyKey is required');
  }

  return {
    amountMinor,
    reasonCode,
    note,
    idempotencyKey,
    ...(relatedInvoiceId ? { relatedInvoiceId } : {}),
  };
}

function validateHttpUrlOrThrow(value: string, field: string): void {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch (_error: unknown) {
    throw new ConsoleBillingError('invalid_body', 400, `Field ${field} must be a valid URL`);
  }
  const protocol = parsed.protocol.toLowerCase();
  if (protocol !== 'http:' && protocol !== 'https:') {
    throw new ConsoleBillingError(
      'invalid_body',
      400,
      `Field ${field} must use http or https protocol`,
    );
  }
}

function parseOptionalIsoDate(value: string | undefined, field: string): string | undefined {
  if (value === undefined) return undefined;
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) {
    throw new ConsoleBillingError(
      'invalid_body',
      400,
      `Field ${field} must be a valid ISO-8601 datetime`,
    );
  }
  return new Date(parsed).toISOString();
}

export function parseStripeCheckoutSessionRequest(body: unknown): StripeCheckoutSessionRequest {
  const obj = requireObject(body, createParseError);
  const successUrl = readRequiredString(obj, 'successUrl', createParseError);
  const cancelUrl = readRequiredString(obj, 'cancelUrl', createParseError);
  const creditPackId = readRequiredString(obj, 'creditPackId', createParseError);
  const customAmountMinorRaw = obj.customAmountMinor;
  validateHttpUrlOrThrow(successUrl, 'successUrl');
  validateHttpUrlOrThrow(cancelUrl, 'cancelUrl');
  if (!isBillingCreditPackId(creditPackId)) {
    throw new ConsoleBillingError('invalid_body', 400, `Unsupported creditPackId: ${creditPackId}`);
  }
  const customAmountMinor =
    customAmountMinorRaw === undefined || customAmountMinorRaw === null
      ? undefined
      : typeof customAmountMinorRaw === 'number'
        ? customAmountMinorRaw
        : Number(customAmountMinorRaw);
  if (
    customAmountMinor !== undefined &&
    (!Number.isFinite(customAmountMinor) || !Number.isInteger(customAmountMinor))
  ) {
    throw new ConsoleBillingError(
      'invalid_body',
      400,
      'Field customAmountMinor must be an integer number of cents',
    );
  }
  if (creditPackId === CUSTOM_BILLING_CREDIT_PACK_ID) {
    if (customAmountMinor === undefined) {
      throw new ConsoleBillingError(
        'invalid_body',
        400,
        'Field customAmountMinor is required when creditPackId is usd_custom',
      );
    }
    validateCustomCreditPackAmountMinor(customAmountMinor);
  } else if (customAmountMinor !== undefined) {
    throw new ConsoleBillingError(
      'invalid_body',
      400,
      'Field customAmountMinor is only supported when creditPackId is usd_custom',
    );
  }
  return {
    successUrl,
    cancelUrl,
    creditPackId: creditPackId as StripeCheckoutSessionRequest['creditPackId'],
    ...(customAmountMinor === undefined ? {} : { customAmountMinor }),
  };
}

export function parseStripeWebhookEventRequest(body: unknown): StripeWebhookEventRequest {
  const obj = requireObject(body, createParseError);
  const eventId = readRequiredString(obj, 'eventId', createParseError);
  const eventTypeRaw = readOptionalString(obj, 'eventType');
  const eventType = eventTypeRaw ? eventTypeRaw.trim() : undefined;
  if (eventType && eventType !== 'checkout.session.completed') {
    throw new ConsoleBillingError(
      'invalid_body',
      400,
      `Unsupported Stripe eventType: ${eventType}`,
    );
  }

  return {
    eventId,
    ...(eventType ? { eventType: 'checkout.session.completed' as const } : {}),
    orgId: readOptionalString(obj, 'orgId'),
    providerCustomerRef: readOptionalString(obj, 'providerCustomerRef'),
    checkoutSessionId: readOptionalString(obj, 'checkoutSessionId'),
    providerRef: readOptionalString(obj, 'providerRef'),
  };
}

export function parseBillingUsageEventRequest(body: unknown): BillingUsageEventRequest {
  const obj = requireObject(body, createParseError);
  const walletId = readRequiredString(obj, 'walletId', createParseError);
  const action = readRequiredString(obj, 'action', createParseError).toLowerCase();
  const succeededRaw = obj.succeeded;
  if (typeof succeededRaw !== 'boolean') {
    throw new ConsoleBillingError('invalid_body', 400, 'Field succeeded must be boolean');
  }

  const validActions = new Set(['transfer', 'swap', 'approve', 'contract_call', 'wallet_created']);
  if (!validActions.has(action)) {
    throw new ConsoleBillingError('invalid_body', 400, `Unsupported action: ${action}`);
  }

  const isSimulation = obj.isSimulation;
  if (isSimulation !== undefined && typeof isSimulation !== 'boolean') {
    throw new ConsoleBillingError('invalid_body', 400, 'Field isSimulation must be boolean');
  }

  const isInternalRetry = obj.isInternalRetry;
  if (isInternalRetry !== undefined && typeof isInternalRetry !== 'boolean') {
    throw new ConsoleBillingError('invalid_body', 400, 'Field isInternalRetry must be boolean');
  }

  return {
    walletId,
    action: action as BillingUsageEventRequest['action'],
    succeeded: succeededRaw,
    ...(isSimulation === undefined ? {} : { isSimulation }),
    ...(isInternalRetry === undefined ? {} : { isInternalRetry }),
    ...(readOptionalString(obj, 'sourceEventId')
      ? { sourceEventId: readOptionalString(obj, 'sourceEventId') }
      : {}),
    ...(parseOptionalIsoDate(readOptionalString(obj, 'occurredAt'), 'occurredAt')
      ? { occurredAt: parseOptionalIsoDate(readOptionalString(obj, 'occurredAt'), 'occurredAt') }
      : {}),
  };
}

export function parseGenerateMonthlyInvoiceRequest(body: unknown): GenerateMonthlyInvoiceRequest {
  const obj = requireObject(body, createParseError);
  const periodMonthUtc = readRequiredString(obj, 'periodMonthUtc', createParseError);
  if (!/^\d{4}-\d{2}$/.test(periodMonthUtc)) {
    throw new ConsoleBillingError(
      'invalid_body',
      400,
      'Field periodMonthUtc must be in YYYY-MM format',
    );
  }
  const month = Number(periodMonthUtc.slice(5, 7));
  if (!Number.isInteger(month) || month < 1 || month > 12) {
    throw new ConsoleBillingError(
      'invalid_body',
      400,
      'Field periodMonthUtc month must be between 01 and 12',
    );
  }
  return { periodMonthUtc };
}
