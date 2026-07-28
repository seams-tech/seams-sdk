import { ConsoleBillingError } from './errors';
import { isBillingCreditPackId } from './creditPacks';
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
  BillingRefundReconcileRequest,
  BillingRefundRequest,
  BillingUsageEventRequest,
  GenerateMonthlyInvoiceRequest,
  StripeCheckoutSessionReconcileRequest,
  StripeCheckoutSessionRequest,
} from './types';

function createParseError(code: string, status: number, message: string): ConsoleBillingError {
  return new ConsoleBillingError(code, status, message);
}

const BILLING_INVOICE_STATUSES = new Set(['OPEN', 'PAID', 'VOID', 'UNCOLLECTIBLE']);
const BILLING_DOCUMENT_TYPES = new Set(['PURCHASE_RECEIPT', 'USAGE_STATEMENT']);
const BILLING_LEDGER_ENTRY_TYPES = new Set([
  'CREDIT_PURCHASE',
  'USAGE_DEBIT',
  'SPONSORED_EXECUTION_DEBIT',
  'MANUAL_ADJUSTMENT',
  'REFUND',
  'DISPUTE_OPENED',
  'DISPUTE_WON',
]);
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
  const rawPeriodMonthUtc = readOptionalQueryString(obj, 'periodMonthUtc');
  const rawEventType = readOptionalQueryString(obj, 'eventType');
  let eventType: BillingAccountActivityRequest['eventType'];
  if (rawEventType) {
    const normalized = rawEventType.toUpperCase();
    if (!BILLING_LEDGER_ENTRY_TYPES.has(normalized)) {
      throw new ConsoleBillingError(
        'invalid_query',
        400,
        `Query parameter eventType must be one of: ${Array.from(BILLING_LEDGER_ENTRY_TYPES).join(', ')}`,
      );
    }
    eventType = normalized as BillingAccountActivityRequest['eventType'];
  }
  return {
    limit: normalizeAccountActivityLimit(rawLimit),
    ...(rawPeriodMonthUtc ? { periodMonthUtc: parseOptionalMonthUtc(rawPeriodMonthUtc) } : {}),
    ...(eventType ? { eventType } : {}),
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
  const creditPackId = readRequiredString(obj, 'creditPackId', createParseError);
  if (!isBillingCreditPackId(creditPackId)) {
    throw new ConsoleBillingError('invalid_body', 400, `Unsupported creditPackId: ${creditPackId}`);
  }
  if ('customAmountMinor' in obj) {
    throw new ConsoleBillingError(
      'invalid_body',
      400,
      'Custom top-up amounts are not supported; select a configured credit pack',
    );
  }
  return {
    creditPackId,
  };
}

export function parseBillingRefundRequest(body: unknown): BillingRefundRequest {
  const obj = requireObject(body, createParseError);
  const purchaseId = readRequiredString(obj, 'purchaseId', createParseError).trim();
  const amountMinor = readRequiredInteger(obj, 'amountMinor', createParseError);
  const reason = readRequiredString(obj, 'reason', createParseError).trim();
  const idempotencyKey = readRequiredString(obj, 'idempotencyKey', createParseError).trim();
  if (amountMinor <= 0) {
    throw new ConsoleBillingError('invalid_body', 400, 'Field amountMinor must be positive');
  }
  if (!purchaseId || !reason || !idempotencyKey) {
    throw new ConsoleBillingError(
      'invalid_body',
      400,
      'Fields purchaseId, reason, and idempotencyKey are required',
    );
  }
  return { purchaseId, amountMinor, reason, idempotencyKey };
}

export function parseBillingRefundReconcileRequest(body: unknown): BillingRefundReconcileRequest {
  const obj = requireObject(body, createParseError);
  return {
    refundId: readRequiredString(obj, 'refundId', createParseError).trim(),
  };
}

export function parseStripeCheckoutSessionReconcileRequest(
  body: unknown,
): StripeCheckoutSessionReconcileRequest {
  const obj = requireObject(body, createParseError);
  return {
    checkoutSessionId: readRequiredString(obj, 'checkoutSessionId', createParseError),
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
