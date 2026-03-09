import { ConsoleBillingError } from './errors';
import { isStablecoinAssetSymbol, isStablecoinSettlementChain } from './stablecoinAssets';
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
  AddCardPaymentMethodRequest,
  BillingInvoiceListRequest,
  BillingUsageEventRequest,
  GenerateMonthlyInvoiceRequest,
  StablecoinPaymentIntentReconcileRequest,
  StablecoinPaymentIntentRequest,
  StablecoinQuoteRequest,
  StripeCheckoutSessionRequest,
  StripeCustomerPortalSessionRequest,
  StripePaymentIntentReconcileRequest,
  StripePaymentIntentRequest,
  StripeWebhookEventRequest,
  StripeSetupIntentRequest,
} from './types';

function createParseError(code: string, status: number, message: string): ConsoleBillingError {
  return new ConsoleBillingError(code, status, message);
}

const BILLING_INVOICE_STATUSES = new Set(['OPEN', 'PAID', 'VOID', 'UNCOLLECTIBLE']);
const DEFAULT_INVOICE_LIST_LIMIT = 25;
const MAX_INVOICE_LIST_LIMIT = 100;

function normalizeInvoiceListLimit(limit: number | undefined): number {
  if (!Number.isFinite(Number(limit)) || Number(limit) <= 0) {
    return DEFAULT_INVOICE_LIST_LIMIT;
  }
  return Math.max(1, Math.min(MAX_INVOICE_LIST_LIMIT, Math.floor(Number(limit))));
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
  return {
    ...(status ? { status } : {}),
    ...(overdueOnly ? { overdueOnly: true } : {}),
    ...(periodMonthUtc ? { periodMonthUtc } : {}),
    ...(rawCursor ? { cursor: rawCursor } : {}),
    limit: normalizeInvoiceListLimit(rawLimit),
  };
}

export function parseAddCardPaymentMethodRequest(body: unknown): AddCardPaymentMethodRequest {
  const obj = requireObject(body, createParseError);
  const providerRef = readRequiredString(obj, 'providerRef', createParseError);
  const brand = readRequiredString(obj, 'brand', createParseError);
  const last4 = readRequiredString(obj, 'last4', createParseError);
  const expMonth = readRequiredInteger(obj, 'expMonth', createParseError);
  const expYear = readRequiredInteger(obj, 'expYear', createParseError);

  if (!/^\d{4}$/.test(last4)) {
    throw new ConsoleBillingError('invalid_body', 400, 'Field last4 must be 4 digits');
  }
  if (expMonth < 1 || expMonth > 12) {
    throw new ConsoleBillingError('invalid_body', 400, 'Field expMonth must be between 1 and 12');
  }
  if (expYear < 2000 || expYear > 9999) {
    throw new ConsoleBillingError('invalid_body', 400, 'Field expYear must be a 4-digit year');
  }

  return {
    providerRef,
    brand,
    last4,
    expMonth,
    expYear,
  };
}

export function parseStripeSetupIntentRequest(body: unknown): StripeSetupIntentRequest {
  if (body === undefined || body === null) return {};
  const obj = requireObject(body, createParseError);
  return {
    returnUrl: readOptionalString(obj, 'returnUrl'),
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

function parseOptionalNullableIsoDate(
  value: string | undefined,
  field: string,
): string | null | undefined {
  if (value === undefined) return undefined;
  if (value === '') return null;
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
  const planId = readOptionalString(obj, 'planId');
  validateHttpUrlOrThrow(successUrl, 'successUrl');
  validateHttpUrlOrThrow(cancelUrl, 'cancelUrl');
  return {
    successUrl,
    cancelUrl,
    planId,
  };
}

export function parseStripeCustomerPortalSessionRequest(
  body: unknown,
): StripeCustomerPortalSessionRequest {
  const obj = requireObject(body, createParseError);
  const returnUrl = readRequiredString(obj, 'returnUrl', createParseError);
  validateHttpUrlOrThrow(returnUrl, 'returnUrl');
  return {
    returnUrl,
  };
}

export function parseStripePaymentIntentRequest(body: unknown): StripePaymentIntentRequest {
  const obj = requireObject(body, createParseError);
  return {
    invoiceId: readRequiredString(obj, 'invoiceId', createParseError),
    paymentMethodId: readOptionalString(obj, 'paymentMethodId'),
  };
}

export function parseStripePaymentIntentReconcileRequest(
  body: unknown,
): StripePaymentIntentReconcileRequest {
  const obj = requireObject(body, createParseError);
  const providerStatus = readRequiredString(obj, 'providerStatus', createParseError).toUpperCase();
  const settledAmountMinorRaw = obj.settledAmountMinor;
  const sourceEventId = readOptionalString(obj, 'sourceEventId');
  const validStatuses = new Set(['ACTION_REQUIRED', 'PENDING', 'SUCCEEDED', 'FAILED', 'CANCELED']);
  if (!validStatuses.has(providerStatus)) {
    throw new ConsoleBillingError(
      'invalid_body',
      400,
      `Unsupported providerStatus: ${providerStatus}`,
    );
  }

  let settledAmountMinor: number | undefined;
  if (settledAmountMinorRaw !== undefined && settledAmountMinorRaw !== null) {
    settledAmountMinor =
      typeof settledAmountMinorRaw === 'number'
        ? settledAmountMinorRaw
        : Number(settledAmountMinorRaw);
    if (!Number.isInteger(settledAmountMinor) || settledAmountMinor < 0) {
      throw new ConsoleBillingError(
        'invalid_body',
        400,
        'Field settledAmountMinor must be an integer >= 0',
      );
    }
  }

  return {
    providerStatus: providerStatus as StripePaymentIntentReconcileRequest['providerStatus'],
    settledAmountMinor,
    sourceEventId,
  };
}

export function parseStripeWebhookEventRequest(body: unknown): StripeWebhookEventRequest {
  const obj = requireObject(body, createParseError);
  const eventId = readRequiredString(obj, 'eventId', createParseError);
  const eventTypeRaw = readOptionalString(obj, 'eventType');
  const eventType = eventTypeRaw ? eventTypeRaw.trim() : undefined;
  const providerRef = readOptionalString(obj, 'providerRef');
  const providerStatusRaw = readOptionalString(obj, 'providerStatus');
  const settledAmountMinorRaw = obj.settledAmountMinor;
  const orgId = readOptionalString(obj, 'orgId');
  const providerCustomerRef = readOptionalString(obj, 'providerCustomerRef');
  const providerSubscriptionRef = readOptionalString(obj, 'providerSubscriptionRef');
  const planId = readOptionalString(obj, 'planId');
  const planName = readOptionalString(obj, 'planName');
  const subscriptionStatusRaw = readOptionalString(obj, 'subscriptionStatus');
  const cancelAtPeriodEndRaw = obj.cancelAtPeriodEnd;
  const currentPeriodStartRaw = readOptionalString(obj, 'currentPeriodStart');
  const currentPeriodEndRaw = readOptionalString(obj, 'currentPeriodEnd');
  const cancelAtRaw = readOptionalString(obj, 'cancelAt');
  const canceledAtRaw = readOptionalString(obj, 'canceledAt');
  const invoiceId = readOptionalString(obj, 'invoiceId');
  const invoiceStatusRaw = readOptionalString(obj, 'invoiceStatus');
  const invoiceAmountDueMinorRaw = obj.invoiceAmountDueMinor;
  const invoiceAmountPaidMinorRaw = obj.invoiceAmountPaidMinor;

  let providerStatus: StripeWebhookEventRequest['providerStatus'] | undefined;
  const validStatuses = new Set(['ACTION_REQUIRED', 'PENDING', 'SUCCEEDED', 'FAILED', 'CANCELED']);
  if (providerStatusRaw !== undefined) {
    const normalized = providerStatusRaw.toUpperCase();
    if (!validStatuses.has(normalized)) {
      throw new ConsoleBillingError(
        'invalid_body',
        400,
        `Unsupported providerStatus: ${normalized}`,
      );
    }
    providerStatus = normalized as StripeWebhookEventRequest['providerStatus'];
  }

  const normalizedEventType = eventType || '';
  const isPaymentIntentProjection =
    !normalizedEventType || normalizedEventType.startsWith('payment_intent.');
  const isSupportedProjectionType =
    isPaymentIntentProjection ||
    normalizedEventType === 'checkout.session.completed' ||
    normalizedEventType.startsWith('customer.subscription.') ||
    normalizedEventType.startsWith('invoice.');
  if (!isSupportedProjectionType) {
    throw new ConsoleBillingError(
      'invalid_body',
      400,
      `Unsupported Stripe eventType: ${normalizedEventType || '(empty)'}`,
    );
  }
  if (isPaymentIntentProjection) {
    if (!providerRef) {
      throw new ConsoleBillingError(
        'invalid_body',
        400,
        'Field providerRef is required for payment-intent webhook projections',
      );
    }
    if (!providerStatus) {
      throw new ConsoleBillingError(
        'invalid_body',
        400,
        'Field providerStatus is required for payment-intent webhook projections',
      );
    }
  }
  if (!isPaymentIntentProjection && !orgId) {
    throw new ConsoleBillingError(
      'invalid_body',
      400,
      'Field orgId is required for non-payment-intent Stripe webhook projections',
    );
  }
  if (cancelAtPeriodEndRaw !== undefined && typeof cancelAtPeriodEndRaw !== 'boolean') {
    throw new ConsoleBillingError(
      'invalid_body',
      400,
      'Field cancelAtPeriodEnd must be a boolean when provided',
    );
  }

  let subscriptionStatus: StripeWebhookEventRequest['subscriptionStatus'] | undefined;
  if (subscriptionStatusRaw !== undefined) {
    const normalized = subscriptionStatusRaw.toUpperCase();
    const validSubscriptionStatuses = new Set(['ACTIVE', 'PAST_DUE', 'CANCELED']);
    if (!validSubscriptionStatuses.has(normalized)) {
      throw new ConsoleBillingError(
        'invalid_body',
        400,
        `Unsupported subscriptionStatus: ${normalized}`,
      );
    }
    subscriptionStatus = normalized as StripeWebhookEventRequest['subscriptionStatus'];
  }

  let invoiceStatus: StripeWebhookEventRequest['invoiceStatus'] | undefined;
  if (invoiceStatusRaw !== undefined) {
    const normalized = invoiceStatusRaw.toUpperCase();
    const validInvoiceStatuses = new Set(['OPEN', 'PAID', 'VOID', 'UNCOLLECTIBLE']);
    if (!validInvoiceStatuses.has(normalized)) {
      throw new ConsoleBillingError(
        'invalid_body',
        400,
        `Unsupported invoiceStatus: ${normalized}`,
      );
    }
    invoiceStatus = normalized as StripeWebhookEventRequest['invoiceStatus'];
  }

  let settledAmountMinor: number | undefined;
  if (settledAmountMinorRaw !== undefined && settledAmountMinorRaw !== null) {
    settledAmountMinor =
      typeof settledAmountMinorRaw === 'number'
        ? settledAmountMinorRaw
        : Number(settledAmountMinorRaw);
    if (!Number.isInteger(settledAmountMinor) || settledAmountMinor < 0) {
      throw new ConsoleBillingError(
        'invalid_body',
        400,
        'Field settledAmountMinor must be an integer >= 0',
      );
    }
  }

  let invoiceAmountDueMinor: number | undefined;
  if (invoiceAmountDueMinorRaw !== undefined && invoiceAmountDueMinorRaw !== null) {
    invoiceAmountDueMinor =
      typeof invoiceAmountDueMinorRaw === 'number'
        ? invoiceAmountDueMinorRaw
        : Number(invoiceAmountDueMinorRaw);
    if (!Number.isInteger(invoiceAmountDueMinor) || invoiceAmountDueMinor < 0) {
      throw new ConsoleBillingError(
        'invalid_body',
        400,
        'Field invoiceAmountDueMinor must be an integer >= 0',
      );
    }
  }

  let invoiceAmountPaidMinor: number | undefined;
  if (invoiceAmountPaidMinorRaw !== undefined && invoiceAmountPaidMinorRaw !== null) {
    invoiceAmountPaidMinor =
      typeof invoiceAmountPaidMinorRaw === 'number'
        ? invoiceAmountPaidMinorRaw
        : Number(invoiceAmountPaidMinorRaw);
    if (!Number.isInteger(invoiceAmountPaidMinor) || invoiceAmountPaidMinor < 0) {
      throw new ConsoleBillingError(
        'invalid_body',
        400,
        'Field invoiceAmountPaidMinor must be an integer >= 0',
      );
    }
  }

  const currentPeriodStart = parseOptionalIsoDate(currentPeriodStartRaw, 'currentPeriodStart');
  const currentPeriodEnd = parseOptionalIsoDate(currentPeriodEndRaw, 'currentPeriodEnd');
  const cancelAt = parseOptionalNullableIsoDate(cancelAtRaw, 'cancelAt');
  const canceledAt = parseOptionalNullableIsoDate(canceledAtRaw, 'canceledAt');

  return {
    eventId,
    eventType: normalizedEventType || undefined,
    providerRef,
    providerStatus,
    settledAmountMinor,
    orgId,
    providerCustomerRef,
    providerSubscriptionRef,
    planId,
    planName,
    subscriptionStatus,
    cancelAtPeriodEnd:
      cancelAtPeriodEndRaw === undefined ? undefined : Boolean(cancelAtPeriodEndRaw),
    currentPeriodStart,
    currentPeriodEnd,
    cancelAt: cancelAt === undefined ? undefined : cancelAt,
    canceledAt: canceledAt === undefined ? undefined : canceledAt,
    invoiceId,
    invoiceStatus,
    invoiceAmountDueMinor,
    invoiceAmountPaidMinor,
  };
}

export function parseStablecoinQuoteRequest(body: unknown): StablecoinQuoteRequest {
  const obj = requireObject(body, createParseError);
  const invoiceId = readRequiredString(obj, 'invoiceId', createParseError);
  const asset = readRequiredString(obj, 'asset', createParseError);
  const chain = readRequiredString(obj, 'chain', createParseError);

  if (!isStablecoinAssetSymbol(asset)) {
    throw new ConsoleBillingError('invalid_body', 400, `Unsupported stablecoin asset: ${asset}`);
  }
  if (!isStablecoinSettlementChain(chain)) {
    throw new ConsoleBillingError('invalid_body', 400, `Unsupported settlement chain: ${chain}`);
  }

  return {
    invoiceId,
    asset,
    chain,
  };
}

export function parseStablecoinPaymentIntentRequest(body: unknown): StablecoinPaymentIntentRequest {
  const obj = requireObject(body, createParseError);
  return {
    invoiceId: readRequiredString(obj, 'invoiceId', createParseError),
    quoteId: readRequiredString(obj, 'quoteId', createParseError),
  };
}

export function parseStablecoinPaymentIntentReconcileRequest(
  body: unknown,
): StablecoinPaymentIntentReconcileRequest {
  const obj = requireObject(body, createParseError);
  const observedAmountMinor = readRequiredInteger(obj, 'observedAmountMinor', createParseError);
  const observedConfirmations = readRequiredInteger(obj, 'observedConfirmations', createParseError);
  const confirmationTimedOutRaw = obj.confirmationTimedOut;
  const sourceEventId = readOptionalString(obj, 'sourceEventId');

  if (observedAmountMinor < 0) {
    throw new ConsoleBillingError('invalid_body', 400, 'Field observedAmountMinor must be >= 0');
  }
  if (observedConfirmations < 0) {
    throw new ConsoleBillingError('invalid_body', 400, 'Field observedConfirmations must be >= 0');
  }
  if (confirmationTimedOutRaw !== undefined && typeof confirmationTimedOutRaw !== 'boolean') {
    throw new ConsoleBillingError(
      'invalid_body',
      400,
      'Field confirmationTimedOut must be a boolean when provided',
    );
  }

  return {
    observedAmountMinor,
    observedConfirmations,
    confirmationTimedOut: Boolean(confirmationTimedOutRaw),
    sourceEventId,
  };
}

export function parseBillingUsageEventRequest(body: unknown): BillingUsageEventRequest {
  const obj = requireObject(body, createParseError);
  const walletId = readRequiredString(obj, 'walletId', createParseError);
  const action = readRequiredString(obj, 'action', createParseError).toLowerCase();
  const succeededRaw = obj.succeeded;
  const isSimulationRaw = obj.isSimulation;
  const isInternalRetryRaw = obj.isInternalRetry;
  const occurredAt = readOptionalString(obj, 'occurredAt');
  const sourceEventId = readOptionalString(obj, 'sourceEventId');

  const validActions = new Set(['transfer', 'swap', 'approve', 'contract_call', 'wallet_created']);
  if (!validActions.has(action)) {
    throw new ConsoleBillingError('invalid_body', 400, `Unsupported usage action: ${action}`);
  }
  if (typeof succeededRaw !== 'boolean') {
    throw new ConsoleBillingError('invalid_body', 400, 'Field succeeded must be a boolean');
  }
  if (isSimulationRaw !== undefined && typeof isSimulationRaw !== 'boolean') {
    throw new ConsoleBillingError(
      'invalid_body',
      400,
      'Field isSimulation must be a boolean when provided',
    );
  }
  if (isInternalRetryRaw !== undefined && typeof isInternalRetryRaw !== 'boolean') {
    throw new ConsoleBillingError(
      'invalid_body',
      400,
      'Field isInternalRetry must be a boolean when provided',
    );
  }
  if (occurredAt !== undefined) {
    const parsed = Date.parse(occurredAt);
    if (!Number.isFinite(parsed)) {
      throw new ConsoleBillingError(
        'invalid_body',
        400,
        'Field occurredAt must be a valid ISO-8601 datetime',
      );
    }
  }

  return {
    walletId,
    action: action as BillingUsageEventRequest['action'],
    succeeded: succeededRaw,
    isSimulation: Boolean(isSimulationRaw),
    isInternalRetry: Boolean(isInternalRetryRaw),
    occurredAt,
    sourceEventId,
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
  if (month < 1 || month > 12) {
    throw new ConsoleBillingError(
      'invalid_body',
      400,
      'Field periodMonthUtc month must be between 01 and 12',
    );
  }
  return { periodMonthUtc };
}
