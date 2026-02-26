import { ConsoleBillingError } from './errors';
import {
  isStablecoinAssetSymbol,
  isStablecoinSettlementChain,
} from './stablecoinAssets';
import type {
  AddCardPaymentMethodRequest,
  BillingUsageEventRequest,
  GenerateMonthlyInvoiceRequest,
  StablecoinPaymentIntentReconcileRequest,
  StablecoinPaymentIntentRequest,
  StablecoinQuoteRequest,
  StripePaymentIntentReconcileRequest,
  StripePaymentIntentRequest,
  StripeWebhookEventRequest,
  StripeSetupIntentRequest,
} from './types';

function requireObject(body: unknown): Record<string, unknown> {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new ConsoleBillingError('invalid_body', 400, 'Expected JSON object request body');
  }
  return body as Record<string, unknown>;
}

function readRequiredString(body: Record<string, unknown>, key: string): string {
  const value = String(body[key] ?? '').trim();
  if (!value) {
    throw new ConsoleBillingError('invalid_body', 400, `Missing required field: ${key}`);
  }
  return value;
}

function readOptionalString(body: Record<string, unknown>, key: string): string | undefined {
  const raw = body[key];
  if (raw === undefined || raw === null) return undefined;
  const value = String(raw).trim();
  return value || undefined;
}

function readRequiredInteger(body: Record<string, unknown>, key: string): number {
  const raw = body[key];
  const n = typeof raw === 'number' ? raw : Number(raw);
  if (!Number.isInteger(n)) {
    throw new ConsoleBillingError('invalid_body', 400, `Field ${key} must be an integer`);
  }
  return n;
}

export function parseAddCardPaymentMethodRequest(body: unknown): AddCardPaymentMethodRequest {
  const obj = requireObject(body);
  const providerRef = readRequiredString(obj, 'providerRef');
  const brand = readRequiredString(obj, 'brand');
  const last4 = readRequiredString(obj, 'last4');
  const expMonth = readRequiredInteger(obj, 'expMonth');
  const expYear = readRequiredInteger(obj, 'expYear');

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
  const obj = requireObject(body);
  return {
    returnUrl: readOptionalString(obj, 'returnUrl'),
  };
}

export function parseStripePaymentIntentRequest(body: unknown): StripePaymentIntentRequest {
  const obj = requireObject(body);
  return {
    invoiceId: readRequiredString(obj, 'invoiceId'),
    paymentMethodId: readOptionalString(obj, 'paymentMethodId'),
  };
}

export function parseStripePaymentIntentReconcileRequest(body: unknown): StripePaymentIntentReconcileRequest {
  const obj = requireObject(body);
  const providerStatus = readRequiredString(obj, 'providerStatus').toUpperCase();
  const settledAmountMinorRaw = obj.settledAmountMinor;
  const sourceEventId = readOptionalString(obj, 'sourceEventId');
  const validStatuses = new Set([
    'ACTION_REQUIRED',
    'PENDING',
    'SUCCEEDED',
    'FAILED',
    'CANCELED',
  ]);
  if (!validStatuses.has(providerStatus)) {
    throw new ConsoleBillingError('invalid_body', 400, `Unsupported providerStatus: ${providerStatus}`);
  }

  let settledAmountMinor: number | undefined;
  if (settledAmountMinorRaw !== undefined && settledAmountMinorRaw !== null) {
    settledAmountMinor = typeof settledAmountMinorRaw === 'number'
      ? settledAmountMinorRaw
      : Number(settledAmountMinorRaw);
    if (!Number.isInteger(settledAmountMinor) || settledAmountMinor < 0) {
      throw new ConsoleBillingError('invalid_body', 400, 'Field settledAmountMinor must be an integer >= 0');
    }
  }

  return {
    providerStatus: providerStatus as StripePaymentIntentReconcileRequest['providerStatus'],
    settledAmountMinor,
    sourceEventId,
  };
}

export function parseStripeWebhookEventRequest(body: unknown): StripeWebhookEventRequest {
  const obj = requireObject(body);
  const eventId = readRequiredString(obj, 'eventId');
  const providerRef = readRequiredString(obj, 'providerRef');
  const providerStatus = readRequiredString(obj, 'providerStatus').toUpperCase();
  const settledAmountMinorRaw = obj.settledAmountMinor;
  const validStatuses = new Set([
    'ACTION_REQUIRED',
    'PENDING',
    'SUCCEEDED',
    'FAILED',
    'CANCELED',
  ]);
  if (!validStatuses.has(providerStatus)) {
    throw new ConsoleBillingError('invalid_body', 400, `Unsupported providerStatus: ${providerStatus}`);
  }

  let settledAmountMinor: number | undefined;
  if (settledAmountMinorRaw !== undefined && settledAmountMinorRaw !== null) {
    settledAmountMinor = typeof settledAmountMinorRaw === 'number'
      ? settledAmountMinorRaw
      : Number(settledAmountMinorRaw);
    if (!Number.isInteger(settledAmountMinor) || settledAmountMinor < 0) {
      throw new ConsoleBillingError('invalid_body', 400, 'Field settledAmountMinor must be an integer >= 0');
    }
  }

  return {
    eventId,
    providerRef,
    providerStatus: providerStatus as StripeWebhookEventRequest['providerStatus'],
    settledAmountMinor,
  };
}

export function parseStablecoinQuoteRequest(body: unknown): StablecoinQuoteRequest {
  const obj = requireObject(body);
  const invoiceId = readRequiredString(obj, 'invoiceId');
  const asset = readRequiredString(obj, 'asset');
  const chain = readRequiredString(obj, 'chain');

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
  const obj = requireObject(body);
  return {
    invoiceId: readRequiredString(obj, 'invoiceId'),
    quoteId: readRequiredString(obj, 'quoteId'),
  };
}

export function parseStablecoinPaymentIntentReconcileRequest(body: unknown): StablecoinPaymentIntentReconcileRequest {
  const obj = requireObject(body);
  const observedAmountMinor = readRequiredInteger(obj, 'observedAmountMinor');
  const observedConfirmations = readRequiredInteger(obj, 'observedConfirmations');
  const confirmationTimedOutRaw = obj.confirmationTimedOut;
  const sourceEventId = readOptionalString(obj, 'sourceEventId');

  if (observedAmountMinor < 0) {
    throw new ConsoleBillingError('invalid_body', 400, 'Field observedAmountMinor must be >= 0');
  }
  if (observedConfirmations < 0) {
    throw new ConsoleBillingError('invalid_body', 400, 'Field observedConfirmations must be >= 0');
  }
  if (
    confirmationTimedOutRaw !== undefined
    && typeof confirmationTimedOutRaw !== 'boolean'
  ) {
    throw new ConsoleBillingError('invalid_body', 400, 'Field confirmationTimedOut must be a boolean when provided');
  }

  return {
    observedAmountMinor,
    observedConfirmations,
    confirmationTimedOut: Boolean(confirmationTimedOutRaw),
    sourceEventId,
  };
}

export function parseBillingUsageEventRequest(body: unknown): BillingUsageEventRequest {
  const obj = requireObject(body);
  const walletId = readRequiredString(obj, 'walletId');
  const action = readRequiredString(obj, 'action').toLowerCase();
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
    throw new ConsoleBillingError('invalid_body', 400, 'Field isSimulation must be a boolean when provided');
  }
  if (isInternalRetryRaw !== undefined && typeof isInternalRetryRaw !== 'boolean') {
    throw new ConsoleBillingError('invalid_body', 400, 'Field isInternalRetry must be a boolean when provided');
  }
  if (occurredAt !== undefined) {
    const parsed = Date.parse(occurredAt);
    if (!Number.isFinite(parsed)) {
      throw new ConsoleBillingError('invalid_body', 400, 'Field occurredAt must be a valid ISO-8601 datetime');
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
  const obj = requireObject(body);
  const periodMonthUtc = readRequiredString(obj, 'periodMonthUtc');
  if (!/^\d{4}-\d{2}$/.test(periodMonthUtc)) {
    throw new ConsoleBillingError('invalid_body', 400, 'Field periodMonthUtc must be in YYYY-MM format');
  }
  const month = Number(periodMonthUtc.slice(5, 7));
  if (month < 1 || month > 12) {
    throw new ConsoleBillingError('invalid_body', 400, 'Field periodMonthUtc month must be between 01 and 12');
  }
  return { periodMonthUtc };
}
