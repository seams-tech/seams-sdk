import { ConsoleBillingError } from './errors';
import { isStablecoinAssetSymbol, isStablecoinSettlementChain } from './stablecoinAssets';
import {
  readOptionalStringField as readOptionalString,
  readRequiredIntegerField as readRequiredInteger,
  readRequiredStringField as readRequiredString,
  requireBodyObject as requireObject,
} from '../shared/requestParse';
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

function createParseError(code: string, status: number, message: string): ConsoleBillingError {
  return new ConsoleBillingError(code, status, message);
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
  const providerRef = readRequiredString(obj, 'providerRef', createParseError);
  const providerStatus = readRequiredString(obj, 'providerStatus', createParseError).toUpperCase();
  const settledAmountMinorRaw = obj.settledAmountMinor;
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
    eventId,
    providerRef,
    providerStatus: providerStatus as StripeWebhookEventRequest['providerStatus'],
    settledAmountMinor,
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
  const observedConfirmations = readRequiredInteger(
    obj,
    'observedConfirmations',
    createParseError,
  );
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
