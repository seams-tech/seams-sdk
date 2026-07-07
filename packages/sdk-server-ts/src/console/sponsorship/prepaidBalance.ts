import type { ConsoleBillingContext, ConsoleBillingService } from '../billing/service';
import type {
  ConsoleBillingPrepaidReservationContext,
  ConsoleBillingPrepaidReservationService,
} from '../billingPrepaidReservations/service';
import { isConsoleBillingPrepaidReservationError } from '../billingPrepaidReservations/errors';
import type {
  ConsoleSponsoredCallChainFamily,
  ConsoleSponsoredCallExecutorKind,
  ConsoleSponsoredCallFeeUnit,
  ConsoleSponsoredCallIntentKind,
  ConsoleSponsoredCallReceiptStatus,
} from '../sponsoredCalls/types';
import type {
  SponsorshipSpendPricingQuote,
  SponsorshipSpendPricingService,
} from './spendCaps';

export class SponsorshipPrepaidBalanceEnforcementError extends Error {
  readonly code: string;

  readonly status: number;

  readonly details?: Record<string, unknown>;

  constructor(code: string, status: number, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = 'SponsorshipPrepaidBalanceEnforcementError';
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

export function isSponsorshipPrepaidBalanceEnforcementError(
  error: unknown,
): error is SponsorshipPrepaidBalanceEnforcementError {
  return error instanceof SponsorshipPrepaidBalanceEnforcementError;
}

export interface SponsoredPrepaidReservationHandle {
  sourceEventId: string;
  estimatedSpendMinor: number;
  estimatedPricingVersion: string;
}

export interface SponsoredPrepaidReservationSettlement {
  reservationId: string | null;
  settledSpendMinor: number;
  pricingVersion: string;
  usedEstimatedFallback: boolean;
  released: boolean;
  settledAt: string;
}

export interface SponsoredPrepaidSettlementQuote {
  settledSpendMinor: number;
  pricingVersion: string;
  usedEstimatedFallback: boolean;
  released: boolean;
}

function assertNeverReceiptStatus(status: never): never {
  throw new SponsorshipPrepaidBalanceEnforcementError(
    'sponsorship_prepaid_balance_invalid',
    500,
    `Unhandled sponsored-call receipt status: ${status}`,
  );
}

function toNonNegativeInteger(value: unknown, label: string): number {
  const parsed = typeof value === 'number' ? value : Number(value);
  if (!Number.isInteger(parsed) || parsed < 0) {
    throw new SponsorshipPrepaidBalanceEnforcementError(
      'sponsorship_prepaid_balance_invalid',
      500,
      `${label} must be a non-negative integer`,
    );
  }
  return parsed;
}

function normalizePricingVersion(value: unknown): string {
  return String(value || '').trim() || 'unknown';
}

function mapPrepaidReservationError(error: unknown): never {
  if (isConsoleBillingPrepaidReservationError(error)) {
    throw new SponsorshipPrepaidBalanceEnforcementError(
      error.code,
      error.status,
      error.message,
      error.details,
    );
  }
  throw error;
}

function shouldUseEstimatedFallback(receiptStatus: ConsoleSponsoredCallReceiptStatus): boolean {
  return receiptStatus === 'success' || receiptStatus === 'reverted';
}

function shouldReleaseWithoutFinalizedSpend(input: {
  receiptStatus: ConsoleSponsoredCallReceiptStatus;
  txOrExecutionRef: string | null;
}): boolean {
  switch (input.receiptStatus) {
    case 'rpc_rejected':
      return true;
    case 'broadcast_failed':
      return !input.txOrExecutionRef;
    case 'success':
    case 'reverted':
      return false;
    default:
      return assertNeverReceiptStatus(input.receiptStatus);
  }
}

function quoteToReservationHandle(input: {
  sourceEventId: string;
  quote: SponsorshipSpendPricingQuote;
}): SponsoredPrepaidReservationHandle {
  return {
    sourceEventId: input.sourceEventId,
    estimatedSpendMinor: toNonNegativeInteger(input.quote.spendMinor, 'estimated spendMinor'),
    estimatedPricingVersion: normalizePricingVersion(input.quote.pricingVersion),
  };
}

export async function reserveSponsoredPrepaidBalance(input: {
  billing: ConsoleBillingService | null | undefined;
  prepaidReservations: ConsoleBillingPrepaidReservationService | null | undefined;
  pricing: SponsorshipSpendPricingService | null | undefined;
  ctx: ConsoleBillingContext & ConsoleBillingPrepaidReservationContext;
  chainFamily: ConsoleSponsoredCallChainFamily;
  intentKind: ConsoleSponsoredCallIntentKind;
  executorKind: ConsoleSponsoredCallExecutorKind;
  environmentId: string;
  policyId: string;
  accountRef: string | null;
  targetRef: string;
  chainId: number;
  sourceEventId: string;
  requestDetails: Record<string, unknown>;
}): Promise<SponsoredPrepaidReservationHandle> {
  if (!input.billing) {
    throw new SponsorshipPrepaidBalanceEnforcementError(
      'sponsorship_prepaid_balance_unavailable',
      503,
      'Sponsored prepaid balance enforcement is not configured on this server',
    );
  }
  if (!input.prepaidReservations) {
    throw new SponsorshipPrepaidBalanceEnforcementError(
      'sponsorship_prepaid_balance_unavailable',
      503,
      'Sponsored prepaid balance reservations are not configured on this server',
    );
  }
  if (!input.pricing) {
    throw new SponsorshipPrepaidBalanceEnforcementError(
      'sponsorship_pricing_unavailable',
      503,
      'Sponsored spend pricing is not configured on this server',
    );
  }

  const overview = await input.billing.getOverview(input.ctx);
  const quote = await input.pricing.estimateSponsoredExecutionSpend({
    chainFamily: input.chainFamily,
    intentKind: input.intentKind,
    executorKind: input.executorKind,
    environmentId: input.environmentId,
    policyId: input.policyId,
    accountRef: input.accountRef,
    targetRef: input.targetRef,
    chainId: input.chainId,
    requestDetails: input.requestDetails,
  });
  const handle = quoteToReservationHandle({
    sourceEventId: input.sourceEventId,
    quote,
  });

  try {
    await input.prepaidReservations.reserve(input.ctx, {
      sourceEventId: handle.sourceEventId,
      environmentId: input.environmentId,
      policyId: input.policyId,
      postedBalanceMinor: overview.creditBalanceMinor,
      estimatedSpendMinor: handle.estimatedSpendMinor,
    });
  } catch (error: unknown) {
    mapPrepaidReservationError(error);
  }

  return handle;
}

export async function resolveSponsoredPrepaidSettlementQuote(input: {
  reservation: SponsoredPrepaidReservationHandle | null;
  pricing: SponsorshipSpendPricingService | null | undefined;
  chainFamily: ConsoleSponsoredCallChainFamily;
  intentKind: ConsoleSponsoredCallIntentKind;
  executorKind: ConsoleSponsoredCallExecutorKind;
  environmentId: string;
  policyId: string;
  accountRef: string | null;
  targetRef: string;
  chainId: number;
  txOrExecutionRef: string | null;
  receiptStatus: ConsoleSponsoredCallReceiptStatus;
  feeUnit: ConsoleSponsoredCallFeeUnit;
  feeAmount: string;
  requestDetails: Record<string, unknown>;
}): Promise<SponsoredPrepaidSettlementQuote | null> {
  if (!input.reservation) return null;
  if (!input.pricing) {
    throw new SponsorshipPrepaidBalanceEnforcementError(
      'sponsorship_pricing_unavailable',
      503,
      'Sponsored spend pricing is not configured on this server',
    );
  }
  if (
    shouldReleaseWithoutFinalizedSpend({
      receiptStatus: input.receiptStatus,
      txOrExecutionRef: input.txOrExecutionRef,
    })
  ) {
    return {
      settledSpendMinor: 0,
      pricingVersion: input.reservation.estimatedPricingVersion,
      usedEstimatedFallback: false,
      released: true,
    };
  }

  let settledSpendMinor = input.reservation.estimatedSpendMinor;
  let pricingVersion = input.reservation.estimatedPricingVersion;
  let usedEstimatedFallback = false;

  try {
    const finalized = await input.pricing.finalizeSponsoredExecutionSpend({
      chainFamily: input.chainFamily,
      intentKind: input.intentKind,
      executorKind: input.executorKind,
      environmentId: input.environmentId,
      policyId: input.policyId,
      accountRef: input.accountRef,
      targetRef: input.targetRef,
      chainId: input.chainId,
      txOrExecutionRef: input.txOrExecutionRef,
      receiptStatus: input.receiptStatus,
      feeUnit: input.feeUnit,
      feeAmount: input.feeAmount,
      requestDetails: input.requestDetails,
      estimatedSpendMinor: input.reservation.estimatedSpendMinor,
      estimatedPricingVersion: input.reservation.estimatedPricingVersion,
    });
    settledSpendMinor = toNonNegativeInteger(finalized.spendMinor, 'finalized spendMinor');
    pricingVersion = normalizePricingVersion(finalized.pricingVersion);
  } catch {
    if (shouldUseEstimatedFallback(input.receiptStatus)) {
      settledSpendMinor = input.reservation.estimatedSpendMinor;
      pricingVersion = input.reservation.estimatedPricingVersion;
      usedEstimatedFallback = true;
    } else {
      settledSpendMinor = 0;
      pricingVersion = input.reservation.estimatedPricingVersion;
    }
  }

  if (settledSpendMinor <= 0) {
    return {
      settledSpendMinor: 0,
      pricingVersion,
      usedEstimatedFallback,
      released: true,
    };
  }

  return {
    settledSpendMinor,
    pricingVersion,
    usedEstimatedFallback,
    released: false,
  };
}

export async function settleSponsoredPrepaidBalance(input: {
  reservation: SponsoredPrepaidReservationHandle | null;
  prepaidReservations: ConsoleBillingPrepaidReservationService | null | undefined;
  pricing: SponsorshipSpendPricingService | null | undefined;
  ctx: ConsoleBillingPrepaidReservationContext;
  chainFamily: ConsoleSponsoredCallChainFamily;
  intentKind: ConsoleSponsoredCallIntentKind;
  executorKind: ConsoleSponsoredCallExecutorKind;
  environmentId: string;
  policyId: string;
  accountRef: string | null;
  targetRef: string;
  chainId: number;
  txOrExecutionRef: string | null;
  receiptStatus: ConsoleSponsoredCallReceiptStatus;
  feeUnit: ConsoleSponsoredCallFeeUnit;
  feeAmount: string;
  requestDetails: Record<string, unknown>;
}): Promise<SponsoredPrepaidReservationSettlement | null> {
  if (!input.reservation) return null;
  if (!input.prepaidReservations) {
    throw new SponsorshipPrepaidBalanceEnforcementError(
      'sponsorship_prepaid_balance_unavailable',
      503,
      'Sponsored prepaid balance reservations are not configured on this server',
    );
  }
  const quote = await resolveSponsoredPrepaidSettlementQuote(input);
  if (!quote) return null;
  const settledAt = new Date().toISOString();
  if (quote.released) {
    let releasedReservationId: string | null = null;
    try {
      const released = await input.prepaidReservations.release(input.ctx, {
        sourceEventId: input.reservation.sourceEventId,
      });
      releasedReservationId = released?.reservation.id || null;
    } catch (error: unknown) {
      mapPrepaidReservationError(error);
    }
    return {
      reservationId: releasedReservationId,
      settledSpendMinor: 0,
      pricingVersion: quote.pricingVersion,
      usedEstimatedFallback: quote.usedEstimatedFallback,
      released: true,
      settledAt,
    };
  }
  let settledReservationId: string | null = null;
  try {
    const settled = await input.prepaidReservations.settle(input.ctx, {
      sourceEventId: input.reservation.sourceEventId,
      settledSpendMinor: quote.settledSpendMinor,
      txOrExecutionRef: input.txOrExecutionRef,
      pricingVersion: quote.pricingVersion,
    });
    settledReservationId = settled?.reservation.id || null;
  } catch (error: unknown) {
    mapPrepaidReservationError(error);
  }
  return {
    reservationId: settledReservationId,
    settledSpendMinor: quote.settledSpendMinor,
    pricingVersion: quote.pricingVersion,
    usedEstimatedFallback: quote.usedEstimatedFallback,
    released: false,
    settledAt,
  };
}
