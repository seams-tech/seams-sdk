import type {
  ConsoleSponsorshipSpendCapContext,
  ConsoleSponsorshipSpendCapService,
} from '../console/sponsorshipSpendCaps/service';
import type { ConsoleSponsorshipSpendCapPeriod } from '../console/sponsorshipSpendCaps/types';
import { isConsoleSponsorshipSpendCapError } from '../console/sponsorshipSpendCaps/errors';
import type {
  ConsoleSponsoredCallChainFamily,
  ConsoleSponsoredCallExecutorKind,
  ConsoleSponsoredCallFeeUnit,
  ConsoleSponsoredCallIntentKind,
  ConsoleSponsoredCallReceiptStatus,
} from '../console/sponsoredCalls/types';
import type { ConsoleGasSponsorshipPolicySpendCap } from '../console/policies/types';

export class SponsorshipSpendCapEnforcementError extends Error {
  readonly code: string;

  readonly status: number;

  readonly details?: Record<string, unknown>;

  constructor(code: string, status: number, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = 'SponsorshipSpendCapEnforcementError';
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

export function isSponsorshipSpendCapEnforcementError(
  error: unknown,
): error is SponsorshipSpendCapEnforcementError {
  return error instanceof SponsorshipSpendCapEnforcementError;
}

export interface SponsorshipSpendPricingQuote {
  spendMinor: number;
  pricingVersion: string;
}

export interface SponsorshipSpendPricingEstimateInput {
  chainFamily: ConsoleSponsoredCallChainFamily;
  intentKind: ConsoleSponsoredCallIntentKind;
  executorKind: ConsoleSponsoredCallExecutorKind;
  environmentId: string;
  policyId: string;
  accountRef: string | null;
  targetRef: string;
  chainId: number;
  requestDetails: Record<string, unknown>;
}

export interface SponsorshipSpendPricingFinalizeInput {
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
  estimatedSpendMinor: number;
  estimatedPricingVersion: string;
}

export interface SponsorshipSpendPricingService {
  estimateSponsoredExecutionSpend(
    input: SponsorshipSpendPricingEstimateInput,
  ): Promise<SponsorshipSpendPricingQuote>;
  finalizeSponsoredExecutionSpend(
    input: SponsorshipSpendPricingFinalizeInput,
  ): Promise<SponsorshipSpendPricingQuote>;
}

export interface SponsorshipSpendCapReservationHandle {
  sourceEventId: string;
  estimatedSpendMinor: number;
  estimatedPricingVersion: string;
  capMinor: number;
  mode: Exclude<ConsoleGasSponsorshipPolicySpendCap['mode'], 'NONE'>;
  period: ConsoleSponsorshipSpendCapPeriod;
}

export interface SponsorshipSpendCapSettlement {
  settledSpendMinor: number;
  pricingVersion: string;
  usedEstimatedFallback: boolean;
}

function toNonNegativeInteger(value: unknown, label: string): number {
  const parsed = typeof value === 'number' ? value : Number(value);
  if (!Number.isInteger(parsed) || parsed < 0) {
    throw new SponsorshipSpendCapEnforcementError(
      'sponsorship_pricing_invalid',
      500,
      `${label} must be a non-negative integer`,
    );
  }
  return parsed;
}

function normalizePricingVersion(value: unknown): string {
  return String(value || '').trim() || 'unknown';
}

function requireConfiguredChainCap(input: {
  spendCap: ConsoleGasSponsorshipPolicySpendCap;
  chainId: number;
}): { capMinor: number; mode: Exclude<ConsoleGasSponsorshipPolicySpendCap['mode'], 'NONE'> } {
  const { spendCap, chainId } = input;
  if (spendCap.mode !== 'CHAIN_TOTAL' && spendCap.mode !== 'WALLET_CHAIN_TOTAL') {
    throw new SponsorshipSpendCapEnforcementError(
      'sponsorship_spend_cap_misconfigured',
      500,
      'Spend cap mode is invalid for reservation enforcement',
    );
  }
  const chainCap = spendCap.capsByChain.find((entry) => entry.chainId === chainId) || null;
  if (!chainCap) {
    throw new SponsorshipSpendCapEnforcementError(
      'sponsorship_spend_cap_misconfigured',
      500,
      `Spend cap is not configured for chain ${chainId}`,
    );
  }
  return {
    capMinor: toNonNegativeInteger(chainCap.capMinor, 'capMinor'),
    mode: spendCap.mode,
  };
}

function mapReservationError(error: unknown): never {
  if (isConsoleSponsorshipSpendCapError(error)) {
    throw new SponsorshipSpendCapEnforcementError(
      error.code,
      error.status,
      error.message,
      error.details,
    );
  }
  throw error;
}

export function buildSponsoredSpendCapSourceEventId(input: {
  chainFamily: ConsoleSponsoredCallChainFamily;
  intentKind: ConsoleSponsoredCallIntentKind;
  idempotencyKey: string;
}): string {
  return `${input.chainFamily}:${input.intentKind}:${String(input.idempotencyKey || '').trim()}`;
}

export async function reserveSponsoredSpendCap(input: {
  spendCap: ConsoleGasSponsorshipPolicySpendCap;
  spendCaps: ConsoleSponsorshipSpendCapService | null | undefined;
  pricing: SponsorshipSpendPricingService | null | undefined;
  ctx: ConsoleSponsorshipSpendCapContext;
  chainFamily: ConsoleSponsoredCallChainFamily;
  intentKind: ConsoleSponsoredCallIntentKind;
  executorKind: ConsoleSponsoredCallExecutorKind;
  environmentId: string;
  policyId: string;
  accountRef: string | null;
  targetRef: string;
  chainId: number | null | undefined;
  sourceEventId: string;
  requestDetails: Record<string, unknown>;
}): Promise<SponsorshipSpendCapReservationHandle | null> {
  if (input.spendCap.mode === 'NONE') return null;
  if (!input.spendCaps) {
    throw new SponsorshipSpendCapEnforcementError(
      'sponsorship_spend_caps_unavailable',
      503,
      'Sponsored spend-cap enforcement is not configured on this server',
    );
  }
  if (!input.pricing) {
    throw new SponsorshipSpendCapEnforcementError(
      'sponsorship_pricing_unavailable',
      503,
      'Sponsored spend pricing is not configured on this server',
    );
  }
  const chainId = Number(input.chainId);
  if (!Number.isInteger(chainId) || chainId <= 0) {
    throw new SponsorshipSpendCapEnforcementError(
      'sponsorship_spend_cap_misconfigured',
      500,
      'Spend-cap enforcement requires a positive chainId',
    );
  }
  const configured = requireConfiguredChainCap({
    spendCap: input.spendCap,
    chainId,
  });
  const estimated = await input.pricing.estimateSponsoredExecutionSpend({
    chainFamily: input.chainFamily,
    intentKind: input.intentKind,
    executorKind: input.executorKind,
    environmentId: input.environmentId,
    policyId: input.policyId,
    accountRef: configured.mode === 'CHAIN_TOTAL' ? null : input.accountRef,
    targetRef: input.targetRef,
    chainId,
    requestDetails: input.requestDetails,
  });
  try {
    await input.spendCaps.reserve(input.ctx, {
      sourceEventId: input.sourceEventId,
      environmentId: input.environmentId,
      policyId: input.policyId,
      accountRef: configured.mode === 'CHAIN_TOTAL' ? null : input.accountRef,
      chainId,
      mode: configured.mode,
      period: input.spendCap.period,
      capMinor: configured.capMinor,
      estimatedSpendMinor: toNonNegativeInteger(estimated.spendMinor, 'estimated spendMinor'),
    });
  } catch (error: unknown) {
    mapReservationError(error);
  }
  return {
    sourceEventId: input.sourceEventId,
    estimatedSpendMinor: toNonNegativeInteger(estimated.spendMinor, 'estimated spendMinor'),
    estimatedPricingVersion: normalizePricingVersion(estimated.pricingVersion),
    capMinor: configured.capMinor,
    mode: configured.mode,
    period: input.spendCap.period,
  };
}

export async function settleSponsoredSpendCap(input: {
  reservation: SponsorshipSpendCapReservationHandle | null;
  spendCaps: ConsoleSponsorshipSpendCapService | null | undefined;
  pricing: SponsorshipSpendPricingService | null | undefined;
  ctx: ConsoleSponsorshipSpendCapContext;
  chainFamily: ConsoleSponsoredCallChainFamily;
  intentKind: ConsoleSponsoredCallIntentKind;
  executorKind: ConsoleSponsoredCallExecutorKind;
  environmentId: string;
  policyId: string;
  accountRef: string | null;
  targetRef: string;
  chainId: number | null | undefined;
  txOrExecutionRef: string | null;
  receiptStatus: ConsoleSponsoredCallReceiptStatus;
  feeUnit: ConsoleSponsoredCallFeeUnit;
  feeAmount: string;
  requestDetails: Record<string, unknown>;
}): Promise<SponsorshipSpendCapSettlement | null> {
  if (!input.reservation) return null;
  if (!input.spendCaps || !input.pricing) {
    throw new SponsorshipSpendCapEnforcementError(
      'sponsorship_spend_caps_unavailable',
      503,
      'Sponsored spend-cap settlement is not configured on this server',
    );
  }
  const chainId = Number(input.chainId);
  if (!Number.isInteger(chainId) || chainId <= 0) {
    throw new SponsorshipSpendCapEnforcementError(
      'sponsorship_spend_cap_misconfigured',
      500,
      'Spend-cap settlement requires a positive chainId',
    );
  }

  let settledSpendMinor = input.reservation.estimatedSpendMinor;
  let pricingVersion = input.reservation.estimatedPricingVersion;
  let usedEstimatedFallback = true;
  try {
    const finalized = await input.pricing.finalizeSponsoredExecutionSpend({
      chainFamily: input.chainFamily,
      intentKind: input.intentKind,
      executorKind: input.executorKind,
      environmentId: input.environmentId,
      policyId: input.policyId,
      accountRef: input.reservation.mode === 'CHAIN_TOTAL' ? null : input.accountRef,
      targetRef: input.targetRef,
      chainId,
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
    usedEstimatedFallback = false;
  } catch {
    settledSpendMinor = input.reservation.estimatedSpendMinor;
    pricingVersion = input.reservation.estimatedPricingVersion;
  }

  try {
    await input.spendCaps.settle(input.ctx, {
      sourceEventId: input.reservation.sourceEventId,
      settledSpendMinor,
    });
  } catch (error: unknown) {
    mapReservationError(error);
  }
  return {
    settledSpendMinor,
    pricingVersion,
    usedEstimatedFallback,
  };
}

export async function releaseSponsoredSpendCap(input: {
  reservation: SponsorshipSpendCapReservationHandle | null;
  spendCaps: ConsoleSponsorshipSpendCapService | null | undefined;
  ctx: ConsoleSponsorshipSpendCapContext;
}): Promise<void> {
  if (!input.reservation) return;
  if (!input.spendCaps) {
    throw new SponsorshipSpendCapEnforcementError(
      'sponsorship_spend_caps_unavailable',
      503,
      'Sponsored spend-cap release is not configured on this server',
    );
  }
  try {
    await input.spendCaps.release(input.ctx, {
      sourceEventId: input.reservation.sourceEventId,
    });
  } catch (error: unknown) {
    mapReservationError(error);
  }
}
