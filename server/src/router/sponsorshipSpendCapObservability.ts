import type { NormalizedRouterLogger } from './logger';
import type {
  ConsoleSponsoredCallChainFamily,
  ConsoleSponsoredCallExecutorKind,
  ConsoleSponsoredCallIntentKind,
  ConsoleSponsoredCallReceiptStatus,
} from '../console/sponsoredCalls';
import type {
  SponsorshipSpendCapReservationHandle,
  SponsorshipSpendCapSettlement,
} from '../sponsorship';

type SponsorshipSpendCapLogBase = {
  logger: NormalizedRouterLogger;
  routeTag: string;
  environmentId: string;
  policyId: string;
  idempotencyKey: string;
  chainFamily: ConsoleSponsoredCallChainFamily;
  intentKind: ConsoleSponsoredCallIntentKind;
  executorKind: ConsoleSponsoredCallExecutorKind;
  chainId: number | null;
  accountRef: string | null;
  targetRef: string;
};

export function logSponsorshipSpendCapReserved(
  input: SponsorshipSpendCapLogBase & {
    reservation: SponsorshipSpendCapReservationHandle;
  },
): void {
  input.logger.info(`[${input.routeTag}] spend-cap reserved`, {
    environmentId: input.environmentId,
    policyId: input.policyId,
    idempotencyKey: input.idempotencyKey,
    sourceEventId: input.reservation.sourceEventId,
    chainFamily: input.chainFamily,
    intentKind: input.intentKind,
    executorKind: input.executorKind,
    chainId: input.chainId,
    accountRef: input.accountRef,
    targetRef: input.targetRef,
    mode: input.reservation.mode,
    period: input.reservation.period,
    capMinor: input.reservation.capMinor,
    estimatedSpendMinor: input.reservation.estimatedSpendMinor,
    pricingVersion: input.reservation.estimatedPricingVersion,
  });
}

export function logSponsorshipSpendCapRejected(
  input: SponsorshipSpendCapLogBase & {
    errorCode: string;
    errorMessage: string;
    errorDetails?: Record<string, unknown>;
  },
): void {
  input.logger.warn(`[${input.routeTag}] spend-cap rejected`, {
    environmentId: input.environmentId,
    policyId: input.policyId,
    idempotencyKey: input.idempotencyKey,
    chainFamily: input.chainFamily,
    intentKind: input.intentKind,
    executorKind: input.executorKind,
    chainId: input.chainId,
    accountRef: input.accountRef,
    targetRef: input.targetRef,
    errorCode: input.errorCode,
    errorMessage: input.errorMessage,
    ...(input.errorDetails ? { errorDetails: input.errorDetails } : {}),
  });
}

export function logSponsorshipSpendCapSettled(
  input: SponsorshipSpendCapLogBase & {
    reservation: SponsorshipSpendCapReservationHandle;
    settlement: SponsorshipSpendCapSettlement;
    txOrExecutionRef: string | null;
    receiptStatus: ConsoleSponsoredCallReceiptStatus;
  },
): void {
  input.logger.info(`[${input.routeTag}] spend-cap settled`, {
    environmentId: input.environmentId,
    policyId: input.policyId,
    idempotencyKey: input.idempotencyKey,
    sourceEventId: input.reservation.sourceEventId,
    chainFamily: input.chainFamily,
    intentKind: input.intentKind,
    executorKind: input.executorKind,
    chainId: input.chainId,
    accountRef: input.accountRef,
    targetRef: input.targetRef,
    txOrExecutionRef: input.txOrExecutionRef,
    receiptStatus: input.receiptStatus,
    estimatedSpendMinor: input.reservation.estimatedSpendMinor,
    settledSpendMinor: input.settlement.settledSpendMinor,
    usedEstimatedFallback: input.settlement.usedEstimatedFallback,
    pricingVersion: input.settlement.pricingVersion,
  });
}
