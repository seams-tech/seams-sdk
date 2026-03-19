import type { ConsoleBillingService } from '../console/billing';
import type { ConsoleBillingPrepaidReservationService } from '../console/billingPrepaidReservations';
import type {
  ConsoleSponsoredCallExecutorKind,
  ConsoleSponsoredCallFeeUnit,
  ConsoleSponsoredCallReceiptStatus,
  ConsoleSponsoredCallRecord,
  ConsoleSponsoredCallService,
  CreateConsoleSponsoredCallRecordRequest,
} from '../console/sponsoredCalls';
import type { ConsoleBillingContext } from '../console/billing/service';
import {
  getConsoleBillingPostgresRuntime,
  recordSponsoredExecutionDebitTx,
} from '../console/billing/postgres';
import type { ConsoleBillingPrepaidReservationContext } from '../console/billingPrepaidReservations';
import {
  getConsoleBillingPrepaidReservationPostgresRuntime,
  releaseConsoleBillingPrepaidReservationTx,
  settleConsoleBillingPrepaidReservationTx,
} from '../console/billingPrepaidReservations/postgres';
import type { ConsoleSponsoredCallContext } from '../console/sponsoredCalls/service';
import {
  createConsoleSponsoredCallRecordTx,
  getConsoleSponsoredCallPostgresRuntime,
} from '../console/sponsoredCalls/postgres';
import { withConsoleTenantContextTx } from '../console/shared/postgresTenantContext';
import type { RouteResponse } from './routeExecutionContext';
import type { SponsorshipSpendPricingService } from '../sponsorship';
import type {
  SponsoredPrepaidReservationHandle,
  SponsoredPrepaidReservationSettlement,
} from '../sponsorship/prepaidBalance';
import { resolveSponsoredPrepaidSettlementQuote } from '../sponsorship/prepaidBalance';
import type { SponsorshipBillingEventServices } from './sponsorshipBillingEvents';
import {
  emitSponsorshipBalanceTransitionEvents,
  readSponsorshipBillingBalanceSnapshot,
} from './sponsorshipBillingEvents';

export interface SponsorshipExecutionAssessment {
  succeeded: boolean;
  txOrExecutionRef: string | null;
  receiptStatus: ConsoleSponsoredCallReceiptStatus;
  feeUnit: ConsoleSponsoredCallFeeUnit;
  feeAmount: string;
  executorKind: ConsoleSponsoredCallExecutorKind;
  responseCode: string;
  responseMessage: string;
  recordErrorCode: string | null;
  recordErrorMessage: string | null;
}

export interface SponsoredExecutionBillingContext {
  orgId: string;
  actorUserId: string;
  roles: string[];
}

export interface RecordSponsoredExecutionInput {
  billing: ConsoleBillingService;
  balanceEvents?: SponsorshipBillingEventServices | null;
  billingSourceEventIdPrefix: string;
  context: SponsoredExecutionBillingContext;
  ledger: ConsoleSponsoredCallService;
  occurredAt?: string;
  buildRecord: (input: {
    prepaidSettlement: FinalizedSponsoredPrepaidSettlement | null;
    billingLedgerEntryId: string | null;
  }) => Omit<
    CreateConsoleSponsoredCallRecordRequest,
    'txOrExecutionRef' | 'receiptStatus' | 'feeUnit' | 'feeAmount' | 'executorKind' | 'errorCode' | 'errorMessage'
  >;
  assessment: SponsorshipExecutionAssessment;
  walletId: string;
  prepaidSettlementInput?: SponsoredExecutionPrepaidSettlementInput | null;
}

export interface SponsoredExecutionPrepaidSettlementInput {
  reservation: SponsoredPrepaidReservationHandle | null;
  prepaidReservations: ConsoleBillingPrepaidReservationService | null | undefined;
  pricing: SponsorshipSpendPricingService | null | undefined;
  ctx: ConsoleBillingPrepaidReservationContext;
  chainFamily: CreateConsoleSponsoredCallRecordRequest['chainFamily'];
  intentKind: CreateConsoleSponsoredCallRecordRequest['intentKind'];
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
}

export interface FinalizedSponsoredPrepaidSettlement
  extends SponsoredPrepaidReservationSettlement {
  sourceEventId: string;
  estimatedSpendMinor: number;
  billingLedgerEntryId: string | null;
}

type TxQueryable = {
  query: (
    text: string,
    values?: unknown[],
  ) => Promise<{
    rows: any[];
    rowCount?: number | undefined;
  }>;
};

export interface RunSponsorshipExecutionOnResultInput<
  TResult,
  TAssessment extends SponsorshipExecutionAssessment,
> {
  result: TResult;
  assessment: TAssessment;
}

export interface RunSponsorshipExecutionOnThrownErrorInput<
  TAssessment extends SponsorshipExecutionAssessment,
> {
  error: unknown;
  assessment: TAssessment;
}

export interface RunSponsorshipExecutionInput<
  TResult,
  TAssessment extends SponsorshipExecutionAssessment,
  TResponseBody extends Record<string, unknown>,
> {
  execute: () => Promise<TResult>;
  assessResult: (result: TResult) => TAssessment;
  onResult: (
    input: RunSponsorshipExecutionOnResultInput<TResult, TAssessment>,
  ) => Promise<RouteResponse<TResponseBody>> | RouteResponse<TResponseBody>;
  assessThrownError?: (error: unknown) => TAssessment;
  onThrownError?: (
    input: RunSponsorshipExecutionOnThrownErrorInput<TAssessment>,
  ) => Promise<RouteResponse<TResponseBody>> | RouteResponse<TResponseBody>;
}

export async function recordSponsoredExecution(
  input: RecordSponsoredExecutionInput,
): Promise<ConsoleSponsoredCallRecord> {
  const beforeBalanceState = await readSponsorshipBillingBalanceSnapshot(input.billing, input.context);
  if (!input.prepaidSettlementInput?.reservation) {
    throw new Error(
      'Atomic sponsored settlement requires an active prepaid reservation handle on recordSponsoredExecution input',
    );
  }
  const billingRuntime = getConsoleBillingPostgresRuntime(input.billing);
  const prepaidRuntime = getConsoleBillingPrepaidReservationPostgresRuntime(
    input.prepaidSettlementInput?.prepaidReservations || null,
  );
  const sponsoredCallsRuntime = getConsoleSponsoredCallPostgresRuntime(input.ledger);
  const canUseAtomicPostgresPath =
    billingRuntime &&
    prepaidRuntime &&
    sponsoredCallsRuntime &&
    billingRuntime.pool === prepaidRuntime.pool &&
    billingRuntime.pool === sponsoredCallsRuntime.pool &&
    billingRuntime.namespace === prepaidRuntime.namespace &&
    billingRuntime.namespace === sponsoredCallsRuntime.namespace;
  if (!canUseAtomicPostgresPath) {
    throw new Error(
      'Atomic sponsored settlement requires Postgres-backed billing, prepaidReservations, and sponsoredCalls services sharing one pool and namespace',
    );
  }
  const runtime = billingRuntime!;
  const record = await withConsoleTenantContextTx(runtime.pool, {
    namespace: runtime.namespace,
    orgId: input.context.orgId,
  }, async (tx: TxQueryable) => {
    const recordId = `scr_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 10)}`;
    const finalized = await finalizeSponsoredPrepaidSettlementInTx(tx, {
      billingNamespace: runtime.namespace,
      billingContext: input.context,
      billingNow: runtime.now(),
      billingSourceEventIdPrefix: input.billingSourceEventIdPrefix,
      walletId: input.walletId,
      occurredAt: input.occurredAt,
      recordId,
      prepaidSettlementInput: input.prepaidSettlementInput!,
    });
    return await createConsoleSponsoredCallRecordTx(tx, {
      namespace: runtime.namespace,
      ctx: input.context,
      now: runtime.now,
      request: {
        ...input.buildRecord({
          prepaidSettlement: finalized?.settlement || null,
          billingLedgerEntryId: finalized?.billingLedgerEntryId || null,
        }),
        id: recordId,
        txOrExecutionRef: input.assessment.txOrExecutionRef,
        receiptStatus: input.assessment.receiptStatus,
        feeUnit: input.assessment.feeUnit,
        feeAmount: input.assessment.feeAmount,
        executorKind: input.assessment.executorKind,
        errorCode: input.assessment.recordErrorCode,
        errorMessage: input.assessment.recordErrorMessage,
      },
    });
  });
  if (input.balanceEvents) {
    await emitSponsorshipBalanceTransitionEvents({
      services: input.balanceEvents,
      ctx: input.context,
      before: beforeBalanceState,
      billing: input.billing,
      trigger: {
        kind: 'sponsored_execution_debit',
        ...(record.environmentId ? { environmentId: record.environmentId } : {}),
        ...(record.route ? { routeId: record.route } : {}),
        ...(record.billingLedgerEntryId ? { ledgerEntryId: record.billingLedgerEntryId } : {}),
        ...(record.idempotencyKey ? { sourceEventId: record.idempotencyKey } : {}),
      },
    });
  }
  return record;
}

export async function runSponsorshipExecution<
  TResult,
  TAssessment extends SponsorshipExecutionAssessment,
  TResponseBody extends Record<string, unknown>,
>(
  input: RunSponsorshipExecutionInput<TResult, TAssessment, TResponseBody>,
): Promise<RouteResponse<TResponseBody>> {
  try {
    const result = await input.execute();
    const assessment = input.assessResult(result);
    return await input.onResult({
      result,
      assessment,
    });
  } catch (error: unknown) {
    if (!input.assessThrownError || !input.onThrownError) {
      throw error;
    }
    const assessment = input.assessThrownError(error);
    return await input.onThrownError({
      error,
      assessment,
    });
  }
}

async function finalizeSponsoredPrepaidSettlementInTx(
  tx: TxQueryable,
  input: {
    billingNamespace: string;
    billingContext: ConsoleBillingContext & ConsoleBillingPrepaidReservationContext & ConsoleSponsoredCallContext;
    billingNow: Date;
    billingSourceEventIdPrefix: string;
    walletId: string;
    occurredAt?: string;
    recordId: string;
    prepaidSettlementInput: SponsoredExecutionPrepaidSettlementInput;
  },
): Promise<{
  settlement: FinalizedSponsoredPrepaidSettlement | null;
  billingLedgerEntryId: string | null;
} | null> {
  const reservation = input.prepaidSettlementInput.reservation;
  if (!reservation) return null;
  const prepaidRuntime = getConsoleBillingPrepaidReservationPostgresRuntime(
    input.prepaidSettlementInput.prepaidReservations,
  );
  if (!prepaidRuntime) return null;
  const quote = await resolveSponsoredPrepaidSettlementQuote(input.prepaidSettlementInput);
  if (!quote) {
    return { settlement: null, billingLedgerEntryId: null };
  }

  const sourceEventId = reservation.sourceEventId;
  const settledAt = input.billingNow.toISOString();
  const reservationMutation = quote.released
    ? await releaseConsoleBillingPrepaidReservationTx(tx as any, {
        namespace: prepaidRuntime.namespace,
        ctx: input.billingContext,
        now: input.billingNow,
        request: {
          sourceEventId,
        },
      })
    : await settleConsoleBillingPrepaidReservationTx(tx as any, {
        namespace: prepaidRuntime.namespace,
        ctx: input.billingContext,
        now: input.billingNow,
        request: {
          sourceEventId,
          settledSpendMinor: quote.settledSpendMinor,
          txOrExecutionRef: input.prepaidSettlementInput.txOrExecutionRef,
          pricingVersion: quote.pricingVersion,
        },
      });
  const settlement: SponsoredPrepaidReservationSettlement = {
    reservationId: reservationMutation?.reservation.id || null,
    settledSpendMinor: quote.settledSpendMinor,
    pricingVersion: quote.pricingVersion,
    usedEstimatedFallback: quote.usedEstimatedFallback,
    released: quote.released,
    settledAt,
  };
  let billingLedgerEntryId: string | null = null;
  if (!settlement.released && settlement.settledSpendMinor > 0) {
    const debit = await recordSponsoredExecutionDebitTx(tx as any, {
      namespace: input.billingNamespace,
      ctx: input.billingContext,
      now: input.billingNow,
      request: {
        amountMinor: settlement.settledSpendMinor,
        sourceEventId: `${input.billingSourceEventIdPrefix}:${input.recordId}`,
        walletId: input.walletId,
        occurredAt: input.occurredAt || settlement.settledAt,
        ...(input.prepaidSettlementInput.txOrExecutionRef
          ? { txOrExecutionRef: input.prepaidSettlementInput.txOrExecutionRef }
          : {}),
        ...(settlement.pricingVersion ? { pricingVersion: settlement.pricingVersion } : {}),
      },
    });
    billingLedgerEntryId = debit.result.ledgerEntryId;
  }

  return {
    settlement: {
      ...settlement,
      sourceEventId,
      estimatedSpendMinor: reservation.estimatedSpendMinor,
      billingLedgerEntryId,
    },
    billingLedgerEntryId,
  };
}
