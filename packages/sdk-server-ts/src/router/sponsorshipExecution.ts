import { secureRandomBase36 } from '@shared/utils/secureRandomId';
import type { ConsoleBillingService } from '../console/billing/service';
import type { ConsoleBillingD1Runtime } from '../console/billing/d1';
import {
  createSponsoredExecutionDebitD1InsertStatement,
  getConsoleBillingD1Runtime,
} from '../console/billing/d1';
import type {
  ConsoleBillingPrepaidReservation,
} from '../console/billingPrepaidReservations/types';
import type {
  ConsoleBillingPrepaidReservationD1Runtime,
} from '../console/billingPrepaidReservations/d1';
import type {
  ConsoleBillingPrepaidReservationService,
} from '../console/billingPrepaidReservations/service';
import {
  createReleaseConsoleBillingPrepaidReservationD1Statement,
  createSettleConsoleBillingPrepaidReservationD1Statement,
  getConsoleBillingPrepaidReservationD1Runtime,
} from '../console/billingPrepaidReservations/d1';
import { ConsoleBillingPrepaidReservationError } from '../console/billingPrepaidReservations/errors';
import type {
  ConsoleSponsoredCallExecutorKind,
  ConsoleSponsoredCallFeeUnit,
  ConsoleSponsoredCallReceiptStatus,
  ConsoleSponsoredCallRecord,
  CreateConsoleSponsoredCallRecordRequest,
} from '../console/sponsoredCalls/types';
import type { ConsoleSponsoredCallService } from '../console/sponsoredCalls/service';
import type { ConsoleSponsoredCallD1Runtime } from '../console/sponsoredCalls/d1';
import {
  createD1ConsoleSponsoredCallRecordInsertStatement,
  getConsoleSponsoredCallD1Runtime,
  loadD1ConsoleSponsoredCallRecordById,
  loadD1ConsoleSponsoredCallRecordByIdempotencyKey,
} from '../console/sponsoredCalls/d1';
import type { ConsoleBillingContext } from '../console/billing/service';
import type { ConsoleBillingPrepaidReservationContext } from '../console/billingPrepaidReservations/service';
import type { ConsoleSponsoredCallContext } from '../console/sponsoredCalls/service';
import type { D1PreparedStatementLike } from '../storage/tenantRoute';
import type { RouteResponse } from './routeExecutionContext';
import type { SponsorshipSpendPricingService } from '../sponsorship/spendCaps';
import type {
  SponsoredPrepaidReservationHandle,
  SponsoredPrepaidReservationSettlement,
  SponsoredPrepaidSettlementQuote,
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
    | 'txOrExecutionRef'
    | 'receiptStatus'
    | 'feeUnit'
    | 'feeAmount'
    | 'executorKind'
    | 'errorCode'
    | 'errorMessage'
  >;
  assessment: SponsorshipExecutionAssessment;
  walletId: string;
  prepaidSettlementInput?: SponsoredExecutionPrepaidSettlementInput | null;
}

interface FinalizedSponsoredPrepaidSettlementD1 {
  billingLedgerEntryId: string | null;
  settlement: FinalizedSponsoredPrepaidSettlement | null;
  statements: D1PreparedStatementLike[];
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

export interface FinalizedSponsoredPrepaidSettlement extends SponsoredPrepaidReservationSettlement {
  sourceEventId: string;
  estimatedSpendMinor: number;
  billingLedgerEntryId: string | null;
}

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
  const beforeBalanceState = await readSponsorshipBillingBalanceSnapshot(
    input.billing,
    input.context,
  );
  const prepaidSettlementInput = input.prepaidSettlementInput;
  if (!prepaidSettlementInput?.reservation) {
    throw new Error(
      'D1 sponsored settlement requires an active prepaid reservation handle on recordSponsoredExecution input',
    );
  }
  const billingD1Runtime = getConsoleBillingD1Runtime(input.billing);
  const prepaidD1Runtime = getConsoleBillingPrepaidReservationD1Runtime(
    prepaidSettlementInput.prepaidReservations || null,
  );
  const sponsoredCallsD1Runtime = getConsoleSponsoredCallD1Runtime(input.ledger);
  const canUseAtomicD1Path = Boolean(
    billingD1Runtime &&
      prepaidD1Runtime &&
      sponsoredCallsD1Runtime &&
      billingD1Runtime.database === prepaidD1Runtime.database &&
      billingD1Runtime.database === sponsoredCallsD1Runtime.database &&
      billingD1Runtime.namespace === prepaidD1Runtime.namespace &&
      billingD1Runtime.namespace === sponsoredCallsD1Runtime.namespace,
  );
  if (
    !canUseAtomicD1Path ||
    !billingD1Runtime ||
    !prepaidD1Runtime ||
    !sponsoredCallsD1Runtime
  ) {
    throw new Error(
      'D1 sponsored settlement requires D1-backed billing, prepaidReservations, and sponsoredCalls services sharing one database and namespace',
    );
  }
  const record = await recordSponsoredExecutionD1({
    input,
    billingRuntime: billingD1Runtime,
    prepaidRuntime: prepaidD1Runtime,
    sponsoredCallsRuntime: sponsoredCallsD1Runtime,
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

interface RecordSponsoredExecutionD1Input {
  input: RecordSponsoredExecutionInput;
  billingRuntime: ConsoleBillingD1Runtime;
  prepaidRuntime: ConsoleBillingPrepaidReservationD1Runtime;
  sponsoredCallsRuntime: ConsoleSponsoredCallD1Runtime;
}

interface BuildD1SponsoredCallRecordRequestInput {
  input: RecordSponsoredExecutionInput;
  recordId: string;
  prepaidSettlement: FinalizedSponsoredPrepaidSettlement | null;
  billingLedgerEntryId: string | null;
}

interface D1PrepaidSettlementBuildInput {
  billingRuntime: ConsoleBillingD1Runtime;
  prepaidRuntime: ConsoleBillingPrepaidReservationD1Runtime;
  billingContext: ConsoleBillingContext &
    ConsoleBillingPrepaidReservationContext &
    ConsoleSponsoredCallContext;
  billingSourceEventIdPrefix: string;
  walletId: string;
  occurredAt?: string;
  recordId: string;
  settledAtMs: number;
  prepaidSettlementInput: SponsoredExecutionPrepaidSettlementInput;
}

interface D1SettledReservationInput extends D1PrepaidSettlementBuildInput {
  reservationHandle: SponsoredPrepaidReservationHandle;
  reservation: ConsoleBillingPrepaidReservation;
  quote: SponsoredPrepaidSettlementQuote;
}

interface D1ReleasedReservationInput extends D1PrepaidSettlementBuildInput {
  reservationHandle: SponsoredPrepaidReservationHandle;
  reservation: ConsoleBillingPrepaidReservation;
  quote: SponsoredPrepaidSettlementQuote;
}

function normalizeRequiredSponsoredRecordIdempotencyKey(
  request: { idempotencyKey?: string | null },
): string {
  const idempotencyKey = String(request.idempotencyKey || '').trim();
  if (!idempotencyKey) {
    throw new Error('Atomic D1 sponsored settlement requires a sponsored-call idempotency key');
  }
  return idempotencyKey;
}

function makeSponsoredCallRecordId(now: Date): string {
  return `scr_${now.getTime().toString(36)}_${secureRandomBase36(8, 'sponsored call record IDs')}`;
}

function buildD1SponsoredCallRecordRequest(
  input: BuildD1SponsoredCallRecordRequestInput,
): CreateConsoleSponsoredCallRecordRequest {
  return {
    ...input.input.buildRecord({
      prepaidSettlement: input.prepaidSettlement,
      billingLedgerEntryId: input.billingLedgerEntryId,
    }),
    id: input.recordId,
    txOrExecutionRef: input.input.assessment.txOrExecutionRef,
    receiptStatus: input.input.assessment.receiptStatus,
    feeUnit: input.input.assessment.feeUnit,
    feeAmount: input.input.assessment.feeAmount,
    executorKind: input.input.assessment.executorKind,
    errorCode: input.input.assessment.recordErrorCode,
    errorMessage: input.input.assessment.recordErrorMessage,
  };
}

function parseD1SponsoredDebitOccurredAtMs(
  occurredAt: string | undefined,
  fallbackMs: number,
): number {
  if (!occurredAt) return fallbackMs;
  const parsed = Date.parse(occurredAt);
  if (!Number.isFinite(parsed)) {
    throw new Error('Invalid occurredAt value for D1 sponsored execution debit');
  }
  return parsed;
}

function isD1ConstraintError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error || '');
  return message.includes('UNIQUE constraint failed') || message.includes('constraint failed');
}

function assertNeverReservationStatus(status: never): never {
  throw new Error(`Unhandled prepaid reservation status: ${status}`);
}

async function loadExistingD1SponsoredRecordByIdempotency(input: {
  runtime: ConsoleSponsoredCallD1Runtime;
  ctx: ConsoleSponsoredCallContext;
  idempotencyKey: string;
}): Promise<ConsoleSponsoredCallRecord | null> {
  return await loadD1ConsoleSponsoredCallRecordByIdempotencyKey({
    database: input.runtime.database,
    namespace: input.runtime.namespace,
    orgId: input.ctx.orgId,
    idempotencyKey: input.idempotencyKey,
  });
}

async function recordSponsoredExecutionD1(
  input: RecordSponsoredExecutionD1Input,
): Promise<ConsoleSponsoredCallRecord> {
  const prepaidSettlementInput = input.input.prepaidSettlementInput;
  if (!prepaidSettlementInput?.reservation) {
    throw new Error(
      'Atomic D1 sponsored settlement requires an active prepaid reservation handle',
    );
  }
  const initialRequest = input.input.buildRecord({
    prepaidSettlement: null,
    billingLedgerEntryId: null,
  });
  const idempotencyKey = normalizeRequiredSponsoredRecordIdempotencyKey(initialRequest);
  const existing = await loadExistingD1SponsoredRecordByIdempotency({
    runtime: input.sponsoredCallsRuntime,
    ctx: input.input.context,
    idempotencyKey,
  });
  if (existing) return existing;

  const createdAt = input.billingRuntime.now();
  const createdAtMs = createdAt.getTime();
  const recordId = makeSponsoredCallRecordId(createdAt);
  const finalized = await finalizeSponsoredPrepaidSettlementD1({
    billingRuntime: input.billingRuntime,
    prepaidRuntime: input.prepaidRuntime,
    billingContext: input.input.context,
    billingSourceEventIdPrefix: input.input.billingSourceEventIdPrefix,
    walletId: input.input.walletId,
    occurredAt: input.input.occurredAt,
    recordId,
    settledAtMs: createdAtMs,
    prepaidSettlementInput,
  });
  const request = buildD1SponsoredCallRecordRequest({
    input: input.input,
    recordId,
    prepaidSettlement: finalized.settlement,
    billingLedgerEntryId: finalized.billingLedgerEntryId,
  });
  const recordInsert = createD1ConsoleSponsoredCallRecordInsertStatement({
    database: input.sponsoredCallsRuntime.database,
    namespace: input.sponsoredCallsRuntime.namespace,
    ctx: input.input.context,
    recordId,
    request,
    createdAtMs,
  });

  try {
    await input.billingRuntime.database.batch([...finalized.statements, recordInsert]);
  } catch (error: unknown) {
    if (!isD1ConstraintError(error)) throw error;
    const duplicate = await loadExistingD1SponsoredRecordByIdempotency({
      runtime: input.sponsoredCallsRuntime,
      ctx: input.input.context,
      idempotencyKey,
    });
    if (duplicate) return duplicate;
    throw error;
  }

  const record = await loadD1ConsoleSponsoredCallRecordById({
    database: input.sponsoredCallsRuntime.database,
    namespace: input.sponsoredCallsRuntime.namespace,
    orgId: input.input.context.orgId,
    recordId,
  });
  if (!record) throw new Error('Failed to insert D1 sponsored-call settlement record');
  return record;
}

async function finalizeSponsoredPrepaidSettlementD1(
  input: D1PrepaidSettlementBuildInput,
): Promise<FinalizedSponsoredPrepaidSettlementD1> {
  const reservationHandle = input.prepaidSettlementInput.reservation;
  if (!reservationHandle) {
    return { settlement: null, billingLedgerEntryId: null, statements: [] };
  }
  if (!input.prepaidSettlementInput.prepaidReservations) {
    throw new ConsoleBillingPrepaidReservationError(
      'unavailable',
      503,
      'Sponsored prepaid reservations are not configured',
    );
  }
  const quote = await resolveSponsoredPrepaidSettlementQuote(input.prepaidSettlementInput);
  if (!quote) {
    return { settlement: null, billingLedgerEntryId: null, statements: [] };
  }
  const reservation =
    await input.prepaidSettlementInput.prepaidReservations.getReservationBySourceEventId(
      input.billingContext,
      reservationHandle.sourceEventId,
    );
  if (!reservation) {
    throw new ConsoleBillingPrepaidReservationError(
      'not_found',
      404,
      'Prepaid reservation was not found for sponsored settlement',
    );
  }
  if (quote.released) {
    return buildReleasedD1PrepaidSettlement({
      ...input,
      reservationHandle,
      reservation,
      quote,
    });
  }
  return buildSettledD1PrepaidSettlement({
    ...input,
    reservationHandle,
    reservation,
    quote,
  });
}

function buildReleasedD1PrepaidSettlement(
  input: D1ReleasedReservationInput,
): FinalizedSponsoredPrepaidSettlementD1 {
  const statements: D1PreparedStatementLike[] = [];
  switch (input.reservation.status) {
    case 'RESERVED':
      statements.push(
        createReleaseConsoleBillingPrepaidReservationD1Statement({
          runtime: input.prepaidRuntime,
          ctx: input.billingContext,
          reservation: input.reservation,
          updatedAtMs: input.settledAtMs,
        }),
      );
      break;
    case 'RELEASED':
    case 'EXPIRED':
      break;
    case 'SETTLED':
      throw new ConsoleBillingPrepaidReservationError(
        'invalid_state',
        409,
        'Settled prepaid reservations cannot be released',
      );
    default:
      assertNeverReservationStatus(input.reservation.status);
  }
  return {
    settlement: {
      reservationId: input.reservation.id,
      settledSpendMinor: 0,
      pricingVersion: input.quote.pricingVersion,
      usedEstimatedFallback: input.quote.usedEstimatedFallback,
      released: true,
      settledAt: new Date(input.settledAtMs).toISOString(),
      sourceEventId: input.reservation.sourceEventId,
      estimatedSpendMinor: input.reservationHandle.estimatedSpendMinor,
      billingLedgerEntryId: null,
    },
    billingLedgerEntryId: null,
    statements,
  };
}

function buildSettledD1PrepaidSettlement(
  input: D1SettledReservationInput,
): FinalizedSponsoredPrepaidSettlementD1 {
  const statements: D1PreparedStatementLike[] = [];
  switch (input.reservation.status) {
    case 'RESERVED':
      statements.push(
        createSettleConsoleBillingPrepaidReservationD1Statement({
          runtime: input.prepaidRuntime,
          ctx: input.billingContext,
          reservation: input.reservation,
          settledSpendMinor: input.quote.settledSpendMinor,
          txOrExecutionRef: input.prepaidSettlementInput.txOrExecutionRef,
          pricingVersion: input.quote.pricingVersion,
          updatedAtMs: input.settledAtMs,
        }),
      );
      break;
    case 'SETTLED':
      if (input.reservation.settledMinor !== input.quote.settledSpendMinor) {
        throw new ConsoleBillingPrepaidReservationError(
          'invalid_state',
          409,
          'Prepaid reservation is already settled with a different amount',
        );
      }
      break;
    case 'RELEASED':
    case 'EXPIRED':
      throw new ConsoleBillingPrepaidReservationError(
        'invalid_state',
        409,
        'Released or expired prepaid reservations cannot be settled',
      );
    default:
      assertNeverReservationStatus(input.reservation.status);
  }

  let billingLedgerEntryId: string | null = null;
  if (input.quote.settledSpendMinor > 0) {
    billingLedgerEntryId = `ble_${input.recordId}`;
    const occurredAtMs = parseD1SponsoredDebitOccurredAtMs(input.occurredAt, input.settledAtMs);
    statements.push(
      createSponsoredExecutionDebitD1InsertStatement({
        runtime: input.billingRuntime,
        ctx: input.billingContext,
        request: {
          amountMinor: input.quote.settledSpendMinor,
          sourceEventId: `${input.billingSourceEventIdPrefix}:${input.reservation.sourceEventId}`,
          walletId: input.walletId,
          occurredAt: new Date(occurredAtMs).toISOString(),
          txOrExecutionRef: input.prepaidSettlementInput.txOrExecutionRef,
          pricingVersion: input.quote.pricingVersion,
        },
        entryId: billingLedgerEntryId,
        occurredAtMs,
      }),
    );
  }

  return {
    settlement: {
      reservationId: input.reservation.id,
      settledSpendMinor: input.quote.settledSpendMinor,
      pricingVersion: input.quote.pricingVersion,
      usedEstimatedFallback: input.quote.usedEstimatedFallback,
      released: false,
      settledAt: new Date(input.settledAtMs).toISOString(),
      sourceEventId: input.reservation.sourceEventId,
      estimatedSpendMinor: input.reservationHandle.estimatedSpendMinor,
      billingLedgerEntryId,
    },
    billingLedgerEntryId,
    statements,
  };
}
