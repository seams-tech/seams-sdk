import { secureRandomBase36 } from '@shared/utils/secureRandomId';
import type { ConsoleBillingService } from '../billing/service';
import type { ConsoleBillingD1Runtime } from '../billing/d1';
import {
  createSponsoredExecutionDebitD1InsertStatement,
  getConsoleBillingD1Runtime,
} from '../billing/d1';
import type {
  ConsoleBillingPrepaidReservation,
} from '../billingPrepaidReservations/types';
import type {
  ConsoleBillingPrepaidReservationD1Runtime,
} from '../billingPrepaidReservations/d1';
import type {
  ConsoleBillingPrepaidReservationService,
} from '../billingPrepaidReservations/service';
import {
  createReleaseConsoleBillingPrepaidReservationD1Statement,
  createSettleConsoleBillingPrepaidReservationD1Statement,
  getConsoleBillingPrepaidReservationD1Runtime,
} from '../billingPrepaidReservations/d1';
import { ConsoleBillingPrepaidReservationError } from '../billingPrepaidReservations/errors';
import type {
  ConsoleSponsoredCallExecutorKind,
  ConsoleSponsoredCallFeeUnit,
  ConsoleSponsoredCallReceiptStatus,
  ConsoleSponsoredCallRecord,
  CreateConsoleSponsoredCallRecordRequest,
} from '../sponsoredCalls/types';
import type { ConsoleSponsoredCallService } from '../sponsoredCalls/service';
import type { ConsoleSponsoredCallD1Runtime } from '../sponsoredCalls/d1';
import {
  createD1ConsoleSponsoredCallRecordInsertStatement,
  getConsoleSponsoredCallD1Runtime,
  loadD1ConsoleSponsoredCallRecordById,
  loadD1ConsoleSponsoredCallRecordByIdempotencyKey,
} from '../sponsoredCalls/d1';
import type { ConsoleBillingContext } from '../billing/service';
import type { ConsoleBillingPrepaidReservationContext } from '../billingPrepaidReservations/service';
import type { ConsoleSponsoredCallContext } from '../sponsoredCalls/service';
import type { D1PreparedStatementLike, D1ResultLike } from '../../storage/tenantRoute';
import type { RouteResponse } from '../../router/routeExecutionContext';
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
  reservationTransition: D1ReservationTransition;
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
        sourceEventId: record.idempotencyKey,
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

type D1ReservationTransition =
  | {
      readonly kind: 'none';
    }
  | {
      readonly kind: 'required';
      readonly action: 'settle' | 'release';
      readonly statementIndex: number;
      readonly sourceEventId: string;
    };

type D1PreviousStatementInsertGuard = {
  readonly kind: 'previous_statement_changed_one';
};

const NO_D1_RESERVATION_TRANSITION: D1ReservationTransition = {
  kind: 'none',
};

const D1_PREVIOUS_STATEMENT_CHANGED_ONE_INSERT_GUARD: D1PreviousStatementInsertGuard = {
  kind: 'previous_statement_changed_one',
};

function normalizeRequiredSponsoredRecordIdempotencyKey(
  request: { idempotencyKey: string },
): string {
  const idempotencyKey = request.idempotencyKey.trim();
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

function assertNeverD1ReservationTransition(transition: never): never {
  throw new Error(`Unhandled D1 reservation transition: ${JSON.stringify(transition)}`);
}

function d1ReservationTransitionInsertGuard(
  transition: D1ReservationTransition,
): D1PreviousStatementInsertGuard | undefined {
  switch (transition.kind) {
    case 'none':
      return undefined;
    case 'required':
      return D1_PREVIOUS_STATEMENT_CHANGED_ONE_INSERT_GUARD;
    default:
      return assertNeverD1ReservationTransition(transition);
  }
}

function d1BatchResultChanges(result: D1ResultLike<unknown> | undefined): number | null {
  const changes = Number(result?.meta?.changes);
  if (!Number.isFinite(changes)) return null;
  return Math.max(0, Math.trunc(changes));
}

function d1ReservationTransitionFailed(input: {
  transition: D1ReservationTransition;
  batchResults: readonly D1ResultLike<unknown>[];
}): boolean {
  switch (input.transition.kind) {
    case 'none':
      return false;
    case 'required': {
      const changes = d1BatchResultChanges(input.batchResults[input.transition.statementIndex]);
      return changes !== null && changes !== 1;
    }
    default:
      return assertNeverD1ReservationTransition(input.transition);
  }
}

function d1ReservationTransitionFailureError(
  transition: D1ReservationTransition,
): ConsoleBillingPrepaidReservationError {
  switch (transition.kind) {
    case 'none':
      return new ConsoleBillingPrepaidReservationError(
        'settlement_failed',
        500,
        'Failed to insert D1 sponsored-call settlement record',
      );
    case 'required':
      return new ConsoleBillingPrepaidReservationError(
        'invalid_state',
        409,
        `Prepaid reservation ${transition.sourceEventId} could not be ${transition.action === 'settle' ? 'settled' : 'released'} from RESERVED state`,
      );
    default:
      return assertNeverD1ReservationTransition(transition);
  }
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
    insertGuard: d1ReservationTransitionInsertGuard(finalized.reservationTransition),
  });

  try {
    const batchResults = await input.billingRuntime.database.batch<D1ResultLike<unknown>>([
      ...finalized.statements,
      recordInsert,
    ]);
    if (
      d1ReservationTransitionFailed({
        transition: finalized.reservationTransition,
        batchResults,
      })
    ) {
      const duplicate = await loadExistingD1SponsoredRecordByIdempotency({
        runtime: input.sponsoredCallsRuntime,
        ctx: input.input.context,
        idempotencyKey,
      });
      if (duplicate) return duplicate;
      throw d1ReservationTransitionFailureError(finalized.reservationTransition);
    }
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
  if (!record) {
    const duplicate = await loadExistingD1SponsoredRecordByIdempotency({
      runtime: input.sponsoredCallsRuntime,
      ctx: input.input.context,
      idempotencyKey,
    });
    if (duplicate) return duplicate;
    throw d1ReservationTransitionFailureError(finalized.reservationTransition);
  }
  return record;
}

async function finalizeSponsoredPrepaidSettlementD1(
  input: D1PrepaidSettlementBuildInput,
): Promise<FinalizedSponsoredPrepaidSettlementD1> {
  const reservationHandle = input.prepaidSettlementInput.reservation;
  if (!reservationHandle) {
    return {
      settlement: null,
      billingLedgerEntryId: null,
      statements: [],
      reservationTransition: NO_D1_RESERVATION_TRANSITION,
    };
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
    return {
      settlement: null,
      billingLedgerEntryId: null,
      statements: [],
      reservationTransition: NO_D1_RESERVATION_TRANSITION,
    };
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
  let reservationTransition: D1ReservationTransition = NO_D1_RESERVATION_TRANSITION;
  switch (input.reservation.status) {
    case 'RESERVED': {
      const statementIndex = statements.length;
      statements.push(
        createReleaseConsoleBillingPrepaidReservationD1Statement({
          runtime: input.prepaidRuntime,
          ctx: input.billingContext,
          reservation: input.reservation,
          updatedAtMs: input.settledAtMs,
        }),
      );
      reservationTransition = {
        kind: 'required',
        action: 'release',
        statementIndex,
        sourceEventId: input.reservation.sourceEventId,
      };
      break;
    }
    case 'RELEASED':
    case 'EXPIRED':
      throw new ConsoleBillingPrepaidReservationError(
        'invalid_state',
        409,
        'Released or expired prepaid reservations cannot create a new sponsored execution record',
      );
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
    reservationTransition,
  };
}

function buildSettledD1PrepaidSettlement(
  input: D1SettledReservationInput,
): FinalizedSponsoredPrepaidSettlementD1 {
  const statements: D1PreparedStatementLike[] = [];
  let reservationTransition: D1ReservationTransition = NO_D1_RESERVATION_TRANSITION;
  switch (input.reservation.status) {
    case 'RESERVED': {
      const statementIndex = statements.length;
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
      reservationTransition = {
        kind: 'required',
        action: 'settle',
        statementIndex,
        sourceEventId: input.reservation.sourceEventId,
      };
      break;
    }
    case 'SETTLED':
      throw new ConsoleBillingPrepaidReservationError(
        'invalid_state',
        409,
        'Settled prepaid reservations cannot create a new sponsored execution record',
      );
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
        insertGuard: D1_PREVIOUS_STATEMENT_CHANGED_ONE_INSERT_GUARD,
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
    reservationTransition,
  };
}
