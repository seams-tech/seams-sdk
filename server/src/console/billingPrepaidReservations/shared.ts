import { ConsoleBillingPrepaidReservationError } from './errors';
import type {
  ConsoleBillingPrepaidReservation,
  ConsoleBillingPrepaidReservationSummary,
  ExpireConsoleBillingPrepaidReservationsRequest,
  ReleaseConsoleBillingPrepaidReservationRequest,
  ReserveConsoleBillingPrepaidReservationRequest,
  SettleConsoleBillingPrepaidReservationRequest,
} from './types';

export function toIso(date: Date): string {
  return date.toISOString();
}

function toInteger(value: unknown, field: string): number {
  const parsed = typeof value === 'number' ? value : Number(value);
  if (!Number.isInteger(parsed)) {
    throw new ConsoleBillingPrepaidReservationError(
      'invalid_request',
      400,
      `${field} must be an integer`,
    );
  }
  return parsed;
}

function toNonNegativeInteger(value: unknown, field: string): number {
  const parsed = toInteger(value, field);
  if (parsed < 0) {
    throw new ConsoleBillingPrepaidReservationError(
      'invalid_request',
      400,
      `${field} must be a non-negative integer`,
    );
  }
  return parsed;
}

function normalizeOptionalString(value: unknown): string | null {
  const normalized = String(value || '').trim();
  return normalized || null;
}

export function normalizeReserveRequest(
  request: ReserveConsoleBillingPrepaidReservationRequest,
  now: Date,
  defaultReservationTtlMs: number,
): Required<Omit<ReserveConsoleBillingPrepaidReservationRequest, 'policyId'>> & {
  policyId: string | null;
  expiresAtMs: number;
  expiresAt: string;
} {
  const sourceEventId = String(request.sourceEventId || '').trim();
  if (!sourceEventId) {
    throw new ConsoleBillingPrepaidReservationError(
      'invalid_request',
      400,
      'sourceEventId is required',
    );
  }
  const environmentId = String(request.environmentId || '').trim();
  if (!environmentId) {
    throw new ConsoleBillingPrepaidReservationError(
      'invalid_request',
      400,
      'environmentId is required',
    );
  }
  const postedBalanceMinor = toInteger(request.postedBalanceMinor, 'postedBalanceMinor');
  const estimatedSpendMinor = toNonNegativeInteger(
    request.estimatedSpendMinor,
    'estimatedSpendMinor',
  );
  if (estimatedSpendMinor <= 0) {
    throw new ConsoleBillingPrepaidReservationError(
      'invalid_request',
      400,
      'estimatedSpendMinor must be positive',
    );
  }
  const ttlMs = Math.max(1, Math.trunc(defaultReservationTtlMs));
  const expiresAtMs = request.expiresAt ? Date.parse(request.expiresAt) : now.getTime() + ttlMs;
  if (!Number.isFinite(expiresAtMs) || expiresAtMs <= now.getTime()) {
    throw new ConsoleBillingPrepaidReservationError(
      'invalid_request',
      400,
      'expiresAt must be a future ISO-8601 datetime',
    );
  }
  return {
    sourceEventId,
    environmentId,
    policyId: normalizeOptionalString(request.policyId),
    postedBalanceMinor,
    estimatedSpendMinor,
    expiresAt: new Date(expiresAtMs).toISOString(),
    expiresAtMs,
  };
}

export function normalizeSettleRequest(
  request: SettleConsoleBillingPrepaidReservationRequest,
): {
  sourceEventId: string;
  settledSpendMinor: number;
  txOrExecutionRef: string | null;
  pricingVersion: string | null;
} {
  const sourceEventId = String(request.sourceEventId || '').trim();
  if (!sourceEventId) {
    throw new ConsoleBillingPrepaidReservationError(
      'invalid_request',
      400,
      'sourceEventId is required',
    );
  }
  return {
    sourceEventId,
    settledSpendMinor: toNonNegativeInteger(request.settledSpendMinor, 'settledSpendMinor'),
    txOrExecutionRef: normalizeOptionalString(request.txOrExecutionRef),
    pricingVersion: normalizeOptionalString(request.pricingVersion),
  };
}

export function normalizeReleaseRequest(
  request: ReleaseConsoleBillingPrepaidReservationRequest,
): { sourceEventId: string } {
  const sourceEventId = String(request.sourceEventId || '').trim();
  if (!sourceEventId) {
    throw new ConsoleBillingPrepaidReservationError(
      'invalid_request',
      400,
      'sourceEventId is required',
    );
  }
  return { sourceEventId };
}

export function normalizeExpireRequest(
  request: ExpireConsoleBillingPrepaidReservationsRequest | undefined,
  now: Date,
): { atMs: number; limit: number } {
  const at = request?.at || now;
  const atMs = at.getTime();
  if (!Number.isFinite(atMs)) {
    throw new ConsoleBillingPrepaidReservationError('invalid_request', 400, 'Invalid at value');
  }
  const rawLimit = Number(request?.limit);
  const limit =
    Number.isInteger(rawLimit) && rawLimit > 0 ? Math.min(rawLimit, 10_000) : 500;
  return {
    atMs,
    limit,
  };
}

export function buildEmptySummary(orgId: string, updatedAt: string): ConsoleBillingPrepaidReservationSummary {
  return {
    orgId,
    reservedMinor: 0,
    activeReservationCount: 0,
    createdAt: updatedAt,
    updatedAt,
  };
}

export function cloneReservation(
  reservation: ConsoleBillingPrepaidReservation,
): ConsoleBillingPrepaidReservation {
  return { ...reservation };
}

export function cloneSummary(
  summary: ConsoleBillingPrepaidReservationSummary,
): ConsoleBillingPrepaidReservationSummary {
  return { ...summary };
}

export function createInsufficientAvailableBalanceError(input: {
  postedBalanceMinor: number;
  reservedMinor: number;
  requestedMinor: number;
}): ConsoleBillingPrepaidReservationError {
  const availableBalanceMinor = input.postedBalanceMinor - input.reservedMinor;
  return new ConsoleBillingPrepaidReservationError(
    'prepaid_balance_insufficient',
    409,
    'Prepaid balance is insufficient for the requested sponsored spend reservation',
    {
      postedBalanceMinor: input.postedBalanceMinor,
      reservedMinor: input.reservedMinor,
      requestedMinor: input.requestedMinor,
      availableBalanceMinor,
    },
  );
}
