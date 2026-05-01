import type { AccountId } from '@/core/types/accountIds';
import type { SigningSessionStatus } from '@/core/types/seams';
import {
  normalizeWalletSigningSpendPlan,
  summarizeSigningLane,
  type BackingMaterialSessionId,
  type SigningLaneContext,
  type SigningLaneSummary,
  type SigningOperationContext,
  type SigningOperationId,
  type ThresholdSessionId,
  type WalletSigningSpendPlan,
} from './types';
import { budgetUnknownSigningSessionStatus } from './budgetProjection';

export type SigningSessionBudgetZeroSpendReason =
  | 'confirmation_cancelled'
  | 'email_otp_failed'
  | 'passkey_failed'
  | 'nonce_preparation_failed'
  | 'signing_failed';

export type SigningSessionBudgetTraceEvent = {
  event:
    | 'wallet_signing_budget_reservation_started'
    | 'wallet_signing_budget_reservation_succeeded'
    | 'wallet_signing_budget_reservation_deduped'
    | 'wallet_signing_budget_reservation_released'
    | 'wallet_signing_budget_reservation_failed'
    | 'wallet_signing_budget_spend_started'
    | 'wallet_signing_budget_spend_deduped'
    | 'wallet_signing_budget_spend_succeeded'
    | 'wallet_signing_budget_spend_failed'
    | 'wallet_signing_budget_zero_spend_recorded';
  operationId: SigningOperationId;
  nearAccountId: AccountId;
  lane: SigningLaneSummary;
  reason: WalletSigningSpendPlan['reason'];
  uses: WalletSigningSpendPlan['uses'];
  thresholdSessionCount: number;
  backingMaterialSessionCount: number;
  status?: Pick<SigningSessionStatus, 'status' | 'remainingUses' | 'expiresAtMs'>;
  error?: string;
  zeroSpendReason?: SigningSessionBudgetZeroSpendReason;
};

export type SigningSessionBudgetRecordSuccessInput = {
  spend: WalletSigningSpendPlan;
  expectedBudgetProjectionVersion?: string;
  trustedStatusAuth?: SigningSessionBudgetStatusAuth;
  alreadyConsumedBackingMaterialSessionIds?: readonly string[];
  alreadyConsumedThresholdSessionIds?: readonly string[];
};

export type SigningSessionBudgetReserveInput = SigningSessionBudgetRecordSuccessInput & {
  expectedBudgetProjectionVersion: string;
};

export type SigningSessionBudgetReservationRecord = SigningSessionBudgetRecordSuccessInput & {
  operationFingerprint: string;
  walletSigningSessionId: string;
  reservedAgainstProjectionVersion: string;
  reservedAgainstRemainingUses: number;
  createdAtMs: number;
};

export type SigningSessionBudgetRecordZeroSpendInput = {
  spend: WalletSigningSpendPlan;
  reason: SigningSessionBudgetZeroSpendReason;
  error?: unknown;
};

export type SigningSessionBudgetReservation = {
  operationId: SigningOperationId;
  release(reason?: SigningSessionBudgetZeroSpendReason): void;
};

export type SigningSessionBudgetStatusReader = (args: {
  nearAccountId: AccountId | string;
  walletSigningSessionId?: string;
  targetBackingMaterialSessionIds?: string[];
  targetThresholdSessionIds?: string[];
  trustedStatusAuth?: SigningSessionBudgetStatusAuth;
}) => Promise<SigningSessionStatus | null>;

export type SigningSessionBudgetStatusAuth = {
  relayerUrl: string;
  thresholdSessionId: string;
  thresholdSessionJwt?: string;
};

export type SigningSessionBudgetConsumer = (args: {
  nearAccountId: AccountId | string;
  walletSigningSessionId: string;
  uses: number;
  reason: WalletSigningSpendPlan['reason'];
  targetBackingMaterialSessionIds?: string[];
  targetThresholdSessionIds?: string[];
  alreadyConsumedBackingMaterialSessionIds?: string[];
  alreadyConsumedThresholdSessionIds?: string[];
  trustedStatusAuth?: SigningSessionBudgetStatusAuth;
}) => Promise<SigningSessionStatus>;

export type SigningSessionBudgetDeps = {
  getStatus?: SigningSessionBudgetStatusReader;
  consumeUse?: SigningSessionBudgetConsumer;
  onTrace?: (event: SigningSessionBudgetTraceEvent) => void;
};

export type SigningSessionPreparedBudgetIdentity = {
  walletSigningSessionId: string;
  projectionVersion: string;
  status: SigningSessionStatus & { status: 'active'; projectionVersion: string };
};

export type SigningSessionBudget = {
  reserve(
    input: SigningSessionBudgetReserveInput,
  ): Promise<SigningSessionBudgetReservation | null>;
  getAvailableStatus(input: {
    nearAccountId: AccountId | string;
    walletSigningSessionId: string;
    targetBackingMaterialSessionIds?: readonly string[];
    targetThresholdSessionIds?: readonly string[];
    trustedStatusAuth?: SigningSessionBudgetStatusAuth;
  }): Promise<SigningSessionStatus | null>;
  recordSuccess(
    input: SigningSessionBudgetRecordSuccessInput,
  ): Promise<SigningSessionStatus | null>;
  recordZeroSpend(input: SigningSessionBudgetRecordZeroSpendInput): void;
  hasRecorded(operationId: SigningOperationId): boolean;
};

export const SIGNING_SESSION_BUDGET_EXHAUSTED_ERROR =
  '[SigningSessionBudget] wallet signing-session budget is exhausted';
export const SIGNING_SESSION_BUDGET_UNKNOWN_ERROR =
  '[SigningSessionBudget] wallet signing-session budget is budget_unknown';
export const SIGNING_SESSION_BUDGET_IN_FLIGHT_ERROR =
  '[SigningSessionBudget] wallet signing-session budget is reserved by in-flight operations';

export function isSigningSessionBudgetExhaustedError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error || '');
  return message.includes(SIGNING_SESSION_BUDGET_EXHAUSTED_ERROR);
}

export function isSigningSessionBudgetUnknownError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error || '');
  return message.includes(SIGNING_SESSION_BUDGET_UNKNOWN_ERROR);
}

export function isSigningSessionBudgetInFlightError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error || '');
  return message.includes(SIGNING_SESSION_BUDGET_IN_FLIGHT_ERROR);
}

export function applySigningSessionBudgetReservationsToStatus(args: {
  status: SigningSessionStatus;
  walletSigningSessionId: string;
  reservationsByOperationId: Map<string, SigningSessionBudgetReservationRecord>;
}): SigningSessionStatus {
  if (args.status.status !== 'active') return args.status;
  const remainingUses = Math.max(0, Math.floor(Number(args.status.remainingUses) || 0));
  const projectionVersion = String(args.status.projectionVersion || '').trim();
  const inFlightReservedUses = getSameProjectionReservedUses({
    reservationsByOperationId: args.reservationsByOperationId,
    walletSigningSessionId: args.walletSigningSessionId,
    projectionVersion,
  });
  const availableUses = Math.max(0, remainingUses - inFlightReservedUses);
  // remainingUses is the server-trusted budget. Local reservations are only
  // in-flight availability hints when they were admitted against the same
  // trusted projection. Opaque projection-version mismatches are non-subtracting
  // to avoid double counting server consumes that have already landed.
  return {
    ...args.status,
    remainingUses,
    inFlightReservedUses,
    availableUses,
  };
}

export async function assertSigningSessionBudgetReservationAvailable(args: {
  getStatus?: SigningSessionBudgetStatusReader;
  input: SigningSessionBudgetRecordSuccessInput;
  reservationsByOperationId: Map<string, SigningSessionBudgetReservationRecord>;
}): Promise<SigningSessionStatus & { status: 'active'; projectionVersion: string }> {
  const spend = args.input.spend;
  if (!args.getStatus) {
    throw budgetUnknownError(spend, 'adapter_unavailable');
  }
  const status = await args.getStatus({
    nearAccountId: spend.nearAccountId,
    walletSigningSessionId: spend.walletSigningSessionId,
    targetBackingMaterialSessionIds: normalizeStringList(spend.backingMaterialSessionIds),
    targetThresholdSessionIds: normalizeStringList(spend.thresholdSessionIds),
    trustedStatusAuth: args.input.trustedStatusAuth,
  });
  if (!status) {
    throw budgetUnknownError(spend, 'missing_trusted_status');
  }
  if (status.status === 'budget_unknown') {
    throw budgetUnknownError(spend, status.statusCode || 'missing_trusted_status');
  }
  if (status.status === 'not_found') {
    throw new Error(
      [
        '[SigningSessionBudget] wallet signing-session budget is not_found',
        formatSpendIdentityForError(spend),
      ].join(' '),
    );
  }
  if (status.status !== 'active') {
    throw new Error(
      `[SigningSessionBudget] wallet signing-session budget is ${status.status}`,
    );
  }
  const projectionVersion = String(status.projectionVersion || '').trim();
  if (!projectionVersion) {
    throw new Error('[SigningSessionBudget] trusted budget status is missing projection version');
  }
  const remainingUses = Math.floor(Number(status.remainingUses) || 0);
  const reservedUses = getSameProjectionReservedUses({
    reservationsByOperationId: args.reservationsByOperationId,
    walletSigningSessionId: spend.walletSigningSessionId,
    projectionVersion,
  });
  if (remainingUses - reservedUses < spend.uses) {
    if (remainingUses >= spend.uses) {
      throw new Error(SIGNING_SESSION_BUDGET_IN_FLIGHT_ERROR);
    }
    throw new Error(SIGNING_SESSION_BUDGET_EXHAUSTED_ERROR);
  }
  const expectedProjectionVersion = String(args.input.expectedBudgetProjectionVersion || '').trim();
  if (!expectedProjectionVersion) {
    throw new Error('[SigningSessionBudget] prepared budget projection version is required');
  }
  return status as SigningSessionStatus & { status: 'active'; projectionVersion: string };
}

export function getSameProjectionReservedUses(args: {
  reservationsByOperationId: Map<string, SigningSessionBudgetReservationRecord>;
  walletSigningSessionId: string;
  projectionVersion?: string;
}): number {
  const walletSigningSessionId = String(args.walletSigningSessionId || '').trim();
  const projectionVersion = String(args.projectionVersion || '').trim();
  if (!walletSigningSessionId || !projectionVersion) return 0;
  let uses = 0;
  for (const reservation of args.reservationsByOperationId.values()) {
    if (reservation.walletSigningSessionId !== walletSigningSessionId) continue;
    if (reservation.reservedAgainstProjectionVersion !== projectionVersion) continue;
    uses += Math.max(0, Math.floor(Number(reservation.spend.uses) || 0));
  }
  return uses;
}

export function budgetUnknownStatusForSpend(
  spend: WalletSigningSpendPlan,
  reason: string = 'missing_trusted_status',
): SigningSessionStatus {
  return budgetUnknownSigningSessionStatus({
    walletSigningSessionId: spend.walletSigningSessionId,
    reason:
      reason === 'adapter_unavailable' ||
      reason === 'status_unavailable' ||
      reason === 'missing_trusted_status'
        ? reason
        : 'missing_trusted_status',
  });
}

function budgetUnknownError(spend: WalletSigningSpendPlan, reason: string): Error {
  return new Error(
    [
      SIGNING_SESSION_BUDGET_UNKNOWN_ERROR,
      `reason=${reason || 'missing_trusted_status'}`,
      formatSpendIdentityForError(spend),
    ].join(' '),
  );
}

function formatSpendIdentityForError(spend: WalletSigningSpendPlan): string {
  return [
    `walletSigningSessionId=${spend.walletSigningSessionId}`,
    `thresholdSessionIds=${normalizeStringList(spend.thresholdSessionIds)?.join(',') || 'none'}`,
    `backingMaterialSessionIds=${normalizeStringList(spend.backingMaterialSessionIds)?.join(',') || 'none'}`,
  ].join(' ');
}

export function normalizeSigningSessionBudgetRecordSuccessInput(
  input: SigningSessionBudgetRecordSuccessInput,
): SigningSessionBudgetRecordSuccessInput {
  return {
    ...input,
    spend: normalizeWalletSigningSpendPlan(input.spend),
  };
}

export function resolveWalletSigningOperationFingerprint(spend: WalletSigningSpendPlan): string {
  return String(spend.operationFingerprint || `operation-id:${spend.operationId}`).trim();
}

export function assertWalletSigningOperationFingerprintMatches(args: {
  operationId: string;
  existingFingerprint: string;
  nextFingerprint: string;
}): void {
  if (args.existingFingerprint === args.nextFingerprint) return;
  throw new Error(
    `[SigningSessionBudget] signing operation id reused for a different operation: ${args.operationId}`,
  );
}

export function summarizeWalletSigningSessionStatus(
  status: SigningSessionStatus,
): SigningSessionBudgetTraceEvent['status'] {
  return {
    status: status.status,
    remainingUses: status.remainingUses,
    expiresAtMs: status.expiresAtMs,
  };
}

export function assertPreparedBudgetProjectionVersion(args: {
  status: SigningSessionStatus;
  expectedBudgetProjectionVersion?: string;
}): void {
  const expected = String(args.expectedBudgetProjectionVersion || '').trim();
  if (!expected) {
    throw new Error('[SigningSessionBudget] prepared budget projection version is required');
  }
  const actual = String(args.status.projectionVersion || '').trim();
  if (!actual) {
    throw new Error('[SigningSessionBudget] trusted budget status is missing projection version');
  }
  if (actual !== expected) {
    throw new Error('[SigningSessionBudget] prepared budget projection is stale');
  }
}

export function createSigningSessionBudgetTraceEvent(
  input: SigningSessionBudgetRecordSuccessInput,
  event: SigningSessionBudgetTraceEvent['event'],
  extra: Pick<SigningSessionBudgetTraceEvent, 'status' | 'error' | 'zeroSpendReason'> = {},
): SigningSessionBudgetTraceEvent {
  const spend = input.spend;
  return {
    event,
    operationId: spend.operationId,
    nearAccountId: spend.nearAccountId,
    lane: summarizeSigningLane(spend.lane),
    reason: spend.reason,
    uses: spend.uses,
    thresholdSessionCount: spend.thresholdSessionIds.length,
    backingMaterialSessionCount: spend.backingMaterialSessionIds.length,
    ...extra,
  };
}

export function normalizeRequired(value: unknown, label: string): string {
  const normalized = String(value || '').trim();
  if (!normalized) {
    throw new Error(`[SigningSessionBudget] ${label} is required`);
  }
  return normalized;
}

export function normalizeStringList(values: readonly string[] | undefined): string[] | undefined {
  const normalized = (values || []).map((value) => String(value || '').trim()).filter(Boolean);
  return normalized.length ? normalized : undefined;
}

export function buildWalletSigningSpendPlan(
  operation: SigningOperationContext,
  lane: SigningLaneContext,
  refs: {
    thresholdSessionId?: ThresholdSessionId;
    backingMaterialSessionId?: BackingMaterialSessionId;
  } = {},
): WalletSigningSpendPlan {
  return {
    operationId: operation.operationId,
    ...(operation.operationFingerprint
      ? { operationFingerprint: operation.operationFingerprint }
      : {}),
    nearAccountId: lane.accountId,
    walletSigningSessionId: lane.walletSigningSessionId,
    lane,
    thresholdSessionIds: uniqueDefined([lane.thresholdSessionId, refs.thresholdSessionId]),
    backingMaterialSessionIds: uniqueDefined([
      lane.backingMaterialSessionId,
      refs.backingMaterialSessionId,
    ]),
    uses: 1,
    reason: operation.intent,
  };
}

function uniqueDefined<TValue extends string>(values: readonly (TValue | undefined)[]): TValue[] {
  const out: TValue[] = [];
  const seen = new Set<string>();

  for (const value of values) {
    if (!value || seen.has(value)) {
      continue;
    }
    seen.add(value);
    out.push(value);
  }

  return out;
}
