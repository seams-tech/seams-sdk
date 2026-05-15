import type { AccountId } from '@/core/types/accountIds';
import type { SigningSessionStatus } from '@/core/types/seams';
import {
  normalizeWalletSigningSpendPlan,
  SigningOperationIntent,
  summarizeSigningLane,
  type BackingMaterialSessionId,
  type SelectedSigningSessionPlanningLane,
  type SigningLaneSummary,
  type SigningOperationContext,
  type SigningOperationId,
  type ThresholdSessionId,
  type WalletSigningSessionId,
  type WalletSigningSpendPlan,
} from '../operationState/types';
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
  walletId: AccountId;
  lane: SigningLaneSummary;
  reason: WalletSigningSpendPlan['reason'];
  uses: WalletSigningSpendPlan['uses'];
  thresholdSessionCount: number;
  backingMaterialSessionCount: number;
  status?: Pick<SigningSessionStatus, 'status' | 'remainingUses' | 'expiresAtMs'>;
  error?: string;
  zeroSpendReason?: SigningSessionBudgetZeroSpendReason;
};

export type WalletBudgetSpend = WalletSigningSpendPlan;

export type ReservedWalletBudgetSpend = {
  kind: 'reserved_success';
  spend: WalletBudgetSpend;
  expectedBudgetProjectionVersion: string;
  trustedStatusAuth?: SigningSessionBudgetStatusAuth;
};

export type UnreservedWalletBudgetSpend = {
  kind: 'unreserved_success';
  spend: WalletBudgetSpend;
  expectedBudgetProjectionVersion: string;
  trustedStatusAuth?: SigningSessionBudgetStatusAuth;
};

type NonEmptyConsumedSessionIdList<TValue extends string = string> = readonly [TValue, ...TValue[]];

type ExternallyConsumedBackingMaterialWalletBudgetSpend = {
  kind: 'externally_consumed_success';
  spend: WalletBudgetSpend;
  trustedStatusAuth?: SigningSessionBudgetStatusAuth;
  alreadyConsumedBackingMaterialSessionIds: NonEmptyConsumedSessionIdList<BackingMaterialSessionId>;
  alreadyConsumedThresholdSessionIds?: readonly ThresholdSessionId[];
};

type ExternallyConsumedThresholdWalletBudgetSpend = {
  kind: 'externally_consumed_success';
  spend: WalletBudgetSpend;
  trustedStatusAuth?: SigningSessionBudgetStatusAuth;
  alreadyConsumedBackingMaterialSessionIds?: readonly BackingMaterialSessionId[];
  alreadyConsumedThresholdSessionIds: NonEmptyConsumedSessionIdList<ThresholdSessionId>;
};

export type ExternallyConsumedWalletBudgetSpend =
  | ExternallyConsumedBackingMaterialWalletBudgetSpend
  | ExternallyConsumedThresholdWalletBudgetSpend;

export type ZeroWalletBudgetSpend = {
  kind: 'zero_spend';
  operationId: SigningOperationId;
  lane: SelectedSigningSessionPlanningLane;
  reason: SigningSessionBudgetZeroSpendReason;
  error?: unknown;
};

export type BudgetFinalizationSpend =
  | ReservedBudgetFinalizationSpend
  | UnreservedBudgetFinalizationSpend
  | ExternallyConsumedBudgetFinalizationSpend
  | ZeroBudgetFinalizationSpend;

export type ReservedBudgetFinalizationSpend = ReservedWalletBudgetSpend;
export type UnreservedBudgetFinalizationSpend = UnreservedWalletBudgetSpend;
export type ExternallyConsumedBudgetFinalizationSpend = ExternallyConsumedWalletBudgetSpend;
export type ZeroBudgetFinalizationSpend = ZeroWalletBudgetSpend;

export type SigningSessionBudgetSuccessInput =
  | ReservedWalletBudgetSpend
  | UnreservedWalletBudgetSpend
  | ExternallyConsumedWalletBudgetSpend;

export type SigningSessionBudgetReserveInput = {
  spend: WalletSigningSpendPlan;
  expectedBudgetProjectionVersion?: string;
  trustedStatusAuth?: SigningSessionBudgetStatusAuth;
};

export type SigningSessionBudgetReservationRecord = SigningSessionBudgetReserveInput & {
  operationFingerprint: string;
  walletSigningSessionId: string;
  reservedAgainstProjectionVersion: string;
  reservedAgainstRemainingUses: number;
  createdAtMs: number;
};

export type SigningSessionBudgetReservation = {
  operationId: SigningOperationId;
  release(reason?: SigningSessionBudgetZeroSpendReason): void;
};

export type WalletBudgetStatusCheck = {
  kind: 'wallet_budget_status_check';
  walletId: AccountId | string;
  walletSigningSessionId: WalletSigningSessionId | string;
  targetBackingMaterialSessionIds?: never;
  targetThresholdSessionIds?: never;
  trustedStatusAuth?: never;
};

export type BackingMaterialBudgetStatusCheck = {
  kind: 'backing_material_budget_status_check';
  walletId: AccountId | string;
  walletSigningSessionId: WalletSigningSessionId | string;
  targetBackingMaterialSessionIds: readonly [
    BackingMaterialSessionId | string,
    ...(BackingMaterialSessionId | string)[],
  ];
  targetThresholdSessionIds?: never;
  trustedStatusAuth?: never;
};

export type ThresholdBudgetStatusCheck = {
  kind: 'threshold_budget_status_check';
  walletId: AccountId | string;
  walletSigningSessionId: WalletSigningSessionId | string;
  targetThresholdSessionIds: readonly [ThresholdSessionId | string, ...(ThresholdSessionId | string)[]];
  targetBackingMaterialSessionIds?: never;
  trustedStatusAuth?: never;
};

export type AuthenticatedThresholdBudgetStatusCheck = {
  kind: 'authenticated_threshold_budget_status_check';
  walletId: AccountId | string;
  walletSigningSessionId: WalletSigningSessionId | string;
  targetThresholdSessionIds: readonly [ThresholdSessionId | string, ...(ThresholdSessionId | string)[]];
  trustedStatusAuth: SigningSessionBudgetStatusAuth;
  targetBackingMaterialSessionIds?: never;
};

export type SigningSessionBudgetStatusCheck =
  | WalletBudgetStatusCheck
  | BackingMaterialBudgetStatusCheck
  | ThresholdBudgetStatusCheck
  | AuthenticatedThresholdBudgetStatusCheck;

export type SigningSessionBudgetStatusReader = (
  args: SigningSessionBudgetStatusCheck,
) => Promise<SigningSessionStatus | null>;

export type SigningSessionBudgetStatusAuth = {
  relayerUrl: string;
  thresholdSessionId: string;
  thresholdSessionAuthToken?: string;
};

export type SigningSessionBudgetConsumer = (args: {
  walletId: AccountId | string;
  walletSigningSessionId: string;
  uses: number;
  reason: WalletSigningSpendPlan['reason'];
  budgetStatusCheck: SigningSessionBudgetStatusCheck;
  alreadyConsumedBackingMaterialSessionIds?: string[];
  alreadyConsumedThresholdSessionIds?: string[];
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
  reserve(input: SigningSessionBudgetReserveInput): Promise<SigningSessionBudgetReservation | null>;
  getAvailableStatus(input: SigningSessionBudgetStatusCheck): Promise<SigningSessionStatus | null>;
  recordSuccess(input: SigningSessionBudgetSuccessInput): Promise<SigningSessionStatus | null>;
  recordZeroSpend(input: ZeroWalletBudgetSpend): void;
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
  input: SigningSessionBudgetReserveInput;
  reservationsByOperationId: Map<string, SigningSessionBudgetReservationRecord>;
}): Promise<SigningSessionStatus & { status: 'active'; projectionVersion: string }> {
  const spend = args.input.spend;
  if (!args.getStatus) {
    throw budgetUnknownError(spend, 'adapter_unavailable');
  }
  const status = await args.getStatus(
    buildSigningSessionBudgetStatusCheckForSpend({
      spend,
      trustedStatusAuth: args.input.trustedStatusAuth,
    }),
  );
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
    throw new Error(`[SigningSessionBudget] wallet signing-session budget is ${status.status}`);
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

export function normalizeWalletBudgetSuccessInput<
  TInput extends SigningSessionBudgetSuccessInput,
>(input: TInput): TInput {
  const normalized = {
    ...input,
    spend: normalizeWalletSigningSpendPlan(input.spend),
  } as TInput;
  if (normalized.kind !== 'externally_consumed_success') {
    return normalized;
  }
  const alreadyConsumedBackingMaterialSessionIds = normalizeStringList(
    normalized.alreadyConsumedBackingMaterialSessionIds,
  ) as BackingMaterialSessionId[] | undefined;
  const alreadyConsumedThresholdSessionIds = normalizeStringList(
    normalized.alreadyConsumedThresholdSessionIds,
  ) as ThresholdSessionId[] | undefined;
  if (
    !alreadyConsumedBackingMaterialSessionIds?.length &&
    !alreadyConsumedThresholdSessionIds?.length
  ) {
    throw new Error(
      '[SigningSessionBudget] externally_consumed_success requires consumed session identities',
    );
  }
  return {
    ...normalized,
    ...(alreadyConsumedBackingMaterialSessionIds
      ? {
          alreadyConsumedBackingMaterialSessionIds,
        }
      : {}),
    ...(alreadyConsumedThresholdSessionIds
      ? {
          alreadyConsumedThresholdSessionIds,
        }
      : {}),
  } as TInput;
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
  input: { spend: WalletBudgetSpend },
  event: SigningSessionBudgetTraceEvent['event'],
  extra: Pick<SigningSessionBudgetTraceEvent, 'status' | 'error' | 'zeroSpendReason'> = {},
): SigningSessionBudgetTraceEvent {
  const spend = input.spend;
  return {
    event,
    operationId: spend.operationId,
    walletId: spend.walletId,
    lane: summarizeSigningLane(spend.lane),
    reason: spend.reason,
    uses: spend.uses,
    thresholdSessionCount: spend.thresholdSessionIds.length,
    backingMaterialSessionCount: spend.backingMaterialSessionIds.length,
    ...extra,
  };
}

export function createZeroSpendTraceEvent(
  input: ZeroWalletBudgetSpend,
  event: Extract<
    SigningSessionBudgetTraceEvent['event'],
    'wallet_signing_budget_reservation_released' | 'wallet_signing_budget_zero_spend_recorded'
  >,
  extra: Pick<SigningSessionBudgetTraceEvent, 'status' | 'error' | 'zeroSpendReason'> = {},
): SigningSessionBudgetTraceEvent {
  return {
    event,
    operationId: input.operationId,
    walletId: input.lane.curve === 'ecdsa' ? input.lane.walletId : input.lane.accountId,
    lane: summarizeSigningLane(input.lane),
    reason: SigningOperationIntent.TransactionSign,
    uses: 1,
    thresholdSessionCount: input.lane.thresholdSessionId ? 1 : 0,
    backingMaterialSessionCount: input.lane.backingMaterialSessionId ? 1 : 0,
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
  lane: SelectedSigningSessionPlanningLane,
): WalletSigningSpendPlan {
  return {
    operationId: operation.operationId,
    ...(operation.operationFingerprint
      ? { operationFingerprint: operation.operationFingerprint }
      : {}),
    walletId: lane.curve === 'ecdsa' ? lane.walletId : lane.accountId,
    walletSigningSessionId: lane.walletSigningSessionId,
    lane,
    thresholdSessionIds: uniqueDefined([lane.thresholdSessionId]),
    backingMaterialSessionIds: uniqueDefined([lane.backingMaterialSessionId]),
    uses: 1,
    reason: operation.intent,
  };
}

export function buildWalletBudgetStatusCheck(args: {
  walletId: AccountId | string;
  walletSigningSessionId: WalletSigningSessionId | string;
}): WalletBudgetStatusCheck {
  return {
    kind: 'wallet_budget_status_check',
    walletId: args.walletId,
    walletSigningSessionId: normalizeRequired(
      args.walletSigningSessionId,
      'walletSigningSessionId',
    ) as WalletSigningSessionId,
  };
}

export function buildBackingMaterialBudgetStatusCheck(args: {
  walletId: AccountId | string;
  walletSigningSessionId: WalletSigningSessionId | string;
  targetBackingMaterialSessionIds: readonly (BackingMaterialSessionId | string)[];
}): BackingMaterialBudgetStatusCheck {
  const targetBackingMaterialSessionIds = normalizeStringList(
    args.targetBackingMaterialSessionIds,
  ) as BackingMaterialSessionId[] | undefined;
  if (!targetBackingMaterialSessionIds?.length) {
    throw new Error('[SigningSessionBudget] targetBackingMaterialSessionIds are required');
  }
  return {
    kind: 'backing_material_budget_status_check',
    walletId: args.walletId,
    walletSigningSessionId: normalizeRequired(
      args.walletSigningSessionId,
      'walletSigningSessionId',
    ) as WalletSigningSessionId,
    targetBackingMaterialSessionIds: [
      targetBackingMaterialSessionIds[0],
      ...targetBackingMaterialSessionIds.slice(1),
    ],
  };
}

export function buildThresholdBudgetStatusCheck(args: {
  walletId: AccountId | string;
  walletSigningSessionId: WalletSigningSessionId | string;
  targetThresholdSessionIds: readonly (ThresholdSessionId | string)[];
}): ThresholdBudgetStatusCheck {
  const targetThresholdSessionIds = normalizeStringList(
    args.targetThresholdSessionIds,
  ) as ThresholdSessionId[] | undefined;
  if (!targetThresholdSessionIds?.length) {
    throw new Error('[SigningSessionBudget] targetThresholdSessionIds are required');
  }
  return {
    kind: 'threshold_budget_status_check',
    walletId: args.walletId,
    walletSigningSessionId: normalizeRequired(
      args.walletSigningSessionId,
      'walletSigningSessionId',
    ) as WalletSigningSessionId,
    targetThresholdSessionIds: [targetThresholdSessionIds[0], ...targetThresholdSessionIds.slice(1)],
  };
}

export function buildAuthenticatedThresholdBudgetStatusCheck(args: {
  walletId: AccountId | string;
  walletSigningSessionId: WalletSigningSessionId | string;
  targetThresholdSessionIds: readonly (ThresholdSessionId | string)[];
  trustedStatusAuth: SigningSessionBudgetStatusAuth;
}): AuthenticatedThresholdBudgetStatusCheck {
  const thresholdCheck = buildThresholdBudgetStatusCheck(args);
  return {
    kind: 'authenticated_threshold_budget_status_check',
    walletId: thresholdCheck.walletId,
    walletSigningSessionId: thresholdCheck.walletSigningSessionId,
    targetThresholdSessionIds: thresholdCheck.targetThresholdSessionIds,
    trustedStatusAuth: args.trustedStatusAuth,
  };
}

export function buildSigningSessionBudgetStatusCheckForSpend(args: {
  spend: WalletSigningSpendPlan;
  trustedStatusAuth?: SigningSessionBudgetStatusAuth;
}): SigningSessionBudgetStatusCheck {
  if (args.trustedStatusAuth) {
    return buildAuthenticatedThresholdBudgetStatusCheck({
      walletId: args.spend.walletId,
      walletSigningSessionId: args.spend.walletSigningSessionId,
      targetThresholdSessionIds: args.spend.thresholdSessionIds,
      trustedStatusAuth: args.trustedStatusAuth,
    });
  }
  if (args.spend.thresholdSessionIds.length) {
    return buildThresholdBudgetStatusCheck({
      walletId: args.spend.walletId,
      walletSigningSessionId: args.spend.walletSigningSessionId,
      targetThresholdSessionIds: args.spend.thresholdSessionIds,
    });
  }
  if (args.spend.backingMaterialSessionIds.length) {
    return buildBackingMaterialBudgetStatusCheck({
      walletId: args.spend.walletId,
      walletSigningSessionId: args.spend.walletSigningSessionId,
      targetBackingMaterialSessionIds: args.spend.backingMaterialSessionIds,
    });
  }
  return buildWalletBudgetStatusCheck({
    walletId: args.spend.walletId,
    walletSigningSessionId: args.spend.walletSigningSessionId,
  });
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
