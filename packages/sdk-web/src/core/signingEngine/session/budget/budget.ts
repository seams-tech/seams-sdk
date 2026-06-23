import type { SigningSessionStatus } from '@/core/types/seams';
import { alphabetizeStringify } from '@shared/utils/digests';
import {
  normalizeWalletSigningSpendPlan,
  SigningOperationIntent,
  SigningSessionIds,
  summarizeSigningLane,
  type BackingMaterialSessionId,
  type EcdsaWalletSigningSpendPlan,
  type Ed25519WalletSigningSpendPlan,
  type SelectedSigningSessionPlanningLane,
  type SigningLaneSummary,
  type SigningOperationContext,
  type SigningOperationFingerprint,
  type SigningOperationId,
  type ThresholdEcdsaSessionId,
  type ThresholdSessionId,
  type SigningGrantId,
  type WalletSigningSpendPlan,
} from '../operationState/types';
import {
  exactSigningLaneIdentity,
  exactSigningLaneIdentityKey,
  thresholdSessionIdsFromExactSigningLaneIdentity,
  type ExactSigningLaneIdentity,
  type ExactSigningLaneIdentityKey,
  type NonEmptyThresholdSessionIds,
} from '../identity/exactSigningLaneIdentity';
import {
  toWalletId,
  type ThresholdEcdsaChainTarget,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  EvmFamilyEcdsaKeyHandle,
  EvmFamilyEcdsaKeyIdentity,
} from '../identity/evmFamilyEcdsaIdentity';
import { budgetUnknownSigningSessionStatus } from './budgetProjection';

export type SigningSessionBudgetZeroSpendReason =
  | 'confirmation_cancelled'
  | 'email_otp_failed'
  | 'passkey_failed'
  | 'nonce_preparation_failed'
  | 'signing_failed';

export type SigningSessionBudgetFinalizationTraceResult =
  | 'finalized'
  | 'already_finalized'
  | 'projection_mismatch'
  | 'missing_reservation'
  | 'reservation_identity_mismatch'
  | 'budget_status_unavailable';

export type SigningSessionBudgetTraceStatus = Pick<
  SigningSessionStatus,
  'status' | 'remainingUses' | 'expiresAtMs'
>;

export type SigningSessionBudgetTraceEventKind =
  | 'wallet_signing_budget_reservation_started'
  | 'wallet_signing_budget_reservation_succeeded'
  | 'wallet_signing_budget_reservation_deduped'
  | 'wallet_signing_budget_reservation_released'
  | 'wallet_signing_budget_reservation_failed'
  | 'wallet_signing_budget_spend_started'
  | 'wallet_signing_budget_spend_deduped'
  | 'wallet_signing_budget_spend_succeeded'
  | 'wallet_signing_budget_spend_failed'
  | 'wallet_signing_budget_finalization_finalized'
  | 'wallet_signing_budget_finalization_already_finalized'
  | 'wallet_signing_budget_finalization_projection_mismatch'
  | 'wallet_signing_budget_finalization_missing_reservation'
  | 'wallet_signing_budget_finalization_identity_mismatch'
  | 'wallet_signing_budget_finalization_status_unavailable'
  | 'wallet_signing_budget_zero_spend_recorded';

type SigningSessionBudgetTraceBase = {
  operationId: SigningOperationId;
  owner: WalletBudgetOwner;
  lane: SigningLaneSummary;
  reason: WalletSigningSpendPlan['reason'];
  uses: WalletSigningSpendPlan['uses'];
  thresholdSessionCount: number;
  backingMaterialSessionCount: number;
};

type SigningSessionBudgetTracePlainEvent = SigningSessionBudgetTraceBase & {
  event:
    | 'wallet_signing_budget_reservation_started'
    | 'wallet_signing_budget_reservation_deduped'
    | 'wallet_signing_budget_spend_started'
    | 'wallet_signing_budget_spend_deduped';
  status?: never;
  error?: never;
  finalizationResult?: never;
  zeroSpendReason?: never;
};

type SigningSessionBudgetTraceReservationReleasedEvent =
  | (SigningSessionBudgetTraceBase & {
      event: 'wallet_signing_budget_reservation_released';
      zeroSpendReason?: never;
      status?: never;
      error?: never;
      finalizationResult?: never;
    })
  | (SigningSessionBudgetTraceBase & {
      event: 'wallet_signing_budget_reservation_released';
      zeroSpendReason: SigningSessionBudgetZeroSpendReason;
      status?: never;
      error?: never;
      finalizationResult?: never;
    });

type SigningSessionBudgetTraceStatusEvent = SigningSessionBudgetTraceBase & {
  event:
    | 'wallet_signing_budget_reservation_succeeded'
    | 'wallet_signing_budget_spend_succeeded';
  status: SigningSessionBudgetTraceStatus;
  error?: never;
  finalizationResult?: never;
  zeroSpendReason?: never;
};

type SigningSessionBudgetTraceErrorEvent = SigningSessionBudgetTraceBase & {
  event:
    | 'wallet_signing_budget_reservation_failed'
    | 'wallet_signing_budget_spend_failed';
  error: string;
  status?: never;
  finalizationResult?: never;
  zeroSpendReason?: never;
};

type SigningSessionBudgetTraceFinalizationSuccessEvent = SigningSessionBudgetTraceBase & {
  event:
    | 'wallet_signing_budget_finalization_finalized'
    | 'wallet_signing_budget_finalization_already_finalized';
  finalizationResult: Extract<
    SigningSessionBudgetFinalizationTraceResult,
    'finalized' | 'already_finalized'
  >;
  status: SigningSessionBudgetTraceStatus;
  error?: never;
  zeroSpendReason?: never;
};

type SigningSessionBudgetTraceFinalizationFailureEvent = SigningSessionBudgetTraceBase & {
  event:
    | 'wallet_signing_budget_finalization_projection_mismatch'
    | 'wallet_signing_budget_finalization_missing_reservation'
    | 'wallet_signing_budget_finalization_identity_mismatch'
    | 'wallet_signing_budget_finalization_status_unavailable';
  finalizationResult: Exclude<
    SigningSessionBudgetFinalizationTraceResult,
    'finalized' | 'already_finalized'
  >;
  error: string;
  status?: never;
  zeroSpendReason?: never;
};

type SigningSessionBudgetTraceZeroSpendRecordedEvent =
  | (SigningSessionBudgetTraceBase & {
      event: 'wallet_signing_budget_zero_spend_recorded';
      zeroSpendReason: SigningSessionBudgetZeroSpendReason;
      error?: never;
      status?: never;
      finalizationResult?: never;
    })
  | (SigningSessionBudgetTraceBase & {
      event: 'wallet_signing_budget_zero_spend_recorded';
      zeroSpendReason: SigningSessionBudgetZeroSpendReason;
      error: string;
      status?: never;
      finalizationResult?: never;
    });

export type SigningSessionBudgetTraceEvent =
  | SigningSessionBudgetTracePlainEvent
  | SigningSessionBudgetTraceReservationReleasedEvent
  | SigningSessionBudgetTraceStatusEvent
  | SigningSessionBudgetTraceErrorEvent
  | SigningSessionBudgetTraceFinalizationSuccessEvent
  | SigningSessionBudgetTraceFinalizationFailureEvent
  | SigningSessionBudgetTraceZeroSpendRecordedEvent;

export type SigningSessionBudgetTraceEventForKind<
  TEvent extends SigningSessionBudgetTraceEventKind,
> = SigningSessionBudgetTraceEvent extends infer TTrace
  ? TTrace extends { event: infer TTraceEvent }
    ? TEvent extends TTraceEvent
      ? Omit<TTrace, 'event'> & { event: TEvent }
      : never
    : never
  : never;

export type SigningSessionBudgetTraceExtraForEvent<
  TEvent extends SigningSessionBudgetTraceEventKind,
> = Omit<
  SigningSessionBudgetTraceEventForKind<TEvent>,
  keyof SigningSessionBudgetTraceBase | 'event'
>;

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

export type ZeroBudgetFinalizationSpend = {
  kind: 'zero_spend';
  operationId: SigningOperationId;
  operationFingerprint: SigningOperationFingerprint;
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
export type ZeroWalletBudgetSpend = ZeroBudgetFinalizationSpend & {
  finalizationCommand: BudgetReservationFinalizationCommand;
};

export type SigningSessionBudgetSuccessFinalizationInput<
  TSpend extends ReservedWalletBudgetSpend | UnreservedWalletBudgetSpend | ExternallyConsumedWalletBudgetSpend,
> = TSpend & {
  finalizationCommand: BudgetReservationFinalizationCommand;
};

export type SigningSessionBudgetSuccessInput =
  | SigningSessionBudgetSuccessFinalizationInput<ReservedWalletBudgetSpend>
  | SigningSessionBudgetSuccessFinalizationInput<UnreservedWalletBudgetSpend>
  | SigningSessionBudgetSuccessFinalizationInput<ExternallyConsumedWalletBudgetSpend>;

export type SigningSessionBudgetReserveInput = {
  spend: WalletSigningSpendPlan;
  expectedBudgetProjectionVersion?: string;
  trustedStatusAuth?: SigningSessionBudgetStatusAuth;
};

export type SigningSessionBudgetReservationRecord = SigningSessionBudgetReserveInput & {
  operationFingerprint: string;
  signingGrantId: string;
  reservationIdentity: SigningBudgetReservationIdentity;
  reservationIdentityKey: SigningBudgetReservationKey;
  reservedAgainstProjectionVersion: string;
  reservedAgainstRemainingUses: number;
  createdAtMs: number;
};

export type KnownBudgetReservationProjectionState = {
  kind: 'known';
  version: string;
};

export type SigningBudgetReservationIdentity = {
  kind: 'signing_budget_reservation_identity';
  operationId: SigningOperationId;
  operationFingerprint: SigningOperationFingerprint;
  walletId: WalletId;
  signingGrantId: SigningGrantId;
  laneIdentity: ExactSigningLaneIdentity;
  laneIdentityKey: ExactSigningLaneIdentityKey;
  thresholdSessionIds: NonEmptyThresholdSessionIds;
  backingMaterialSessionIds: readonly BackingMaterialSessionId[];
  admittedProjection: KnownBudgetReservationProjectionState;
  reservedUses: number;
};

export type SigningBudgetReservationKey = string & {
  readonly __brand: 'SigningBudgetReservationKey';
};

export type BudgetReservationFinalizationCommand = {
  kind: 'budget_reservation_finalization_command';
  reservation: SigningBudgetReservationIdentity;
  outcome: 'signed' | 'failed_before_sign' | 'broadcast_failed';
};

export type SigningBudgetFinalizationResult =
  | {
      kind: 'finalized';
      reservation: SigningBudgetReservationIdentity;
      remainingUses: number;
      projectionVersion: string;
    }
  | {
      kind: 'already_finalized';
      reservation: SigningBudgetReservationIdentity;
      remainingUses: number;
      projectionVersion: string;
    }
  | {
      kind: 'projection_mismatch';
      reservation: SigningBudgetReservationIdentity;
      expectedProjectionVersion: string;
      actualProjectionVersion: string;
    }
  | {
      kind: 'missing_reservation';
      reservation: SigningBudgetReservationIdentity;
    }
  | {
      kind: 'reservation_identity_mismatch';
      expected: SigningBudgetReservationIdentity;
      actual: SigningBudgetReservationIdentity;
    }
  | {
      kind: 'budget_status_unavailable';
      reservation: SigningBudgetReservationIdentity;
      status: 'not_found' | 'budget_unknown' | 'missing_status';
    };

export type SigningSessionBudgetReservation = {
  kind: 'reserved';
  operationId: SigningOperationId;
  release(reason?: SigningSessionBudgetZeroSpendReason): void;
};

export type SigningSessionBudgetReservationConflict = {
  kind: 'reservation_identity_mismatch';
  expected: SigningBudgetReservationIdentity;
  actual: SigningBudgetReservationIdentity;
  operationId?: never;
  release?: never;
};

export type SigningSessionBudgetReserveResult =
  | SigningSessionBudgetReservation
  | SigningSessionBudgetReservationConflict
  | null;

export function isSigningSessionBudgetReservation(
  result: SigningSessionBudgetReserveResult,
): result is SigningSessionBudgetReservation {
  return result?.kind === 'reserved';
}

export type Ed25519WalletBudgetOwner = {
  curve: 'ed25519';
  walletId: WalletId;
  accountId?: never;
};

export type EcdsaWalletBudgetOwner = {
  curve: 'ecdsa';
  walletId: WalletId;
  accountId?: never;
};

export type WalletBudgetOwner = Ed25519WalletBudgetOwner | EcdsaWalletBudgetOwner;

export type WalletBudgetStatusCheck = {
  kind: 'wallet_budget_status_check';
  owner: WalletBudgetOwner;
  walletId?: never;
  signingGrantId: SigningGrantId | string;
  targetBackingMaterialSessionIds?: never;
  targetThresholdSessionIds?: never;
  trustedStatusAuth?: never;
};

export type BackingMaterialBudgetStatusCheck = {
  kind: 'backing_material_budget_status_check';
  owner: WalletBudgetOwner;
  walletId?: never;
  signingGrantId: SigningGrantId | string;
  targetBackingMaterialSessionIds: readonly [
    BackingMaterialSessionId | string,
    ...(BackingMaterialSessionId | string)[],
  ];
  targetThresholdSessionIds?: never;
  trustedStatusAuth?: never;
};

export type ThresholdBudgetStatusCheck = {
  kind: 'threshold_budget_status_check';
  owner: WalletBudgetOwner;
  walletId?: never;
  signingGrantId: SigningGrantId | string;
  targetThresholdSessionIds: readonly [
    ThresholdSessionId | string,
    ...(ThresholdSessionId | string)[],
  ];
  targetBackingMaterialSessionIds?: never;
  trustedStatusAuth?: never;
};

export type AuthenticatedThresholdBudgetStatusCheck = {
  kind: 'authenticated_threshold_budget_status_check';
  owner: WalletBudgetOwner;
  walletId?: never;
  signingGrantId: SigningGrantId | string;
  targetThresholdSessionIds: readonly [
    ThresholdSessionId | string,
    ...(ThresholdSessionId | string)[],
  ];
  trustedStatusAuth: SigningSessionBudgetStatusAuth;
  targetBackingMaterialSessionIds?: never;
};

export type EcdsaLaneBudgetStatusCheck = {
  kind: 'ecdsa_lane_budget_status_check';
  key: EvmFamilyEcdsaKeyIdentity;
  keyHandle: EvmFamilyEcdsaKeyHandle;
  chainTarget: ThresholdEcdsaChainTarget;
  signingGrantId: SigningGrantId | string;
  thresholdSessionId: ThresholdEcdsaSessionId | string;
  walletId?: never;
  targetThresholdSessionIds?: never;
  targetBackingMaterialSessionIds?: never;
  trustedStatusAuth?: never;
};

export type AuthenticatedEcdsaLaneBudgetStatusCheck = {
  kind: 'authenticated_ecdsa_lane_budget_status_check';
  key: EvmFamilyEcdsaKeyIdentity;
  keyHandle: EvmFamilyEcdsaKeyHandle;
  chainTarget: ThresholdEcdsaChainTarget;
  signingGrantId: SigningGrantId | string;
  thresholdSessionId: ThresholdEcdsaSessionId | string;
  trustedStatusAuth: SigningSessionBudgetStatusAuth;
  walletId?: never;
  targetThresholdSessionIds?: never;
  targetBackingMaterialSessionIds?: never;
};

export type SigningSessionBudgetStatusCheck =
  | WalletBudgetStatusCheck
  | BackingMaterialBudgetStatusCheck
  | ThresholdBudgetStatusCheck
  | AuthenticatedThresholdBudgetStatusCheck
  | EcdsaLaneBudgetStatusCheck
  | AuthenticatedEcdsaLaneBudgetStatusCheck;

export type SigningSessionBudgetStatusReader = (
  args: SigningSessionBudgetStatusCheck,
) => Promise<SigningSessionStatus | null>;

export type SigningSessionBudgetStatusAuth = {
  relayerUrl: string;
  thresholdSessionId: string;
  walletSessionJwt: string;
};

export type SigningSessionBudgetStatusSync = (args: {
  owner: WalletBudgetOwner;
  walletId?: never;
  signingGrantId: string;
  uses: number;
  reason: WalletSigningSpendPlan['reason'];
  budgetStatusCheck: SigningSessionBudgetStatusCheck;
  alreadyConsumedBackingMaterialSessionIds?: string[];
  alreadyConsumedThresholdSessionIds?: string[];
}) => Promise<SigningSessionStatus>;

export type SigningSessionBudgetDeps = {
  getStatus?: SigningSessionBudgetStatusReader;
  consumeUse?: SigningSessionBudgetStatusSync;
  onTrace?: (event: SigningSessionBudgetTraceEvent) => void;
};

export type SigningSessionPreparedBudgetIdentity = {
  signingGrantId: string;
  projectionVersion: string;
  status: SigningSessionStatus & { status: 'active'; projectionVersion: string };
};

export type SigningSessionBudget = {
  reserve(input: SigningSessionBudgetReserveInput): Promise<SigningSessionBudgetReserveResult>;
  getAvailableStatus(input: SigningSessionBudgetStatusCheck): Promise<SigningSessionStatus | null>;
  recordSuccess(input: SigningSessionBudgetSuccessInput): Promise<SigningBudgetFinalizationResult>;
  recordZeroSpend(input: ZeroWalletBudgetSpend): void;
  hasRecorded(operationId: SigningOperationId): boolean;
};

export const SIGNING_SESSION_BUDGET_EXHAUSTED_ERROR =
  '[SigningSessionBudget] signing grant budget is exhausted';
export const SIGNING_SESSION_BUDGET_UNKNOWN_ERROR =
  '[SigningSessionBudget] signing grant budget is budget_unknown';
export const SIGNING_SESSION_BUDGET_IN_FLIGHT_ERROR =
  '[SigningSessionBudget] signing grant budget is reserved by in-flight operations';

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

export function isSigningSessionBudgetAdmissionBlockedError(error: unknown): boolean {
  return isSigningSessionBudgetExhaustedError(error) || isSigningSessionBudgetInFlightError(error);
}

export function applySigningSessionBudgetReservationsToStatus(args: {
  status: SigningSessionStatus;
  signingGrantId: string;
  reservationsByOperationId: Map<string, SigningSessionBudgetReservationRecord>;
}): SigningSessionStatus {
  if (args.status.status !== 'active') return args.status;
  const remainingUses = Math.max(0, Math.floor(Number(args.status.remainingUses) || 0));
  const serverAvailableUses = availableUsesForBudgetAdmission(args.status);
  const projectionVersion = String(args.status.projectionVersion || '').trim();
  const inFlightReservedUses = getSameProjectionReservedUses({
    reservationsByOperationId: args.reservationsByOperationId,
    signingGrantId: args.signingGrantId,
    projectionVersion,
  });
  const availableUses = Math.max(0, serverAvailableUses - inFlightReservedUses);
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
        '[SigningSessionBudget] signing grant budget is not_found',
        formatSpendIdentityForError(spend),
      ].join(' '),
    );
  }
  if (status.status !== 'active') {
    throw new Error(`[SigningSessionBudget] signing grant budget is ${status.status}`);
  }
  const projectionVersion = String(status.projectionVersion || '').trim();
  if (!projectionVersion) {
    throw new Error('[SigningSessionBudget] trusted budget status is missing projection version');
  }
  const remainingUses = Math.floor(Number(status.remainingUses) || 0);
  const serverAvailableUses = availableUsesForBudgetAdmission(status);
  const reservedUses = getSameProjectionReservedUses({
    reservationsByOperationId: args.reservationsByOperationId,
    signingGrantId: spend.signingGrantId,
    projectionVersion,
  });
  const availableUses = serverAvailableUses - reservedUses;
  if (availableUses < spend.uses) {
    if (remainingUses >= spend.uses || serverAvailableUses >= spend.uses) {
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

export function availableUsesForBudgetAdmission(status: SigningSessionStatus): number {
  const remainingUses = Math.max(0, Math.floor(Number(status.remainingUses) || 0));
  if (status.availableUses === undefined) return remainingUses;
  const availableUses = Math.max(0, Math.floor(Number(status.availableUses) || 0));
  return Math.min(remainingUses, availableUses);
}

export function getSameProjectionReservedUses(args: {
  reservationsByOperationId: Map<string, SigningSessionBudgetReservationRecord>;
  signingGrantId: string;
  projectionVersion?: string;
}): number {
  const signingGrantId = String(args.signingGrantId || '').trim();
  const projectionVersion = String(args.projectionVersion || '').trim();
  if (!signingGrantId || !projectionVersion) return 0;
  let uses = 0;
  for (const reservation of args.reservationsByOperationId.values()) {
    if (reservation.signingGrantId !== signingGrantId) continue;
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
    signingGrantId: spend.signingGrantId,
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
    `signingGrantId=${spend.signingGrantId}`,
    `thresholdSessionIds=${normalizeStringList(spend.thresholdSessionIds)?.join(',') || 'none'}`,
    `backingMaterialSessionIds=${normalizeStringList(spend.backingMaterialSessionIds)?.join(',') || 'none'}`,
  ].join(' ');
}

export function normalizeWalletBudgetSuccessInput<TInput extends SigningSessionBudgetSuccessInput>(
  input: TInput,
): TInput {
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

export function buildSigningBudgetReservationIdentity(args: {
  spend: WalletSigningSpendPlan;
  projectionVersion: string;
}): SigningBudgetReservationIdentity {
  const spend = normalizeWalletSigningSpendPlan(args.spend);
  const projectionVersion = normalizeRequired(args.projectionVersion, 'projectionVersion');
  const laneIdentity = exactSigningLaneIdentity(spend.lane);
  const laneIdentityKey = exactSigningLaneIdentityKey(laneIdentity);
  const thresholdSessionIds = resolveNonEmptyThresholdSessionIds({
    spend,
    laneIdentity,
  });
  return {
    kind: 'signing_budget_reservation_identity',
    operationId: spend.operationId,
    operationFingerprint: SigningSessionIds.signingOperationFingerprint(
      resolveWalletSigningOperationFingerprint(spend),
    ),
    walletId: walletBudgetOwnerId(walletBudgetOwnerForLane(spend.lane)),
    signingGrantId: spend.signingGrantId,
    laneIdentity,
    laneIdentityKey,
    thresholdSessionIds,
    backingMaterialSessionIds: normalizeBackingMaterialSessionIds(spend.backingMaterialSessionIds),
    admittedProjection: {
      kind: 'known',
      version: projectionVersion,
    },
    reservedUses: Math.max(1, Math.floor(Number(spend.uses) || 1)),
  };
}

export function signingBudgetReservationKey(
  identity: SigningBudgetReservationIdentity,
): SigningBudgetReservationKey {
  return alphabetizeStringify({
    kind: identity.kind,
    operationId: String(identity.operationId),
    operationFingerprint: String(identity.operationFingerprint),
    walletId: String(identity.walletId),
    signingGrantId: String(identity.signingGrantId),
    laneIdentityKey: String(identity.laneIdentityKey),
    thresholdSessionIds: identity.thresholdSessionIds.map(String),
    backingMaterialSessionIds: identity.backingMaterialSessionIds.map(String),
    admittedProjection: identity.admittedProjection,
    reservedUses: identity.reservedUses,
  }) as SigningBudgetReservationKey;
}

function resolveNonEmptyThresholdSessionIds(args: {
  spend: WalletSigningSpendPlan;
  laneIdentity: ExactSigningLaneIdentity;
}): NonEmptyThresholdSessionIds {
  const normalized = normalizeStringList(args.spend.thresholdSessionIds) as
    | ThresholdSessionId[]
    | undefined;
  if (normalized?.length) return [normalized[0], ...normalized.slice(1)];
  return thresholdSessionIdsFromExactSigningLaneIdentity(args.laneIdentity);
}

function normalizeBackingMaterialSessionIds(
  values: readonly BackingMaterialSessionId[],
): readonly BackingMaterialSessionId[] {
  const normalized = normalizeStringList(values) as BackingMaterialSessionId[] | undefined;
  return normalized || [];
}

export function summarizeSigningGrantStatus(
  status: SigningSessionStatus,
): SigningSessionBudgetTraceStatus {
  return {
    status: status.status,
    remainingUses: status.remainingUses,
    expiresAtMs: status.expiresAtMs,
  };
}

export function createSigningSessionBudgetTraceEvent<
  TEvent extends SigningSessionBudgetTraceEventKind,
>(
  input: { spend: WalletBudgetSpend },
  event: TEvent,
  extra: SigningSessionBudgetTraceExtraForEvent<TEvent>,
): SigningSessionBudgetTraceEventForKind<TEvent> {
  const spend = input.spend;
  return {
    event,
    operationId: spend.operationId,
    owner: walletBudgetOwnerForLane(spend.lane),
    lane: summarizeSigningLane(spend.lane),
    reason: spend.reason,
    uses: spend.uses,
    thresholdSessionCount: spend.thresholdSessionIds.length,
    backingMaterialSessionCount: spend.backingMaterialSessionIds.length,
    ...extra,
  } as SigningSessionBudgetTraceEventForKind<TEvent>;
}

export function createZeroSpendTraceEvent<
  TEvent extends Extract<
    SigningSessionBudgetTraceEventKind,
    'wallet_signing_budget_reservation_released' | 'wallet_signing_budget_zero_spend_recorded'
  >,
>(
  input: ZeroWalletBudgetSpend,
  event: TEvent,
  extra: SigningSessionBudgetTraceExtraForEvent<TEvent>,
): SigningSessionBudgetTraceEventForKind<TEvent> {
  return {
    event,
    operationId: input.operationId,
    owner: walletBudgetOwnerForLane(input.lane),
    lane: summarizeSigningLane(input.lane),
    reason: SigningOperationIntent.TransactionSign,
    uses: 1,
    thresholdSessionCount: input.lane.thresholdSessionId ? 1 : 0,
    backingMaterialSessionCount: input.lane.backingMaterialSessionId ? 1 : 0,
    ...extra,
  } as SigningSessionBudgetTraceEventForKind<TEvent>;
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
  const uses = 1;
  const base = {
    operationId: operation.operationId,
    ...(operation.operationFingerprint
      ? { operationFingerprint: operation.operationFingerprint }
      : {}),
    walletId: lane.walletId,
    signingGrantId: lane.signingGrantId,
    lane,
    thresholdSessionIds: uniqueDefined([lane.thresholdSessionId]),
    backingMaterialSessionIds: uniqueDefined([lane.backingMaterialSessionId]),
    uses,
    reason: operation.intent,
  };
  return normalizeWalletSigningSpendPlan(
    lane.curve === 'ecdsa'
      ? (base as EcdsaWalletSigningSpendPlan)
      : (base as Ed25519WalletSigningSpendPlan),
  );
}

export function buildWalletBudgetStatusCheck(args: {
  owner: WalletBudgetOwner;
  signingGrantId: SigningGrantId | string;
}): WalletBudgetStatusCheck {
  return {
    kind: 'wallet_budget_status_check',
    owner: args.owner,
    signingGrantId: normalizeRequired(
      args.signingGrantId,
      'signingGrantId',
    ) as SigningGrantId,
  };
}

export function buildBackingMaterialBudgetStatusCheck(args: {
  owner: WalletBudgetOwner;
  signingGrantId: SigningGrantId | string;
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
    owner: args.owner,
    signingGrantId: normalizeRequired(
      args.signingGrantId,
      'signingGrantId',
    ) as SigningGrantId,
    targetBackingMaterialSessionIds: [
      targetBackingMaterialSessionIds[0],
      ...targetBackingMaterialSessionIds.slice(1),
    ],
  };
}

export function buildThresholdBudgetStatusCheck(args: {
  owner: WalletBudgetOwner;
  signingGrantId: SigningGrantId | string;
  targetThresholdSessionIds: readonly (ThresholdSessionId | string)[];
}): ThresholdBudgetStatusCheck {
  const targetThresholdSessionIds = normalizeStringList(args.targetThresholdSessionIds) as
    | ThresholdSessionId[]
    | undefined;
  if (!targetThresholdSessionIds?.length) {
    throw new Error('[SigningSessionBudget] targetThresholdSessionIds are required');
  }
  return {
    kind: 'threshold_budget_status_check',
    owner: args.owner,
    signingGrantId: normalizeRequired(
      args.signingGrantId,
      'signingGrantId',
    ) as SigningGrantId,
    targetThresholdSessionIds: [
      targetThresholdSessionIds[0],
      ...targetThresholdSessionIds.slice(1),
    ],
  };
}

export function buildAuthenticatedThresholdBudgetStatusCheck(args: {
  owner: WalletBudgetOwner;
  signingGrantId: SigningGrantId | string;
  targetThresholdSessionIds: readonly (ThresholdSessionId | string)[];
  trustedStatusAuth: SigningSessionBudgetStatusAuth;
}): AuthenticatedThresholdBudgetStatusCheck {
  const thresholdCheck = buildThresholdBudgetStatusCheck(args);
  return {
    kind: 'authenticated_threshold_budget_status_check',
    owner: thresholdCheck.owner,
    signingGrantId: thresholdCheck.signingGrantId,
    targetThresholdSessionIds: thresholdCheck.targetThresholdSessionIds,
    trustedStatusAuth: args.trustedStatusAuth,
  };
}

export function isEcdsaLaneBudgetStatusCheck(
  args: SigningSessionBudgetStatusCheck,
): args is EcdsaLaneBudgetStatusCheck | AuthenticatedEcdsaLaneBudgetStatusCheck {
  return (
    args.kind === 'ecdsa_lane_budget_status_check' ||
    args.kind === 'authenticated_ecdsa_lane_budget_status_check'
  );
}

export function assertBudgetStatusCheckHasConcreteLaneIdentity(
  args: SigningSessionBudgetStatusCheck,
): void {
  if (!isEcdsaLaneBudgetStatusCheck(args)) return;
  normalizeRequired(args.signingGrantId, 'signingGrantId');
  normalizeRequired(args.thresholdSessionId, 'thresholdSessionId');
  if (!args.key) {
    throw new Error('[SigningSessionBudget] ECDSA budget status requires shared key identity');
  }
  normalizeRequired(args.keyHandle, 'keyHandle');
  if (!args.chainTarget || (args.chainTarget.kind !== 'evm' && args.chainTarget.kind !== 'tempo')) {
    throw new Error('[SigningSessionBudget] ECDSA budget status requires concrete chain target');
  }
}

export function ed25519WalletBudgetOwner(walletId: WalletId | string): Ed25519WalletBudgetOwner {
  return { curve: 'ed25519', walletId: toWalletId(walletId) };
}

export function ecdsaWalletBudgetOwner(walletId: WalletId): EcdsaWalletBudgetOwner {
  return { curve: 'ecdsa', walletId };
}

export function walletBudgetOwnerForLane(
  lane: SelectedSigningSessionPlanningLane,
): WalletBudgetOwner {
  return lane.curve === 'ecdsa'
    ? ecdsaWalletBudgetOwner(toWalletId(lane.walletId))
    : ed25519WalletBudgetOwner(lane.walletId);
}

export function walletBudgetOwnerId(owner: WalletBudgetOwner): WalletId {
  return owner.walletId;
}

export function walletBudgetOwnerKey(owner: WalletBudgetOwner): string {
  return `${owner.curve}:${walletBudgetOwnerId(owner)}`;
}

export function ownerForBudgetStatusCheck(
  args: SigningSessionBudgetStatusCheck,
): WalletBudgetOwner {
  return isEcdsaLaneBudgetStatusCheck(args)
    ? ecdsaWalletBudgetOwner(args.key.walletId)
    : args.owner;
}

export function thresholdSessionIdsForBudgetStatusCheck(
  args: SigningSessionBudgetStatusCheck,
): string[] {
  if (isEcdsaLaneBudgetStatusCheck(args)) {
    return [normalizeRequired(args.thresholdSessionId, 'thresholdSessionId')];
  }
  return args.kind === 'threshold_budget_status_check' ||
    args.kind === 'authenticated_threshold_budget_status_check'
    ? [...args.targetThresholdSessionIds].map((value) =>
        normalizeRequired(value, 'thresholdSessionId'),
      )
    : [];
}

export function buildEcdsaLaneBudgetStatusCheck(args: {
  key: EvmFamilyEcdsaKeyIdentity;
  keyHandle: EvmFamilyEcdsaKeyHandle | string;
  chainTarget: ThresholdEcdsaChainTarget;
  signingGrantId: SigningGrantId | string;
  thresholdSessionId: ThresholdEcdsaSessionId | string;
}): EcdsaLaneBudgetStatusCheck {
  return buildEcdsaLaneBudgetStatusCheckInternal({
    kind: 'ecdsa_lane_budget_status_check',
    key: args.key,
    keyHandle: args.keyHandle,
    chainTarget: args.chainTarget,
    signingGrantId: args.signingGrantId,
    thresholdSessionId: args.thresholdSessionId,
  });
}

export function buildAuthenticatedEcdsaLaneBudgetStatusCheck(args: {
  key: EvmFamilyEcdsaKeyIdentity;
  keyHandle: EvmFamilyEcdsaKeyHandle | string;
  chainTarget: ThresholdEcdsaChainTarget;
  signingGrantId: SigningGrantId | string;
  thresholdSessionId: ThresholdEcdsaSessionId | string;
  trustedStatusAuth: SigningSessionBudgetStatusAuth;
}): AuthenticatedEcdsaLaneBudgetStatusCheck {
  return {
    ...buildEcdsaLaneBudgetStatusCheckInternal({
      kind: 'authenticated_ecdsa_lane_budget_status_check',
      key: args.key,
      keyHandle: args.keyHandle,
      chainTarget: args.chainTarget,
      signingGrantId: args.signingGrantId,
      thresholdSessionId: args.thresholdSessionId,
    }),
    trustedStatusAuth: args.trustedStatusAuth,
  };
}

function buildEcdsaLaneBudgetStatusCheckInternal<
  TKind extends
    | EcdsaLaneBudgetStatusCheck['kind']
    | AuthenticatedEcdsaLaneBudgetStatusCheck['kind'],
>(args: {
  kind: TKind;
  key: EvmFamilyEcdsaKeyIdentity;
  keyHandle: EvmFamilyEcdsaKeyHandle | string;
  chainTarget: ThresholdEcdsaChainTarget;
  signingGrantId: SigningGrantId | string;
  thresholdSessionId: ThresholdEcdsaSessionId | string;
}): TKind extends EcdsaLaneBudgetStatusCheck['kind']
  ? EcdsaLaneBudgetStatusCheck
  : Omit<AuthenticatedEcdsaLaneBudgetStatusCheck, 'trustedStatusAuth'> {
  const signingGrantId = normalizeRequired(
    args.signingGrantId,
    'signingGrantId',
  ) as SigningGrantId;
  const thresholdSessionId = normalizeRequired(
    args.thresholdSessionId,
    'thresholdSessionId',
  ) as ThresholdEcdsaSessionId;
  if (!args.key) {
    throw new Error('[SigningSessionBudget] ECDSA budget status requires shared key identity');
  }
  const keyHandle = normalizeRequired(args.keyHandle, 'keyHandle') as EvmFamilyEcdsaKeyHandle;
  if (!args.chainTarget || (args.chainTarget.kind !== 'evm' && args.chainTarget.kind !== 'tempo')) {
    throw new Error('[SigningSessionBudget] ECDSA budget status requires concrete chain target');
  }
  return {
    kind: args.kind,
    key: args.key,
    keyHandle,
    chainTarget: args.chainTarget,
    signingGrantId,
    thresholdSessionId,
  } as TKind extends EcdsaLaneBudgetStatusCheck['kind']
    ? EcdsaLaneBudgetStatusCheck
    : Omit<AuthenticatedEcdsaLaneBudgetStatusCheck, 'trustedStatusAuth'>;
}

export function buildSigningSessionBudgetStatusCheckForSpend(args: {
  spend: WalletSigningSpendPlan;
  trustedStatusAuth?: SigningSessionBudgetStatusAuth;
}): SigningSessionBudgetStatusCheck {
  if (isEcdsaWalletSigningSpendPlan(args.spend)) {
    if (args.trustedStatusAuth) {
      return buildAuthenticatedEcdsaLaneBudgetStatusCheck({
        key: args.spend.lane.key,
        keyHandle: args.spend.lane.keyHandle,
        chainTarget: args.spend.lane.chainTarget,
        signingGrantId: args.spend.signingGrantId,
        thresholdSessionId: args.spend.lane.thresholdSessionId,
        trustedStatusAuth: args.trustedStatusAuth,
      });
    }
    return buildEcdsaLaneBudgetStatusCheck({
      key: args.spend.lane.key,
      keyHandle: args.spend.lane.keyHandle,
      chainTarget: args.spend.lane.chainTarget,
      signingGrantId: args.spend.signingGrantId,
      thresholdSessionId: args.spend.lane.thresholdSessionId,
    });
  }
  if (args.trustedStatusAuth) {
    return buildAuthenticatedThresholdBudgetStatusCheck({
      owner: walletBudgetOwnerForLane(args.spend.lane),
      signingGrantId: args.spend.signingGrantId,
      targetThresholdSessionIds: args.spend.thresholdSessionIds,
      trustedStatusAuth: args.trustedStatusAuth,
    });
  }
  if (args.spend.thresholdSessionIds.length) {
    return buildThresholdBudgetStatusCheck({
      owner: walletBudgetOwnerForLane(args.spend.lane),
      signingGrantId: args.spend.signingGrantId,
      targetThresholdSessionIds: args.spend.thresholdSessionIds,
    });
  }
  if (args.spend.backingMaterialSessionIds.length) {
    return buildBackingMaterialBudgetStatusCheck({
      owner: walletBudgetOwnerForLane(args.spend.lane),
      signingGrantId: args.spend.signingGrantId,
      targetBackingMaterialSessionIds: args.spend.backingMaterialSessionIds,
    });
  }
  return buildWalletBudgetStatusCheck({
    owner: walletBudgetOwnerForLane(args.spend.lane),
    signingGrantId: args.spend.signingGrantId,
  });
}

function isEcdsaWalletSigningSpendPlan(
  spend: WalletSigningSpendPlan,
): spend is EcdsaWalletSigningSpendPlan {
  return spend.lane.curve === 'ecdsa';
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
