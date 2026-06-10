import {
  SigningOperationIntent,
  type SigningLaneSummary,
  type SigningOperationId,
} from '../operationState/types';
import type {
  SigningSessionBudgetTraceEvent,
  SigningSessionBudgetTraceStatus,
  WalletBudgetOwner,
} from './budget';

declare const owner: WalletBudgetOwner;
declare const lane: SigningLaneSummary;

const base = {
  operationId: 'operation-1' as SigningOperationId,
  owner,
  lane,
  reason: SigningOperationIntent.TransactionSign,
  uses: 1 as const,
  thresholdSessionCount: 1,
  backingMaterialSessionCount: 1,
};

const activeStatus: SigningSessionBudgetTraceStatus = {
  status: 'active',
  remainingUses: 2,
  expiresAtMs: 1_900_000_000_000,
};

const spendSucceededTrace: SigningSessionBudgetTraceEvent = {
  ...base,
  event: 'wallet_signing_budget_spend_succeeded',
  status: activeStatus,
};
void spendSucceededTrace;

// @ts-expect-error spend success traces require status.
const spendSucceededWithoutStatus: SigningSessionBudgetTraceEvent = {
  ...base,
  event: 'wallet_signing_budget_spend_succeeded',
};
void spendSucceededWithoutStatus;

// @ts-expect-error success traces reject error payloads.
const spendSucceededWithError: SigningSessionBudgetTraceEvent = {
  ...base,
  event: 'wallet_signing_budget_spend_succeeded',
  status: activeStatus,
  error: 'unexpected error',
};
void spendSucceededWithError;

// @ts-expect-error failure traces require an error.
const reservationFailureWithoutError: SigningSessionBudgetTraceEvent = {
  ...base,
  event: 'wallet_signing_budget_reservation_failed',
};
void reservationFailureWithoutError;

const finalizationFailure: SigningSessionBudgetTraceEvent = {
  ...base,
  event: 'wallet_signing_budget_finalization_projection_mismatch',
  finalizationResult: 'projection_mismatch',
  error: 'expected projection-a, got projection-b',
};
void finalizationFailure;

// @ts-expect-error finalization failure traces require an error.
const finalizationFailureWithoutError: SigningSessionBudgetTraceEvent = {
  ...base,
  event: 'wallet_signing_budget_finalization_projection_mismatch',
  finalizationResult: 'projection_mismatch',
};
void finalizationFailureWithoutError;

// @ts-expect-error zero-spend traces require a zero-spend reason.
const zeroSpendWithoutReason: SigningSessionBudgetTraceEvent = {
  ...base,
  event: 'wallet_signing_budget_zero_spend_recorded',
};
void zeroSpendWithoutReason;

export {};
