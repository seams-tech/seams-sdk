import type { AccountId } from '@/core/types/accountIds';
import type { SigningSessionStatus } from '@/core/types/tatchi';
import {
  normalizeWalletSigningSpendPlan,
  summarizeSigningLane,
  type SigningLaneSummary,
  type SigningOperationId,
  type WalletSigningSpendPlan,
} from '../signingSessionTypes';

export type WalletSigningBudgetLedgerZeroSpendReason =
  | 'confirmation_cancelled'
  | 'email_otp_failed'
  | 'passkey_failed'
  | 'nonce_preparation_failed'
  | 'signing_failed';

export type WalletSigningBudgetLedgerTraceEvent = {
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
  zeroSpendReason?: WalletSigningBudgetLedgerZeroSpendReason;
};

export type WalletSigningBudgetLedgerRecordSuccessInput = {
  spend: WalletSigningSpendPlan;
  alreadyConsumedBackingMaterialSessionIds?: readonly string[];
  alreadyConsumedThresholdSessionIds?: readonly string[];
};

export type WalletSigningBudgetLedgerRecordZeroSpendInput = {
  spend: WalletSigningSpendPlan;
  reason: WalletSigningBudgetLedgerZeroSpendReason;
  error?: unknown;
};

export type WalletSigningBudgetReservation = {
  operationId: SigningOperationId;
  release(reason?: WalletSigningBudgetLedgerZeroSpendReason): void;
};

export type WalletSigningBudgetStatusReader = (args: {
  nearAccountId: AccountId | string;
  walletSigningSessionId?: string;
  targetBackingMaterialSessionIds?: string[];
  targetThresholdSessionIds?: string[];
}) => Promise<SigningSessionStatus | null>;

export type WalletSigningBudgetConsumer = (args: {
  nearAccountId: AccountId | string;
  walletSigningSessionId: string;
  uses: number;
  reason: WalletSigningSpendPlan['reason'];
  targetBackingMaterialSessionIds?: string[];
  targetThresholdSessionIds?: string[];
  alreadyConsumedBackingMaterialSessionIds?: string[];
  alreadyConsumedThresholdSessionIds?: string[];
}) => Promise<SigningSessionStatus>;

export type WalletSigningBudgetLedgerDeps = {
  getStatus?: WalletSigningBudgetStatusReader;
  consumeUse?: WalletSigningBudgetConsumer;
  onTrace?: (event: WalletSigningBudgetLedgerTraceEvent) => void;
};

export type WalletSigningBudgetLedger = {
  reserve(
    input: WalletSigningBudgetLedgerRecordSuccessInput,
  ): Promise<WalletSigningBudgetReservation | null>;
  getAvailableStatus(input: {
    nearAccountId: AccountId | string;
    walletSigningSessionId: string;
    targetBackingMaterialSessionIds?: readonly string[];
    targetThresholdSessionIds?: readonly string[];
  }): Promise<SigningSessionStatus | null>;
  recordSuccess(
    input: WalletSigningBudgetLedgerRecordSuccessInput,
  ): Promise<SigningSessionStatus | null>;
  recordZeroSpend(input: WalletSigningBudgetLedgerRecordZeroSpendInput): void;
  hasRecorded(operationId: SigningOperationId): boolean;
};

export const WALLET_SIGNING_BUDGET_EXHAUSTED_ERROR =
  '[WalletSigningBudgetLedger] wallet signing-session budget is exhausted';

export function isWalletSigningBudgetExhaustedError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error || '');
  return message.includes(WALLET_SIGNING_BUDGET_EXHAUSTED_ERROR);
}

export function applyWalletSigningBudgetReservationsToStatus(args: {
  status: SigningSessionStatus;
  walletSigningSessionId: string;
  reservedUsesByWalletSessionId: Map<string, number>;
}): SigningSessionStatus {
  if (args.status.status !== 'active') return args.status;
  const remainingUses = Math.max(0, Math.floor(Number(args.status.remainingUses) || 0));
  const reservedUses = Math.max(
    0,
    Math.floor(Number(args.reservedUsesByWalletSessionId.get(args.walletSigningSessionId)) || 0),
  );
  const availableUses = Math.max(0, remainingUses - reservedUses);
  if (availableUses <= 0) {
    return {
      ...args.status,
      status: 'exhausted',
      remainingUses: 0,
    };
  }
  return {
    ...args.status,
    remainingUses: availableUses,
  };
}

export async function assertWalletSigningBudgetReservationAvailable(args: {
  getStatus?: WalletSigningBudgetStatusReader;
  input: WalletSigningBudgetLedgerRecordSuccessInput;
  reservedUsesByWalletSessionId: Map<string, number>;
}): Promise<void> {
  const spend = args.input.spend;
  if (!args.getStatus) return;
  const status = await args.getStatus({
    nearAccountId: spend.nearAccountId,
    walletSigningSessionId: spend.walletSigningSessionId,
    targetBackingMaterialSessionIds: normalizeStringList(spend.backingMaterialSessionIds),
    targetThresholdSessionIds: normalizeStringList(spend.thresholdSessionIds),
  });
  if (!status || status.status === 'not_found') {
    throw new Error('[WalletSigningBudgetLedger] wallet signing-session budget is not available');
  }
  if (status.status !== 'active') {
    throw new Error(
      `[WalletSigningBudgetLedger] wallet signing-session budget is ${status.status}`,
    );
  }
  const remainingUses = Math.floor(Number(status.remainingUses) || 0);
  const reservedUses = args.reservedUsesByWalletSessionId.get(spend.walletSigningSessionId) || 0;
  if (remainingUses - reservedUses < spend.uses) {
    throw new Error(WALLET_SIGNING_BUDGET_EXHAUSTED_ERROR);
  }
}

export function normalizeWalletSigningBudgetLedgerRecordSuccessInput(
  input: WalletSigningBudgetLedgerRecordSuccessInput,
): WalletSigningBudgetLedgerRecordSuccessInput {
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
    `[WalletSigningBudgetLedger] signing operation id reused for a different operation: ${args.operationId}`,
  );
}

export function summarizeWalletSigningSessionStatus(
  status: SigningSessionStatus,
): WalletSigningBudgetLedgerTraceEvent['status'] {
  return {
    status: status.status,
    remainingUses: status.remainingUses,
    expiresAtMs: status.expiresAtMs,
  };
}

export function createWalletSigningBudgetLedgerTraceEvent(
  input: WalletSigningBudgetLedgerRecordSuccessInput,
  event: WalletSigningBudgetLedgerTraceEvent['event'],
  extra: Pick<WalletSigningBudgetLedgerTraceEvent, 'status' | 'error' | 'zeroSpendReason'> = {},
): WalletSigningBudgetLedgerTraceEvent {
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
    throw new Error(`[WalletSigningBudgetLedger] ${label} is required`);
  }
  return normalized;
}

export function normalizeStringList(values: readonly string[] | undefined): string[] | undefined {
  const normalized = (values || []).map((value) => String(value || '').trim()).filter(Boolean);
  return normalized.length ? normalized : undefined;
}
