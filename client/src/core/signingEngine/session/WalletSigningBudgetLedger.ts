import type { AccountId } from '@/core/types/accountIds';
import type { SigningSessionStatus } from '@/core/types/tatchi';
import type { WalletSigningSessionCoordinator } from './WalletSigningSessionCoordinator';
import {
  summarizeSigningLane,
  normalizeWalletSigningSpendPlan,
  type SigningLaneSummary,
  type SigningOperationId,
  type WalletSigningSpendPlan,
} from './signingSessionTypes';

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

export type WalletSigningBudgetLedgerDeps = {
  getStatus?: WalletSigningSessionCoordinator['getStatus'];
  consumeUse?: WalletSigningSessionCoordinator['consumeUse'];
  onTrace?: (event: WalletSigningBudgetLedgerTraceEvent) => void;
};

export type WalletSigningBudgetLedgerRecordSuccessInput = {
  spend: WalletSigningSpendPlan;
  alreadyConsumedBackingMaterialSessionIds?: readonly string[];
  alreadyConsumedThresholdSessionIds?: readonly string[];
};

export const WALLET_SIGNING_BUDGET_EXHAUSTED_ERROR =
  '[WalletSigningBudgetLedger] wallet signing-session budget is exhausted';

export function isWalletSigningBudgetExhaustedError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error || '');
  return message.includes(WALLET_SIGNING_BUDGET_EXHAUSTED_ERROR);
}

export type WalletSigningBudgetLedgerZeroSpendReason =
  | 'confirmation_cancelled'
  | 'email_otp_failed'
  | 'passkey_failed'
  | 'nonce_preparation_failed'
  | 'signing_failed';

export type WalletSigningBudgetLedgerRecordZeroSpendInput = {
  spend: WalletSigningSpendPlan;
  reason: WalletSigningBudgetLedgerZeroSpendReason;
  error?: unknown;
};

export type WalletSigningBudgetReservation = {
  operationId: SigningOperationId;
  release(reason?: WalletSigningBudgetLedgerZeroSpendReason): void;
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

export function createWalletSigningBudgetLedger(
  deps: WalletSigningBudgetLedgerDeps,
): WalletSigningBudgetLedger {
  const successfulSpendsByOperationId = new Map<
    string,
    {
      // Operation ids are request-scoped idempotency keys, not reusable budget
      // buckets. Binding the payload fingerprint prevents a retry/caller bug from
      // deduping a different transaction and hiding a real budget spend failure.
      operationFingerprint: string;
      promise: Promise<SigningSessionStatus | null>;
    }
  >();
  const reservationsByOperationId = new Map<string, WalletSigningBudgetLedgerRecordSuccessInput>();
  const reservedUsesByWalletSessionId = new Map<string, number>();
  const walletReservationQueues = new Map<string, Promise<unknown>>();

  return {
    async reserve(input) {
      const normalizedInput = normalizeWalletSigningBudgetLedgerRecordSuccessInput(input);
      const spend = normalizedInput.spend;
      const operationId = normalizeRequired(spend.operationId, 'operationId');
      const walletSigningSessionId = normalizeRequired(
        spend.walletSigningSessionId,
        'walletSigningSessionId',
      );
      const existingSpend = successfulSpendsByOperationId.get(operationId);
      if (existingSpend) {
        assertWalletSigningOperationFingerprintMatches({
          operationId,
          existingFingerprint: existingSpend.operationFingerprint,
          nextFingerprint: resolveWalletSigningOperationFingerprint(spend),
        });
        emitWalletSigningBudgetLedgerTrace(
          deps,
          normalizedInput,
          'wallet_signing_budget_reservation_deduped',
        );
        return null;
      }
      if (reservationsByOperationId.has(operationId)) {
        assertWalletSigningOperationFingerprintMatches({
          operationId,
          existingFingerprint: resolveWalletSigningOperationFingerprint(
            reservationsByOperationId.get(operationId)!.spend,
          ),
          nextFingerprint: resolveWalletSigningOperationFingerprint(spend),
        });
        emitWalletSigningBudgetLedgerTrace(
          deps,
          normalizedInput,
          'wallet_signing_budget_reservation_deduped',
        );
        return null;
      }

      return await enqueueWalletReservation(
        walletReservationQueues,
        walletSigningSessionId,
        async () => {
          if (reservationsByOperationId.has(operationId)) {
            assertWalletSigningOperationFingerprintMatches({
              operationId,
              existingFingerprint: resolveWalletSigningOperationFingerprint(
                reservationsByOperationId.get(operationId)!.spend,
              ),
              nextFingerprint: resolveWalletSigningOperationFingerprint(spend),
            });
            emitWalletSigningBudgetLedgerTrace(
              deps,
              normalizedInput,
              'wallet_signing_budget_reservation_deduped',
            );
            return null;
          }

          emitWalletSigningBudgetLedgerTrace(
            deps,
            normalizedInput,
            'wallet_signing_budget_reservation_started',
          );
          try {
            await assertWalletSigningBudgetReservationAvailable({
              deps,
              input: normalizedInput,
              reservedUsesByWalletSessionId,
            });
          } catch (error) {
            emitWalletSigningBudgetLedgerTrace(
              deps,
              normalizedInput,
              'wallet_signing_budget_reservation_failed',
              {
                error: error instanceof Error ? error.message : String(error || 'unknown error'),
              },
            );
            throw error;
          }

          reservationsByOperationId.set(operationId, normalizedInput);
          reservedUsesByWalletSessionId.set(
            walletSigningSessionId,
            (reservedUsesByWalletSessionId.get(walletSigningSessionId) || 0) + spend.uses,
          );
          emitWalletSigningBudgetLedgerTrace(
            deps,
            normalizedInput,
            'wallet_signing_budget_reservation_succeeded',
          );
          return createWalletSigningBudgetReservation({
            operationId: spend.operationId,
            release: (reason) => {
              releaseWalletSigningBudgetReservation({
                deps,
                reservationsByOperationId,
                reservedUsesByWalletSessionId,
                input: normalizedInput,
                reason,
              });
            },
          });
        },
      );
    },

    async getAvailableStatus(input) {
      const walletSigningSessionId = normalizeRequired(
        input.walletSigningSessionId,
        'walletSigningSessionId',
      );
      if (!deps.getStatus) return null;
      const status = await deps.getStatus({
        nearAccountId: input.nearAccountId,
        walletSigningSessionId,
        targetBackingMaterialSessionIds: normalizeStringList(input.targetBackingMaterialSessionIds),
        targetThresholdSessionIds: normalizeStringList(input.targetThresholdSessionIds),
      });
      if (!status) {
        return {
          sessionId: walletSigningSessionId,
          status: 'not_found',
        };
      }
      return applyWalletSigningBudgetReservationsToStatus({
        status,
        walletSigningSessionId,
        reservedUsesByWalletSessionId,
      });
    },

    async recordSuccess(input) {
      const normalizedInput = normalizeWalletSigningBudgetLedgerRecordSuccessInput(input);
      const operationId = normalizeRequired(normalizedInput.spend.operationId, 'operationId');
      const existing = successfulSpendsByOperationId.get(operationId);
      if (existing) {
        assertWalletSigningOperationFingerprintMatches({
          operationId,
          existingFingerprint: existing.operationFingerprint,
          nextFingerprint: resolveWalletSigningOperationFingerprint(normalizedInput.spend),
        });
        emitWalletSigningBudgetLedgerTrace(
          deps,
          normalizedInput,
          'wallet_signing_budget_spend_deduped',
        );
        return await existing.promise;
      }
      const reservation = reservationsByOperationId.get(operationId);
      if (reservation) {
        assertWalletSigningOperationFingerprintMatches({
          operationId,
          existingFingerprint: resolveWalletSigningOperationFingerprint(reservation.spend),
          nextFingerprint: resolveWalletSigningOperationFingerprint(normalizedInput.spend),
        });
      }

      const spendPromise = recordWalletSigningSpend(deps, normalizedInput)
        .catch((error) => {
          successfulSpendsByOperationId.delete(operationId);
          emitWalletSigningBudgetLedgerTrace(
            deps,
            normalizedInput,
            'wallet_signing_budget_spend_failed',
            {
              error: error instanceof Error ? error.message : String(error || 'unknown error'),
            },
          );
          throw error;
        })
        .finally(() => {
          releaseWalletSigningBudgetReservation({
            deps,
            reservationsByOperationId,
            reservedUsesByWalletSessionId,
            input: normalizedInput,
          });
        });
      successfulSpendsByOperationId.set(operationId, {
        operationFingerprint: resolveWalletSigningOperationFingerprint(normalizedInput.spend),
        promise: spendPromise,
      });
      return await spendPromise;
    },

    recordZeroSpend(input) {
      const spend = normalizeWalletSigningSpendPlan(input.spend);
      releaseWalletSigningBudgetReservation({
        deps,
        reservationsByOperationId,
        reservedUsesByWalletSessionId,
        input: { spend },
        reason: input.reason,
      });
      emitWalletSigningBudgetLedgerTrace(
        deps,
        { spend },
        'wallet_signing_budget_zero_spend_recorded',
        {
          zeroSpendReason: input.reason,
          ...(input.error
            ? { error: input.error instanceof Error ? input.error.message : String(input.error) }
            : {}),
        },
      );
    },

    hasRecorded(operationId) {
      return successfulSpendsByOperationId.has(String(operationId));
    },
  };
}

function applyWalletSigningBudgetReservationsToStatus(args: {
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

async function enqueueWalletReservation<TValue>(
  queues: Map<string, Promise<unknown>>,
  walletSigningSessionId: string,
  task: () => Promise<TValue>,
): Promise<TValue> {
  const previous = queues.get(walletSigningSessionId) || Promise.resolve();
  const next = previous.catch(() => undefined).then(task);
  const queueEntry = next
    .catch(() => undefined)
    .then(() => {
      if (queues.get(walletSigningSessionId) === queueEntry) {
        queues.delete(walletSigningSessionId);
      }
    });
  queues.set(walletSigningSessionId, queueEntry);
  return await next;
}

async function assertWalletSigningBudgetReservationAvailable(args: {
  deps: WalletSigningBudgetLedgerDeps;
  input: WalletSigningBudgetLedgerRecordSuccessInput;
  reservedUsesByWalletSessionId: Map<string, number>;
}): Promise<void> {
  const spend = args.input.spend;
  if (!args.deps.getStatus) return;
  const status = await args.deps.getStatus({
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

function createWalletSigningBudgetReservation(args: {
  operationId: SigningOperationId;
  release: (reason?: WalletSigningBudgetLedgerZeroSpendReason) => void;
}): WalletSigningBudgetReservation {
  let released = false;
  return {
    operationId: args.operationId,
    release(reason) {
      if (released) return;
      released = true;
      args.release(reason);
    },
  };
}

function releaseWalletSigningBudgetReservation(args: {
  deps: WalletSigningBudgetLedgerDeps;
  reservationsByOperationId: Map<string, WalletSigningBudgetLedgerRecordSuccessInput>;
  reservedUsesByWalletSessionId: Map<string, number>;
  input: WalletSigningBudgetLedgerRecordSuccessInput;
  reason?: WalletSigningBudgetLedgerZeroSpendReason;
}): void {
  const spend = args.input.spend;
  const operationId = normalizeRequired(spend.operationId, 'operationId');
  const reservation = args.reservationsByOperationId.get(operationId);
  if (!reservation) return;
  args.reservationsByOperationId.delete(operationId);
  const walletSigningSessionId = normalizeRequired(
    reservation.spend.walletSigningSessionId,
    'walletSigningSessionId',
  );
  const nextReservedUses = Math.max(
    0,
    (args.reservedUsesByWalletSessionId.get(walletSigningSessionId) || 0) - reservation.spend.uses,
  );
  if (nextReservedUses > 0) {
    args.reservedUsesByWalletSessionId.set(walletSigningSessionId, nextReservedUses);
  } else {
    args.reservedUsesByWalletSessionId.delete(walletSigningSessionId);
  }
  emitWalletSigningBudgetLedgerTrace(
    args.deps,
    reservation,
    'wallet_signing_budget_reservation_released',
    args.reason ? { zeroSpendReason: args.reason } : {},
  );
}

function normalizeWalletSigningBudgetLedgerRecordSuccessInput(
  input: WalletSigningBudgetLedgerRecordSuccessInput,
): WalletSigningBudgetLedgerRecordSuccessInput {
  return {
    ...input,
    spend: normalizeWalletSigningSpendPlan(input.spend),
  };
}

async function recordWalletSigningSpend(
  deps: WalletSigningBudgetLedgerDeps,
  input: WalletSigningBudgetLedgerRecordSuccessInput,
): Promise<SigningSessionStatus | null> {
  if (!deps.consumeUse) {
    throw new Error(
      '[WalletSigningBudgetLedger] consumeUse is required to record wallet signing-session spend',
    );
  }
  const spend = input.spend;
  const walletSigningSessionId = normalizeRequired(
    spend.walletSigningSessionId,
    'walletSigningSessionId',
  );
  const nearAccountId = normalizeRequired(spend.nearAccountId, 'nearAccountId') as AccountId;
  emitWalletSigningBudgetLedgerTrace(deps, input, 'wallet_signing_budget_spend_started');
  const status = await deps.consumeUse({
    nearAccountId,
    walletSigningSessionId,
    uses: spend.uses,
    reason: spend.reason,
    targetBackingMaterialSessionIds: normalizeStringList(spend.backingMaterialSessionIds),
    targetThresholdSessionIds: normalizeStringList(spend.thresholdSessionIds),
    alreadyConsumedBackingMaterialSessionIds: normalizeStringList(
      input.alreadyConsumedBackingMaterialSessionIds,
    ),
    alreadyConsumedThresholdSessionIds: normalizeStringList(
      input.alreadyConsumedThresholdSessionIds,
    ),
  });
  if (!status) {
    throw new Error('[WalletSigningBudgetLedger] wallet signing-session spend returned no status');
  }
  if (status.status === 'not_found') {
    throw new Error('[WalletSigningBudgetLedger] wallet signing-session spend returned not_found');
  }
  const statusSummary = status ? summarizeWalletSigningSessionStatus(status) : undefined;
  emitWalletSigningBudgetLedgerTrace(
    deps,
    input,
    'wallet_signing_budget_spend_succeeded',
    statusSummary ? { status: statusSummary } : {},
  );
  return status || null;
}

function resolveWalletSigningOperationFingerprint(spend: WalletSigningSpendPlan): string {
  return String(spend.operationFingerprint || `operation-id:${spend.operationId}`).trim();
}

function assertWalletSigningOperationFingerprintMatches(args: {
  operationId: string;
  existingFingerprint: string;
  nextFingerprint: string;
}): void {
  if (args.existingFingerprint === args.nextFingerprint) return;
  throw new Error(
    `[WalletSigningBudgetLedger] signing operation id reused for a different operation: ${args.operationId}`,
  );
}

function summarizeWalletSigningSessionStatus(
  status: SigningSessionStatus,
): WalletSigningBudgetLedgerTraceEvent['status'] {
  return {
    status: status.status,
    remainingUses: status.remainingUses,
    expiresAtMs: status.expiresAtMs,
  };
}

function emitWalletSigningBudgetLedgerTrace(
  deps: WalletSigningBudgetLedgerDeps,
  input: WalletSigningBudgetLedgerRecordSuccessInput,
  event: WalletSigningBudgetLedgerTraceEvent['event'],
  extra: Pick<WalletSigningBudgetLedgerTraceEvent, 'status' | 'error' | 'zeroSpendReason'> = {},
): void {
  try {
    const spend = input.spend;
    deps.onTrace?.({
      event,
      operationId: spend.operationId,
      nearAccountId: spend.nearAccountId,
      lane: summarizeSigningLane(spend.lane),
      reason: spend.reason,
      uses: spend.uses,
      thresholdSessionCount: spend.thresholdSessionIds.length,
      backingMaterialSessionCount: spend.backingMaterialSessionIds.length,
      ...extra,
    });
  } catch {}
}

function normalizeRequired(value: unknown, label: string): string {
  const normalized = String(value || '').trim();
  if (!normalized) {
    throw new Error(`[WalletSigningBudgetLedger] ${label} is required`);
  }
  return normalized;
}

function normalizeStringList(values: readonly string[] | undefined): string[] | undefined {
  const normalized = (values || []).map((value) => String(value || '').trim()).filter(Boolean);
  return normalized.length ? normalized : undefined;
}
