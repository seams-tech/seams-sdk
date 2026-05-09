import type { AccountId } from '@/core/types/accountIds';
import type { SigningSessionStatus } from '@/core/types/seams';
import {
  applySigningSessionBudgetReservationsToStatus,
  assertPreparedBudgetProjectionVersion,
  assertSigningSessionBudgetReservationAvailable,
  assertWalletSigningOperationFingerprintMatches,
  createSigningSessionBudgetTraceEvent,
  normalizeRequired,
  normalizeSigningSessionBudgetRecordSuccessInput,
  normalizeStringList,
  resolveWalletSigningOperationFingerprint,
  SIGNING_SESSION_BUDGET_UNKNOWN_ERROR,
  type SigningSessionBudget,
  type SigningSessionBudgetConsumer,
  type SigningSessionBudgetRecordSuccessInput,
  type SigningSessionBudgetRecordZeroSpendInput,
  type SigningSessionBudgetReservation,
  type SigningSessionBudgetReservationRecord,
  type SigningSessionBudgetStatusAuth,
  type SigningSessionBudgetTraceEvent,
  type SigningSessionBudgetZeroSpendReason,
} from './budget';

type SuccessfulSpendRecord = {
  operationFingerprint: string;
  promise: Promise<SigningSessionStatus | null>;
};

export type BudgetCoordinatorDeps = {
  readStatus: (args: {
    nearAccountId: AccountId | string;
    walletSigningSessionId?: string;
    targetBackingMaterialSessionIds?: string[];
    targetThresholdSessionIds?: string[];
    trustedStatusAuth?: SigningSessionBudgetStatusAuth;
  }) => Promise<SigningSessionStatus>;
  consumeUse?: SigningSessionBudgetConsumer;
  onTrace?: (event: SigningSessionBudgetTraceEvent) => void;
};

export class BudgetCoordinator implements SigningSessionBudget {
  private readonly successfulSpendsByOperationId = new Map<string, SuccessfulSpendRecord>();
  private readonly reservationsByOperationId = new Map<
    string,
    SigningSessionBudgetReservationRecord
  >();
  private readonly walletReservationQueues = new Map<string, Promise<unknown>>();

  constructor(private readonly deps: BudgetCoordinatorDeps) {}

  async reserve(
    input: Parameters<SigningSessionBudget['reserve']>[0],
  ): ReturnType<SigningSessionBudget['reserve']> {
    const normalizedInput = normalizeSigningSessionBudgetRecordSuccessInput(input);
    const spend = normalizedInput.spend;
    const operationId = normalizeRequired(spend.operationId, 'operationId');
    const walletSigningSessionId = normalizeRequired(
      spend.walletSigningSessionId,
      'walletSigningSessionId',
    );
    const existingSpend = this.successfulSpendsByOperationId.get(operationId);
    if (existingSpend) {
      assertWalletSigningOperationFingerprintMatches({
        operationId,
        existingFingerprint: existingSpend.operationFingerprint,
        nextFingerprint: resolveWalletSigningOperationFingerprint(spend),
      });
      this.emitTrace(normalizedInput, 'wallet_signing_budget_reservation_deduped');
      return null;
    }
    const existingReservation = this.reservationsByOperationId.get(operationId);
    if (existingReservation) {
      assertWalletSigningOperationFingerprintMatches({
        operationId,
        existingFingerprint: resolveWalletSigningOperationFingerprint(existingReservation.spend),
        nextFingerprint: resolveWalletSigningOperationFingerprint(spend),
      });
      this.emitTrace(normalizedInput, 'wallet_signing_budget_reservation_deduped');
      return null;
    }

    return await this.enqueueWalletReservation(walletSigningSessionId, async () => {
      const admittedReservation = this.reservationsByOperationId.get(operationId);
      if (admittedReservation) {
        assertWalletSigningOperationFingerprintMatches({
          operationId,
          existingFingerprint: resolveWalletSigningOperationFingerprint(admittedReservation.spend),
          nextFingerprint: resolveWalletSigningOperationFingerprint(spend),
        });
        this.emitTrace(normalizedInput, 'wallet_signing_budget_reservation_deduped');
        return null;
      }

      this.emitTrace(normalizedInput, 'wallet_signing_budget_reservation_started');
      let admittedStatus: Awaited<ReturnType<typeof assertSigningSessionBudgetReservationAvailable>>;
      try {
        admittedStatus = await assertSigningSessionBudgetReservationAvailable({
          getStatus: (statusArgs) => this.deps.readStatus(statusArgs),
          input: normalizedInput,
          reservationsByOperationId: this.reservationsByOperationId,
        });
      } catch (error) {
        this.emitTrace(normalizedInput, 'wallet_signing_budget_reservation_failed', {
          error: error instanceof Error ? error.message : String(error || 'unknown error'),
        });
        throw error;
      }

      this.reservationsByOperationId.set(operationId, {
        ...normalizedInput,
        expectedBudgetProjectionVersion: admittedStatus.projectionVersion,
        operationFingerprint: resolveWalletSigningOperationFingerprint(spend),
        walletSigningSessionId,
        reservedAgainstProjectionVersion: admittedStatus.projectionVersion,
        reservedAgainstRemainingUses: Math.max(
          0,
          Math.floor(Number(admittedStatus.remainingUses) || 0),
        ),
        createdAtMs: Date.now(),
      });
      this.emitTrace(normalizedInput, 'wallet_signing_budget_reservation_succeeded');
      return this.createReservation(spend.operationId, (reason) => {
        this.releaseReservation(normalizedInput, reason);
      });
    });
  }

  async getAvailableStatus(
    input: Parameters<SigningSessionBudget['getAvailableStatus']>[0],
  ): ReturnType<SigningSessionBudget['getAvailableStatus']> {
    const walletSigningSessionId = normalizeRequired(
      input.walletSigningSessionId,
      'walletSigningSessionId',
    );
    const status = await this.deps.readStatus({
      nearAccountId: input.nearAccountId,
      walletSigningSessionId,
      targetBackingMaterialSessionIds: normalizeStringList(input.targetBackingMaterialSessionIds),
      targetThresholdSessionIds: normalizeStringList(input.targetThresholdSessionIds),
      trustedStatusAuth: input.trustedStatusAuth,
    });
    return applySigningSessionBudgetReservationsToStatus({
      status,
      walletSigningSessionId,
      reservationsByOperationId: this.reservationsByOperationId,
    });
  }

  async recordSuccess(
    input: SigningSessionBudgetRecordSuccessInput,
  ): ReturnType<SigningSessionBudget['recordSuccess']> {
    const normalizedInput = normalizeSigningSessionBudgetRecordSuccessInput(input);
    const operationId = normalizeRequired(normalizedInput.spend.operationId, 'operationId');
    const existing = this.successfulSpendsByOperationId.get(operationId);
    if (existing) {
      assertWalletSigningOperationFingerprintMatches({
        operationId,
        existingFingerprint: existing.operationFingerprint,
        nextFingerprint: resolveWalletSigningOperationFingerprint(normalizedInput.spend),
      });
      this.emitTrace(normalizedInput, 'wallet_signing_budget_spend_deduped');
      return await existing.promise;
    }
    const reservation = this.reservationsByOperationId.get(operationId);
    let spendInput = normalizedInput;
    if (reservation) {
      assertWalletSigningOperationFingerprintMatches({
        operationId,
        existingFingerprint: resolveWalletSigningOperationFingerprint(reservation.spend),
        nextFingerprint: resolveWalletSigningOperationFingerprint(normalizedInput.spend),
      });
      spendInput = {
        ...normalizedInput,
        expectedBudgetProjectionVersion: reservation.expectedBudgetProjectionVersion,
      };
    }
    if (!reservation) {
      const status = await this.deps.readStatus({
        nearAccountId: normalizedInput.spend.nearAccountId,
        walletSigningSessionId: normalizedInput.spend.walletSigningSessionId,
        targetBackingMaterialSessionIds: normalizeStringList(
          normalizedInput.spend.backingMaterialSessionIds,
        ),
        targetThresholdSessionIds: normalizeStringList(normalizedInput.spend.thresholdSessionIds),
        trustedStatusAuth: normalizedInput.trustedStatusAuth,
      });
      if (status.status === 'budget_unknown') {
        throw new Error(SIGNING_SESSION_BUDGET_UNKNOWN_ERROR);
      }
      const hasAuthoritativeExternalSpend =
        Boolean(
          normalizeStringList(normalizedInput.alreadyConsumedBackingMaterialSessionIds)?.length,
        ) ||
        Boolean(normalizeStringList(normalizedInput.alreadyConsumedThresholdSessionIds)?.length);
      if (!hasAuthoritativeExternalSpend) {
        assertPreparedBudgetProjectionVersion({
          status,
          expectedBudgetProjectionVersion: normalizedInput.expectedBudgetProjectionVersion,
        });
      }
    }

    const spendPromise = this.recordSpend(spendInput)
      .catch((error) => {
        this.successfulSpendsByOperationId.delete(operationId);
        this.emitTrace(spendInput, 'wallet_signing_budget_spend_failed', {
          error: error instanceof Error ? error.message : String(error || 'unknown error'),
        });
        throw error;
      })
      .finally(() => {
        this.releaseReservation(spendInput);
      });
    this.successfulSpendsByOperationId.set(operationId, {
      operationFingerprint: resolveWalletSigningOperationFingerprint(spendInput.spend),
      promise: spendPromise,
    });
    return await spendPromise;
  }

  recordZeroSpend(input: SigningSessionBudgetRecordZeroSpendInput): void {
    const spend = normalizeSigningSessionBudgetRecordSuccessInput({
      spend: input.spend,
    }).spend;
    this.releaseReservation({ spend }, input.reason);
    this.emitTrace({ spend }, 'wallet_signing_budget_zero_spend_recorded', {
      zeroSpendReason: input.reason,
      ...(input.error
        ? { error: input.error instanceof Error ? input.error.message : String(input.error) }
        : {}),
    });
  }

  hasRecorded(operationId: string): boolean {
    return this.successfulSpendsByOperationId.has(String(operationId));
  }

  private async enqueueWalletReservation<TValue>(
    walletSigningSessionId: string,
    task: () => Promise<TValue>,
  ): Promise<TValue> {
    const previous = this.walletReservationQueues.get(walletSigningSessionId) || Promise.resolve();
    const next = previous.catch(() => undefined).then(task);
    const queueEntry = next
      .catch(() => undefined)
      .then(() => {
        if (this.walletReservationQueues.get(walletSigningSessionId) === queueEntry) {
          this.walletReservationQueues.delete(walletSigningSessionId);
        }
      });
    this.walletReservationQueues.set(walletSigningSessionId, queueEntry);
    return await next;
  }

  private createReservation(
    operationId: SigningSessionBudgetReservation['operationId'],
    release: (reason?: SigningSessionBudgetZeroSpendReason) => void,
  ): SigningSessionBudgetReservation {
    let released = false;
    return {
      operationId,
      release(reason) {
        if (released) return;
        released = true;
        release(reason);
      },
    };
  }

  private releaseReservation(
    input: SigningSessionBudgetRecordSuccessInput,
    reason?: SigningSessionBudgetZeroSpendReason,
  ): void {
    const operationId = normalizeRequired(input.spend.operationId, 'operationId');
    const reservation = this.reservationsByOperationId.get(operationId);
    if (!reservation) return;
    this.reservationsByOperationId.delete(operationId);
    this.emitTrace(
      reservation,
      'wallet_signing_budget_reservation_released',
      reason ? { zeroSpendReason: reason } : {},
    );
  }

  private async recordSpend(
    input: SigningSessionBudgetRecordSuccessInput,
  ): Promise<SigningSessionStatus | null> {
    if (!this.deps.consumeUse) {
      throw new Error(
        '[SigningSessionBudget] consumeUse is required to record wallet signing-session spend',
      );
    }
    const spend = input.spend;
    const walletSigningSessionId = normalizeRequired(
      spend.walletSigningSessionId,
      'walletSigningSessionId',
    );
    const nearAccountId = normalizeRequired(spend.nearAccountId, 'nearAccountId') as AccountId;
    this.emitTrace(input, 'wallet_signing_budget_spend_started');
    const status = await this.deps.consumeUse({
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
      trustedStatusAuth: input.trustedStatusAuth,
    });
    if (!status) {
      throw new Error('[SigningSessionBudget] wallet signing-session spend returned no status');
    }
    if (status.status === 'not_found') {
      throw new Error('[SigningSessionBudget] wallet signing-session spend returned not_found');
    }
    if (status.status === 'budget_unknown') {
      throw new Error(
        '[SigningSessionBudget] wallet signing-session spend returned budget_unknown',
      );
    }
    this.emitTrace(input, 'wallet_signing_budget_spend_succeeded', {
      status: {
        status: status.status,
        remainingUses: status.remainingUses,
        expiresAtMs: status.expiresAtMs,
      },
    });
    return status || null;
  }

  private emitTrace(
    input: SigningSessionBudgetRecordSuccessInput,
    event: SigningSessionBudgetTraceEvent['event'],
    extra: Pick<SigningSessionBudgetTraceEvent, 'status' | 'error' | 'zeroSpendReason'> = {},
  ): void {
    this.deps.onTrace?.(createSigningSessionBudgetTraceEvent(input, event, extra));
  }
}
