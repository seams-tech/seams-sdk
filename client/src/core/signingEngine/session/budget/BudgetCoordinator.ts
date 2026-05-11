import type { AccountId } from '@/core/types/accountIds';
import type { SigningSessionStatus } from '@/core/types/seams';
import { normalizeWalletSigningSpendPlan } from '../operationState/types';
import {
  applySigningSessionBudgetReservationsToStatus,
  assertPreparedBudgetProjectionVersion,
  assertSigningSessionBudgetReservationAvailable,
  assertWalletSigningOperationFingerprintMatches,
  buildSigningSessionBudgetStatusCheckForSpend,
  createZeroSpendTraceEvent,
  createSigningSessionBudgetTraceEvent,
  normalizeRequired,
  normalizeWalletBudgetSuccessInput,
  normalizeStringList,
  resolveWalletSigningOperationFingerprint,
  SIGNING_SESSION_BUDGET_UNKNOWN_ERROR,
  type SigningSessionBudget,
  type SigningSessionBudgetConsumer,
  type SigningSessionBudgetReservation,
  type SigningSessionBudgetReservationRecord,
  type SigningSessionBudgetReserveInput,
  type SigningSessionBudgetSuccessInput,
  type SigningSessionBudgetTraceEvent,
  type SigningSessionBudgetZeroSpendReason,
  type WalletBudgetSpend,
  type ZeroWalletBudgetSpend,
} from './budget';

type SuccessfulSpendRecord = {
  operationFingerprint: string;
  promise: Promise<SigningSessionStatus | null>;
};

export type BudgetCoordinatorDeps = {
  readStatus: (args: Parameters<SigningSessionBudget['getAvailableStatus']>[0]) => Promise<SigningSessionStatus>;
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
    const normalizedInput: SigningSessionBudgetReserveInput = {
      ...input,
      spend: normalizeWalletSigningSpendPlan(input.spend),
    };
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
    const walletSigningSessionId = normalizeRequired(input.walletSigningSessionId, 'walletSigningSessionId');
    const status = await this.deps.readStatus({
      ...input,
      walletSigningSessionId,
    });
    return applySigningSessionBudgetReservationsToStatus({
      status,
      walletSigningSessionId,
      reservationsByOperationId: this.reservationsByOperationId,
    });
  }

  async recordSuccess(
    input: SigningSessionBudgetSuccessInput,
  ): ReturnType<SigningSessionBudget['recordSuccess']> {
    const normalizedInput = normalizeWalletBudgetSuccessInput(input);
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
    if (reservation) {
      assertWalletSigningOperationFingerprintMatches({
        operationId,
        existingFingerprint: resolveWalletSigningOperationFingerprint(reservation.spend),
        nextFingerprint: resolveWalletSigningOperationFingerprint(normalizedInput.spend),
      });
      if (normalizedInput.kind === 'unreserved_success') {
        throw new Error(
          '[SigningSessionBudget] reserved operations must finalize with reserved_success',
        );
      }
      if (
        normalizedInput.kind === 'reserved_success' &&
        normalizedInput.expectedBudgetProjectionVersion !==
          (reservation.expectedBudgetProjectionVersion ||
            reservation.reservedAgainstProjectionVersion)
      ) {
        throw new Error(
          '[SigningSessionBudget] reserved_success projection does not match reservation',
        );
      }
    } else if (normalizedInput.kind === 'reserved_success') {
      throw new Error(
        '[SigningSessionBudget] reserved_success requires an existing reservation',
      );
    }
    if (!reservation) {
      const status = await this.deps.readStatus(
        buildSigningSessionBudgetStatusCheckForSpend({
          spend: normalizedInput.spend,
          trustedStatusAuth: normalizedInput.trustedStatusAuth,
        }),
      );
      if (status.status === 'budget_unknown') {
        throw new Error(SIGNING_SESSION_BUDGET_UNKNOWN_ERROR);
      }
      if (normalizedInput.kind !== 'externally_consumed_success') {
        assertPreparedBudgetProjectionVersion({
          status,
          expectedBudgetProjectionVersion: normalizedInput.expectedBudgetProjectionVersion,
        });
      }
    }

    const spendPromise = this.recordSpend(normalizedInput)
      .catch((error) => {
        this.successfulSpendsByOperationId.delete(operationId);
        this.emitTrace(normalizedInput, 'wallet_signing_budget_spend_failed', {
          error: error instanceof Error ? error.message : String(error || 'unknown error'),
        });
        throw error;
      })
      .finally(() => {
        this.releaseReservation(normalizedInput);
      });
    this.successfulSpendsByOperationId.set(operationId, {
      operationFingerprint: resolveWalletSigningOperationFingerprint(normalizedInput.spend),
      promise: spendPromise,
    });
    return await spendPromise;
  }

  recordZeroSpend(input: ZeroWalletBudgetSpend): void {
    this.releaseZeroSpendReservation(input);
    this.deps.onTrace?.(
      createZeroSpendTraceEvent(input, 'wallet_signing_budget_zero_spend_recorded', {
        zeroSpendReason: input.reason,
        ...(input.error
          ? { error: input.error instanceof Error ? input.error.message : String(input.error) }
          : {}),
      }),
    );
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
    input: { spend: WalletBudgetSpend },
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

  private releaseZeroSpendReservation(input: ZeroWalletBudgetSpend): void {
    const reservation = this.reservationsByOperationId.get(input.operationId);
    if (!reservation) return;
    this.reservationsByOperationId.delete(input.operationId);
    this.deps.onTrace?.(
      createZeroSpendTraceEvent(input, 'wallet_signing_budget_reservation_released', {
        zeroSpendReason: input.reason,
      }),
    );
  }

  private async recordSpend(
    input: SigningSessionBudgetSuccessInput,
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
    const budgetStatusCheck = buildSigningSessionBudgetStatusCheckForSpend({
      spend,
      trustedStatusAuth: input.trustedStatusAuth,
    });
    const status = await this.deps.consumeUse({
      nearAccountId,
      walletSigningSessionId,
      uses: spend.uses,
      reason: spend.reason,
      budgetStatusCheck,
      ...(input.kind === 'externally_consumed_success'
        ? {
            alreadyConsumedBackingMaterialSessionIds: normalizeStringList(
              input.alreadyConsumedBackingMaterialSessionIds,
            ),
            alreadyConsumedThresholdSessionIds: normalizeStringList(
              input.alreadyConsumedThresholdSessionIds,
            ),
          }
        : {}),
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
    input: { spend: WalletBudgetSpend },
    event: SigningSessionBudgetTraceEvent['event'],
    extra: Pick<SigningSessionBudgetTraceEvent, 'status' | 'error' | 'zeroSpendReason'> = {},
  ): void {
    this.deps.onTrace?.(createSigningSessionBudgetTraceEvent(input, event, extra));
  }
}
