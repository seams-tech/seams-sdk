import type { AccountId } from '@/core/types/accountIds';
import type { SigningSessionStatus } from '@/core/types/tatchi';
import {
  createSigningPlannerDecisionTraceEvent,
  planSigningSession,
  type SigningPlannerDecisionTraceEvent,
  type SigningSessionPlannerInput,
  type SigningSessionReadiness,
} from './signingSession/planner';
import {
  applyWalletSigningBudgetReservationsToStatus,
  assertWalletSigningBudgetReservationAvailable,
  assertWalletSigningOperationFingerprintMatches,
  createWalletSigningBudgetLedgerTraceEvent,
  isWalletSigningBudgetExhaustedError,
  normalizeRequired,
  normalizeStringList,
  normalizeWalletSigningBudgetLedgerRecordSuccessInput,
  resolveWalletSigningOperationFingerprint,
  summarizeWalletSigningSessionStatus,
  WALLET_SIGNING_BUDGET_EXHAUSTED_ERROR,
  type WalletSigningBudgetLedger,
  type WalletSigningBudgetLedgerDeps,
  type WalletSigningBudgetLedgerRecordSuccessInput,
  type WalletSigningBudgetLedgerRecordZeroSpendInput,
  type WalletSigningBudgetLedgerTraceEvent,
  type WalletSigningBudgetLedgerZeroSpendReason,
  type WalletSigningBudgetReservation,
  type WalletSigningBudgetConsumer,
  type WalletSigningBudgetStatusReader,
} from './signingSession/budget';

export {
  WALLET_SIGNING_BUDGET_EXHAUSTED_ERROR,
  isWalletSigningBudgetExhaustedError,
  type WalletSigningBudgetReservation,
};
import {
  createWalletSigningSessionCoordinator,
  type WalletSigningSessionConsumeUseArgs,
  type WalletSigningSessionCoordinator,
  type WalletSigningSessionCoordinatorDeps,
  type WalletSigningSessionCoordinatorState,
} from './WalletSigningSessionCoordinator';
import { applyWalletBudgetStatusToSigningSessionReadiness } from './signingSession/readiness';
import type { SigningLaneContext, SigningSessionPlan } from './signingSessionTypes';

export type { SigningSessionReadiness };

export type ResolveSigningSessionAuthPlanInput = SigningSessionPlannerInput;

export type ResolveSigningSessionAuthPlanFromReadinessInput = {
  lane: SigningLaneContext;
  readiness: SigningSessionReadiness;
  expiresAtMs?: number;
  remainingUses?: number;
  usesNeeded?: number;
  forceFreshAuth?: boolean;
  sensitiveOperationPolicy?: SigningSessionPlannerInput['sensitiveOperationPolicy'];
  missingWhenExpiresAtMissing?: boolean;
};

export type ResolveSigningSessionAuthPlanFromReadinessResult = {
  signingSessionPlan: SigningSessionPlan;
  readiness: SigningSessionReadiness;
  expiresAtMs: number;
  remainingUses: number;
};

export type SigningSessionCoordinatorDeps = WalletSigningSessionCoordinatorDeps &
  WalletSigningBudgetLedgerDeps & {
  onPlannerTrace?: (event: SigningPlannerDecisionTraceEvent) => void;
  onWalletBudgetTrace?: WalletSigningBudgetLedgerDeps['onTrace'];
};

type SigningSessionCoordinatorBudgetState = {
  successfulSpendsByOperationId: Map<
    string,
    {
      operationFingerprint: string;
      promise: Promise<SigningSessionStatus | null>;
    }
  >;
  reservationsByOperationId: Map<string, WalletSigningBudgetLedgerRecordSuccessInput>;
  reservedUsesByWalletSessionId: Map<string, number>;
  walletReservationQueues: Map<string, Promise<unknown>>;
};

export class SigningSessionCoordinator
  implements WalletSigningSessionCoordinator, WalletSigningBudgetLedger
{
  private readonly onPlannerTrace?: (event: SigningPlannerDecisionTraceEvent) => void;
  private readonly onWalletBudgetTrace?: WalletSigningBudgetLedgerDeps['onTrace'];
  private readonly walletBudgetStatusReader?: WalletSigningBudgetStatusReader;
  private readonly walletBudgetConsumer?: WalletSigningBudgetConsumer;
  private readonly walletSessionState: WalletSigningSessionCoordinatorState;
  private readonly walletBudgetState: SigningSessionCoordinatorBudgetState;
  private readonly walletSessionCoordinator: WalletSigningSessionCoordinator;

  constructor(deps: SigningSessionCoordinatorDeps = {}) {
    this.onPlannerTrace = deps.onPlannerTrace;
    this.onWalletBudgetTrace = deps.onWalletBudgetTrace || deps.onTrace;
    this.walletSessionState = {
      statusOverrides: new Map(),
    };
    this.walletBudgetState = {
      // Operation ids are request-scoped idempotency keys. Binding each id to
      // the payload fingerprint prevents a retry from hiding a different spend.
      successfulSpendsByOperationId: new Map(),
      reservationsByOperationId: new Map(),
      reservedUsesByWalletSessionId: new Map(),
      walletReservationQueues: new Map(),
    };
    this.walletSessionCoordinator = createWalletSigningSessionCoordinator(
      deps,
      this.walletSessionState,
    );
    const canReadWalletSessionStatus = hasWalletSigningSessionReadinessDeps(deps);
    const canConsumeWalletSessionUses = hasWalletSigningSessionConsumeDeps(deps);
    this.walletBudgetStatusReader = Object.prototype.hasOwnProperty.call(deps, 'getStatus')
      ? deps.getStatus
      : canReadWalletSessionStatus
        ? (statusArgs) => this.getStatus(statusArgs)
        : undefined;
    this.walletBudgetConsumer = Object.prototype.hasOwnProperty.call(deps, 'consumeUse')
      ? deps.consumeUse
      : canConsumeWalletSessionUses
        ? (consumeArgs) => this.consumeUse(consumeArgs)
        : undefined;
  }

  resolveAuthPlan(
    input: ResolveSigningSessionAuthPlanInput,
    onTrace?: (event: SigningPlannerDecisionTraceEvent) => void,
  ): SigningSessionPlan {
    const plan = planSigningSession(input);
    const traceEvent = createSigningPlannerDecisionTraceEvent(input, plan);
    onTrace?.(traceEvent);
    if (!onTrace) this.onPlannerTrace?.(traceEvent);
    return plan;
  }

  async resolveAuthPlanFromReadiness(
    input: ResolveSigningSessionAuthPlanFromReadinessInput,
    onTrace?: (event: SigningPlannerDecisionTraceEvent) => void,
  ): Promise<ResolveSigningSessionAuthPlanFromReadinessResult> {
    const budgetAware = await this.applyWalletBudgetToReadiness(input);
    return {
      ...budgetAware,
      signingSessionPlan: this.resolveAuthPlan(
        {
          lane: input.lane,
          readiness: budgetAware.readiness,
          forceFreshAuth: input.forceFreshAuth,
          sensitiveOperationPolicy: input.sensitiveOperationPolicy,
        },
        onTrace,
      ),
    };
  }

  async getStatus(
    args: Parameters<WalletSigningSessionCoordinator['getStatus']>[0],
  ): ReturnType<WalletSigningSessionCoordinator['getStatus']> {
    return await this.walletSessionCoordinator.getStatus(args);
  }

  async getLaneClaimsForAccount(
    nearAccountId: Parameters<WalletSigningSessionCoordinator['getLaneClaimsForAccount']>[0],
  ): ReturnType<WalletSigningSessionCoordinator['getLaneClaimsForAccount']> {
    return await this.walletSessionCoordinator.getLaneClaimsForAccount(nearAccountId);
  }

  async consumeUse(
    args: WalletSigningSessionConsumeUseArgs,
  ): ReturnType<WalletSigningSessionCoordinator['consumeUse']> {
    return await this.walletSessionCoordinator.consumeUse(args);
  }

  async clear(
    args: Parameters<WalletSigningSessionCoordinator['clear']>[0],
  ): ReturnType<WalletSigningSessionCoordinator['clear']> {
    await this.walletSessionCoordinator.clear(args);
  }

  async reserve(
    input: WalletSigningBudgetLedgerRecordSuccessInput,
  ): ReturnType<WalletSigningBudgetLedger['reserve']> {
    const normalizedInput = normalizeWalletSigningBudgetLedgerRecordSuccessInput(input);
    const spend = normalizedInput.spend;
    const operationId = normalizeRequired(spend.operationId, 'operationId');
    const walletSigningSessionId = normalizeRequired(
      spend.walletSigningSessionId,
      'walletSigningSessionId',
    );
    const { successfulSpendsByOperationId, reservationsByOperationId } = this.walletBudgetState;
    const existingSpend = successfulSpendsByOperationId.get(operationId);
    if (existingSpend) {
      assertWalletSigningOperationFingerprintMatches({
        operationId,
        existingFingerprint: existingSpend.operationFingerprint,
        nextFingerprint: resolveWalletSigningOperationFingerprint(spend),
      });
      this.emitWalletBudgetTrace(normalizedInput, 'wallet_signing_budget_reservation_deduped');
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
      this.emitWalletBudgetTrace(normalizedInput, 'wallet_signing_budget_reservation_deduped');
      return null;
    }

    return await this.enqueueWalletReservation(walletSigningSessionId, async () => {
      if (reservationsByOperationId.has(operationId)) {
        assertWalletSigningOperationFingerprintMatches({
          operationId,
          existingFingerprint: resolveWalletSigningOperationFingerprint(
            reservationsByOperationId.get(operationId)!.spend,
          ),
          nextFingerprint: resolveWalletSigningOperationFingerprint(spend),
        });
        this.emitWalletBudgetTrace(normalizedInput, 'wallet_signing_budget_reservation_deduped');
        return null;
      }

      this.emitWalletBudgetTrace(normalizedInput, 'wallet_signing_budget_reservation_started');
      try {
        await assertWalletSigningBudgetReservationAvailable({
          getStatus: this.walletBudgetStatusReader,
          input: normalizedInput,
          reservedUsesByWalletSessionId: this.walletBudgetState.reservedUsesByWalletSessionId,
        });
      } catch (error) {
        this.emitWalletBudgetTrace(normalizedInput, 'wallet_signing_budget_reservation_failed', {
          error: error instanceof Error ? error.message : String(error || 'unknown error'),
        });
        throw error;
      }

      reservationsByOperationId.set(operationId, normalizedInput);
      this.walletBudgetState.reservedUsesByWalletSessionId.set(
        walletSigningSessionId,
        (this.walletBudgetState.reservedUsesByWalletSessionId.get(walletSigningSessionId) || 0) +
          spend.uses,
      );
      this.emitWalletBudgetTrace(normalizedInput, 'wallet_signing_budget_reservation_succeeded');
      return this.createWalletBudgetReservation(spend.operationId, (reason) => {
        this.releaseWalletBudgetReservation(normalizedInput, reason);
      });
    });
  }

  async getAvailableStatus(
    input: Parameters<WalletSigningBudgetLedger['getAvailableStatus']>[0],
  ): ReturnType<WalletSigningBudgetLedger['getAvailableStatus']> {
    const walletSigningSessionId = normalizeRequired(
      input.walletSigningSessionId,
      'walletSigningSessionId',
    );
    if (!this.walletBudgetStatusReader) return null;
    const status = await this.walletBudgetStatusReader({
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
      reservedUsesByWalletSessionId: this.walletBudgetState.reservedUsesByWalletSessionId,
    });
  }

  async recordSuccess(
    input: WalletSigningBudgetLedgerRecordSuccessInput,
  ): ReturnType<WalletSigningBudgetLedger['recordSuccess']> {
    const normalizedInput = normalizeWalletSigningBudgetLedgerRecordSuccessInput(input);
    const operationId = normalizeRequired(normalizedInput.spend.operationId, 'operationId');
    const { successfulSpendsByOperationId, reservationsByOperationId } = this.walletBudgetState;
    const existing = successfulSpendsByOperationId.get(operationId);
    if (existing) {
      assertWalletSigningOperationFingerprintMatches({
        operationId,
        existingFingerprint: existing.operationFingerprint,
        nextFingerprint: resolveWalletSigningOperationFingerprint(normalizedInput.spend),
      });
      this.emitWalletBudgetTrace(normalizedInput, 'wallet_signing_budget_spend_deduped');
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

    const spendPromise = this.recordWalletSigningSpend(normalizedInput)
      .catch((error) => {
        successfulSpendsByOperationId.delete(operationId);
        this.emitWalletBudgetTrace(normalizedInput, 'wallet_signing_budget_spend_failed', {
          error: error instanceof Error ? error.message : String(error || 'unknown error'),
        });
        throw error;
      })
      .finally(() => {
        this.releaseWalletBudgetReservation(normalizedInput);
      });
    successfulSpendsByOperationId.set(operationId, {
      operationFingerprint: resolveWalletSigningOperationFingerprint(normalizedInput.spend),
      promise: spendPromise,
    });
    return await spendPromise;
  }

  recordZeroSpend(input: WalletSigningBudgetLedgerRecordZeroSpendInput): void {
    const spend = normalizeWalletSigningBudgetLedgerRecordSuccessInput({
      spend: input.spend,
    }).spend;
    this.releaseWalletBudgetReservation({ spend }, input.reason);
    this.emitWalletBudgetTrace({ spend }, 'wallet_signing_budget_zero_spend_recorded', {
      zeroSpendReason: input.reason,
      ...(input.error
        ? { error: input.error instanceof Error ? input.error.message : String(input.error) }
        : {}),
    });
  }

  hasRecorded(operationId: Parameters<WalletSigningBudgetLedger['hasRecorded']>[0]): boolean {
    return this.walletBudgetState.successfulSpendsByOperationId.has(String(operationId));
  }

  private async applyWalletBudgetToReadiness(
    input: ResolveSigningSessionAuthPlanFromReadinessInput,
  ): Promise<Pick<ResolveSigningSessionAuthPlanFromReadinessResult, 'readiness' | 'expiresAtMs' | 'remainingUses'>> {
    const walletSigningSessionId = String(input.lane.walletSigningSessionId || '').trim();
    const walletBudgetStatus = walletSigningSessionId
      ? await this.getAvailableStatus({
          nearAccountId: input.lane.accountId,
          walletSigningSessionId,
          ...(input.lane.backingMaterialSessionId
            ? { targetBackingMaterialSessionIds: [input.lane.backingMaterialSessionId] }
            : {}),
          ...(input.lane.thresholdSessionId
            ? { targetThresholdSessionIds: [input.lane.thresholdSessionId] }
            : {}),
        }).catch(() => ({
          sessionId: walletSigningSessionId,
          status: 'unavailable' as const,
        }))
      : null;
    return applyWalletBudgetStatusToSigningSessionReadiness({
      ...input.readiness,
      walletBudgetStatus,
      expiresAtMs: Math.floor(Number(input.expiresAtMs) || 0),
      remainingUses: Math.floor(Number(input.remainingUses) || 0),
      usesNeeded: input.usesNeeded,
      missingWhenExpiresAtMissing: input.missingWhenExpiresAtMissing,
    });
  }

  private async enqueueWalletReservation<TValue>(
    walletSigningSessionId: string,
    task: () => Promise<TValue>,
  ): Promise<TValue> {
    const queues = this.walletBudgetState.walletReservationQueues;
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

  private createWalletBudgetReservation(
    operationId: WalletSigningBudgetReservation['operationId'],
    release: (reason?: WalletSigningBudgetLedgerZeroSpendReason) => void,
  ): WalletSigningBudgetReservation {
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

  private releaseWalletBudgetReservation(
    input: WalletSigningBudgetLedgerRecordSuccessInput,
    reason?: WalletSigningBudgetLedgerZeroSpendReason,
  ): void {
    const spend = input.spend;
    const operationId = normalizeRequired(spend.operationId, 'operationId');
    const reservation = this.walletBudgetState.reservationsByOperationId.get(operationId);
    if (!reservation) return;
    this.walletBudgetState.reservationsByOperationId.delete(operationId);
    const walletSigningSessionId = normalizeRequired(
      reservation.spend.walletSigningSessionId,
      'walletSigningSessionId',
    );
    const nextReservedUses = Math.max(
      0,
      (this.walletBudgetState.reservedUsesByWalletSessionId.get(walletSigningSessionId) || 0) -
        reservation.spend.uses,
    );
    if (nextReservedUses > 0) {
      this.walletBudgetState.reservedUsesByWalletSessionId.set(
        walletSigningSessionId,
        nextReservedUses,
      );
    } else {
      this.walletBudgetState.reservedUsesByWalletSessionId.delete(walletSigningSessionId);
    }
    this.emitWalletBudgetTrace(
      reservation,
      'wallet_signing_budget_reservation_released',
      reason ? { zeroSpendReason: reason } : {},
    );
  }

  private async recordWalletSigningSpend(
    input: WalletSigningBudgetLedgerRecordSuccessInput,
  ): Promise<SigningSessionStatus | null> {
    if (!this.walletBudgetConsumer) {
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
    this.emitWalletBudgetTrace(input, 'wallet_signing_budget_spend_started');
    const status = await this.walletBudgetConsumer({
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
    this.emitWalletBudgetTrace(
      input,
      'wallet_signing_budget_spend_succeeded',
      statusSummary ? { status: statusSummary } : {},
    );
    return status || null;
  }

  private emitWalletBudgetTrace(
    input: WalletSigningBudgetLedgerRecordSuccessInput,
    event: WalletSigningBudgetLedgerTraceEvent['event'],
    extra: Pick<WalletSigningBudgetLedgerTraceEvent, 'status' | 'error' | 'zeroSpendReason'> = {},
  ): void {
    try {
      this.onWalletBudgetTrace?.(createWalletSigningBudgetLedgerTraceEvent(input, event, extra));
    } catch {}
  }
}

function hasWalletSigningSessionReadinessDeps(deps: SigningSessionCoordinatorDeps): boolean {
  return Boolean(
    deps.touchConfirm ||
      deps.listThresholdEcdsaSessionRecordsForLookup ||
      deps.getEmailOtpWarmSessionStatus,
  );
}

function hasWalletSigningSessionConsumeDeps(deps: SigningSessionCoordinatorDeps): boolean {
  return Boolean(
    deps.consumeUse ||
      deps.touchConfirm?.consumeWarmSessionUses ||
      deps.consumeEmailOtpWarmSessionUses ||
      deps.markThresholdEd25519EmailOtpSessionConsumedForAccount,
  );
}
