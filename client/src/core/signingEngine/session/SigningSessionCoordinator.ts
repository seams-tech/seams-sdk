import type { AccountId } from '@/core/types/accountIds';
import type { SigningSessionStatus } from '@/core/types/tatchi';
import {
  deleteSigningSessionSealedRecord,
  updateSigningSessionSealedRecordPolicy,
} from '../api/session/signingSessionSealedStore';
import {
  createSigningPlannerDecisionTraceEvent,
  planSigningSession,
  type SigningPlannerDecisionTraceEvent,
  type SigningSessionPlannerInput,
  type SigningSessionReadiness,
} from './signingSession/planner';
import {
  applySigningSessionBudgetReservationsToStatus,
  assertSigningSessionBudgetReservationAvailable,
  assertWalletSigningOperationFingerprintMatches,
  createSigningSessionBudgetTraceEvent,
  isSigningSessionBudgetExhaustedError,
  normalizeRequired,
  normalizeStringList,
  normalizeSigningSessionBudgetRecordSuccessInput,
  resolveWalletSigningOperationFingerprint,
  summarizeWalletSigningSessionStatus,
  SIGNING_SESSION_BUDGET_EXHAUSTED_ERROR,
  type SigningSessionBudget,
  type SigningSessionBudgetDeps,
  type SigningSessionBudgetRecordSuccessInput,
  type SigningSessionBudgetRecordZeroSpendInput,
  type SigningSessionBudgetTraceEvent,
  type SigningSessionBudgetZeroSpendReason,
  type SigningSessionBudgetReservation,
  type SigningSessionBudgetConsumer,
  type SigningSessionBudgetStatusReader,
} from './signingSession/budget';
import {
  bindCallerProvidedSigningOperationIdToFingerprint,
  type SigningOperationIdBindingState,
} from './signingSession/operationIdBinding';

export {
  SIGNING_SESSION_BUDGET_EXHAUSTED_ERROR,
  isSigningSessionBudgetExhaustedError,
  type SigningSessionBudgetReservation,
};
import {
  applyWalletBudgetStatusToSigningSessionReadiness,
  clearWalletSigningSession,
  consumeWalletSigningSessionUse,
  discoverLanesForAccount,
  normalizeNonEmpty,
  readClaimsForLanes,
  statusFromClaim,
  walletScopedClaimsForLanes,
  type WalletSigningSessionReadinessDeps,
  type WalletSigningSessionStatusOverride,
} from './signingSession/readiness';
import type {
  SigningLaneContext,
  SigningOperationFingerprint,
  SigningOperationId,
  SigningOperationIntent,
  SigningSessionPlan,
} from './signingSession/types';
import type { WarmSessionPrfClaim } from './warmSigning/types';

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

export type WalletSigningSessionConsumeUseArgs = {
  nearAccountId: AccountId | string;
  walletSigningSessionId: string;
  uses: number;
  reason: SigningOperationIntent;
  targetBackingMaterialSessionIds?: string[];
  targetThresholdSessionIds?: string[];
  alreadyConsumedBackingMaterialSessionIds?: string[];
  alreadyConsumedThresholdSessionIds?: string[];
};

export type SigningSessionStatusPort = {
  getStatus(args: {
    nearAccountId: AccountId | string;
    walletSigningSessionId?: string;
    targetBackingMaterialSessionIds?: string[];
    targetThresholdSessionIds?: string[];
  }): Promise<SigningSessionStatus | null>;
  getLaneClaimsForAccount(
    nearAccountId: AccountId | string,
  ): Promise<Map<string, WarmSessionPrfClaim | null>>;
  consumeUse(args: WalletSigningSessionConsumeUseArgs): Promise<SigningSessionStatus>;
  clear(args: { nearAccountId: AccountId | string; walletSigningSessionId: string }): Promise<void>;
};

export type SigningSessionStatusDeps = WalletSigningSessionReadinessDeps;

export type SigningSessionStatusState = {
  statusOverrides: Map<string, WalletSigningSessionStatusOverride>;
};

export type SigningSessionCoordinatorDeps = SigningSessionStatusDeps &
  SigningSessionBudgetDeps & {
  onPlannerTrace?: (event: SigningPlannerDecisionTraceEvent) => void;
  onWalletBudgetTrace?: SigningSessionBudgetDeps['onTrace'];
};

type SigningSessionCoordinatorBudgetState = {
  successfulSpendsByOperationId: Map<
    string,
    {
      operationFingerprint: string;
      promise: Promise<SigningSessionStatus | null>;
    }
  >;
  reservationsByOperationId: Map<string, SigningSessionBudgetRecordSuccessInput>;
  reservedUsesByWalletSessionId: Map<string, number>;
  walletReservationQueues: Map<string, Promise<unknown>>;
};

export class SigningSessionCoordinator
  implements SigningSessionStatusPort, SigningSessionBudget
{
  private readonly onPlannerTrace?: (event: SigningPlannerDecisionTraceEvent) => void;
  private readonly onWalletBudgetTrace?: SigningSessionBudgetDeps['onTrace'];
  private readonly walletBudgetStatusReader?: SigningSessionBudgetStatusReader;
  private readonly walletBudgetConsumer?: SigningSessionBudgetConsumer;
  private readonly walletSessionDeps: SigningSessionStatusDeps;
  private readonly walletSessionState: SigningSessionStatusState;
  private readonly walletBudgetState: SigningSessionCoordinatorBudgetState;
  private readonly operationIdBindingState: SigningOperationIdBindingState;

  constructor(deps: SigningSessionCoordinatorDeps = {}) {
    this.onPlannerTrace = deps.onPlannerTrace;
    this.onWalletBudgetTrace = deps.onWalletBudgetTrace || deps.onTrace;
    this.walletSessionDeps = {
      ...deps,
      updateSigningSessionSealedRecordPolicy:
        deps.updateSigningSessionSealedRecordPolicy || updateSigningSessionSealedRecordPolicy,
      deleteSigningSessionSealedRecord:
        deps.deleteSigningSessionSealedRecord || deleteSigningSessionSealedRecord,
    };
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
    this.operationIdBindingState = {
      callerProvidedOperationFingerprintsById: new Map(),
    };
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
    args: Parameters<SigningSessionStatusPort['getStatus']>[0],
  ): ReturnType<SigningSessionStatusPort['getStatus']> {
    const walletSigningSessionIdFilter = normalizeNonEmpty(args.walletSigningSessionId);
    const lanes = discoverLanesForAccount(this.walletSessionDeps, args.nearAccountId).filter(
      (lane) => !walletSigningSessionIdFilter || lane.walletSigningSessionId === walletSigningSessionIdFilter,
    );
    if (!lanes.length) return null;
    const walletSigningSessionId = walletSigningSessionIdFilter || lanes[0].walletSigningSessionId;
    const targetBacking = new Set(
      (args.targetBackingMaterialSessionIds || []).map(normalizeNonEmpty).filter(Boolean),
    );
    const targetThreshold = new Set(
      (args.targetThresholdSessionIds || []).map(normalizeNonEmpty).filter(Boolean),
    );
    const hasExplicitTarget = targetBacking.size > 0 || targetThreshold.size > 0;
    const statusLanes = hasExplicitTarget
      ? lanes.filter(
          (lane) =>
            targetBacking.has(lane.backingMaterialSessionId) ||
            targetThreshold.has(lane.thresholdSessionId),
        )
      : lanes;
    if (hasExplicitTarget && !statusLanes.length) {
      return {
        sessionId: walletSigningSessionId,
        status: 'not_found',
      };
    }
    const rawClaims = await readClaimsForLanes({
      deps: this.walletSessionDeps,
      lanes: statusLanes,
    });
    const scopedClaims = walletScopedClaimsForLanes({
      lanes: statusLanes,
      claimsByThresholdSessionId: rawClaims,
      statusOverrides: this.walletSessionState.statusOverrides,
    });
    const claims = statusLanes
      .map((lane) => scopedClaims.get(lane.thresholdSessionId) || null)
      .filter(Boolean);
    const claim =
      claims.find((candidate) => candidate?.state === 'expired') ||
      claims.find((candidate) => candidate?.state === 'exhausted') ||
      claims.find((candidate) => candidate?.state === 'unavailable') ||
      claims.find((candidate) => candidate?.state === 'warm') ||
      null;
    return statusFromClaim({ walletSigningSessionId, lanes: statusLanes, claim });
  }

  async getLaneClaimsForAccount(
    nearAccountId: Parameters<SigningSessionStatusPort['getLaneClaimsForAccount']>[0],
  ): ReturnType<SigningSessionStatusPort['getLaneClaimsForAccount']> {
    const lanes = discoverLanesForAccount(this.walletSessionDeps, nearAccountId);
    const rawClaims = await readClaimsForLanes({ deps: this.walletSessionDeps, lanes });
    return walletScopedClaimsForLanes({
      lanes,
      claimsByThresholdSessionId: rawClaims,
      statusOverrides: this.walletSessionState.statusOverrides,
    });
  }

  async consumeUse(
    args: WalletSigningSessionConsumeUseArgs,
  ): ReturnType<SigningSessionStatusPort['consumeUse']> {
    return await consumeWalletSigningSessionUse({
      deps: this.walletSessionDeps,
      statusOverrides: this.walletSessionState.statusOverrides,
      readStatus: (statusArgs) => this.getStatus(statusArgs),
      input: args,
    });
  }

  async clear(
    args: Parameters<SigningSessionStatusPort['clear']>[0],
  ): ReturnType<SigningSessionStatusPort['clear']> {
    await clearWalletSigningSession({
      deps: this.walletSessionDeps,
      statusOverrides: this.walletSessionState.statusOverrides,
      nearAccountId: args.nearAccountId,
      walletSigningSessionId: args.walletSigningSessionId,
    });
  }

  bindCallerProvidedOperationIdToFingerprint(args: {
    operationId: SigningOperationId;
    operationFingerprint: SigningOperationFingerprint;
  }): void {
    bindCallerProvidedSigningOperationIdToFingerprint({
      state: this.operationIdBindingState,
      operationId: args.operationId,
      operationFingerprint: args.operationFingerprint,
    });
  }

  async reserve(
    input: SigningSessionBudgetRecordSuccessInput,
  ): ReturnType<SigningSessionBudget['reserve']> {
    const normalizedInput = normalizeSigningSessionBudgetRecordSuccessInput(input);
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
        await assertSigningSessionBudgetReservationAvailable({
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
    input: Parameters<SigningSessionBudget['getAvailableStatus']>[0],
  ): ReturnType<SigningSessionBudget['getAvailableStatus']> {
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
    return applySigningSessionBudgetReservationsToStatus({
      status,
      walletSigningSessionId,
      reservedUsesByWalletSessionId: this.walletBudgetState.reservedUsesByWalletSessionId,
    });
  }

  async recordSuccess(
    input: SigningSessionBudgetRecordSuccessInput,
  ): ReturnType<SigningSessionBudget['recordSuccess']> {
    const normalizedInput = normalizeSigningSessionBudgetRecordSuccessInput(input);
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

  recordZeroSpend(input: SigningSessionBudgetRecordZeroSpendInput): void {
    const spend = normalizeSigningSessionBudgetRecordSuccessInput({
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

  hasRecorded(operationId: Parameters<SigningSessionBudget['hasRecorded']>[0]): boolean {
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

  private releaseWalletBudgetReservation(
    input: SigningSessionBudgetRecordSuccessInput,
    reason?: SigningSessionBudgetZeroSpendReason,
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
    input: SigningSessionBudgetRecordSuccessInput,
  ): Promise<SigningSessionStatus | null> {
    if (!this.walletBudgetConsumer) {
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
      throw new Error('[SigningSessionBudget] wallet signing-session spend returned no status');
    }
    if (status.status === 'not_found') {
      throw new Error('[SigningSessionBudget] wallet signing-session spend returned not_found');
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
    input: SigningSessionBudgetRecordSuccessInput,
    event: SigningSessionBudgetTraceEvent['event'],
    extra: Pick<SigningSessionBudgetTraceEvent, 'status' | 'error' | 'zeroSpendReason'> = {},
  ): void {
    try {
      this.onWalletBudgetTrace?.(createSigningSessionBudgetTraceEvent(input, event, extra));
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
