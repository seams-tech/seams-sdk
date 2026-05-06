import type { AccountId } from '@/core/types/accountIds';
import type { SigningSessionStatus } from '@/core/types/seams';
import {
  deleteExactSealedSession,
  updateExactSealedSessionPolicy,
} from './sealedSessionStore';
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
  assertPreparedBudgetProjectionVersion,
  assertWalletSigningOperationFingerprintMatches,
  createSigningSessionBudgetTraceEvent,
  isSigningSessionBudgetExhaustedError,
  isSigningSessionBudgetUnknownError,
  normalizeRequired,
  normalizeStringList,
  normalizeSigningSessionBudgetRecordSuccessInput,
  resolveWalletSigningOperationFingerprint,
  summarizeWalletSigningSessionStatus,
  SIGNING_SESSION_BUDGET_EXHAUSTED_ERROR,
  SIGNING_SESSION_BUDGET_UNKNOWN_ERROR,
  type SigningSessionBudget,
  type SigningSessionBudgetDeps,
  type SigningSessionBudgetRecordSuccessInput,
  type SigningSessionBudgetRecordZeroSpendInput,
  type SigningSessionBudgetTraceEvent,
  type SigningSessionBudgetZeroSpendReason,
  type SigningSessionBudgetReservation,
  type SigningSessionBudgetReserveInput,
  type SigningSessionBudgetReservationRecord,
  type SigningSessionPreparedBudgetIdentity,
  type SigningSessionBudgetConsumer,
  type SigningSessionBudgetStatusReader,
  type SigningSessionBudgetStatusAuth,
} from './signingSession/budget';
import { budgetUnknownSigningSessionStatus } from './signingSession/budgetProjection';
import {
  bindCallerProvidedSigningOperationIdToFingerprint,
  type SigningOperationIdBindingState,
} from './signingSession/operationIdBinding';

export {
  SIGNING_SESSION_BUDGET_EXHAUSTED_ERROR,
  SIGNING_SESSION_BUDGET_UNKNOWN_ERROR,
  isSigningSessionBudgetExhaustedError,
  isSigningSessionBudgetUnknownError,
  type SigningSessionBudgetReservation,
};
import {
  applyWalletBudgetStatusToSigningSessionReadiness,
  clearWalletSigningSession,
  consumeWalletSigningSessionUse,
  discoverLanesForAccount,
  normalizeNonEmpty,
  readDirectSigningSessionStatusForTargets,
  readClaimsForLanes,
  readWalletScopedLaneClaimsForAccount,
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
import {
  selectedSigningLaneContextFromTransactionLane,
  type TransactionLane,
} from './signingSession/transactionState';
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
  trustedStatusAuth?: SigningSessionBudgetStatusAuth;
};

export type SigningSessionStatusPort = {
  getStatus(args: {
    nearAccountId: AccountId | string;
    walletSigningSessionId?: string;
    targetBackingMaterialSessionIds?: string[];
    targetThresholdSessionIds?: string[];
    trustedStatusAuth?: SigningSessionBudgetStatusAuth;
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
  reservationsByOperationId: Map<string, SigningSessionBudgetReservationRecord>;
  walletReservationQueues: Map<string, Promise<unknown>>;
};

export class SigningSessionCoordinator
  implements SigningSessionStatusPort, SigningSessionBudget
{
  private readonly onPlannerTrace?: (event: SigningPlannerDecisionTraceEvent) => void;
  private readonly onWalletBudgetTrace?: SigningSessionBudgetDeps['onTrace'];
  private readonly walletBudgetStatusReader?: SigningSessionBudgetStatusReader;
  private readonly walletBudgetStatusSource: 'provided' | 'material_fallback' | 'none';
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
      updateExactSealedSessionPolicy:
        deps.updateExactSealedSessionPolicy || updateExactSealedSessionPolicy,
      deleteExactSealedSession:
        deps.deleteExactSealedSession || deleteExactSealedSession,
    };
    this.walletSessionState = {
      statusOverrides: new Map(),
    };
    this.walletBudgetState = {
      // Operation ids are request-scoped idempotency keys. Binding each id to
      // the payload fingerprint prevents a retry from hiding a different spend.
      successfulSpendsByOperationId: new Map(),
      reservationsByOperationId: new Map(),
      walletReservationQueues: new Map(),
    };
    this.operationIdBindingState = {
      callerProvidedOperationFingerprintsById: new Map(),
    };
    const canConsumeWalletSessionUses = hasWalletSigningSessionConsumeDeps(deps);
    this.walletBudgetStatusReader = deps.getStatus;
    this.walletBudgetStatusSource = 'provided';
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
    const targetBacking = new Set(
      (args.targetBackingMaterialSessionIds || []).map(normalizeNonEmpty).filter(Boolean),
    );
    const targetThreshold = new Set(
      (args.targetThresholdSessionIds || []).map(normalizeNonEmpty).filter(Boolean),
    );
    const hasExplicitTarget = targetBacking.size > 0 || targetThreshold.size > 0;
    const readDirectTargetStatus = async (): Promise<SigningSessionStatus | null> => {
      if (!hasExplicitTarget || !walletSigningSessionIdFilter) return null;
      // Budget reservation already carries the exact selected material ids.
      // Use those ids directly so a missing volatile lane projection cannot
      // hide a restored, usable session.
      return await readDirectSigningSessionStatusForTargets({
        deps: this.walletSessionDeps,
        walletSigningSessionId: walletSigningSessionIdFilter,
        targetBackingMaterialSessionIds: targetBacking,
        targetThresholdSessionIds: targetThreshold,
      });
    };
    const lanes = discoverLanesForAccount(this.walletSessionDeps, args.nearAccountId).filter(
      (lane) => !walletSigningSessionIdFilter || lane.walletSigningSessionId === walletSigningSessionIdFilter,
    );
    if (!lanes.length) return await readDirectTargetStatus();
    const walletSigningSessionId = walletSigningSessionIdFilter || lanes[0].walletSigningSessionId;
    const statusLanes = hasExplicitTarget
      ? lanes.filter(
          (lane) =>
            targetBacking.has(lane.backingMaterialSessionId) ||
            targetThreshold.has(lane.thresholdSessionId),
        )
      : lanes;
    if (hasExplicitTarget && !statusLanes.length) {
      return (await readDirectTargetStatus()) || {
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
    return await readWalletScopedLaneClaimsForAccount({
      deps: this.walletSessionDeps,
      nearAccountId,
      statusOverrides: this.walletSessionState.statusOverrides,
    });
  }

  async consumeUse(
    args: WalletSigningSessionConsumeUseArgs,
  ): ReturnType<SigningSessionStatusPort['consumeUse']> {
    const hasAlreadyConsumedMaterial =
      (args.alreadyConsumedBackingMaterialSessionIds || []).length > 0 ||
      (args.alreadyConsumedThresholdSessionIds || []).length > 0;
    return await consumeWalletSigningSessionUse({
      deps: this.walletSessionDeps,
      statusOverrides: this.walletSessionState.statusOverrides,
      readStatus: async (statusArgs) => {
        if (hasAlreadyConsumedMaterial) {
          const trustedStatus = await this.readWalletBudgetStatus(statusArgs).catch(() => null);
          if (trustedStatus && trustedStatus.status !== 'budget_unknown') return trustedStatus;
        }
        return await this.getStatus(statusArgs);
      },
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
    input: SigningSessionBudgetReserveInput,
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
      let admittedStatus: Awaited<
        ReturnType<typeof assertSigningSessionBudgetReservationAvailable>
      >;
      try {
        admittedStatus = await assertSigningSessionBudgetReservationAvailable({
          getStatus: (statusArgs) => this.readWalletBudgetStatus(statusArgs),
          input: normalizedInput,
          reservationsByOperationId: this.walletBudgetState.reservationsByOperationId,
        });
      } catch (error) {
        this.emitWalletBudgetTrace(normalizedInput, 'wallet_signing_budget_reservation_failed', {
          error: error instanceof Error ? error.message : String(error || 'unknown error'),
        });
        throw error;
      }

      reservationsByOperationId.set(operationId, {
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
    const status = await this.readWalletBudgetStatus({
      nearAccountId: input.nearAccountId,
      walletSigningSessionId,
      targetBackingMaterialSessionIds: normalizeStringList(input.targetBackingMaterialSessionIds),
      targetThresholdSessionIds: normalizeStringList(input.targetThresholdSessionIds),
      trustedStatusAuth: input.trustedStatusAuth,
    });
    return applySigningSessionBudgetReservationsToStatus({
      status,
      walletSigningSessionId,
      reservationsByOperationId: this.walletBudgetState.reservationsByOperationId,
    });
  }

  async prepareBudgetIdentity(input: {
    nearAccountId: AccountId | string;
    lane: SigningLaneContext | TransactionLane;
    trustedStatusAuth?: SigningSessionBudgetStatusAuth;
    operationUsesNeeded?: number;
  }): Promise<SigningSessionPreparedBudgetIdentity> {
    const lane =
      !('keyKind' in input.lane)
        ? selectedSigningLaneContextFromTransactionLane(input.lane)
        : input.lane;
    const walletSigningSessionId = normalizeRequired(
      lane.walletSigningSessionId,
      'walletSigningSessionId',
    );
    const status = await this.getAvailableStatus({
      nearAccountId: input.nearAccountId,
      walletSigningSessionId,
      ...(lane.backingMaterialSessionId
        ? { targetBackingMaterialSessionIds: [lane.backingMaterialSessionId] }
        : {}),
      ...(lane.thresholdSessionId
        ? { targetThresholdSessionIds: [lane.thresholdSessionId] }
        : {}),
      ...(input.trustedStatusAuth ? { trustedStatusAuth: input.trustedStatusAuth } : {}),
    });
    if (!status || status.status === 'budget_unknown') {
      throw new Error(SIGNING_SESSION_BUDGET_UNKNOWN_ERROR);
    }
    if (status.status !== 'active') {
      throw new Error(`[SigningSessionBudget] wallet signing-session budget is ${status.status}`);
    }
    const usesNeeded = Math.max(1, Math.floor(Number(input.operationUsesNeeded) || 1));
    const remainingUses = Math.max(0, Math.floor(Number(status.remainingUses) || 0));
    if (remainingUses < usesNeeded) {
      throw new Error(SIGNING_SESSION_BUDGET_EXHAUSTED_ERROR);
    }
    const projectionVersion = String(status.projectionVersion || '').trim();
    if (!projectionVersion) {
      throw new Error('[SigningSessionBudget] trusted budget status is missing projection version');
    }
    return {
      walletSigningSessionId,
      projectionVersion,
      status: status as SigningSessionPreparedBudgetIdentity['status'],
    };
  }

  private async readWalletBudgetStatus(args: {
    nearAccountId: AccountId | string;
    walletSigningSessionId?: string;
    targetBackingMaterialSessionIds?: string[];
    targetThresholdSessionIds?: string[];
    trustedStatusAuth?: SigningSessionBudgetStatusAuth;
  }): Promise<SigningSessionStatus> {
    const walletSigningSessionId = normalizeRequired(
      args.walletSigningSessionId,
      'walletSigningSessionId',
    );
    if (!this.walletBudgetStatusReader) {
      return budgetUnknownSigningSessionStatus({
        walletSigningSessionId,
        reason: 'adapter_unavailable',
      });
    }
    const status = await this.walletBudgetStatusReader(args);
    if (!status) {
      return budgetUnknownSigningSessionStatus({
        walletSigningSessionId,
        reason: 'missing_trusted_status',
      });
    }
    if (
      this.walletBudgetStatusSource !== 'provided' &&
      (status.status === 'not_found' || status.status === 'unavailable')
    ) {
      // The material fallback reports hot-material availability, not authoritative
      // wallet budget. Keep missing/unavailable material separate from terminal
      // wallet budget states so restored lanes do not become false not_found.
      return budgetUnknownSigningSessionStatus({
        walletSigningSessionId,
        reason:
          status.status === 'unavailable' ? 'status_unavailable' : 'missing_trusted_status',
      });
    }
    const projectionVersion = String(status.projectionVersion || '').trim();
    if (status.status === 'active' && !projectionVersion) {
      return budgetUnknownSigningSessionStatus({
        walletSigningSessionId,
        reason: 'missing_trusted_status',
      });
    }
    return projectionVersion ? { ...status, projectionVersion } : status;
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
    let spendInput = normalizedInput;
    if (reservation) {
      assertWalletSigningOperationFingerprintMatches({
        operationId,
        existingFingerprint: resolveWalletSigningOperationFingerprint(reservation.spend),
        nextFingerprint: resolveWalletSigningOperationFingerprint(normalizedInput.spend),
      });
      // A reservation is the checked budget boundary for this operation. If a
      // later finalizer is reconstructed after local reservation accounting has
      // changed the available projection, keep consuming against the reserved
      // projection instead of treating the operation's own reservation as stale.
      spendInput = {
        ...normalizedInput,
        expectedBudgetProjectionVersion: reservation.expectedBudgetProjectionVersion,
      };
    }
    if (!reservation) {
      const status = await this.readWalletBudgetStatus({
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

    const spendPromise = this.recordWalletSigningSpend(spendInput)
      .catch((error) => {
        successfulSpendsByOperationId.delete(operationId);
        this.emitWalletBudgetTrace(spendInput, 'wallet_signing_budget_spend_failed', {
          error: error instanceof Error ? error.message : String(error || 'unknown error'),
        });
        throw error;
      })
      .finally(() => {
        this.releaseWalletBudgetReservation(spendInput);
      });
    successfulSpendsByOperationId.set(operationId, {
      operationFingerprint: resolveWalletSigningOperationFingerprint(spendInput.spend),
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
      trustedStatusAuth: input.trustedStatusAuth,
    });
    if (!status) {
      throw new Error('[SigningSessionBudget] wallet signing-session spend returned no status');
    }
    if (status.status === 'not_found') {
      throw new Error('[SigningSessionBudget] wallet signing-session spend returned not_found');
    }
    if (status.status === 'budget_unknown') {
      throw new Error('[SigningSessionBudget] wallet signing-session spend returned budget_unknown');
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
      deps.listConcreteThresholdEcdsaSessionRecordsForSubject ||
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
