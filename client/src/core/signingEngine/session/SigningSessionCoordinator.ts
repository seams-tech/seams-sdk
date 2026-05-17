import type { AccountId } from '@/core/types/accountIds';
import type { SigningSessionStatus } from '@/core/types/seams';
import { deleteExactSealedSession, updateExactSealedSessionPolicy } from './persistence/sealedSessionStore';
import {
  createSigningPlannerDecisionTraceEvent,
  planSigningSession,
  type SigningPlannerDecisionTraceEvent,
  type SigningSessionPlannerInput,
  type SigningSessionReadiness,
} from './planning/planner';
import {
  assertPreparedBudgetProjectionVersion,
  buildAuthenticatedEcdsaLaneBudgetStatusCheck,
  buildAuthenticatedThresholdBudgetStatusCheck,
  buildBackingMaterialBudgetStatusCheck,
  buildEcdsaLaneBudgetStatusCheck,
  buildThresholdBudgetStatusCheck,
  buildWalletBudgetStatusCheck,
  isEcdsaLaneBudgetStatusCheck,
  thresholdSessionIdsForBudgetStatusCheck,
  walletIdForBudgetStatusCheck,
  isSigningSessionBudgetExhaustedError,
  isSigningSessionBudgetUnknownError,
  normalizeRequired,
  SIGNING_SESSION_BUDGET_EXHAUSTED_ERROR,
  SIGNING_SESSION_BUDGET_UNKNOWN_ERROR,
  type SigningSessionBudget,
  type SigningSessionBudgetDeps,
  type SigningSessionBudgetReservation,
  type SigningSessionBudgetReserveInput,
  type SigningSessionBudgetStatusCheck,
  type SigningSessionPreparedBudgetIdentity,
  type SigningSessionBudgetStatusReader,
  type SigningSessionBudgetStatusAuth,
  type SigningSessionBudgetSuccessInput,
  type ZeroWalletBudgetSpend,
} from './budget/budget';
import { BudgetCoordinator } from './budget/BudgetCoordinator';
import { budgetUnknownSigningSessionStatus } from './budget/budgetProjection';
import {
  SigningOperationIdBindingRegistry,
} from './planning/operationIdBinding';

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
  discoverLanesForWallet,
  normalizeNonEmpty,
  readDirectSigningSessionStatusForTargets,
  readClaimsForLanes,
  readWalletScopedLaneClaimsForWallet,
  statusFromClaim,
  walletScopedClaimsForLanes,
  type WalletSigningSessionReadinessDeps,
  type WalletSigningSessionStatusOverride,
} from './availability/readiness';
import type {
  SelectedSigningSessionPlanningLane,
  SigningOperationFingerprint,
  SigningOperationId,
  SigningOperationIntent,
  SigningSessionPlan,
  WalletSigningSessionId,
} from './operationState/types';
import type { WarmSessionPrfClaim } from './warmCapabilities/types';

export type { SigningSessionReadiness };

export type ResolveSigningSessionAuthPlanInput = SigningSessionPlannerInput;

export type ResolveSigningSessionAuthPlanFromReadinessInput = {
  lane: SelectedSigningSessionPlanningLane;
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
  walletId: AccountId | string;
  walletSigningSessionId: string;
  uses: number;
  reason: SigningOperationIntent;
  budgetStatusCheck: SigningSessionBudgetStatusCheck;
  alreadyConsumedBackingMaterialSessionIds?: string[];
  alreadyConsumedThresholdSessionIds?: string[];
};

export type SigningSessionStatusPort = {
  getStatus(args: {
    walletId: AccountId | string;
    walletSigningSessionId?: string;
    targetBackingMaterialSessionIds?: string[];
    targetThresholdSessionIds?: string[];
    trustedStatusAuth?: SigningSessionBudgetStatusAuth;
  }): Promise<SigningSessionStatus | null>;
  getLaneClaimsForWallet(
    walletId: AccountId | string,
  ): Promise<Map<string, WarmSessionPrfClaim | null>>;
  consumeUse(args: WalletSigningSessionConsumeUseArgs): Promise<SigningSessionStatus>;
  clear(args: { walletId: AccountId | string; walletSigningSessionId: string }): Promise<void>;
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

export class SigningSessionCoordinator implements SigningSessionStatusPort, SigningSessionBudget {
  private readonly onPlannerTrace?: (event: SigningPlannerDecisionTraceEvent) => void;
  private readonly onWalletBudgetTrace?: SigningSessionBudgetDeps['onTrace'];
  private readonly walletBudgetStatusReader?: SigningSessionBudgetStatusReader;
  private readonly walletBudgetStatusSource: 'provided' | 'material_fallback' | 'none';
  private readonly walletSessionDeps: SigningSessionStatusDeps;
  private readonly walletSessionState: SigningSessionStatusState;
  private readonly walletBudget: BudgetCoordinator;
  private readonly operationIdBindings: SigningOperationIdBindingRegistry;

  constructor(deps: SigningSessionCoordinatorDeps = {}) {
    this.onPlannerTrace = deps.onPlannerTrace;
    this.onWalletBudgetTrace = deps.onWalletBudgetTrace || deps.onTrace;
    this.walletSessionDeps = {
      ...deps,
      updateExactSealedSessionPolicy:
        deps.updateExactSealedSessionPolicy || updateExactSealedSessionPolicy,
      deleteExactSealedSession: deps.deleteExactSealedSession || deleteExactSealedSession,
    };
    this.walletSessionState = {
      statusOverrides: new Map(),
    };
    this.operationIdBindings = new SigningOperationIdBindingRegistry();
    const canConsumeWalletSessionUses = hasWalletSigningSessionConsumeDeps(deps);
    this.walletBudgetStatusReader = deps.getStatus;
    this.walletBudgetStatusSource = 'provided';
    const walletBudgetConsumer = Object.prototype.hasOwnProperty.call(deps, 'consumeUse')
      ? deps.consumeUse
      : canConsumeWalletSessionUses
        ? (consumeArgs: WalletSigningSessionConsumeUseArgs) => this.consumeUse(consumeArgs)
        : undefined;
    this.walletBudget = new BudgetCoordinator({
      readStatus: (args) => this.readWalletBudgetStatus(args),
      consumeUse: walletBudgetConsumer,
      onTrace: this.onWalletBudgetTrace,
    });
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
    const lanes = discoverLanesForWallet(this.walletSessionDeps, args.walletId).filter(
      (lane) =>
        !walletSigningSessionIdFilter ||
        lane.walletSigningSessionId === walletSigningSessionIdFilter,
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
      return (
        (await readDirectTargetStatus()) || {
          sessionId: walletSigningSessionId,
          status: 'not_found',
        }
      );
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

  async getLaneClaimsForWallet(
    walletId: Parameters<SigningSessionStatusPort['getLaneClaimsForWallet']>[0],
  ): ReturnType<SigningSessionStatusPort['getLaneClaimsForWallet']> {
    return await readWalletScopedLaneClaimsForWallet({
      deps: this.walletSessionDeps,
      walletId,
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
        return await this.getStatus(buildLegacyStatusQueryFromBudgetStatusCheck(statusArgs));
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
      walletId: args.walletId,
      walletSigningSessionId: args.walletSigningSessionId,
    });
  }

  bindCallerProvidedOperationIdToFingerprint(args: {
    operationId: SigningOperationId;
    operationFingerprint: SigningOperationFingerprint;
  }): void {
    this.operationIdBindings.bindCallerProvidedOperationIdToFingerprint(args);
  }

  async reserve(
    input: SigningSessionBudgetReserveInput,
  ): ReturnType<SigningSessionBudget['reserve']> {
    const walletSigningSessionId = normalizeRequired(
      input.spend.walletSigningSessionId,
      'walletSigningSessionId',
    );
    return await this.walletBudget.reserve({
      ...input,
      spend: {
        ...input.spend,
        walletSigningSessionId: walletSigningSessionId as WalletSigningSessionId,
      },
    });
  }

  async getAvailableStatus(
    input: Parameters<SigningSessionBudget['getAvailableStatus']>[0],
  ): ReturnType<SigningSessionBudget['getAvailableStatus']> {
    const walletSigningSessionId = normalizeRequired(input.walletSigningSessionId, 'walletSigningSessionId');
    return await this.walletBudget.getAvailableStatus({
      ...input,
      walletSigningSessionId,
    });
  }

  async prepareBudgetIdentity(input: {
    lane: SelectedSigningSessionPlanningLane;
    trustedStatusAuth?: SigningSessionBudgetStatusAuth;
    operationUsesNeeded?: number;
  }): Promise<SigningSessionPreparedBudgetIdentity> {
    const walletSigningSessionId = normalizeRequired(
      input.lane.walletSigningSessionId,
      'walletSigningSessionId',
    );
    const status = await this.getAvailableStatus(
      buildBudgetStatusCheckForLane({
        lane: input.lane,
        trustedStatusAuth: input.trustedStatusAuth,
      }),
    );
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

  private async readWalletBudgetStatus(
    budgetStatusCheck: SigningSessionBudgetStatusCheck,
  ): Promise<SigningSessionStatus> {
    const walletSigningSessionId = budgetStatusCheck.walletSigningSessionId;
    if (!this.walletBudgetStatusReader) {
      return budgetUnknownSigningSessionStatus({
        walletSigningSessionId,
        reason: 'adapter_unavailable',
      });
    }
    const status = await this.walletBudgetStatusReader(budgetStatusCheck);
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
      return budgetUnknownSigningSessionStatus({
        walletSigningSessionId,
        reason: status.status === 'unavailable' ? 'status_unavailable' : 'missing_trusted_status',
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
    input: SigningSessionBudgetSuccessInput,
  ): ReturnType<SigningSessionBudget['recordSuccess']> {
    return await this.walletBudget.recordSuccess(input);
  }

  recordZeroSpend(input: ZeroWalletBudgetSpend): void {
    this.walletBudget.recordZeroSpend(input);
  }

  hasRecorded(operationId: Parameters<SigningSessionBudget['hasRecorded']>[0]): boolean {
    return this.walletBudget.hasRecorded(String(operationId));
  }

  private async applyWalletBudgetToReadiness(
    input: ResolveSigningSessionAuthPlanFromReadinessInput,
  ): Promise<
    Pick<
      ResolveSigningSessionAuthPlanFromReadinessResult,
      'readiness' | 'expiresAtMs' | 'remainingUses'
    >
  > {
    const walletSigningSessionId = String(input.lane.walletSigningSessionId || '').trim();
    const walletBudgetStatus = walletSigningSessionId
        ? await this.walletBudget
          .getAvailableStatus(
            buildBudgetStatusCheckForLane({
              lane: input.lane,
            }),
          )
          .catch(() => ({
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
}

function hasWalletSigningSessionConsumeDeps(deps: SigningSessionCoordinatorDeps): boolean {
  return Boolean(
    deps.consumeUse ||
    deps.touchConfirm?.consumeWarmSessionUses ||
    deps.consumeEmailOtpWarmSessionUses ||
    deps.markThresholdEd25519EmailOtpSessionConsumedForAccount,
  );
}

function buildBudgetStatusCheckForLane(args: {
  lane: SelectedSigningSessionPlanningLane;
  trustedStatusAuth?: SigningSessionBudgetStatusAuth;
}): SigningSessionBudgetStatusCheck {
  const walletId = args.lane.curve === 'ecdsa' ? args.lane.walletId : args.lane.accountId;
  if (args.lane.curve === 'ecdsa') {
    if (args.trustedStatusAuth) {
      return buildAuthenticatedEcdsaLaneBudgetStatusCheck({
        key: args.lane.key,
        chainTarget: args.lane.chainTarget,
        walletSigningSessionId: args.lane.walletSigningSessionId,
        thresholdSessionId: args.lane.thresholdSessionId,
        trustedStatusAuth: args.trustedStatusAuth,
      });
    }
    return buildEcdsaLaneBudgetStatusCheck({
      key: args.lane.key,
      chainTarget: args.lane.chainTarget,
      walletSigningSessionId: args.lane.walletSigningSessionId,
      thresholdSessionId: args.lane.thresholdSessionId,
    });
  }
  if (args.trustedStatusAuth && args.lane.thresholdSessionId) {
    return buildAuthenticatedThresholdBudgetStatusCheck({
      walletId,
      walletSigningSessionId: args.lane.walletSigningSessionId,
      targetThresholdSessionIds: [args.lane.thresholdSessionId],
      trustedStatusAuth: args.trustedStatusAuth,
    });
  }
  if (args.lane.thresholdSessionId) {
    return buildThresholdBudgetStatusCheck({
      walletId,
      walletSigningSessionId: args.lane.walletSigningSessionId,
      targetThresholdSessionIds: [args.lane.thresholdSessionId],
    });
  }
  if (args.lane.backingMaterialSessionId) {
    return buildBackingMaterialBudgetStatusCheck({
      walletId,
      walletSigningSessionId: args.lane.walletSigningSessionId,
      targetBackingMaterialSessionIds: [args.lane.backingMaterialSessionId],
    });
  }
  return buildWalletBudgetStatusCheck({
    walletId,
    walletSigningSessionId: args.lane.walletSigningSessionId,
  });
}

function buildLegacyStatusQueryFromBudgetStatusCheck(args: SigningSessionBudgetStatusCheck): {
  walletId: AccountId | string;
  walletSigningSessionId: string;
  targetBackingMaterialSessionIds?: string[];
  targetThresholdSessionIds?: string[];
  trustedStatusAuth?: SigningSessionBudgetStatusAuth;
} {
  if (isEcdsaLaneBudgetStatusCheck(args)) {
    return {
      walletId: walletIdForBudgetStatusCheck(args),
      walletSigningSessionId: args.walletSigningSessionId,
      targetThresholdSessionIds: thresholdSessionIdsForBudgetStatusCheck(args),
      ...(args.kind === 'authenticated_ecdsa_lane_budget_status_check'
        ? { trustedStatusAuth: args.trustedStatusAuth }
        : {}),
    };
  }
  if (args.kind === 'authenticated_threshold_budget_status_check') {
    return {
      walletId: args.walletId,
      walletSigningSessionId: args.walletSigningSessionId,
      targetThresholdSessionIds: [...args.targetThresholdSessionIds],
      trustedStatusAuth: args.trustedStatusAuth,
    };
  }
  if (args.kind === 'threshold_budget_status_check') {
    return {
      walletId: args.walletId,
      walletSigningSessionId: args.walletSigningSessionId,
      targetThresholdSessionIds: [...args.targetThresholdSessionIds],
    };
  }
  if (args.kind === 'backing_material_budget_status_check') {
    return {
      walletId: args.walletId,
      walletSigningSessionId: args.walletSigningSessionId,
      targetBackingMaterialSessionIds: [...args.targetBackingMaterialSessionIds],
    };
  }
  return {
    walletId: args.walletId,
    walletSigningSessionId: args.walletSigningSessionId,
  };
}
