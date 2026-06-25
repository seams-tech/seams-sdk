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
  buildAuthenticatedEcdsaLaneBudgetStatusCheck,
  buildAuthenticatedThresholdBudgetStatusCheck,
  availableUsesForBudgetAdmission,
  buildBackingMaterialBudgetStatusCheck,
  buildEcdsaLaneBudgetStatusCheck,
  buildThresholdBudgetStatusCheck,
  buildWalletBudgetStatusCheck,
  ecdsaLaneBudgetStatusIdentityFieldsForLane,
  isEcdsaLaneBudgetStatusCheck,
  ownerForBudgetStatusCheck,
  thresholdSessionIdsForBudgetStatusCheck,
  walletBudgetOwnerForLane,
  walletBudgetOwnerId,
  isSigningSessionBudgetAdmissionBlockedError,
  isSigningSessionBudgetExhaustedError,
  isSigningSessionBudgetUnknownError,
  normalizeRequired,
  SIGNING_SESSION_BUDGET_EXHAUSTED_ERROR,
  SIGNING_SESSION_BUDGET_IN_FLIGHT_ERROR,
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
  type WalletBudgetOwner,
  type ZeroWalletBudgetSpend,
} from './budget/budget';
import { signingLaneAuthMethod } from './identity/signingLaneAuthBinding';
import { BudgetCoordinator } from './budget/BudgetCoordinator';
import { budgetUnknownSigningSessionStatus } from './budget/budgetProjection';
import {
  SigningOperationIdBindingRegistry,
} from './planning/operationIdBinding';

export {
  SIGNING_SESSION_BUDGET_EXHAUSTED_ERROR,
  SIGNING_SESSION_BUDGET_UNKNOWN_ERROR,
  isSigningSessionBudgetAdmissionBlockedError,
  isSigningSessionBudgetExhaustedError,
  isSigningSessionBudgetUnknownError,
  type SigningSessionBudgetReservation,
};
import {
  applyWalletBudgetStatusToSigningSessionReadiness,
  clearSigningGrant,
  consumeSigningGrantUse,
  discoverLanesForWallet,
  normalizeNonEmpty,
  readDirectSigningSessionStatusForTargets,
  readClaimsForLanes,
  readWalletScopedLaneClaimsForWallet,
  statusFromClaim,
  walletScopedClaimsForLanes,
  type SigningGrantReadinessDeps,
  type SigningGrantStatusOverride,
  type DiscoveredSigningSessionLane,
} from './availability/readiness';
import {
  buildEvmFamilyEcdsaSignerBinding,
  exactEcdsaSigningLaneIdentity,
  exactSigningLaneIdentityMatches,
  type ExactEcdsaSigningLaneIdentity,
} from './identity/exactSigningLaneIdentity';
import {
  toExactEcdsaSigningLaneIdentity,
  type ThresholdEcdsaSessionRecord,
} from './persistence/records';
import type {
  SelectedSigningSessionPlanningLane,
  SigningOperationFingerprint,
  SigningOperationId,
  SigningOperationIntent,
  SigningSessionPlan,
  SigningGrantId,
} from './operationState/types';
import type { WarmSessionPrfClaim } from './warmCapabilities/types';
import { toWalletId, type WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

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

export type SigningGrantConsumeUseArgs = {
  owner: WalletBudgetOwner;
  signingGrantId: string;
  uses: number;
  reason: SigningOperationIntent;
  budgetStatusCheck: SigningSessionBudgetStatusCheck;
  alreadyConsumedBackingMaterialSessionIds?: string[];
  alreadyConsumedThresholdSessionIds?: string[];
};

export type SigningSessionStatusPort = {
  getStatus(args: {
    walletId: WalletId | string;
    signingGrantId?: string;
    targetBackingMaterialSessionIds?: string[];
    targetThresholdSessionIds?: string[];
    trustedStatusAuth?: SigningSessionBudgetStatusAuth;
    budgetStatusCheck?: SigningSessionBudgetStatusCheck;
  }): Promise<SigningSessionStatus | null>;
  getLaneClaimsForWallet(
    walletId: WalletId | string,
  ): Promise<Map<string, WarmSessionPrfClaim | null>>;
  consumeUse(args: SigningGrantConsumeUseArgs): Promise<SigningSessionStatus>;
  clear(args: { walletId: WalletId | string; signingGrantId: string }): Promise<void>;
};

export type SigningSessionStatusDeps = SigningGrantReadinessDeps;

export type SigningSessionStatusState = {
  statusOverrides: Map<string, SigningGrantStatusOverride>;
};

function exactEcdsaBudgetStatusLane(
  check: SigningSessionBudgetStatusCheck | undefined,
): ExactEcdsaSigningLaneIdentity | null {
  if (!check || !isEcdsaLaneBudgetStatusCheck(check)) return null;
  return exactEcdsaSigningLaneIdentity({
    signer: buildEvmFamilyEcdsaSignerBinding({
      walletId: check.key.walletId,
      chainTarget: check.chainTarget,
      keyHandle: check.keyHandle,
      key: check.key,
    }),
    auth: check.auth,
    signingGrantId: check.signingGrantId,
    thresholdSessionId: check.thresholdSessionId,
  });
}

function isRecordObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function isThresholdEcdsaSessionRecord(value: unknown): value is ThresholdEcdsaSessionRecord {
  return (
    isRecordObject(value) &&
    'chainTarget' in value &&
    'keyHandle' in value &&
    'thresholdSessionId' in value &&
    'signingGrantId' in value
  );
}

function discoveredLaneMatchesExactEcdsaBudgetLane(args: {
  lane: DiscoveredSigningSessionLane;
  budgetLane: ExactEcdsaSigningLaneIdentity | null;
}): boolean {
  if (!args.budgetLane) return true;
  if (args.lane.curve !== 'ecdsa') return false;
  if (!isThresholdEcdsaSessionRecord(args.lane.record)) return false;
  try {
    return exactSigningLaneIdentityMatches(
      toExactEcdsaSigningLaneIdentity(args.lane.record),
      args.budgetLane,
    );
  } catch {
    return false;
  }
}

export type SigningSessionCoordinatorDeps = SigningSessionStatusDeps &
  SigningSessionBudgetDeps & {
    onPlannerTrace?: (event: SigningPlannerDecisionTraceEvent) => void;
    onWalletBudgetTrace?: SigningSessionBudgetDeps['onTrace'];
  };

export class SigningSessionCoordinator implements SigningSessionStatusPort, SigningSessionBudget {
  private readonly onPlannerTrace?: (event: SigningPlannerDecisionTraceEvent) => void;
  private readonly onWalletBudgetTrace?: SigningSessionBudgetDeps['onTrace'];
  private readonly walletBudgetStatusReader?: SigningSessionBudgetStatusReader;
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
    this.walletBudgetStatusReader = deps.getStatus;
    this.walletBudget = new BudgetCoordinator({
      readStatus: (args) => this.readWalletBudgetStatus(args),
      syncSuccessfulSpendStatus: deps.consumeUse || this.syncServerConsumedSpendStatus,
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
    const walletId = toWalletId(args.walletId);
    const signingGrantIdFilter = normalizeNonEmpty(args.signingGrantId);
    const targetBacking = new Set(
      (args.targetBackingMaterialSessionIds || []).map(normalizeNonEmpty).filter(Boolean),
    );
    const targetThreshold = new Set(
      (args.targetThresholdSessionIds || []).map(normalizeNonEmpty).filter(Boolean),
    );
    const ecdsaBudgetLane = exactEcdsaBudgetStatusLane(args.budgetStatusCheck);
    const hasExplicitTarget = targetBacking.size > 0 || targetThreshold.size > 0;
    const readDirectTargetStatus = async (): Promise<SigningSessionStatus | null> => {
      if (!hasExplicitTarget || !signingGrantIdFilter) return null;
      // Budget reservation already carries the exact selected material ids.
      // Use those ids directly so a missing volatile lane projection cannot
      // hide a restored, usable session.
      return await readDirectSigningSessionStatusForTargets({
        deps: this.walletSessionDeps,
        signingGrantId: signingGrantIdFilter,
        targetBackingMaterialSessionIds: targetBacking,
        targetThresholdSessionIds: targetThreshold,
      });
    };
    const lanes = discoverLanesForWallet(this.walletSessionDeps, walletId).filter(
      (lane) =>
        (!signingGrantIdFilter || lane.signingGrantId === signingGrantIdFilter) &&
        discoveredLaneMatchesExactEcdsaBudgetLane({
          lane,
          budgetLane: ecdsaBudgetLane,
        }),
    );
    if (!lanes.length) return await readDirectTargetStatus();
    const signingGrantId = signingGrantIdFilter || lanes[0].signingGrantId;
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
          sessionId: signingGrantId,
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
    return statusFromClaim({ signingGrantId, lanes: statusLanes, claim });
  }

  async getLaneClaimsForWallet(
    walletId: Parameters<SigningSessionStatusPort['getLaneClaimsForWallet']>[0],
  ): ReturnType<SigningSessionStatusPort['getLaneClaimsForWallet']> {
    return await readWalletScopedLaneClaimsForWallet({
      deps: this.walletSessionDeps,
      walletId: toWalletId(walletId),
      statusOverrides: this.walletSessionState.statusOverrides,
    });
  }

  async consumeUse(
    args: SigningGrantConsumeUseArgs,
  ): ReturnType<SigningSessionStatusPort['consumeUse']> {
    const hasAlreadyConsumedMaterial =
      (args.alreadyConsumedBackingMaterialSessionIds || []).length > 0 ||
      (args.alreadyConsumedThresholdSessionIds || []).length > 0;
    return await consumeSigningGrantUse({
      deps: this.walletSessionDeps,
      statusOverrides: this.walletSessionState.statusOverrides,
      readStatus: async (statusArgs) => {
        if (hasAlreadyConsumedMaterial) {
          const trustedStatus = await this.readWalletBudgetStatus(statusArgs).catch(() => null);
          if (trustedStatus && trustedStatus.status !== 'budget_unknown') return trustedStatus;
        }
        return await this.getStatus(buildStatusQueryFromBudgetStatusCheck(statusArgs));
      },
      input: args,
    });
  }

  private syncServerConsumedSpendStatus = async (
    args: SigningGrantConsumeUseArgs,
  ): Promise<SigningSessionStatus> => {
    return await this.readWalletBudgetStatus(args.budgetStatusCheck);
  };

  async clear(
    args: Parameters<SigningSessionStatusPort['clear']>[0],
  ): ReturnType<SigningSessionStatusPort['clear']> {
    await clearSigningGrant({
      deps: this.walletSessionDeps,
      statusOverrides: this.walletSessionState.statusOverrides,
      walletId: toWalletId(args.walletId),
      signingGrantId: args.signingGrantId,
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
    normalizeRequired(input.spend.lane.signingGrantId, 'signingGrantId');
    return await this.walletBudget.reserve({
      ...input,
    });
  }

  async getAvailableStatus(
    input: Parameters<SigningSessionBudget['getAvailableStatus']>[0],
  ): ReturnType<SigningSessionBudget['getAvailableStatus']> {
    const signingGrantId = normalizeRequired(input.signingGrantId, 'signingGrantId');
    return await this.walletBudget.getAvailableStatus({
      ...input,
      signingGrantId,
    });
  }

  async prepareBudgetIdentity(input: {
    lane: SelectedSigningSessionPlanningLane;
    trustedStatusAuth?: SigningSessionBudgetStatusAuth;
    operationUsesNeeded?: number;
  }): Promise<SigningSessionPreparedBudgetIdentity> {
    const signingGrantId = normalizeRequired(
      input.lane.signingGrantId,
      'signingGrantId',
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
      throw new Error(`[SigningSessionBudget] signing grant budget is ${status.status}`);
    }
    const usesNeeded = Math.max(1, Math.floor(Number(input.operationUsesNeeded) || 1));
    const remainingUses = Math.max(0, Math.floor(Number(status.remainingUses) || 0));
    const availableUses = availableUsesForBudgetAdmission(status);
    if (availableUses < usesNeeded) {
      if (remainingUses >= usesNeeded) {
        throw new Error(SIGNING_SESSION_BUDGET_IN_FLIGHT_ERROR);
      }
      throw new Error(SIGNING_SESSION_BUDGET_EXHAUSTED_ERROR);
    }
    const projectionVersion = String(status.projectionVersion || '').trim();
    if (!projectionVersion) {
      throw new Error('[SigningSessionBudget] trusted budget status is missing projection version');
    }
    return {
      signingGrantId,
      projectionVersion,
      status: {
        ...status,
        remainingUses: availableUses,
        availableUses,
      } as SigningSessionPreparedBudgetIdentity['status'],
    };
  }

  private async readWalletBudgetStatus(
    budgetStatusCheck: SigningSessionBudgetStatusCheck,
  ): Promise<SigningSessionStatus> {
    const signingGrantId = budgetStatusCheck.signingGrantId;
    if (!this.walletBudgetStatusReader) {
      return budgetUnknownSigningSessionStatus({
        signingGrantId,
        reason: 'adapter_unavailable',
      });
    }
    const status = await this.walletBudgetStatusReader(budgetStatusCheck);
    if (!status) {
      return budgetUnknownSigningSessionStatus({
        signingGrantId,
        reason: 'missing_trusted_status',
      });
    }
    const projectionVersion = String(status.projectionVersion || '').trim();
    if (status.status === 'active' && !projectionVersion) {
      return budgetUnknownSigningSessionStatus({
        signingGrantId,
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
    const signingGrantId = String(input.lane.signingGrantId || '').trim();
    const walletBudgetStatus = signingGrantId
      ? await this.walletBudget
          .getAvailableStatus(
            buildBudgetStatusCheckForLane({
              lane: input.lane,
            }),
          )
          .catch(() => ({
            sessionId: signingGrantId,
            status: 'unavailable' as const,
          }))
      : null;
    const emailOtpEd25519PreflightUnavailable =
      signingLaneAuthMethod(input.lane.auth) === 'email_otp' &&
      input.lane.curve === 'ed25519' &&
      (walletBudgetStatus?.status === 'budget_unknown' ||
        walletBudgetStatus?.status === 'unavailable');
    const ecdsaStepUpPreflightUnavailable =
      input.lane.curve === 'ecdsa' &&
      input.readiness.status === 'ready' &&
      (walletBudgetStatus?.status === 'budget_unknown' ||
        walletBudgetStatus?.status === 'unavailable');
    // Email OTP can mint a fresh Ed25519 session at step-up. Treat an
    // unreadable preflight as reauthable so server-side authorize remains
    // the budget enforcement point instead of failing before the prompt.
    // ECDSA transaction lanes have the same reconnect boundary for passkey
    // and Email OTP step-up, so stale/unauthorized budget probes must prompt
    // fresh auth instead of surfacing a terminal "session not ready" error.
    const budgetStatusForPlanning =
      (emailOtpEd25519PreflightUnavailable || ecdsaStepUpPreflightUnavailable) &&
      walletBudgetStatus
        ? {
            sessionId: signingGrantId,
            status: 'not_found' as const,
            statusCode: walletBudgetStatus.status,
          }
        : walletBudgetStatus;
    if (emailOtpEd25519PreflightUnavailable && walletBudgetStatus) {
      console.warn('[SigningSessionCoordinator][email-otp-ed25519] budget preflight unavailable', {
        signingGrantId,
        thresholdSessionId: input.lane.thresholdSessionId,
        budgetStatus: walletBudgetStatus.status,
        readiness: input.readiness.status,
        remainingUses: input.remainingUses,
        usesNeeded: input.usesNeeded,
      });
    }
    if (ecdsaStepUpPreflightUnavailable && walletBudgetStatus) {
      console.warn('[SigningSessionCoordinator][ecdsa] budget preflight unavailable', {
        signingGrantId,
        thresholdSessionId: input.lane.thresholdSessionId,
        budgetStatus: walletBudgetStatus.status,
        readiness: input.readiness.status,
        remainingUses: input.remainingUses,
        usesNeeded: input.usesNeeded,
      });
    }
    return applyWalletBudgetStatusToSigningSessionReadiness({
      ...input.readiness,
      walletBudgetStatus: budgetStatusForPlanning,
      expiresAtMs: Math.floor(Number(input.expiresAtMs) || 0),
      remainingUses: Math.floor(Number(input.remainingUses) || 0),
      usesNeeded: input.usesNeeded,
      missingWhenExpiresAtMissing: input.missingWhenExpiresAtMissing,
    });
  }
}

function buildBudgetStatusCheckForLane(args: {
  lane: SelectedSigningSessionPlanningLane;
  trustedStatusAuth?: SigningSessionBudgetStatusAuth;
}): SigningSessionBudgetStatusCheck {
  const owner = walletBudgetOwnerForLane(args.lane);
  if (args.lane.curve === 'ecdsa') {
    const identityFields = ecdsaLaneBudgetStatusIdentityFieldsForLane(args.lane);
    if (args.trustedStatusAuth) {
      return buildAuthenticatedEcdsaLaneBudgetStatusCheck({
        ...identityFields,
        trustedStatusAuth: args.trustedStatusAuth,
      });
    }
    return buildEcdsaLaneBudgetStatusCheck({
      ...identityFields,
    });
  }
  if (args.trustedStatusAuth && args.lane.thresholdSessionId) {
    return buildAuthenticatedThresholdBudgetStatusCheck({
      owner,
      signingGrantId: args.lane.signingGrantId,
      targetThresholdSessionIds: [args.lane.thresholdSessionId],
      trustedStatusAuth: args.trustedStatusAuth,
    });
  }
  if (args.lane.thresholdSessionId) {
    return buildThresholdBudgetStatusCheck({
      owner,
      signingGrantId: args.lane.signingGrantId,
      targetThresholdSessionIds: [args.lane.thresholdSessionId],
    });
  }
  if (args.lane.backingMaterialSessionId) {
    return buildBackingMaterialBudgetStatusCheck({
      owner,
      signingGrantId: args.lane.signingGrantId,
      targetBackingMaterialSessionIds: [args.lane.backingMaterialSessionId],
    });
  }
  return buildWalletBudgetStatusCheck({
    owner,
    signingGrantId: args.lane.signingGrantId,
  });
}

function buildStatusQueryFromBudgetStatusCheck(args: SigningSessionBudgetStatusCheck): {
  walletId: WalletId | string;
  signingGrantId: string;
  targetBackingMaterialSessionIds?: string[];
  targetThresholdSessionIds?: string[];
  trustedStatusAuth?: SigningSessionBudgetStatusAuth;
  budgetStatusCheck?: SigningSessionBudgetStatusCheck;
} {
  if (isEcdsaLaneBudgetStatusCheck(args)) {
    return {
      walletId: walletBudgetOwnerId(ownerForBudgetStatusCheck(args)),
      signingGrantId: args.signingGrantId,
      targetThresholdSessionIds: thresholdSessionIdsForBudgetStatusCheck(args),
      budgetStatusCheck: args,
      ...(args.kind === 'authenticated_ecdsa_lane_budget_status_check'
        ? { trustedStatusAuth: args.trustedStatusAuth }
        : {}),
    };
  }
  if (args.kind === 'authenticated_threshold_budget_status_check') {
    return {
      walletId: walletBudgetOwnerId(args.owner),
      signingGrantId: args.signingGrantId,
      targetThresholdSessionIds: [...args.targetThresholdSessionIds],
      trustedStatusAuth: args.trustedStatusAuth,
    };
  }
  if (args.kind === 'threshold_budget_status_check') {
    return {
      walletId: walletBudgetOwnerId(args.owner),
      signingGrantId: args.signingGrantId,
      targetThresholdSessionIds: [...args.targetThresholdSessionIds],
    };
  }
  if (args.kind === 'backing_material_budget_status_check') {
    return {
      walletId: walletBudgetOwnerId(args.owner),
      signingGrantId: args.signingGrantId,
      targetBackingMaterialSessionIds: [...args.targetBackingMaterialSessionIds],
    };
  }
  return {
    walletId: walletBudgetOwnerId(args.owner),
    signingGrantId: args.signingGrantId,
  };
}
