import type { SigningSessionStatus } from '@/core/types/seams';
import {
  createSigningSessionExpiredEvent,
  type SdkLifecycleEvent,
  type SdkLifecycleEventListener,
  type SigningSessionExpiredEvent,
  type SigningSessionExpiryDetectionSource,
} from '@/core/types/sdkSentEvents';
import {
  createSigningPlannerDecisionTraceEvent,
  planSigningSession,
  type SigningPlannerDecisionTraceEvent,
  type EcdsaSigningSessionReadiness,
  type Ed25519SigningSessionReadiness,
  type SigningSessionPlannerInput,
  type SigningSessionReadiness,
} from './planning/planner';
import {
  buildAuthenticatedThresholdBudgetStatusCheck,
  buildBackingMaterialBudgetStatusCheck,
  buildThresholdBudgetStatusCheck,
  buildWalletBudgetStatusCheck,
  walletBudgetOwnerForLane,
  normalizeRequired,
  type SigningSessionBudgetStatusCheck,
  type SigningSessionBudgetStatusReader,
  type SigningSessionBudgetStatusAuth,
} from './budget/budget';
import type { SigningAdmissionQueueKey } from './budget/admission';
import { signingLaneAuthMethod } from './identity/signingLaneAuthBinding';
import { budgetUnknownSigningSessionStatus } from './budget/budgetStatusReader';
import {
  SigningOperationIdBindingRegistry,
} from './planning/operationIdBinding';

export type { SigningSessionBudgetStatusAuth } from './budget/budget';
import {
  applyWalletBudgetStatusToSigningSessionReadiness,
  clearSigningGrant,
  discoverLanesForWallet,
  normalizeNonEmpty,
  readDirectSigningSessionStatusForTargets,
  readClaimsForLanes,
  readWalletScopedLaneClaimsForWallet,
  statusFromClaim,
  walletScopedClaimsForLanes,
  type SigningGrantReadinessDeps,
  type SigningGrantStatusOverride,
} from './availability/readiness';
import {
  ClientWalletSessionExpiryInvalidator,
  type ClientWalletSessionExpiryInvalidationResult,
  type ClientWalletSessionInvalidationReadinessDeps,
  type WalletSessionExpiredEvent,
} from './availability/clientSessionExpiryInvalidator';
import type { ExpiredWalletSessionAuthorizationState } from './identity/clientSessionPersistenceState';
import type {
  SelectedEcdsaSigningSessionPlanningLane,
  SelectedEd25519SigningSessionPlanningLane,
  SigningOperationFingerprint,
  SigningOperationId,
  SigningSessionPlan,
} from './operationState/types';
import type { WarmSessionPrfClaim } from './warmCapabilities/types';
import { toWalletId, type WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { walletSessionAuthorizations } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';

export type { SigningSessionReadiness };

type ResolveSigningSessionAuthPlanFromReadinessOptions = {
  expiresAtMs?: number;
  remainingUses?: number;
  usesNeeded?: number;
  trustedStatusAuth?: SigningSessionBudgetStatusAuth;
  forceFreshAuth?: boolean;
  sensitiveOperationPolicy?: SigningSessionPlannerInput['sensitiveOperationPolicy'];
  missingWhenExpiresAtMissing?: boolean;
};

type ResolveEd25519SigningSessionAuthPlanFromReadinessInput =
  ResolveSigningSessionAuthPlanFromReadinessOptions & {
    lane: SelectedEd25519SigningSessionPlanningLane;
    readiness: Ed25519SigningSessionReadiness;
  };

type ResolveEcdsaSigningSessionAuthPlanFromReadinessInput =
  ResolveSigningSessionAuthPlanFromReadinessOptions & {
    lane: SelectedEcdsaSigningSessionPlanningLane;
    readiness: EcdsaSigningSessionReadiness;
  };

export type ResolveSigningSessionAuthPlanFromReadinessInput =
  | ResolveEd25519SigningSessionAuthPlanFromReadinessInput
  | ResolveEcdsaSigningSessionAuthPlanFromReadinessInput;

function isEd25519SigningSessionAuthPlanInput(
  input: ResolveSigningSessionAuthPlanFromReadinessInput,
): input is ResolveEd25519SigningSessionAuthPlanFromReadinessInput {
  return input.lane.curve === 'ed25519' && input.readiness.curve === 'ed25519';
}

function isEcdsaSigningSessionAuthPlanInput(
  input: ResolveSigningSessionAuthPlanFromReadinessInput,
): input is ResolveEcdsaSigningSessionAuthPlanFromReadinessInput {
  return input.lane.curve === 'ecdsa' && input.readiness.curve === 'ecdsa';
}

export type ResolveSigningSessionAuthPlanFromReadinessResult =
  | {
      signingSessionPlan: SigningSessionPlan;
      readiness: Ed25519SigningSessionReadiness;
      expiresAtMs: number;
      remainingUses: number;
    }
  | {
      signingSessionPlan: SigningSessionPlan;
      readiness: EcdsaSigningSessionReadiness;
      expiresAtMs: number;
      remainingUses: number;
    };

export type SigningSessionStatusPort = {
  getStatus(args: {
    walletId: WalletId | string;
    signingGrantId: string;
    targetBackingMaterialSessionIds?: string[];
    targetThresholdSessionIds?: string[];
    trustedStatusAuth?: SigningSessionBudgetStatusAuth;
    budgetStatusCheck?: SigningSessionBudgetStatusCheck;
  }): Promise<SigningSessionStatus | null>;
  getLaneClaimsForWallet(
    walletId: WalletId | string,
  ): Promise<Map<string, WarmSessionPrfClaim | null>>;
  clear(args: { walletId: WalletId | string; signingGrantId: string }): Promise<void>;
};

export type SigningSessionStatusState = {
  statusOverrides: Map<string, SigningGrantStatusOverride>;
};

export type SigningSessionCoordinatorDeps = SigningGrantReadinessDeps &
  ClientWalletSessionInvalidationReadinessDeps & {
    getStatus?: SigningSessionBudgetStatusReader;
    onPlannerTrace?: (event: SigningPlannerDecisionTraceEvent) => void;
  };

export interface SigningSessionLifecycleSubscription {
  unsubscribe(): void;
}

export type SigningSessionExpiryInvalidationResult =
  | {
      readonly kind: 'invalidated';
      readonly event: SigningSessionExpiredEvent;
    }
  | Extract<
      ClientWalletSessionExpiryInvalidationResult,
      { readonly kind: 'already_invalidated' | 'unavailable' }
    >;

class SigningSessionLifecycleSubscriptionHandle
  implements SigningSessionLifecycleSubscription
{
  readonly #listeners: Set<SdkLifecycleEventListener>;
  readonly #listener: SdkLifecycleEventListener;
  #active = true;

  constructor(args: {
    readonly listeners: Set<SdkLifecycleEventListener>;
    readonly listener: SdkLifecycleEventListener;
  }) {
    this.#listeners = args.listeners;
    this.#listener = args.listener;
  }

  unsubscribe(): void {
    if (!this.#active) return;
    this.#active = false;
    this.#listeners.delete(this.#listener);
  }
}

function mapWalletSessionExpiredEvent(args: {
  readonly event: WalletSessionExpiredEvent;
  readonly source: SigningSessionExpiryDetectionSource;
}): SigningSessionExpiredEvent {
  return createSigningSessionExpiredEvent({
    walletId: args.event.walletId,
    walletSessionId: args.event.walletSessionId,
    authMethod: args.event.authMethod,
    expiresAtMs: args.event.expiresAtMs,
    detectedAtMs: args.event.detectedAtMs,
    source: args.source,
  });
}

export class SigningSessionCoordinator implements SigningSessionStatusPort {
  private readonly onPlannerTrace?: (event: SigningPlannerDecisionTraceEvent) => void;
  private readonly walletBudgetStatusReader?: SigningSessionBudgetStatusReader;
  private readonly walletSessionDeps: SigningGrantReadinessDeps;
  private readonly walletSessionState: SigningSessionStatusState;
  private readonly operationIdBindings: SigningOperationIdBindingRegistry;
  private readonly walletSessionExpiryInvalidator: ClientWalletSessionExpiryInvalidator;
  private readonly lifecycleListeners = new Set<SdkLifecycleEventListener>();
  private readonly signingGrantAdmissionRefreshQueues = new Map<string, Promise<unknown>>();

  constructor(deps: SigningSessionCoordinatorDeps) {
    this.onPlannerTrace = deps.onPlannerTrace;
    this.walletSessionDeps = deps;
    this.walletSessionState = {
      statusOverrides: new Map(),
    };
    this.walletSessionExpiryInvalidator = new ClientWalletSessionExpiryInvalidator({
      readiness: {
        touchConfirm: deps.touchConfirm,
        clearEmailOtpWarmSessionMaterial: deps.clearEmailOtpWarmSessionMaterial,
      },
      statusOverrides: this.walletSessionState.statusOverrides,
    });
    this.operationIdBindings = new SigningOperationIdBindingRegistry();
    this.walletBudgetStatusReader = deps.getStatus;
  }

  subscribeLifecycle(listener: SdkLifecycleEventListener): SigningSessionLifecycleSubscription {
    this.lifecycleListeners.add(listener);
    return new SigningSessionLifecycleSubscriptionHandle({
      listeners: this.lifecycleListeners,
      listener,
    });
  }

  async invalidateExpiredWalletSession(args: {
    readonly state: ExpiredWalletSessionAuthorizationState;
    readonly source: SigningSessionExpiryDetectionSource;
  }): Promise<SigningSessionExpiryInvalidationResult> {
    const authorization = await walletSessionAuthorizations.readActiveForWallet(
      args.state.walletId,
    );
    if (
      authorization.kind !== 'found' ||
      authorization.projection.authMethod !== args.state.authMethod
    ) {
      return {
        kind: 'unavailable',
        failures: ['ecdsa_projection'],
        event: null,
      };
    }
    const invalidation = await this.walletSessionExpiryInvalidator.invalidate({
      state: args.state,
      walletSessionId: authorization.projection.walletSessionId,
    });
    if (invalidation.kind !== 'invalidated') return invalidation;
    const event = mapWalletSessionExpiredEvent({
      event: invalidation.event,
      source: args.source,
    });
    this.emitLifecycleEvent(event);
    return { kind: 'invalidated', event };
  }

  private emitLifecycleEvent(event: SdkLifecycleEvent): void {
    for (const listener of this.lifecycleListeners) {
      try {
        listener(event);
      } catch (error: unknown) {
        console.error('[SigningSessionCoordinator] lifecycle listener failed', error);
      }
    }
  }

  resolveAuthPlan(
    input: SigningSessionPlannerInput,
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
    if (isEd25519SigningSessionAuthPlanInput(input)) {
      const budgetAware = await this.applyWalletBudgetToEd25519Readiness(input);
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
    if (isEcdsaSigningSessionAuthPlanInput(input)) {
      const expiresAtMs =
        input.readiness.status === 'ready' ||
        input.readiness.status === 'exhausted' ||
        input.readiness.status === 'expired'
          ? input.readiness.expiresAtMs
          : Math.floor(Number(input.expiresAtMs) || 0);
      const remainingUses =
        input.readiness.status === 'ready' || input.readiness.status === 'exhausted'
          ? input.readiness.remainingUses
          : 0;
      return {
        readiness: input.readiness,
        expiresAtMs,
        remainingUses,
        signingSessionPlan: this.resolveAuthPlan(
          {
            lane: input.lane,
            readiness: input.readiness,
            forceFreshAuth: input.forceFreshAuth,
            sensitiveOperationPolicy: input.sensitiveOperationPolicy,
          },
          onTrace,
        ),
      };
    }
    throw new Error('[SigningSessionCoordinator] lane and readiness curves do not match');
  }

  async getStatus(
    args: Parameters<SigningSessionStatusPort['getStatus']>[0],
  ): ReturnType<SigningSessionStatusPort['getStatus']> {
    const walletId = toWalletId(args.walletId);
    const signingGrantId = normalizeRequired(args.signingGrantId, 'signingGrantId');
    const targetBacking = new Set(
      (args.targetBackingMaterialSessionIds || []).map(normalizeNonEmpty).filter(Boolean),
    );
    const targetThreshold = new Set(
      (args.targetThresholdSessionIds || []).map(normalizeNonEmpty).filter(Boolean),
    );
    const hasExplicitTarget = targetBacking.size > 0 || targetThreshold.size > 0;
    const readDirectTargetStatus = async (): Promise<SigningSessionStatus | null> => {
      if (!hasExplicitTarget) return null;
      // The status query carries the exact selected material ids. Use those
      // ids directly so a missing volatile lane projection cannot hide a
      // restored, usable session.
      return await readDirectSigningSessionStatusForTargets({
        deps: this.walletSessionDeps,
        signingGrantId,
        targetBackingMaterialSessionIds: targetBacking,
        targetThresholdSessionIds: targetThreshold,
      });
    };
    const lanes = (await discoverLanesForWallet(this.walletSessionDeps, walletId)).filter(
      (lane) => lane.signingGrantId === signingGrantId,
    );
    if (!lanes.length) return await readDirectTargetStatus();
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

  async getAvailableStatus(
    input: SigningSessionBudgetStatusCheck,
  ): Promise<SigningSessionStatus | null> {
    const signingGrantId = normalizeRequired(input.signingGrantId, 'signingGrantId');
    if (!this.walletBudgetStatusReader) return null;
    return await this.walletBudgetStatusReader({
      ...input,
      signingGrantId,
    });
  }

  bindCallerProvidedOperationIdToFingerprint(args: {
    operationId: SigningOperationId;
    operationFingerprint: SigningOperationFingerprint;
  }): void {
    this.operationIdBindings.bindCallerProvidedOperationIdToFingerprint(args);
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

  async runSigningGrantAdmissionRetry<TValue>(args: {
    queueKey: SigningAdmissionQueueKey;
    refresh: () => Promise<TValue>;
    retryAfterRefresh: () => Promise<TValue>;
  }): Promise<TValue> {
    const queueKey = String(args.queueKey);
    const existing = this.signingGrantAdmissionRefreshQueues.get(queueKey);
    if (existing) {
      await existing.catch(() => undefined);
      return await args.retryAfterRefresh();
    }
    const refreshPromise = args.refresh();
    const queueEntry = refreshPromise
      .catch(() => undefined)
      .then(() => {
        if (this.signingGrantAdmissionRefreshQueues.get(queueKey) === queueEntry) {
          this.signingGrantAdmissionRefreshQueues.delete(queueKey);
        }
      });
    this.signingGrantAdmissionRefreshQueues.set(queueKey, queueEntry);
    return await refreshPromise;
  }

  private async applyWalletBudgetToEd25519Readiness(
    input: ResolveEd25519SigningSessionAuthPlanFromReadinessInput,
  ): Promise<{
    readiness: Ed25519SigningSessionReadiness;
    expiresAtMs: number;
    remainingUses: number;
  }> {
    const signingGrantId = String(input.lane.signingGrantId).trim();
    const walletBudgetStatus = await this.readWalletBudgetStatus(
      buildBudgetStatusCheckForLane({
        lane: input.lane,
        trustedStatusAuth: input.trustedStatusAuth,
      }),
    )
      .catch(() => ({
        sessionId: signingGrantId,
        status: 'unavailable' as const,
      }));
    const emailOtpEd25519PreflightUnavailable =
      signingLaneAuthMethod(input.lane.auth) === 'email_otp' &&
      input.lane.curve === 'ed25519' &&
      (walletBudgetStatus?.status === 'budget_unknown' ||
        walletBudgetStatus?.status === 'unavailable');
    const passkeyEd25519PreflightUnavailable =
      signingLaneAuthMethod(input.lane.auth) === 'passkey' &&
      input.readiness.status === 'ready' &&
      (walletBudgetStatus?.status === 'budget_unknown' ||
        walletBudgetStatus?.status === 'unavailable');
    // Email OTP can mint a fresh Ed25519 session at step-up. Treat an
    // unreadable preflight as reauthable so server-side authorize remains
    // the budget enforcement point instead of failing before the prompt.
    let budgetStatusForPlanning: SigningSessionStatus | null = walletBudgetStatus;
    if (passkeyEd25519PreflightUnavailable) {
      budgetStatusForPlanning = null;
    } else if (emailOtpEd25519PreflightUnavailable) {
      budgetStatusForPlanning = {
        sessionId: signingGrantId,
        status: 'not_found',
        statusCode: walletBudgetStatus.status,
      };
    }
    if (emailOtpEd25519PreflightUnavailable) {
      console.warn('[SigningSessionCoordinator][email-otp-ed25519] budget preflight unavailable', {
        signingGrantId,
        thresholdSessionId: input.lane.thresholdSessionId,
        budgetStatus: walletBudgetStatus.status,
        readiness: input.readiness.status,
        remainingUses: input.remainingUses,
        usesNeeded: input.usesNeeded,
      });
    }
    if (passkeyEd25519PreflightUnavailable) {
      console.debug('[SigningSessionCoordinator][passkey-ed25519] budget preflight deferred', {
        signingGrantId,
        thresholdSessionId: input.lane.thresholdSessionId,
        budgetStatus: walletBudgetStatus.status,
        readiness: input.readiness.status,
        remainingUses: input.remainingUses,
        usesNeeded: input.usesNeeded,
      });
    }
    return applyWalletBudgetStatusToSigningSessionReadiness({
      status: input.readiness.status,
      thresholdSessionId: input.readiness.thresholdSessionId,
      walletBudgetStatus: budgetStatusForPlanning,
      expiresAtMs: Math.floor(Number(input.expiresAtMs) || 0),
      remainingUses: Math.floor(Number(input.remainingUses) || 0),
      usesNeeded: input.usesNeeded,
      missingWhenExpiresAtMissing: input.missingWhenExpiresAtMissing,
    });
  }
}

function buildBudgetStatusCheckForLane(args: {
  lane: SelectedEd25519SigningSessionPlanningLane;
  trustedStatusAuth?: SigningSessionBudgetStatusAuth;
}): SigningSessionBudgetStatusCheck {
  const owner = walletBudgetOwnerForLane(args.lane);
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
