import {
  SigningAuthPlanKind,
  type SigningAuthPlan,
} from '@/core/signingEngine/stepUpConfirmation/types';
import { availableUsesForBudgetAdmission } from '@/core/signingEngine/session/budget/budget';
import {
  formatThresholdSigningSessionAvailabilityError,
  SIGNING_SESSION_AUTH_UNAVAILABLE_ERROR,
  THRESHOLD_SESSION_MISSING_ERROR,
} from '@/core/signingEngine/session/warmCapabilities/statusReader';
import { createWarmSessionCapabilityReader } from '@/core/signingEngine/session/warmCapabilities/capabilityReader';
import type { WarmSessionCapabilityReaderTouchConfirmInput } from '@/core/signingEngine/session/warmCapabilities/capabilityReader';
import { createWarmSessionStatusReader } from '@/core/signingEngine/session/warmCapabilities/statusReader';
import type {
  ThresholdWarmSessionStatusReader,
  WarmSessionCapabilityReader,
} from '@/core/signingEngine/session/warmCapabilities/types';
import type {
  WarmSessionEd25519UnsealAuthorizationStore,
  WarmSessionPersistedRestorer,
  WarmSessionStatusResult,
} from '@/core/signingEngine/uiConfirm/uiConfirm.types';
import {
  buildNearTransactionSigningLane,
  type NearTransactionSigningLane,
} from '@/core/signingEngine/session/operationState/lanes';
import {
  type ResolveSigningSessionAuthPlanFromReadinessInput,
  type ResolveSigningSessionAuthPlanFromReadinessResult,
  type SigningSessionReadiness,
} from '@/core/signingEngine/session/SigningSessionCoordinator';
import {
  createSigningBoundaryTraceEvent,
  emitSigningBoundaryTrace,
  emitSigningLaneResolutionTrace,
  emitSigningPlannerDecisionTrace,
} from '@/core/signingEngine/session/operationState/trace';
import {
  SigningOperationIntent,
  SigningSessionPlanKind,
  SigningSessionIds,
} from '@/core/signingEngine/session/operationState/types';
import type {
  NearAccountRef,
  ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { classifyRouterAbEd25519PersistedSigningRecord } from '@/core/signingEngine/session/routerAbSigningWalletSession';
import type { SigningSessionStatus } from '@/core/types/seams';

export type NearSigningSessionAuthPlan = {
  sessionId: string;
  lane: NearTransactionSigningLane;
  signingAuthPlan: SigningAuthPlan;
  confirmationAuthPayload: { signingAuthPlan: SigningAuthPlan };
  warmSessionReady: boolean;
};
export type NearSigningSessionAuthContext = {
  sessionId: string;
  accountId: string;
  lane: NearTransactionSigningLane;
  coordinatorInput: ResolveSigningSessionAuthPlanFromReadinessInput;
};
export { SIGNING_SESSION_AUTH_UNAVAILABLE_ERROR };

type NearSigningSessionCoordinatorPort = WarmSessionCapabilityReaderTouchConfirmInput &
  Partial<WarmSessionPersistedRestorer> &
  Partial<
    Pick<WarmSessionEd25519UnsealAuthorizationStore, 'claimWarmSessionEd25519UnsealAuthorization'>
  >;

type NearWarmSessionReader = WarmSessionCapabilityReader &
  ThresholdWarmSessionStatusReader &
  Partial<WarmSessionPersistedRestorer> &
  Partial<
    Pick<WarmSessionEd25519UnsealAuthorizationStore, 'claimWarmSessionEd25519UnsealAuthorization'>
  >;
type NearEd25519Capability = Awaited<
  ReturnType<WarmSessionCapabilityReader['getWarmSession']>
>['capabilities']['ed25519'];
type ResolveEd25519PlannerReadinessArgs = {
  warmSessionReader: NearWarmSessionReader;
  nearAccountId: string;
  capability: NearEd25519Capability;
  sessionId: string;
  requiredSignatureUses?: number;
  operationLabel?: string;
};
type Ed25519PlannerAuthMethod = 'passkey' | 'email_otp';
type Ed25519PlannerReadinessResult = {
  readiness: SigningSessionReadiness;
  expiresAtMs: number;
  remainingUses: number;
};

type Ed25519InitialPlannerState =
  | {
      kind: 'auth_missing';
      capability: NearEd25519Capability;
    }
  | {
      kind: 'passkey_prf_unavailable';
      capability: NearEd25519Capability;
      statusCode?: string;
    }
  | {
      kind: 'email_otp_prf_unavailable';
      capability: NearEd25519Capability;
    }
  | {
      kind: 'email_otp_material_pending';
      capability: NearEd25519Capability;
    }
  | {
      kind: 'passkey_material_repairable';
      capability: NearEd25519Capability;
    }
  | {
      kind: 'invalid';
      capability: NearEd25519Capability;
    }
  | {
      kind: 'ready';
      capability: NearEd25519Capability;
    }
  | {
      kind: 'email_otp_status_backed';
      capability: NearEd25519Capability;
    }
  | {
      kind: 'passkey_refreshable';
      capability: NearEd25519Capability;
    };

type Ed25519PostRefreshPlannerState =
  | {
      kind: 'restore_available';
      capability: NearEd25519Capability;
    }
  | {
      kind: 'runtime_validated';
      capability: NearEd25519Capability;
    }
  | {
      kind: 'pending_without_restore';
      capability: NearEd25519Capability;
    }
  | {
      kind: 'status_backed';
      capability: NearEd25519Capability;
      authMethod: Ed25519PlannerAuthMethod;
    }
  | {
      kind: 'missing';
      capability: NearEd25519Capability;
      authMethod: Ed25519PlannerAuthMethod;
    }
  | {
      kind: 'invalid';
      capability: NearEd25519Capability;
    };

type TrustedEd25519SigningSessionStatus =
  | {
      kind: 'active';
      remainingUses: number;
      availableUses: number;
      expiresAtMs: number;
    }
  | {
      kind: 'exhausted';
    }
  | {
      kind: 'expired';
    }
  | {
      kind: 'unavailable';
      statusCode?: string;
    }
  | {
      kind: 'budget_unknown';
    }
  | {
      kind: 'not_found';
    }
  | {
      kind: 'missing_status';
    };

export function createNearSigningSessionCoordinator(
  touchConfirm: NearSigningSessionCoordinatorPort,
): NearWarmSessionReader {
  const getEmailOtpWarmSessionStatus = async (
    sessionId: string,
  ): Promise<WarmSessionStatusResult> => {
    if (typeof touchConfirm?.getWarmSessionStatus === 'function') {
      return await touchConfirm.getWarmSessionStatus({ sessionId });
    }
    return {
      ok: false,
      code: 'not_found',
      message: 'Email OTP warm-session status reader is unavailable',
    };
  };
  return {
    ...createWarmSessionCapabilityReader({
      touchConfirm: touchConfirm ?? null,
      signingSessionSeal: null,
      getEmailOtpWarmSessionStatus,
    }),
    ...createWarmSessionStatusReader({
      touchConfirm,
      getEmailOtpWarmSessionStatus,
    }),
    ...(typeof touchConfirm?.restorePersistedSessionForSigning === 'function'
      ? {
          restorePersistedSessionForSigning:
            touchConfirm.restorePersistedSessionForSigning.bind(touchConfirm),
        }
      : {}),
    ...(typeof touchConfirm?.claimWarmSessionEd25519UnsealAuthorization === 'function'
      ? {
          claimWarmSessionEd25519UnsealAuthorization:
            touchConfirm.claimWarmSessionEd25519UnsealAuthorization.bind(touchConfirm),
        }
      : {}),
  };
}

export async function resolveNearSigningSessionAuthContext(args: {
  warmSessionReader: NearWarmSessionReader;
  nearAccount: NearAccountRef;
  operationLabel: string;
  requiredSignatureUses?: number;
}): Promise<NearSigningSessionAuthContext> {
  const accountId = String(args.nearAccount.accountId || '').trim();
  const warmSession = await args.warmSessionReader.getWarmSession(accountId);
  const capability = warmSession.capabilities.ed25519;
  const record = capability.record;
  const sessionId = String(record?.thresholdSessionId || '').trim();
  if (!record || !sessionId) {
    throw new Error(SIGNING_SESSION_AUTH_UNAVAILABLE_ERROR);
  }
  const isEmailOtpSession = record?.source === 'email_otp';
  const signingGrantId = String(record?.signingGrantId || '').trim();
  if (!signingGrantId) {
    throw new Error('[SigningEngine][near] missing signing grant id for transaction auth planning');
  }
  const lane =
    record?.source === 'email_otp'
      ? buildNearTransactionSigningLane({
          accountId,
          authMethod: 'email_otp',
          signingGrantId: SigningSessionIds.signingGrant(signingGrantId),
          thresholdSessionId: SigningSessionIds.thresholdEd25519Session(sessionId),
          retention: record.emailOtpAuthContext?.retention || 'session',
          sessionOrigin: record.emailOtpAuthContext?.reason === 'login' ? 'login' : 'per_operation',
        })
      : buildNearTransactionSigningLane({
          accountId,
          authMethod: 'passkey',
          signingGrantId: SigningSessionIds.signingGrant(signingGrantId),
          thresholdSessionId: SigningSessionIds.thresholdEd25519Session(sessionId),
          storageSource: record.source,
        });
  emitSigningLaneResolutionTrace('near', lane, {
    reason: 'near_threshold_auth_plan',
  });

  const readiness = await resolvePlannerReadinessForEd25519({
    warmSessionReader: args.warmSessionReader,
    nearAccountId: accountId,
    capability,
    sessionId,
    requiredSignatureUses: args.requiredSignatureUses,
    operationLabel: args.operationLabel,
  });
  emitSigningBoundaryTrace(
    'near',
    createSigningBoundaryTraceEvent({
      event: 'pre_confirm_readiness_checked',
      lane,
      readinessStatus: readiness.readiness.status,
      phase: 'pre_confirm',
    }),
  );
  const persistedRecordState = classifyRouterAbEd25519PersistedSigningRecord(record);
  const emailOtpMaterialNeedsFreshAuth =
    persistedRecordState.kind === 'auth_ready_material_pending';
  const coordinatorInput = {
    lane,
    readiness: readiness.readiness,
    expiresAtMs: readiness.expiresAtMs,
    remainingUses: readiness.remainingUses,
    usesNeeded: args.requiredSignatureUses,
    forceFreshAuth:
      isEmailOtpSession &&
      capability.state === 'ready' &&
      capability.prfClaim?.state !== 'warm' &&
      emailOtpMaterialNeedsFreshAuth,
  };
  return {
    sessionId,
    accountId,
    lane,
    coordinatorInput,
  };
}

export function buildNearSigningSessionAuthPlan(args: {
  context: NearSigningSessionAuthContext;
  resolvedSigningSession: ResolveSigningSessionAuthPlanFromReadinessResult;
}): NearSigningSessionAuthPlan {
  const { sessionId, accountId, lane } = args.context;
  const resolvedSigningSession = args.resolvedSigningSession;
  const plan = resolvedSigningSession.signingSessionPlan;

  switch (plan.kind) {
    case SigningSessionPlanKind.WarmSession: {
      const signingAuthPlan: SigningAuthPlan = {
        kind: SigningAuthPlanKind.WarmSession,
        method: lane.authMethod,
        accountId,
        intent: SigningOperationIntent.TransactionSign,
        curve: 'ed25519',
        sessionId,
        retention: lane.retention,
        expiresAtMs: resolvedSigningSession.expiresAtMs,
        remainingUses: resolvedSigningSession.remainingUses,
      };
      return {
        sessionId,
        lane,
        signingAuthPlan,
        confirmationAuthPayload: { signingAuthPlan },
        warmSessionReady: true,
      };
    }
    case SigningSessionPlanKind.PasskeyReauth: {
      const signingAuthPlan: SigningAuthPlan = {
        kind: SigningAuthPlanKind.PasskeyReauth,
        method: 'passkey',
      };
      return {
        sessionId,
        lane,
        signingAuthPlan,
        confirmationAuthPayload: { signingAuthPlan },
        warmSessionReady: false,
      };
    }
    case SigningSessionPlanKind.EmailOtpReauth: {
      const signingAuthPlan: SigningAuthPlan = {
        kind: SigningAuthPlanKind.EmailOtpReauth,
        method: 'email_otp',
      };
      return {
        sessionId,
        lane,
        signingAuthPlan,
        confirmationAuthPayload: { signingAuthPlan },
        warmSessionReady: false,
      };
    }
    case SigningSessionPlanKind.NotReady:
      throw new Error(`[SigningEngine][near] signing session is not ready: ${plan.reason}`);
    default:
      return assertNeverSigningSessionAuthMode(plan);
  }
}

async function resolvePlannerReadinessForEd25519(
  args: ResolveEd25519PlannerReadinessArgs,
): Promise<Ed25519PlannerReadinessResult> {
  const initialState = classifyInitialEd25519PlannerState(args.capability);

  switch (initialState.kind) {
    case 'auth_missing':
      return missingEd25519PlannerReadiness(args, initialState.capability);
    case 'email_otp_prf_unavailable':
      return missingEd25519PlannerReadiness(args, initialState.capability);
    case 'email_otp_material_pending':
      return missingEd25519PlannerReadiness(args, initialState.capability);
    case 'passkey_material_repairable':
      return admitCapabilityBackedEd25519PlannerReadiness({
        plannerInput: args,
        capability: initialState.capability,
        remainingUses: ed25519ReadyCapabilityRemainingUses(initialState.capability),
      });
    case 'passkey_prf_unavailable':
      throw new Error(formatThresholdSigningSessionAvailabilityError(initialState.statusCode));
    case 'invalid':
      throw new Error('[SigningEngine] Ed25519 signing session record is invalid');
    case 'ready':
      return admitCapabilityBackedEd25519PlannerReadiness({
        plannerInput: args,
        capability: initialState.capability,
        remainingUses: ed25519ReadyCapabilityRemainingUses(initialState.capability),
      });
    case 'email_otp_status_backed':
      return await resolveStatusBackedEd25519PlannerReadiness({
        plannerInput: args,
        capability: initialState.capability,
        authMethod: 'email_otp',
        activeUseSource: 'remaining_uses',
      });
    case 'passkey_refreshable':
      return await resolveRefreshablePasskeyEd25519PlannerReadiness({
        plannerInput: args,
        capability: initialState.capability,
      });
    default:
      return assertNeverSigningSessionAuthMode(initialState);
  }
}

function classifyInitialEd25519PlannerState(
  capability: NearEd25519Capability,
): Ed25519InitialPlannerState {
  const authMethod = ed25519PlannerAuthMethod(capability);

  switch (capability.state) {
    case 'auth_missing':
      return { kind: 'auth_missing', capability };
    case 'prf_unavailable':
      return classifyPrfUnavailableEd25519PlannerState({ capability, authMethod });
    case 'material_pending':
      return classifyMaterialPendingEd25519PlannerState({ capability, authMethod });
    case 'invalid':
      return { kind: 'invalid', capability };
    case 'ready':
      return { kind: 'ready', capability };
    case 'missing':
    case 'prf_missing':
      return classifyStatusOrRefreshBackedEd25519PlannerState({ capability, authMethod });
    default:
      return assertNeverSigningSessionAuthMode(capability);
  }
}

function classifyPrfUnavailableEd25519PlannerState(args: {
  capability: NearEd25519Capability;
  authMethod: Ed25519PlannerAuthMethod;
}): Ed25519InitialPlannerState {
  switch (args.authMethod) {
    case 'email_otp':
      return { kind: 'email_otp_prf_unavailable', capability: args.capability };
    case 'passkey':
      return {
        kind: 'passkey_prf_unavailable',
        capability: args.capability,
        statusCode: args.capability.prfClaim?.code,
      };
    default:
      return assertNeverSigningSessionAuthMode(args.authMethod);
  }
}

function classifyMaterialPendingEd25519PlannerState(args: {
  capability: NearEd25519Capability;
  authMethod: Ed25519PlannerAuthMethod;
}): Ed25519InitialPlannerState {
  switch (args.authMethod) {
    case 'email_otp':
      return { kind: 'email_otp_material_pending', capability: args.capability };
    case 'passkey':
      switch (args.capability.prfClaim?.state) {
        case 'warm':
          return classifyWarmPasskeyMaterialPendingPlannerState(args.capability);
        case 'missing':
        case 'expired':
        case 'exhausted':
        case 'unavailable':
        case undefined:
          return { kind: 'passkey_refreshable', capability: args.capability };
        default:
          return assertNeverSigningSessionAuthMode(args.capability.prfClaim);
      }
    default:
      return assertNeverSigningSessionAuthMode(args.authMethod);
  }
}

function classifyWarmPasskeyMaterialPendingPlannerState(
  capability: NearEd25519Capability,
): Ed25519InitialPlannerState {
  const persistedState = classifyRouterAbEd25519PersistedSigningRecord(capability.record);
  switch (persistedState.kind) {
    case 'restore_available':
      return { kind: 'passkey_material_repairable', capability };
    case 'runtime_validated':
      return { kind: 'ready', capability };
    case 'material_hint_unvalidated':
    case 'auth_ready_material_pending':
    case 'non_signing':
    case 'invalid':
      return { kind: 'passkey_refreshable', capability };
    default:
      return assertNeverSigningSessionAuthMode(persistedState);
  }
}

function classifyStatusOrRefreshBackedEd25519PlannerState(args: {
  capability: NearEd25519Capability;
  authMethod: Ed25519PlannerAuthMethod;
}): Ed25519InitialPlannerState {
  switch (args.authMethod) {
    case 'email_otp':
      return { kind: 'email_otp_status_backed', capability: args.capability };
    case 'passkey':
      return { kind: 'passkey_refreshable', capability: args.capability };
    default:
      return assertNeverSigningSessionAuthMode(args.authMethod);
  }
}

async function resolveRefreshablePasskeyEd25519PlannerReadiness(args: {
  plannerInput: ResolveEd25519PlannerReadinessArgs;
  capability: NearEd25519Capability;
}): Promise<Ed25519PlannerReadinessResult> {
  await restorePasskeyEd25519SessionBeforePlanningBestEffort(args.plannerInput);
  const capability = await readRefreshedEd25519CapabilityOrCurrent({
    warmSessionReader: args.plannerInput.warmSessionReader,
    sessionId: args.plannerInput.sessionId,
    current: args.capability,
  });
  const state = classifyPostRefreshEd25519PlannerState(capability);

  switch (state.kind) {
    case 'restore_available':
      return await resolveStatusBackedEd25519PlannerReadiness({
        plannerInput: args.plannerInput,
        capability: state.capability,
        authMethod: 'passkey',
        activeUseSource: 'available_uses',
      });
    case 'runtime_validated':
      return admitCapabilityBackedEd25519PlannerReadiness({
        plannerInput: args.plannerInput,
        capability: state.capability,
        remainingUses: ed25519CapabilityRemainingUses(state.capability),
      });
    case 'pending_without_restore':
      return pendingWithoutRestoreEd25519PlannerReadiness({
        plannerInput: args.plannerInput,
        capability: state.capability,
      });
    case 'status_backed':
      return await resolveStatusBackedEd25519PlannerReadiness({
        plannerInput: args.plannerInput,
        capability: state.capability,
        authMethod: state.authMethod,
        activeUseSource: 'remaining_uses',
      });
    case 'missing':
      return resolveMissingPostRefreshEd25519PlannerReadiness({
        plannerInput: args.plannerInput,
        capability: state.capability,
        authMethod: state.authMethod,
      });
    case 'invalid':
      throw new Error('[SigningEngine] Ed25519 signing session record is invalid');
    default:
      return assertNeverSigningSessionAuthMode(state);
  }
}

function classifyPostRefreshEd25519PlannerState(
  capability: NearEd25519Capability,
): Ed25519PostRefreshPlannerState {
  const persistedState = classifyRouterAbEd25519PersistedSigningRecord(capability.record);

  switch (persistedState.kind) {
    case 'runtime_validated':
      return { kind: 'runtime_validated', capability };
    case 'restore_available':
      return { kind: 'restore_available', capability };
    case 'material_hint_unvalidated':
    case 'auth_ready_material_pending':
    case 'non_signing':
    case 'invalid':
      return classifyPostRefreshCapabilityState(capability);
    default:
      return assertNeverSigningSessionAuthMode(persistedState);
  }
}

function classifyPostRefreshCapabilityState(
  capability: NearEd25519Capability,
): Ed25519PostRefreshPlannerState {
  const authMethod = ed25519PlannerAuthMethod(capability);

  switch (capability.state) {
    case 'material_pending':
      return { kind: 'pending_without_restore', capability };
    case 'missing':
      return { kind: 'missing', capability, authMethod };
    case 'invalid':
      return { kind: 'invalid', capability };
    case 'auth_missing':
    case 'ready':
    case 'prf_missing':
    case 'prf_unavailable':
      return { kind: 'status_backed', capability, authMethod };
    default:
      return assertNeverSigningSessionAuthMode(capability);
  }
}

async function restorePasskeyEd25519SessionBeforePlanningBestEffort(args: {
  warmSessionReader: NearWarmSessionReader;
  nearAccountId: string;
  capability: NearEd25519Capability;
  sessionId: string;
  operationLabel?: string;
}): Promise<void> {
  try {
    await restorePasskeyEd25519SessionBeforePlanning(args);
  } catch (error) {
    logPasskeyEd25519PlanningRestoreFailure({ plannerInput: args, error });
  }
}

function logPasskeyEd25519PlanningRestoreFailure(args: {
  plannerInput: Pick<
    ResolveEd25519PlannerReadinessArgs,
    'nearAccountId' | 'sessionId' | 'operationLabel'
  >;
  error: unknown;
}): void {
  if (!args.plannerInput.operationLabel) return;
  console.warn(
    `[SigningEngine][near] ${args.plannerInput.operationLabel} sealed session restore failed before auth planning`,
    {
      nearAccountId: args.plannerInput.nearAccountId,
      sessionId: args.plannerInput.sessionId,
      error: args.error instanceof Error ? args.error.message : String(args.error || 'unknown error'),
    },
  );
}

async function readRefreshedEd25519CapabilityOrCurrent(args: {
  warmSessionReader: NearWarmSessionReader;
  sessionId: string;
  current: NearEd25519Capability;
}): Promise<NearEd25519Capability> {
  try {
    const refreshed = await args.warmSessionReader.getEd25519CapabilityByThresholdSessionId(
      args.sessionId,
    );
    return refreshed?.record ? refreshed : args.current;
  } catch {
    return args.current;
  }
}

async function resolveStatusBackedEd25519PlannerReadiness(args: {
  plannerInput: ResolveEd25519PlannerReadinessArgs;
  capability: NearEd25519Capability;
  authMethod: Ed25519PlannerAuthMethod;
  activeUseSource: 'remaining_uses' | 'available_uses';
}): Promise<Ed25519PlannerReadinessResult> {
  const trustedStatus = toTrustedEd25519SigningSessionStatus(
    await args.plannerInput.warmSessionReader.getEd25519SigningSessionStatusForSession({
      nearAccountId: args.plannerInput.nearAccountId,
      thresholdSessionId: args.plannerInput.sessionId,
    }),
  );
  return admitTrustedEd25519SigningSessionStatus({
    trustedStatus,
    capability: args.capability,
    authMethod: args.authMethod,
    activeUseSource: args.activeUseSource,
    usesNeeded: normalizeRequiredSignatureUses(args.plannerInput.requiredSignatureUses),
    thresholdSessionId: SigningSessionIds.thresholdEd25519Session(args.plannerInput.sessionId),
  });
}

function admitTrustedEd25519SigningSessionStatus(args: {
  trustedStatus: TrustedEd25519SigningSessionStatus;
  capability: NearEd25519Capability;
  authMethod: Ed25519PlannerAuthMethod;
  activeUseSource: 'remaining_uses' | 'available_uses';
  usesNeeded: number;
  thresholdSessionId: ReturnType<typeof SigningSessionIds.thresholdEd25519Session>;
}): Ed25519PlannerReadinessResult {
  switch (args.trustedStatus.kind) {
    case 'active':
      return admitActiveTrustedEd25519SigningSessionStatus({
        trustedStatus: args.trustedStatus,
        capability: args.capability,
        activeUseSource: args.activeUseSource,
        usesNeeded: args.usesNeeded,
        thresholdSessionId: args.thresholdSessionId,
      });
    case 'exhausted':
      return buildEd25519PlannerReadiness({
        status: 'exhausted',
        thresholdSessionId: args.thresholdSessionId,
        capability: args.capability,
        remainingUses: 0,
      });
    case 'expired':
      return buildEd25519PlannerReadiness({
        status: 'expired',
        thresholdSessionId: args.thresholdSessionId,
        capability: args.capability,
        remainingUses: 0,
      });
    case 'unavailable':
      return unavailableTrustedEd25519SigningSessionReadiness({
        trustedStatus: args.trustedStatus,
        capability: args.capability,
        authMethod: args.authMethod,
        thresholdSessionId: args.thresholdSessionId,
      });
    case 'budget_unknown':
    case 'not_found':
    case 'missing_status':
      return buildEd25519PlannerReadiness({
        status: 'missing_session',
        thresholdSessionId: args.thresholdSessionId,
        capability: args.capability,
        remainingUses: 0,
      });
    default:
      return assertNeverSigningSessionAuthMode(args.trustedStatus);
  }
}

function admitActiveTrustedEd25519SigningSessionStatus(args: {
  trustedStatus: Extract<TrustedEd25519SigningSessionStatus, { kind: 'active' }>;
  capability: NearEd25519Capability;
  activeUseSource: 'remaining_uses' | 'available_uses';
  usesNeeded: number;
  thresholdSessionId: ReturnType<typeof SigningSessionIds.thresholdEd25519Session>;
}): Ed25519PlannerReadinessResult {
  const remainingUses =
    args.activeUseSource === 'available_uses'
      ? args.trustedStatus.availableUses
      : args.trustedStatus.remainingUses;
  const status = remainingUses < args.usesNeeded ? 'exhausted' : 'ready';
  return buildEd25519PlannerReadiness({
    status,
    thresholdSessionId: args.thresholdSessionId,
    capability: args.capability,
    remainingUses,
    expiresAtMs: args.trustedStatus.expiresAtMs,
  });
}

function unavailableTrustedEd25519SigningSessionReadiness(args: {
  trustedStatus: Extract<TrustedEd25519SigningSessionStatus, { kind: 'unavailable' }>;
  capability: NearEd25519Capability;
  authMethod: Ed25519PlannerAuthMethod;
  thresholdSessionId: ReturnType<typeof SigningSessionIds.thresholdEd25519Session>;
}): Ed25519PlannerReadinessResult {
  switch (args.authMethod) {
    case 'email_otp':
      return buildEd25519PlannerReadiness({
        status: 'missing_session',
        thresholdSessionId: args.thresholdSessionId,
        capability: args.capability,
        remainingUses: 0,
      });
    case 'passkey':
      throw new Error(formatThresholdSigningSessionAvailabilityError(args.trustedStatus.statusCode));
    default:
      return assertNeverSigningSessionAuthMode(args.authMethod);
  }
}

function pendingWithoutRestoreEd25519PlannerReadiness(args: {
  plannerInput: ResolveEd25519PlannerReadinessArgs;
  capability: NearEd25519Capability;
}): Ed25519PlannerReadinessResult {
  const thresholdSessionId = SigningSessionIds.thresholdEd25519Session(args.plannerInput.sessionId);
  const remainingUses = ed25519CapabilityRemainingUses(args.capability);
  const status =
    remainingUses < normalizeRequiredSignatureUses(args.plannerInput.requiredSignatureUses)
      ? 'exhausted'
      : 'missing_session';
  return buildEd25519PlannerReadiness({
    status,
    thresholdSessionId,
    capability: args.capability,
    remainingUses: status === 'exhausted' ? remainingUses : 0,
  });
}

function resolveMissingPostRefreshEd25519PlannerReadiness(args: {
  plannerInput: ResolveEd25519PlannerReadinessArgs;
  capability: NearEd25519Capability;
  authMethod: Ed25519PlannerAuthMethod;
}): Ed25519PlannerReadinessResult {
  const thresholdSessionId = SigningSessionIds.thresholdEd25519Session(args.plannerInput.sessionId);

  switch (args.authMethod) {
    case 'email_otp':
      return buildEd25519PlannerReadiness({
        status: 'missing_session',
        thresholdSessionId,
        capability: args.capability,
        remainingUses: 0,
      });
    case 'passkey':
      throw new Error(THRESHOLD_SESSION_MISSING_ERROR);
    default:
      return assertNeverSigningSessionAuthMode(args.authMethod);
  }
}

function missingEd25519PlannerReadiness(
  args: ResolveEd25519PlannerReadinessArgs,
  capability: NearEd25519Capability,
): Ed25519PlannerReadinessResult {
  return buildEd25519PlannerReadiness({
    status: 'missing_session',
    thresholdSessionId: SigningSessionIds.thresholdEd25519Session(args.sessionId),
    capability,
    remainingUses: 0,
  });
}

function admitCapabilityBackedEd25519PlannerReadiness(args: {
  plannerInput: ResolveEd25519PlannerReadinessArgs;
  capability: NearEd25519Capability;
  remainingUses: number;
}): Ed25519PlannerReadinessResult {
  const status =
    args.remainingUses < normalizeRequiredSignatureUses(args.plannerInput.requiredSignatureUses)
      ? 'exhausted'
      : 'ready';
  return buildEd25519PlannerReadiness({
    status,
    thresholdSessionId: SigningSessionIds.thresholdEd25519Session(args.plannerInput.sessionId),
    capability: args.capability,
    remainingUses: args.remainingUses,
  });
}

function buildEd25519PlannerReadiness(args: {
  status: SigningSessionReadiness['status'];
  thresholdSessionId: ReturnType<typeof SigningSessionIds.thresholdEd25519Session>;
  capability: NearEd25519Capability;
  expiresAtMs?: number;
  remainingUses?: number;
}): Ed25519PlannerReadinessResult {
  const expiresAtMs = args.expiresAtMs ?? ed25519CapabilityExpiresAtMs(args.capability);
  const remainingUses = args.remainingUses ?? ed25519CapabilityRemainingUses(args.capability);

  switch (args.status) {
    case 'ready':
    case 'exhausted':
      return {
        readiness: {
          status: args.status,
          thresholdSessionId: args.thresholdSessionId,
          remainingUses,
          expiresAtMs,
        },
        expiresAtMs,
        remainingUses,
      };
    case 'expired':
      return {
        readiness: {
          status: 'expired',
          thresholdSessionId: args.thresholdSessionId,
          expiresAtMs,
        },
        expiresAtMs,
        remainingUses,
      };
    case 'missing_session':
    case 'auth_unavailable':
    case 'status_unavailable':
    case 'budget_unknown':
      return {
        readiness: {
          status: args.status,
          thresholdSessionId: args.thresholdSessionId,
        },
        expiresAtMs,
        remainingUses,
      };
    default:
      return assertNeverSigningSessionAuthMode(args.status);
  }
}

function toTrustedEd25519SigningSessionStatus(
  status: SigningSessionStatus | null,
): TrustedEd25519SigningSessionStatus {
  if (!status) return { kind: 'missing_status' };

  switch (status.status) {
    case 'active':
      return {
        kind: 'active',
        remainingUses: Math.max(0, Math.floor(Number(status.remainingUses) || 0)),
        availableUses: availableUsesForBudgetAdmission(status),
        expiresAtMs: Math.floor(Number(status.expiresAtMs) || 0),
      };
    case 'exhausted':
      return { kind: 'exhausted' };
    case 'expired':
      return { kind: 'expired' };
    case 'unavailable':
      return { kind: 'unavailable', statusCode: status.statusCode };
    case 'budget_unknown':
      return { kind: 'budget_unknown' };
    case 'not_found':
      return { kind: 'not_found' };
    default:
      return assertNeverSigningSessionAuthMode(status.status);
  }
}

function ed25519PlannerAuthMethod(
  capability: NearEd25519Capability,
): Ed25519PlannerAuthMethod {
  return capability.record?.source === 'email_otp' ? 'email_otp' : 'passkey';
}

function ed25519ReadyCapabilityRemainingUses(capability: NearEd25519Capability): number {
  switch (capability.prfClaim?.state) {
    case 'warm':
      return Math.max(0, Math.floor(Number(capability.prfClaim.remainingUses) || 0));
    case 'missing':
    case 'expired':
    case 'exhausted':
    case 'unavailable':
    case undefined:
      return Math.max(0, Math.floor(Number(capability.record?.remainingUses) || 0));
    default:
      return assertNeverSigningSessionAuthMode(capability.prfClaim);
  }
}

function ed25519CapabilityRemainingUses(capability: NearEd25519Capability): number {
  return Math.max(
    0,
    Math.floor(Number(capability.prfClaim?.remainingUses ?? capability.record?.remainingUses) || 0),
  );
}

function ed25519CapabilityExpiresAtMs(capability: NearEd25519Capability): number {
  return Math.floor(
    Number(capability.prfClaim?.expiresAtMs ?? capability.record?.expiresAtMs) || Date.now(),
  );
}

async function restorePasskeyEd25519SessionBeforePlanning(args: {
  warmSessionReader: NearWarmSessionReader;
  nearAccountId: string;
  capability: Awaited<
    ReturnType<WarmSessionCapabilityReader['getWarmSession']>
  >['capabilities']['ed25519'];
  sessionId: string;
}): Promise<void> {
  const record = args.capability.record;
  if (!record || record.source === 'email_otp') return;
  const persistedState = classifyRouterAbEd25519PersistedSigningRecord(record);
  if (args.capability.prfClaim?.state === 'warm' && persistedState.kind === 'runtime_validated') {
    return;
  }
  if (typeof args.warmSessionReader.restorePersistedSessionForSigning !== 'function') return;
  const signingGrantId = String(record.signingGrantId || '').trim();
  const thresholdSessionId = String(record.thresholdSessionId || args.sessionId || '').trim();
  if (!signingGrantId || !thresholdSessionId) return;
  await args.warmSessionReader.restorePersistedSessionForSigning({
    walletId: args.nearAccountId,
    authMethod: 'passkey',
    curve: 'ed25519',
    chain: 'near',
    signingGrantId,
    thresholdSessionId,
    reason: 'transaction',
  });
}

function normalizeRequiredSignatureUses(requiredSignatureUsesRaw: unknown): number {
  const requiredSignatureUses = Math.floor(Number(requiredSignatureUsesRaw) || 0);
  return requiredSignatureUses > 0 ? requiredSignatureUses : 1;
}

function assertNeverSigningSessionAuthMode(value: never): never {
  throw new Error(`Unexpected NEAR signing auth mode state: ${String(value)}`);
}
