import type { SigningAuthPlan } from '@/core/signingEngine/stepUpConfirmation/types';
import { signingAuthPlanFromSigningSessionPlan } from '../../shared/signingConfirmation';
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
import { thresholdEd25519LaneCandidateFromSessionRecord } from '@/core/signingEngine/session/persistence/records';
import {
  exactEd25519SigningLaneIdentity,
  nearEd25519SignerBindingFromBoundaryFields,
} from '@/core/signingEngine/session/identity/exactSigningLaneIdentity';
import {
  parseEd25519WorkerMaterialBindingDigest,
  parseEd25519WorkerMaterialKeyId,
} from '@/core/signingEngine/session/keyMaterialBrands';
import type {
  NearCommandSubject,
  ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
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
  walletId: string;
  nearAccountId: string;
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

type PrePlanningEd25519MaterialRestoreResult =
  | {
      kind: 'already_ready';
      capability: NearEd25519Capability;
    }
  | {
      kind: 'restored';
      capability: NearEd25519Capability;
      restored: number;
    }
  | {
      kind: 'not_applicable';
      reason:
        | 'auth_method_not_passkey'
        | 'record_not_restore_available'
        | 'operation_does_not_require_ed25519_material';
      capability: NearEd25519Capability;
    }
  | {
      kind: 'missing_unseal_authorization';
      code:
        | 'not_found'
        | 'expired'
        | 'exhausted'
        | 'scope_mismatch'
        | 'material_unseal_authorization_required';
      capability: NearEd25519Capability;
    }
  | {
      kind: 'missing_sealed_material';
      code:
        | 'no_durable_restore_records'
        | 'durable_restore_missing_worker_material'
        | 'material_restore_required';
      capability: NearEd25519Capability;
    }
  | {
      kind: 'worker_restore_failed';
      code:
        | 'restore_command_failed'
        | 'worker_validation_failed'
        | 'capability_refresh_failed'
        | 'unexpected_restore_error';
      capability: NearEd25519Capability;
      message: string;
    };

type TrustedActiveEd25519SigningBudgetStatus = SigningSessionStatus & {
  status: 'active';
  remainingUses: number;
  committedRemainingUses: number;
  inFlightReservedUses: number;
  availableUses: number;
  expiresAtMs: number;
  projectionVersion: string;
};

type TrustedInactiveEd25519SigningSessionStatus =
  | {
      sessionId: string;
      status: 'exhausted';
    }
  | {
      sessionId: string;
      status: 'expired';
    }
  | {
      sessionId: string;
      status: 'unavailable';
      statusCode?: string;
    }
  | {
      sessionId: string;
      status: 'budget_unknown';
    }
  | {
      sessionId: string;
      status: 'not_found';
    };

type TrustedEd25519SigningSessionStatus =
  | TrustedActiveEd25519SigningBudgetStatus
  | TrustedInactiveEd25519SigningSessionStatus
  | {
      status: 'missing_status';
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
  commandSubject: NearCommandSubject;
  operationLabel: string;
  requiredSignatureUses?: number;
}): Promise<NearSigningSessionAuthContext> {
  const walletId = toWalletId(args.commandSubject.walletSession.walletId);
  const nearAccountId = String(args.commandSubject.nearAccount.accountId || '').trim();
  const warmSession = await args.warmSessionReader.getWarmSession(walletId);
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
  const recordCandidate = thresholdEd25519LaneCandidateFromSessionRecord({ record });
  if (!recordCandidate) {
    throw new Error('[SigningEngine][near] selected Ed25519 record has no lane candidate');
  }
  const lane =
    record?.source === 'email_otp'
      ? recordCandidate.auth.kind === 'email_otp'
        ? buildNearTransactionSigningLane({
            walletId: record.walletId,
            nearAccountId: record.nearAccountId,
            nearEd25519SigningKeyId: record.nearEd25519SigningKeyId,
            signerSlot: recordCandidate.signerSlot,
            auth: recordCandidate.auth,
            signingGrantId: SigningSessionIds.signingGrant(signingGrantId),
            thresholdSessionId: SigningSessionIds.thresholdEd25519Session(sessionId),
            retention: record.emailOtpAuthContext?.retention || 'session',
            sessionOrigin:
              record.emailOtpAuthContext?.reason === 'login' ? 'login' : 'per_operation',
          })
        : null
      : recordCandidate.auth.kind === 'passkey'
        ? buildNearTransactionSigningLane({
            walletId: record.walletId,
            nearAccountId: record.nearAccountId,
            nearEd25519SigningKeyId: record.nearEd25519SigningKeyId,
            signerSlot: recordCandidate.signerSlot,
            auth: recordCandidate.auth,
            signingGrantId: SigningSessionIds.signingGrant(signingGrantId),
            thresholdSessionId: SigningSessionIds.thresholdEd25519Session(sessionId),
            storageSource: record.source,
          })
        : null;
  if (!lane) {
    throw new Error('[SigningEngine][near] selected Ed25519 record auth branch is invalid');
  }
  emitSigningLaneResolutionTrace('near', lane, {
    reason: 'near_threshold_auth_plan',
  });

  const readiness = await resolvePlannerReadinessForEd25519({
    warmSessionReader: args.warmSessionReader,
    nearAccountId,
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
    walletId,
    nearAccountId,
    lane,
    coordinatorInput,
  };
}

export function buildNearSigningSessionAuthPlan(args: {
  context: NearSigningSessionAuthContext;
  resolvedSigningSession: ResolveSigningSessionAuthPlanFromReadinessResult;
}): NearSigningSessionAuthPlan {
  const { sessionId, walletId, lane } = args.context;
  const resolvedSigningSession = args.resolvedSigningSession;
  const plan = resolvedSigningSession.signingSessionPlan;

  if (plan.kind !== SigningSessionPlanKind.NotReady) {
    const signer = lane.identity.signer;
    const signingAuthPlan = signingAuthPlanFromSigningSessionPlan({
      plan,
      accountId: String(signer.account.nearAccountId),
      intent: SigningOperationIntent.TransactionSign,
      curve: 'ed25519',
      expiresAtMs: resolvedSigningSession.expiresAtMs,
      remainingUses: resolvedSigningSession.remainingUses,
    });
    return {
      sessionId,
      lane,
      signingAuthPlan,
      confirmationAuthPayload: { signingAuthPlan },
      warmSessionReady: plan.kind === SigningSessionPlanKind.WarmSession,
    };
  }

  switch (plan.kind) {
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
  const prePlanningRestore = await resolvePrePlanningPasskeyEd25519MaterialRestore(
    args.plannerInput,
  );
  if (prePlanningRestore.kind === 'missing_unseal_authorization') {
    return missingEd25519PlannerReadiness(args.plannerInput, prePlanningRestore.capability);
  }
  const capability = prePlanningRestoreCapabilityForPlanning({
    plannerInput: args.plannerInput,
    result: prePlanningRestore,
  });
  const state = classifyPostRefreshEd25519PlannerState(capability);

  switch (state.kind) {
    case 'restore_available':
      return await resolveStatusBackedEd25519PlannerReadiness({
        plannerInput: args.plannerInput,
        capability: state.capability,
        authMethod: 'passkey',
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

function prePlanningRestoreCapabilityForPlanning(args: {
  plannerInput: ResolveEd25519PlannerReadinessArgs;
  result: PrePlanningEd25519MaterialRestoreResult;
}): NearEd25519Capability {
  switch (args.result.kind) {
    case 'already_ready':
    case 'restored':
    case 'not_applicable':
      return args.result.capability;
    case 'missing_sealed_material':
      throw new Error(
        `[SigningEngine][near] material_restore_required: pre_confirm:${args.result.code}:${args.plannerInput.sessionId}`,
      );
    case 'missing_unseal_authorization':
      throw new Error(
        `[SigningEngine][near] material_unseal_authorization_required: pre_confirm:${args.result.code}:${args.plannerInput.sessionId}`,
      );
    case 'worker_restore_failed':
      throw new Error(
        `[SigningEngine][near] worker_restore_failed: pre_confirm:${args.result.code}:${args.result.message}`,
      );
    default:
      return assertNeverSigningSessionAuthMode(args.result);
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

async function resolvePrePlanningPasskeyEd25519MaterialRestore(args: {
  warmSessionReader: NearWarmSessionReader;
  nearAccountId: string;
  capability: NearEd25519Capability;
  sessionId: string;
  operationLabel?: string;
}): Promise<PrePlanningEd25519MaterialRestoreResult> {
  const record = args.capability.record;
  if (!record || record.source === 'email_otp') {
    return {
      kind: 'not_applicable',
      reason: 'auth_method_not_passkey',
      capability: args.capability,
    };
  }
  const persistedState = classifyRouterAbEd25519PersistedSigningRecord(record);
  switch (persistedState.kind) {
    case 'runtime_validated':
      return { kind: 'already_ready', capability: args.capability };
    case 'restore_available':
      return await restorePasskeyEd25519SessionBeforePlanning(args);
    case 'material_hint_unvalidated':
    case 'auth_ready_material_pending':
    case 'non_signing':
    case 'invalid':
      return {
        kind: 'not_applicable',
        reason: 'record_not_restore_available',
        capability: args.capability,
      };
    default:
      return assertNeverSigningSessionAuthMode(persistedState);
  }
}

function prePlanningRestoreFailureFromError(args: {
  error: unknown;
  capability: NearEd25519Capability;
}): PrePlanningEd25519MaterialRestoreResult {
  const message = errorMessageForPrePlanningRestore(args.error);
  if (message.includes('material_unseal_authorization_required')) {
    return {
      kind: 'missing_unseal_authorization',
      code: 'material_unseal_authorization_required',
      capability: args.capability,
    };
  }
  if (message.includes('not_found')) {
    return { kind: 'missing_unseal_authorization', code: 'not_found', capability: args.capability };
  }
  if (message.includes('expired')) {
    return { kind: 'missing_unseal_authorization', code: 'expired', capability: args.capability };
  }
  if (message.includes('exhausted')) {
    return { kind: 'missing_unseal_authorization', code: 'exhausted', capability: args.capability };
  }
  if (message.includes('scope_mismatch')) {
    return {
      kind: 'missing_unseal_authorization',
      code: 'scope_mismatch',
      capability: args.capability,
    };
  }
  if (message.includes('no_durable_restore_records')) {
    return {
      kind: 'missing_sealed_material',
      code: 'no_durable_restore_records',
      capability: args.capability,
    };
  }
  if (message.includes('durable_restore_missing_worker_material')) {
    return {
      kind: 'missing_sealed_material',
      code: 'durable_restore_missing_worker_material',
      capability: args.capability,
    };
  }
  if (message.includes('material_restore_required')) {
    return {
      kind: 'missing_sealed_material',
      code: 'material_restore_required',
      capability: args.capability,
    };
  }
  if (message.includes('validation')) {
    return {
      kind: 'worker_restore_failed',
      code: 'worker_validation_failed',
      capability: args.capability,
      message,
    };
  }
  if (message.includes('restore')) {
    return {
      kind: 'worker_restore_failed',
      code: 'restore_command_failed',
      capability: args.capability,
      message,
    };
  }
  return {
    kind: 'worker_restore_failed',
    code: 'unexpected_restore_error',
    capability: args.capability,
    message,
  };
}

function errorMessageForPrePlanningRestore(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error || 'unknown error');
}

async function readRefreshedEd25519CapabilityAfterRestore(args: {
  warmSessionReader: NearWarmSessionReader;
  sessionId: string;
  capability: NearEd25519Capability;
  restored: number;
}): Promise<PrePlanningEd25519MaterialRestoreResult> {
  try {
    const refreshed = await args.warmSessionReader.getEd25519CapabilityByThresholdSessionId(
      args.sessionId,
    );
    if (!refreshed?.record) {
      return {
        kind: 'worker_restore_failed',
        code: 'capability_refresh_failed',
        capability: args.capability,
        message: 'post-restore Ed25519 capability read returned no record',
      };
    }
    return {
      kind: 'restored',
      capability: refreshed,
      restored: args.restored,
    };
  } catch (error) {
    return {
      kind: 'worker_restore_failed',
      code: 'capability_refresh_failed',
      capability: args.capability,
      message: errorMessageForPrePlanningRestore(error),
    };
  }
}

async function resolveStatusBackedEd25519PlannerReadiness(args: {
  plannerInput: ResolveEd25519PlannerReadinessArgs;
  capability: NearEd25519Capability;
  authMethod: Ed25519PlannerAuthMethod;
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
    usesNeeded: normalizeRequiredSignatureUses(args.plannerInput.requiredSignatureUses),
    thresholdSessionId: SigningSessionIds.thresholdEd25519Session(args.plannerInput.sessionId),
  });
}

function admitTrustedEd25519SigningSessionStatus(args: {
  trustedStatus: TrustedEd25519SigningSessionStatus;
  capability: NearEd25519Capability;
  authMethod: Ed25519PlannerAuthMethod;
  usesNeeded: number;
  thresholdSessionId: ReturnType<typeof SigningSessionIds.thresholdEd25519Session>;
}): Ed25519PlannerReadinessResult {
  switch (args.trustedStatus.status) {
    case 'active':
      return admitActiveTrustedEd25519SigningSessionStatus({
        trustedStatus: args.trustedStatus,
        capability: args.capability,
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
  trustedStatus: TrustedActiveEd25519SigningBudgetStatus;
  capability: NearEd25519Capability;
  usesNeeded: number;
  thresholdSessionId: ReturnType<typeof SigningSessionIds.thresholdEd25519Session>;
}): Ed25519PlannerReadinessResult {
  const remainingUses = availableUsesForBudgetAdmission(args.trustedStatus);
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
  trustedStatus: Extract<TrustedEd25519SigningSessionStatus, { status: 'unavailable' }>;
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
  if (!status) return { status: 'missing_status' };

  switch (status.status) {
    case 'active': {
      const remainingUses = parseNonNegativeIntegerStatusField(status.remainingUses);
      const committedRemainingUses = parseNonNegativeIntegerStatusField(
        status.committedRemainingUses,
      );
      const inFlightReservedUses = parseNonNegativeIntegerStatusField(
        status.inFlightReservedUses,
      );
      const availableUses = parseNonNegativeIntegerStatusField(status.availableUses);
      const expiresAtMs = parsePositiveIntegerStatusField(status.expiresAtMs);
      const projectionVersion = String(status.projectionVersion || '').trim();
      if (
        remainingUses === null ||
        committedRemainingUses === null ||
        inFlightReservedUses === null ||
        availableUses === null ||
        expiresAtMs === null ||
        !projectionVersion
      ) {
        return { sessionId: status.sessionId, status: 'budget_unknown' };
      }
      return {
        sessionId: status.sessionId,
        status: 'active',
        remainingUses,
        committedRemainingUses,
        inFlightReservedUses,
        availableUses,
        expiresAtMs,
        projectionVersion,
      };
    }
    case 'exhausted':
      return { sessionId: status.sessionId, status: 'exhausted' };
    case 'expired':
      return { sessionId: status.sessionId, status: 'expired' };
    case 'unavailable':
      return { sessionId: status.sessionId, status: 'unavailable', statusCode: status.statusCode };
    case 'budget_unknown':
      return { sessionId: status.sessionId, status: 'budget_unknown' };
    case 'not_found':
      return { sessionId: status.sessionId, status: 'not_found' };
    default:
      return assertNeverSigningSessionAuthMode(status.status);
  }
}

function parseNonNegativeIntegerStatusField(value: unknown): number | null {
  const parsed = Math.floor(Number(value));
  if (!Number.isSafeInteger(parsed) || parsed < 0) return null;
  return parsed;
}

function parsePositiveIntegerStatusField(value: unknown): number | null {
  const parsed = parseNonNegativeIntegerStatusField(value);
  return parsed && parsed > 0 ? parsed : null;
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
}): Promise<PrePlanningEd25519MaterialRestoreResult> {
  const record = args.capability.record;
  if (!record || record.source === 'email_otp') {
    return {
      kind: 'not_applicable',
      reason: 'auth_method_not_passkey',
      capability: args.capability,
    };
  }
  if (typeof args.warmSessionReader.restorePersistedSessionForSigning !== 'function') {
    return { kind: 'missing_unseal_authorization', code: 'not_found', capability: args.capability };
  }
  const signingGrantId = String(record.signingGrantId || '').trim();
  const thresholdSessionId = String(record.thresholdSessionId || args.sessionId || '').trim();
  const candidate = thresholdEd25519LaneCandidateFromSessionRecord({ record });
  if (!signingGrantId || !thresholdSessionId || !candidate) {
    return {
      kind: 'missing_sealed_material',
      code: 'material_restore_required',
      capability: args.capability,
    };
  }
  try {
    const result = await args.warmSessionReader.restorePersistedSessionForSigning({
      walletId: record.walletId,
      authMethod: 'passkey',
      curve: 'ed25519',
      chain: 'near',
      signingGrantId,
      thresholdSessionId,
      reason: 'transaction',
      materialRestoreIdentity: {
        kind: 'ed25519_worker_material_restore',
        lane: exactEd25519SigningLaneIdentity({
          signer: nearEd25519SignerBindingFromBoundaryFields({
            walletId: record.walletId,
            nearAccountId: record.nearAccountId,
            nearEd25519SigningKeyId: record.nearEd25519SigningKeyId,
            signerSlot: record.signerSlot,
          }),
          auth: candidate.auth,
          signingGrantId,
          thresholdSessionId,
        }),
        materialBindingDigest: parseEd25519WorkerMaterialBindingDigest(
          record.ed25519WorkerMaterialBindingDigest,
        ),
        materialKeyId: parseEd25519WorkerMaterialKeyId(record.materialKeyId),
      },
    });
    if (result.deferred > 0) {
      return {
        kind: 'missing_unseal_authorization',
        code: 'material_unseal_authorization_required',
        capability: args.capability,
      };
    }
    if (result.restored > 0 || result.attempted > 0) {
      return await readRefreshedEd25519CapabilityAfterRestore({
        warmSessionReader: args.warmSessionReader,
        sessionId: thresholdSessionId,
        capability: args.capability,
        restored: result.restored,
      });
    }
    return {
      kind: 'missing_sealed_material',
      code: 'no_durable_restore_records',
      capability: args.capability,
    };
  } catch (error) {
    return prePlanningRestoreFailureFromError({ error, capability: args.capability });
  }
}

function normalizeRequiredSignatureUses(requiredSignatureUsesRaw: unknown): number {
  const requiredSignatureUses = Math.floor(Number(requiredSignatureUsesRaw) || 0);
  return requiredSignatureUses > 0 ? requiredSignatureUses : 1;
}

function assertNeverSigningSessionAuthMode(value: never): never {
  throw new Error(`Unexpected NEAR signing auth mode state: ${String(value)}`);
}
