import type { SigningAuthPlan } from '@/core/signingEngine/stepUpConfirmation/types';
import { signingAuthPlanFromSigningSessionPlan } from '../../shared/signingConfirmation';
import { committedUsesForBudgetAdmission } from '@/core/signingEngine/session/budget/budget';
import {
  formatThresholdSigningSessionAvailabilityError,
  SIGNING_SESSION_AUTH_UNAVAILABLE_ERROR,
} from '@/core/signingEngine/session/warmCapabilities/statusReader';
import {
  createWarmSessionCapabilityReader,
  type WarmSessionCapabilityReaderTouchConfirmInput,
} from '@/core/signingEngine/session/warmCapabilities/capabilityReader';
import { createWarmSessionStatusReader } from '@/core/signingEngine/session/warmCapabilities/statusReader';
import type {
  ThresholdWarmSessionStatusReader,
  WarmSessionCapabilityReader,
} from '@/core/signingEngine/session/warmCapabilities/types';
import type { WarmSessionStatusResult } from '@/core/signingEngine/uiConfirm/uiConfirm.types';
import {
  buildNearTransactionSigningLane,
  type NearTransactionSigningLane,
} from '@/core/signingEngine/session/operationState/lanes';
import type {
  ResolveSigningSessionAuthPlanFromReadinessInput,
  ResolveSigningSessionAuthPlanFromReadinessResult,
  SigningSessionReadiness,
} from '@/core/signingEngine/session/SigningSessionCoordinator';
import {
  emailOtpAuthContextReason,
  emailOtpAuthContextRetention,
  type ThresholdEd25519SessionStoreSource,
} from '@/core/signingEngine/session/identity/laneIdentity';
import { SIGNER_AUTH_METHODS, type SignerAuthMethod } from '@shared/utils/signerDomain';
import {
  createSigningBoundaryTraceEvent,
  emitSigningBoundaryTrace,
  emitSigningLaneResolutionTrace,
} from '@/core/signingEngine/session/operationState/trace';
import {
  SigningOperationIntent,
  SigningSessionIds,
  SigningSessionPlanKind,
} from '@/core/signingEngine/session/operationState/types';
import { thresholdEd25519LaneCandidateFromSessionRecord } from '@/core/signingEngine/session/persistence/records';
import type { NearCommandSubject } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { SigningSessionStatus } from '@/core/types/seams';
import { toAccountId } from '@/core/types/accountIds';

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

type NearSigningSessionCoordinatorPort = WarmSessionCapabilityReaderTouchConfirmInput;
type NearWarmSessionReader = WarmSessionCapabilityReader & ThresholdWarmSessionStatusReader;
type NearEd25519Capability = Awaited<
  ReturnType<WarmSessionCapabilityReader['getWarmSession']>
>['capabilities']['ed25519'];
type Ed25519PlannerAuthMethod = Extract<
  SignerAuthMethod,
  typeof SIGNER_AUTH_METHODS.passkey | typeof SIGNER_AUTH_METHODS.emailOtp
>;
type ResolveEd25519PlannerReadinessArgs = {
  warmSessionReader: NearWarmSessionReader;
  nearAccountId: string;
  capability: NearEd25519Capability;
  sessionId: string;
  requiredSignatureUses?: number;
};
type Ed25519PlannerReadinessResult = {
  readiness: SigningSessionReadiness;
  expiresAtMs: number;
  remainingUses: number;
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
  | { sessionId: string; status: 'exhausted' }
  | { sessionId: string; status: 'expired' }
  | { sessionId: string; status: 'unavailable'; statusCode?: string }
  | { sessionId: string; status: 'budget_unknown' }
  | { sessionId: string; status: 'not_found' };

type TrustedEd25519SigningSessionStatus =
  | TrustedActiveEd25519SigningBudgetStatus
  | TrustedInactiveEd25519SigningSessionStatus
  | { status: 'missing_status' };

async function readEmailOtpWarmSessionStatus(
  touchConfirm: NearSigningSessionCoordinatorPort,
  sessionId: string,
): Promise<WarmSessionStatusResult> {
  if (typeof touchConfirm?.getWarmSessionStatus === 'function') {
    return await touchConfirm.getWarmSessionStatus({ sessionId });
  }
  return {
    ok: false,
    code: 'not_found',
    message: 'Email OTP warm-session status reader is unavailable',
  };
}

export function createNearSigningSessionCoordinator(
  touchConfirm: NearSigningSessionCoordinatorPort,
): NearWarmSessionReader {
  const getEmailOtpWarmSessionStatus = readEmailOtpWarmSessionStatus.bind(null, touchConfirm);
  return {
    ...createWarmSessionCapabilityReader({
      touchConfirm,
      signingSessionSeal: null,
      getEmailOtpWarmSessionStatus,
    }),
    ...createWarmSessionStatusReader({
      touchConfirm,
      getEmailOtpWarmSessionStatus,
    }),
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
  const capability = await args.warmSessionReader.getEd25519CapabilityForNearAccount(
    toAccountId(nearAccountId),
  );
  const record = capability?.record;
  const sessionId = String(record?.thresholdSessionId || '').trim();
  if (!capability || !record || !sessionId) {
    throw new Error(SIGNING_SESSION_AUTH_UNAVAILABLE_ERROR);
  }
  if (
    String(record.walletId) !== String(walletId) ||
    String(record.nearAccountId) !== nearAccountId
  ) {
    throw new Error(
      '[SigningEngine][near] exact Ed25519 capability does not match command subject',
    );
  }
  const signingGrantId = String(record.signingGrantId || '').trim();
  if (!signingGrantId) {
    throw new Error('[SigningEngine][near] missing signing grant id for transaction auth planning');
  }
  const recordCandidate = thresholdEd25519LaneCandidateFromSessionRecord({ record });
  if (!recordCandidate) {
    throw new Error('[SigningEngine][near] selected Ed25519 record has no lane candidate');
  }
  const source = record.source;
  let lane: NearTransactionSigningLane | null;
  switch (source) {
    case SIGNER_AUTH_METHODS.emailOtp: {
      const emailOtpAuthContext = record.emailOtpAuthContext;
      lane =
        recordCandidate.auth.kind === SIGNER_AUTH_METHODS.emailOtp && emailOtpAuthContext
          ? buildNearTransactionSigningLane({
              walletId: record.walletId,
              nearAccountId: record.nearAccountId,
              nearEd25519SigningKeyId: record.nearEd25519SigningKeyId,
              signerSlot: recordCandidate.signerSlot,
              auth: recordCandidate.auth,
              signingGrantId: SigningSessionIds.signingGrant(signingGrantId),
              thresholdSessionId: SigningSessionIds.thresholdEd25519Session(sessionId),
              retention: emailOtpAuthContextRetention(emailOtpAuthContext),
              sessionOrigin:
                emailOtpAuthContextReason(emailOtpAuthContext) === 'login'
                  ? 'login'
                  : 'per_operation',
            })
          : null;
      break;
    }
    case 'login':
    case 'registration':
    case 'add-signer':
    case 'manual-connect':
    case 'bootstrap':
      lane =
        recordCandidate.auth.kind === SIGNER_AUTH_METHODS.passkey
          ? buildNearTransactionSigningLane({
              walletId: record.walletId,
              nearAccountId: record.nearAccountId,
              nearEd25519SigningKeyId: record.nearEd25519SigningKeyId,
              signerSlot: recordCandidate.signerSlot,
              auth: recordCandidate.auth,
              signingGrantId: SigningSessionIds.signingGrant(signingGrantId),
              thresholdSessionId: SigningSessionIds.thresholdEd25519Session(sessionId),
              storageSource: source,
            })
          : null;
      break;
    default:
      return assertNeverThresholdEd25519SessionSource(source);
  }
  if (!lane) {
    throw new Error('[SigningEngine][near] selected Ed25519 record auth branch is invalid');
  }
  emitSigningLaneResolutionTrace('near', lane, { reason: 'near_threshold_auth_plan' });
  const readiness = await resolvePlannerReadinessForEd25519({
    warmSessionReader: args.warmSessionReader,
    nearAccountId,
    capability,
    sessionId,
    requiredSignatureUses: args.requiredSignatureUses,
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
  return {
    sessionId,
    walletId,
    nearAccountId,
    lane,
    coordinatorInput: {
      lane,
      readiness: readiness.readiness,
      expiresAtMs: readiness.expiresAtMs,
      remainingUses: readiness.remainingUses,
      usesNeeded: args.requiredSignatureUses,
    },
  };
}

export function buildNearSigningSessionAuthPlan(args: {
  context: NearSigningSessionAuthContext;
  resolvedSigningSession: ResolveSigningSessionAuthPlanFromReadinessResult;
}): NearSigningSessionAuthPlan {
  const { sessionId, lane } = args.context;
  const resolvedSigningSession = args.resolvedSigningSession;
  const plan = resolvedSigningSession.signingSessionPlan;
  if (plan.kind === SigningSessionPlanKind.NotReady) {
    throw new Error(`[SigningEngine][near] signing session is not ready: ${plan.reason}`);
  }
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

async function resolvePlannerReadinessForEd25519(
  args: ResolveEd25519PlannerReadinessArgs,
): Promise<Ed25519PlannerReadinessResult> {
  const authMethod = ed25519PlannerAuthMethod(args.capability);
  switch (args.capability.state) {
    case 'ready':
      return admitCapabilityBackedEd25519PlannerReadiness({
        plannerInput: args,
        capability: args.capability,
      });
    case 'auth_missing':
      return missingEd25519PlannerReadiness(args);
    case 'invalid':
      throw new Error('[SigningEngine] Ed25519 signing session record is invalid');
    case 'prf_unavailable':
      if (authMethod === SIGNER_AUTH_METHODS.passkey) {
        throw new Error(
          formatThresholdSigningSessionAvailabilityError(args.capability.prfClaim?.code),
        );
      }
      return missingEd25519PlannerReadiness(args);
    case 'missing':
    case 'prf_missing':
      return await resolveStatusBackedEd25519PlannerReadiness({
        plannerInput: args,
        capability: args.capability,
        authMethod,
      });
    default:
      return assertNeverSigningSessionAuthMode(args.capability);
  }
}

async function resolveStatusBackedEd25519PlannerReadiness(args: {
  plannerInput: ResolveEd25519PlannerReadinessArgs;
  capability: NearEd25519Capability;
  authMethod: Ed25519PlannerAuthMethod | null;
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
  authMethod: Ed25519PlannerAuthMethod | null;
  usesNeeded: number;
  thresholdSessionId: ReturnType<typeof SigningSessionIds.thresholdEd25519Session>;
}): Ed25519PlannerReadinessResult {
  switch (args.trustedStatus.status) {
    case 'active': {
      const remainingUses = committedUsesForBudgetAdmission(args.trustedStatus);
      return buildEd25519PlannerReadiness({
        status: remainingUses < args.usesNeeded ? 'exhausted' : 'ready',
        thresholdSessionId: args.thresholdSessionId,
        capability: args.capability,
        remainingUses,
        expiresAtMs: args.trustedStatus.expiresAtMs,
      });
    }
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
      if (args.authMethod === SIGNER_AUTH_METHODS.passkey) {
        throw new Error(
          formatThresholdSigningSessionAvailabilityError(args.trustedStatus.statusCode),
        );
      }
      return buildEd25519PlannerReadiness({
        status: 'missing_session',
        thresholdSessionId: args.thresholdSessionId,
        capability: args.capability,
        remainingUses: 0,
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

function missingEd25519PlannerReadiness(
  args: ResolveEd25519PlannerReadinessArgs,
): Ed25519PlannerReadinessResult {
  return buildEd25519PlannerReadiness({
    status: 'missing_session',
    thresholdSessionId: SigningSessionIds.thresholdEd25519Session(args.sessionId),
    capability: args.capability,
    remainingUses: 0,
  });
}

function admitCapabilityBackedEd25519PlannerReadiness(args: {
  plannerInput: ResolveEd25519PlannerReadinessArgs;
  capability: NearEd25519Capability;
}): Ed25519PlannerReadinessResult {
  const remainingUses = ed25519CapabilityRemainingUses(args.capability);
  return buildEd25519PlannerReadiness({
    status:
      remainingUses < normalizeRequiredSignatureUses(args.plannerInput.requiredSignatureUses)
        ? 'exhausted'
        : 'ready',
    thresholdSessionId: SigningSessionIds.thresholdEd25519Session(args.plannerInput.sessionId),
    capability: args.capability,
    remainingUses,
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
        readiness: { status: 'expired', thresholdSessionId: args.thresholdSessionId, expiresAtMs },
        expiresAtMs,
        remainingUses,
      };
    case 'missing_session':
    case 'auth_unavailable':
    case 'status_unavailable':
    case 'budget_unknown':
      return {
        readiness: { status: args.status, thresholdSessionId: args.thresholdSessionId },
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
      const inFlightReservedUses = parseNonNegativeIntegerStatusField(status.inFlightReservedUses);
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
    case 'active_restorable':
    case 'not_found':
      return { sessionId: status.sessionId, status: 'not_found' };
    case 'exhausted':
      return { sessionId: status.sessionId, status: 'exhausted' };
    case 'expired':
      return { sessionId: status.sessionId, status: 'expired' };
    case 'unavailable':
      return {
        sessionId: status.sessionId,
        status: 'unavailable',
        statusCode: status.statusCode,
      };
    case 'budget_unknown':
      return { sessionId: status.sessionId, status: 'budget_unknown' };
    default:
      return assertNeverSigningSessionAuthMode(status.status);
  }
}

function parseNonNegativeIntegerStatusField(value: unknown): number | null {
  const parsed = Math.floor(Number(value));
  return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : null;
}

function parsePositiveIntegerStatusField(value: unknown): number | null {
  const parsed = parseNonNegativeIntegerStatusField(value);
  return parsed !== null && parsed > 0 ? parsed : null;
}

function ed25519PlannerAuthMethod(
  capability: NearEd25519Capability,
): Ed25519PlannerAuthMethod | null {
  return ed25519PlannerAuthMethodForSource(capability.record?.source);
}

function ed25519PlannerAuthMethodForSource(
  source: ThresholdEd25519SessionStoreSource | undefined,
): Ed25519PlannerAuthMethod | null {
  switch (source) {
    case SIGNER_AUTH_METHODS.emailOtp:
      return SIGNER_AUTH_METHODS.emailOtp;
    case undefined:
      return null;
    case 'login':
    case 'registration':
    case 'add-signer':
    case 'manual-connect':
    case 'bootstrap':
      return SIGNER_AUTH_METHODS.passkey;
    default:
      return assertNeverThresholdEd25519SessionSource(source);
  }
}

function assertNeverThresholdEd25519SessionSource(value: never): never {
  throw new Error(`Unsupported threshold Ed25519 session source: ${String(value)}`);
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

function normalizeRequiredSignatureUses(value: unknown): number {
  return Math.max(1, Math.floor(Number(value) || 1));
}

function assertNeverSigningSessionAuthMode(value: never): never {
  throw new Error(`Unhandled near signing auth state: ${JSON.stringify(value)}`);
}
