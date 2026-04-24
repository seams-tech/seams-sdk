import {
  SigningAuthPlanKind,
  type SigningAuthPlan,
} from '@/core/signingEngine/touchConfirm/shared/confirmTypes';
import {
  formatThresholdSigningSessionAvailabilityError,
  THRESHOLD_SESSION_AUTH_UNAVAILABLE_ERROR,
  THRESHOLD_SESSION_MISSING_ERROR,
} from '@/core/signingEngine/session/WarmSessionStatusReader';
import { createWarmSessionCapabilityReader } from '@/core/signingEngine/session/WarmSessionCapabilityReader';
import { createWarmSessionStatusReader } from '@/core/signingEngine/session/WarmSessionStatusReader';
import type {
  ThresholdWarmSessionStatusReader,
  WarmSessionCapabilityReader,
  WarmSessionProvisioner,
} from '@/core/signingEngine/session/WarmSessionServiceTypes';
import { claimWarmSessionPrfFirst } from '@/core/signingEngine/session/warmSessionRuntime';
import type { WarmSessionStatusResult } from '@/core/signingEngine/touchConfirm';
import { buildNearTransactionSigningLane } from '@/core/signingEngine/session/SigningLaneBuilders';
import {
  createSigningSessionPlanner,
  type SigningSessionReadiness,
} from '@/core/signingEngine/session/SigningSessionPlanner';
import {
  createSigningBoundaryTraceEvent,
  emitSigningBoundaryTrace,
  emitSigningLaneResolutionTrace,
  emitSigningPlannerDecisionTrace,
} from '@/core/signingEngine/session/SigningSessionTrace';
import {
  SigningOperationIntent,
  SigningSessionPlanKind,
  SigningSessionIds,
  type SigningLaneContext,
} from '@/core/signingEngine/session/signingSessionTypes';

export type NearThresholdSigningAuthPlan = {
  sessionId: string;
  lane: SigningLaneContext;
  signingAuthPlan?: SigningAuthPlan;
  touchConfirmAuthPayload: { signingAuthPlan: SigningAuthPlan };
  warmSessionReady: boolean;
};
export { THRESHOLD_SESSION_AUTH_UNAVAILABLE_ERROR };

type NearSigningSessionCoordinatorPort = Parameters<
  typeof createWarmSessionCapabilityReader
>[0] extends infer FactoryDeps
  ? NonNullable<FactoryDeps> extends { touchConfirm?: infer TouchConfirm }
    ? TouchConfirm
    : never
  : never;

export function createNearSigningSessionCoordinator(
  touchConfirm: NearSigningSessionCoordinatorPort,
): WarmSessionCapabilityReader &
  ThresholdWarmSessionStatusReader &
  Pick<WarmSessionProvisioner, 'claimPrfFirstByThresholdSessionId'> {
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
      touchConfirm,
      getEmailOtpWarmSessionStatus,
    }),
    ...createWarmSessionStatusReader({
      touchConfirm,
      getEmailOtpWarmSessionStatus,
    }),
    claimPrfFirstByThresholdSessionId: (claimArgs) =>
      claimWarmSessionPrfFirst({
        touchConfirm,
        thresholdSessionId: claimArgs.thresholdSessionId,
        errorContext: claimArgs.errorContext,
        uses: claimArgs.uses,
      }),
  };
}

export async function resolveNearThresholdSigningAuthPlan(args: {
  signingSessionCoordinator: WarmSessionCapabilityReader & ThresholdWarmSessionStatusReader;
  nearAccountId: string;
  operationLabel: string;
  usesNeeded?: number;
}): Promise<NearThresholdSigningAuthPlan> {
  const accountId = String(args.nearAccountId || '').trim();
  const warmSession = await args.signingSessionCoordinator.getWarmSession(accountId);
  const capability = warmSession.capabilities.ed25519;
  const record = capability.record;
  const sessionId = String(record?.thresholdSessionId || '').trim();
  if (!record || !sessionId) {
    throw new Error(THRESHOLD_SESSION_AUTH_UNAVAILABLE_ERROR);
  }
  const isEmailOtpSession = record?.source === 'email_otp';
  const walletSigningSessionId = String(record?.walletSigningSessionId || '').trim();
  if (!walletSigningSessionId) {
    throw new Error(
      '[SigningEngine][near] missing wallet signing session id for transaction auth planning',
    );
  }
  const lane =
    record?.source === 'email_otp'
      ? buildNearTransactionSigningLane({
          accountId,
          authMethod: 'email_otp',
          walletSigningSessionId: SigningSessionIds.walletSigningSession(walletSigningSessionId),
          thresholdSessionId: SigningSessionIds.thresholdEd25519Session(sessionId),
          retention: record.emailOtpAuthContext?.retention || 'session',
          sessionOrigin: record.emailOtpAuthContext?.reason === 'login' ? 'login' : 'per_operation',
        })
      : buildNearTransactionSigningLane({
          accountId,
          authMethod: 'passkey',
          walletSigningSessionId: SigningSessionIds.walletSigningSession(walletSigningSessionId),
          thresholdSessionId: SigningSessionIds.thresholdEd25519Session(sessionId),
          storageSource: record.source,
        });
  emitSigningLaneResolutionTrace('near', lane, {
    reason: 'near_threshold_auth_plan',
  });

  const readiness = await resolvePlannerReadinessForEd25519({
    signingSessionCoordinator: args.signingSessionCoordinator,
    nearAccountId: accountId,
    capability,
    sessionId,
    usesNeeded: args.usesNeeded,
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
  const plan = createSigningSessionPlanner({
    onTrace: (event) => emitSigningPlannerDecisionTrace('near', event),
  }).plan({
    lane,
    readiness: readiness.readiness,
    forceFreshAuth:
      isEmailOtpSession &&
      capability.state === 'ready' &&
      capability.prfClaim?.state !== 'warm' &&
      !String(record?.xClientBaseB64u || '').trim(),
  });

  if (plan.kind === SigningSessionPlanKind.WarmSession) {
    const signingAuthPlan: SigningAuthPlan = {
      kind: SigningAuthPlanKind.WarmSession,
      method: lane.authMethod,
      accountId,
      intent: SigningOperationIntent.TransactionSign,
      curve: 'ed25519',
      sessionId,
      retention: lane.retention,
      expiresAtMs: readiness.expiresAtMs,
      remainingUses: readiness.remainingUses,
    };
    return {
      sessionId,
      lane,
      signingAuthPlan,
      touchConfirmAuthPayload: { signingAuthPlan },
      warmSessionReady: true,
    };
  }
  if (plan.kind === SigningSessionPlanKind.PasskeyReauth) {
    const signingAuthPlan: SigningAuthPlan = {
      kind: SigningAuthPlanKind.PasskeyReauth,
      method: 'passkey',
    };
    return {
      sessionId,
      lane,
      signingAuthPlan,
      touchConfirmAuthPayload: { signingAuthPlan },
      warmSessionReady: false,
    };
  }
  if (plan.kind === SigningSessionPlanKind.NotReady) {
    throw new Error(`[SigningEngine][near] signing session is not ready: ${plan.reason}`);
  }
  const signingAuthPlan: SigningAuthPlan = {
    kind: SigningAuthPlanKind.EmailOtpReauth,
    method: 'email_otp',
  };
  return {
    sessionId,
    lane,
    signingAuthPlan,
    touchConfirmAuthPayload: { signingAuthPlan },
    warmSessionReady: false,
  };
}

async function resolvePlannerReadinessForEd25519(args: {
  signingSessionCoordinator: WarmSessionCapabilityReader & ThresholdWarmSessionStatusReader;
  nearAccountId: string;
  capability: Awaited<
    ReturnType<WarmSessionCapabilityReader['getWarmSession']>
  >['capabilities']['ed25519'];
  sessionId: string;
  usesNeeded?: number;
  operationLabel?: string;
}): Promise<{
  readiness: SigningSessionReadiness;
  expiresAtMs: number;
  remainingUses: number;
}> {
  const isEmailOtpSession = args.capability.record?.source === 'email_otp';
  const thresholdSessionId = SigningSessionIds.thresholdEd25519Session(args.sessionId);
  const resolveExpiresAtMs = (): number =>
    Math.floor(
      Number(args.capability.prfClaim?.expiresAtMs ?? args.capability.record?.expiresAtMs) ||
        Date.now(),
    );
  const resolveRemainingUses = (): number =>
    Math.max(
      0,
      Math.floor(
        Number(args.capability.prfClaim?.remainingUses ?? args.capability.record?.remainingUses) ||
          0,
      ),
    );
  const buildReadiness = (
    status: SigningSessionReadiness['status'],
    remainingUses = resolveRemainingUses(),
  ) => ({
    readiness: {
      status,
      thresholdSessionId,
    },
    expiresAtMs: resolveExpiresAtMs(),
    remainingUses,
  });

  if (args.capability.state === 'auth_missing') {
    return isEmailOtpSession
      ? buildReadiness('missing_session', 0)
      : buildReadiness('auth_unavailable', 0);
  }
  if (args.capability.state === 'prf_unavailable') {
    if (isEmailOtpSession) return buildReadiness('missing_session', 0);
    throw new Error(formatThresholdSigningSessionAvailabilityError(args.capability.prfClaim?.code));
  }
  if (args.capability.state === 'ready') {
    const remainingUses = Math.floor(
      Number(
        args.capability.prfClaim?.state === 'warm'
          ? args.capability.prfClaim.remainingUses
          : args.capability.record?.remainingUses,
      ) || 0,
    );
    if (remainingUses < normalizeUsesNeeded(args.usesNeeded)) {
      return buildReadiness('exhausted', remainingUses);
    }
    return buildReadiness('ready', remainingUses);
  }

  const status = await args.signingSessionCoordinator.getEd25519SigningSessionStatusForSession({
    nearAccountId: args.nearAccountId,
    thresholdSessionId: args.sessionId,
  });
  if (status?.status === 'unavailable') {
    if (isEmailOtpSession) return buildReadiness('missing_session', 0);
    throw new Error(formatThresholdSigningSessionAvailabilityError(status.statusCode));
  }
  if (status?.status === 'expired') {
    return buildReadiness('expired', 0);
  }
  if (status?.status === 'exhausted') {
    return buildReadiness('exhausted', 0);
  }
  if (status?.status === 'active') {
    if (isEmailOtpSession) return buildReadiness('missing_session', 0);
    return buildReadiness('missing_session', Math.floor(Number(status.remainingUses) || 0));
  }
  if (args.capability.state === 'missing') {
    if (isEmailOtpSession) return buildReadiness('missing_session', 0);
    throw new Error(THRESHOLD_SESSION_MISSING_ERROR);
  }
  if (isEmailOtpSession) {
    return buildReadiness('missing_session', 0);
  }

  if (args.operationLabel) {
    console.warn(
      `[SigningEngine][near] ${args.operationLabel} warm session cache is unavailable; falling back to WebAuthn`,
      {
        nearAccountId: args.nearAccountId,
        sessionId: args.sessionId,
        code: status?.status || 'not_found',
      },
    );
  }
  return buildReadiness('missing_session', 0);
}

function normalizeUsesNeeded(usesNeededRaw: unknown): number {
  const usesNeeded = Math.floor(Number(usesNeededRaw) || 0);
  return usesNeeded > 0 ? usesNeeded : 1;
}
