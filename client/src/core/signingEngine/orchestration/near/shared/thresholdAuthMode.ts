import {
  SigningAuthPlanKind,
  type SigningAuthPlan,
} from '@/core/signingEngine/touchConfirm/shared/confirmTypes';
import {
  formatThresholdSigningSessionAvailabilityError,
  THRESHOLD_SESSION_AUTH_UNAVAILABLE_ERROR,
  THRESHOLD_SESSION_MISSING_ERROR,
} from '@/core/signingEngine/session/warmSigning/statusReader';
import { createWarmSessionCapabilityReader } from '@/core/signingEngine/session/warmSigning/capabilityReader';
import { createWarmSessionStatusReader } from '@/core/signingEngine/session/warmSigning/statusReader';
import type {
  ThresholdWarmSessionStatusReader,
  WarmSessionCapabilityReader,
  WarmSessionProvisioner,
} from '@/core/signingEngine/session/warmSigning/types';
import { claimWarmSessionPrfFirst } from '@/core/signingEngine/session/warmSigning/runtime';
import type {
  WarmSessionPersistedRestorer,
  WarmSessionStatusResult,
} from '@/core/signingEngine/touchConfirm';
import { buildNearTransactionSigningLane } from '@/core/signingEngine/session/signingSession/lanes';
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
} from '@/core/signingEngine/session/signingSession/trace';
import {
  SigningOperationIntent,
  SigningSessionPlanKind,
  SigningSessionIds,
  type SigningLaneContext,
} from '@/core/signingEngine/session/signingSession/types';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/session/signingSession/ecdsaChainTarget';

export type NearThresholdSigningAuthPlan = {
  sessionId: string;
  lane: SigningLaneContext;
  signingAuthPlan: SigningAuthPlan;
  touchConfirmAuthPayload: { signingAuthPlan: SigningAuthPlan };
  warmSessionReady: boolean;
};
export type NearThresholdSigningAuthContext = {
  sessionId: string;
  accountId: string;
  lane: SigningLaneContext;
  coordinatorInput: ResolveSigningSessionAuthPlanFromReadinessInput;
};
export { THRESHOLD_SESSION_AUTH_UNAVAILABLE_ERROR };

type NearSigningSessionCoordinatorPort =
  Parameters<typeof createWarmSessionCapabilityReader>[0] extends infer FactoryDeps
    ? NonNullable<FactoryDeps> extends { touchConfirm?: infer TouchConfirm }
      ? TouchConfirm & Partial<WarmSessionPersistedRestorer>
      : never
    : never;

async function restorePasskeySessionBeforeClaim(args: {
  touchConfirm: NearSigningSessionCoordinatorPort;
  claim: {
    walletId?: string;
    authMethod?: 'passkey' | 'email_otp';
    curve?: 'ed25519' | 'ecdsa';
    chain?: 'near';
    chainTarget?: ThresholdEcdsaChainTarget;
    walletSigningSessionId?: string;
    thresholdSessionId: string;
  };
}): Promise<void> {
  if (args.claim.authMethod !== 'passkey') return;
  if (typeof args.touchConfirm?.restorePersistedSessionForSigning !== 'function') return;
  const walletId = String(args.claim.walletId || '').trim();
  const walletSigningSessionId = String(args.claim.walletSigningSessionId || '').trim();
  const thresholdSessionId = String(args.claim.thresholdSessionId || '').trim();
  if (!walletId || !walletSigningSessionId || !thresholdSessionId) return;
  const curve = args.claim.curve;
  const chain = args.claim.chain;
  if (curve === 'ed25519') {
    if (chain !== 'near') return;
    await args.touchConfirm.restorePersistedSessionForSigning({
      walletId,
      authMethod: 'passkey',
      curve: 'ed25519',
      chain: 'near',
      walletSigningSessionId,
      thresholdSessionId,
      reason: 'transaction',
    });
    return;
  }
  if (curve !== 'ecdsa' || !args.claim.chainTarget) {
    return;
  }
  await args.touchConfirm.restorePersistedSessionForSigning({
    walletId,
    authMethod: 'passkey',
    curve: 'ecdsa',
    chainTarget: args.claim.chainTarget,
    walletSigningSessionId,
    thresholdSessionId,
    reason: 'transaction',
  });
}

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
    claimPrfFirstByThresholdSessionId: async (claimArgs) => {
      let consume = claimArgs.consume;
      if (typeof consume !== 'boolean') {
        if (claimArgs.authMethod !== 'passkey') {
          consume = true;
        } else {
          const statusBeforeRestore = await touchConfirm
            ?.getWarmSessionStatus?.({ sessionId: claimArgs.thresholdSessionId })
            .catch(() => null);
          // Restoring from a durable seal removes the server seal and spends one
          // trusted use. In that case the immediate PRF claim must only read the
          // freshly rehydrated material; hot in-memory claims still spend locally.
          consume = statusBeforeRestore?.ok === true;
        }
      }
      return claimWarmSessionPrfFirst({
        touchConfirm,
        thresholdSessionId: claimArgs.thresholdSessionId,
        errorContext: claimArgs.errorContext,
        uses: claimArgs.uses,
        consume,
        restoreBeforeClaim: () =>
          restorePasskeySessionBeforeClaim({ touchConfirm, claim: claimArgs }),
      });
    },
  };
}

export async function resolveNearThresholdSigningAuthContext(args: {
  warmSessionReader: WarmSessionCapabilityReader & ThresholdWarmSessionStatusReader;
  nearAccountId: string;
  operationLabel: string;
  usesNeeded?: number;
}): Promise<NearThresholdSigningAuthContext> {
  const accountId = String(args.nearAccountId || '').trim();
  const warmSession = await args.warmSessionReader.getWarmSession(accountId);
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
    warmSessionReader: args.warmSessionReader,
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
  const coordinatorInput = {
    lane,
    readiness: readiness.readiness,
    expiresAtMs: readiness.expiresAtMs,
    remainingUses: readiness.remainingUses,
    usesNeeded: args.usesNeeded,
    forceFreshAuth:
      isEmailOtpSession &&
      capability.state === 'ready' &&
      capability.prfClaim?.state !== 'warm' &&
      !String(record?.xClientBaseB64u || '').trim(),
  };
  return {
    sessionId,
    accountId,
    lane,
    coordinatorInput,
  };
}

export function buildNearThresholdSigningAuthPlan(args: {
  context: NearThresholdSigningAuthContext;
  resolvedSigningSession: ResolveSigningSessionAuthPlanFromReadinessResult;
}): NearThresholdSigningAuthPlan {
  const { sessionId, accountId, lane } = args.context;
  const resolvedSigningSession = args.resolvedSigningSession;
  const plan = resolvedSigningSession.signingSessionPlan;

  if (plan.kind === SigningSessionPlanKind.WarmSession) {
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
  warmSessionReader: WarmSessionCapabilityReader & ThresholdWarmSessionStatusReader;
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
  const buildReadiness = (input: {
    status: SigningSessionReadiness['status'];
    expiresAtMs?: number;
    remainingUses?: number;
  }) => {
    return {
      readiness: {
        status: input.status,
        thresholdSessionId,
      },
      expiresAtMs: input.expiresAtMs ?? resolveExpiresAtMs(),
      remainingUses: input.remainingUses ?? resolveRemainingUses(),
    };
  };

  if (args.capability.state === 'auth_missing') {
    // A persisted Ed25519 lane with missing volatile auth is still enough to
    // choose the step-up method. Treat it as reauthable instead of terminal so
    // exhausted passkey sessions can prompt TouchID and mint a fresh session.
    return buildReadiness({ status: 'missing_session', remainingUses: 0 });
  }
  if (args.capability.state === 'prf_unavailable') {
    if (isEmailOtpSession) {
      return buildReadiness({ status: 'missing_session', remainingUses: 0 });
    }
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
      return buildReadiness({ status: 'exhausted', remainingUses });
    }
    return buildReadiness({ status: 'ready', remainingUses });
  }

  const status = await args.warmSessionReader.getEd25519SigningSessionStatusForSession({
    nearAccountId: args.nearAccountId,
    thresholdSessionId: args.sessionId,
  });
  if (status?.status === 'unavailable') {
    if (isEmailOtpSession) {
      return buildReadiness({ status: 'missing_session', remainingUses: 0 });
    }
    throw new Error(formatThresholdSigningSessionAvailabilityError(status.statusCode));
  }
  if (status?.status === 'expired') {
    return buildReadiness({ status: 'expired', remainingUses: 0 });
  }
  if (status?.status === 'exhausted') {
    return buildReadiness({ status: 'exhausted', remainingUses: 0 });
  }
  if (status?.status === 'active') {
    if (isEmailOtpSession) {
      return buildReadiness({ status: 'missing_session', remainingUses: 0 });
    }
    return buildReadiness({
      status: 'missing_session',
      remainingUses: Math.floor(Number(status.remainingUses) || 0),
    });
  }
  if (args.capability.state === 'missing') {
    if (isEmailOtpSession) {
      return buildReadiness({ status: 'missing_session', remainingUses: 0 });
    }
    throw new Error(THRESHOLD_SESSION_MISSING_ERROR);
  }
  if (isEmailOtpSession) {
    return buildReadiness({ status: 'missing_session', remainingUses: 0 });
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
  return buildReadiness({ status: 'missing_session', remainingUses: 0 });
}

function normalizeUsesNeeded(usesNeededRaw: unknown): number {
  const usesNeeded = Math.floor(Number(usesNeededRaw) || 0);
  return usesNeeded > 0 ? usesNeeded : 1;
}
