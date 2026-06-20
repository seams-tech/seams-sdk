import {
  SigningAuthPlanKind,
  type SigningAuthPlan,
} from '@/core/signingEngine/stepUpConfirmation/types';
import {
  formatThresholdSigningSessionAvailabilityError,
  SIGNING_SESSION_AUTH_UNAVAILABLE_ERROR,
  THRESHOLD_SESSION_MISSING_ERROR,
} from '@/core/signingEngine/session/warmCapabilities/statusReader';
import { createWarmSessionCapabilityReader } from '@/core/signingEngine/session/warmCapabilities/capabilityReader';
import { createWarmSessionStatusReader } from '@/core/signingEngine/session/warmCapabilities/statusReader';
import type {
  ThresholdWarmSessionStatusReader,
  WarmSessionCapabilityReader,
  WarmSessionProvisioner,
} from '@/core/signingEngine/session/warmCapabilities/types';
import { claimPasskeyEcdsaPrfFirst } from '@/core/signingEngine/session/passkey/ecdsaRecovery';
import { claimPasskeyEd25519PrfFirst } from '@/core/signingEngine/session/passkey/ed25519Recovery';
import { claimWarmSessionPrfFirst } from '@/core/signingEngine/session/passkey/prfClaim';
import type {
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
import {
  classifyRouterAbEd25519PersistedSigningRecord,
} from '@/core/signingEngine/session/routerAbSigningWalletSession';

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

type NearSigningSessionCoordinatorPort = Parameters<
  typeof createWarmSessionCapabilityReader
>[0] extends infer FactoryDeps
  ? NonNullable<FactoryDeps> extends { touchConfirm?: infer UiConfirm }
    ? UiConfirm & Partial<WarmSessionPersistedRestorer>
    : never
  : never;

type NearWarmSessionReader = WarmSessionCapabilityReader &
  ThresholdWarmSessionStatusReader &
  Partial<WarmSessionPersistedRestorer>;
type NearEd25519Capability = Awaited<
  ReturnType<WarmSessionCapabilityReader['getWarmSession']>
>['capabilities']['ed25519'];

export function createNearSigningSessionCoordinator(
  touchConfirm: NearSigningSessionCoordinatorPort,
): NearWarmSessionReader & Pick<WarmSessionProvisioner, 'claimPrfFirstByThresholdSessionId'> {
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
    claimPrfFirstByThresholdSessionId: async (claimArgs) => {
      let consume = claimArgs.consume;
      if (typeof consume !== 'boolean') {
        if (claimArgs.kind === 'threshold_only_claim') {
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
      switch (claimArgs.kind) {
        case 'threshold_only_claim':
          return await claimWarmSessionPrfFirst({
            touchConfirm,
            thresholdSessionId: claimArgs.thresholdSessionId,
            errorContext: claimArgs.errorContext,
            uses: claimArgs.uses,
            consume,
          });
        case 'wallet_scoped_ecdsa_claim':
          return await claimPasskeyEcdsaPrfFirst({
            touchConfirm,
            walletId: claimArgs.walletId,
            signingGrantId: claimArgs.signingGrantId,
            thresholdSessionId: claimArgs.thresholdSessionId,
            chainTarget: claimArgs.chainTarget,
            errorContext: claimArgs.errorContext,
            uses: claimArgs.uses,
            consume,
          });
        case 'wallet_scoped_ed25519_claim':
          if (claimArgs.authMethod === 'email_otp') {
            return await claimWarmSessionPrfFirst({
              touchConfirm,
              thresholdSessionId: claimArgs.thresholdSessionId,
              errorContext: claimArgs.errorContext,
              uses: claimArgs.uses,
              consume,
              curve: 'ed25519',
              chain: 'near',
            });
          }
          return await claimPasskeyEd25519PrfFirst({
            touchConfirm,
            walletId: claimArgs.walletId,
            signingGrantId: claimArgs.signingGrantId,
            thresholdSessionId: claimArgs.thresholdSessionId,
            errorContext: claimArgs.errorContext,
            uses: claimArgs.uses,
            consume,
          });
      }
    },
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
    throw new Error(
      '[SigningEngine][near] missing wallet signing session id for transaction auth planning',
    );
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
      (!String(record?.ed25519HssMaterialHandle || '').trim() ||
        !String(record?.ed25519HssMaterialBindingDigest || '').trim() ||
        !String(record?.clientVerifyingShareB64u || '').trim()),
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
      confirmationAuthPayload: { signingAuthPlan },
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
      confirmationAuthPayload: { signingAuthPlan },
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
    confirmationAuthPayload: { signingAuthPlan },
    warmSessionReady: false,
  };
}

async function resolvePlannerReadinessForEd25519(args: {
  warmSessionReader: NearWarmSessionReader;
  nearAccountId: string;
  capability: NearEd25519Capability;
  sessionId: string;
  requiredSignatureUses?: number;
  operationLabel?: string;
}): Promise<{
  readiness: SigningSessionReadiness;
  expiresAtMs: number;
  remainingUses: number;
}> {
  let capability = args.capability;
  let isEmailOtpSession = capability.record?.source === 'email_otp';
  const thresholdSessionId = SigningSessionIds.thresholdEd25519Session(args.sessionId);
  const hasSignableEd25519Record = (state: NearEd25519Capability): boolean =>
    classifyRouterAbEd25519PersistedSigningRecord(state.record).kind === 'signable';
  const resolveExpiresAtMs = (): number =>
    Math.floor(
      Number(capability.prfClaim?.expiresAtMs ?? capability.record?.expiresAtMs) ||
        Date.now(),
    );
  const resolveRemainingUses = (): number =>
    Math.max(
      0,
      Math.floor(
        Number(capability.prfClaim?.remainingUses ?? capability.record?.remainingUses) || 0,
      ),
    );
  const buildReadiness = (input: {
    status: SigningSessionReadiness['status'];
    expiresAtMs?: number;
    remainingUses?: number;
  }): {
    readiness: SigningSessionReadiness;
    expiresAtMs: number;
    remainingUses: number;
  } => {
    const expiresAtMs = input.expiresAtMs ?? resolveExpiresAtMs();
    const remainingUses = input.remainingUses ?? resolveRemainingUses();
    const readiness: SigningSessionReadiness =
      input.status === 'ready' || input.status === 'exhausted'
        ? {
            status: input.status,
            thresholdSessionId,
            remainingUses,
            expiresAtMs,
          }
        : input.status === 'expired'
          ? {
              status: input.status,
              thresholdSessionId,
              expiresAtMs,
            }
          : {
              status: input.status,
              thresholdSessionId,
            };
    return {
      readiness,
      expiresAtMs,
      remainingUses,
    };
  };

  if (capability.state === 'auth_missing') {
    // A persisted Ed25519 lane with missing volatile auth is still enough to
    // choose the step-up method. Treat it as reauthable instead of terminal so
    // exhausted passkey sessions can prompt TouchID and mint a fresh session.
    return buildReadiness({ status: 'missing_session', remainingUses: 0 });
  }
  if (capability.state === 'prf_unavailable') {
    if (isEmailOtpSession) {
      return buildReadiness({ status: 'missing_session', remainingUses: 0 });
    }
    throw new Error(formatThresholdSigningSessionAvailabilityError(capability.prfClaim?.code));
  }
  if (capability.state === 'material_pending' && isEmailOtpSession) {
    return buildReadiness({ status: 'missing_session', remainingUses: 0 });
  }
  if (capability.state === 'material_pending') {
    const remainingUses = resolveRemainingUses();
    if (remainingUses < normalizeRequiredSignatureUses(args.requiredSignatureUses)) {
      return buildReadiness({ status: 'exhausted', remainingUses });
    }
    return buildReadiness({ status: 'ready', remainingUses });
  }
  if (capability.state === 'invalid') {
    throw new Error('[SigningEngine] Ed25519 signing session record is invalid');
  }
  if (capability.state === 'ready') {
    const remainingUses = Math.floor(
      Number(
        capability.prfClaim?.state === 'warm'
          ? capability.prfClaim.remainingUses
          : capability.record?.remainingUses,
      ) || 0,
    );
    if (remainingUses < normalizeRequiredSignatureUses(args.requiredSignatureUses)) {
      return buildReadiness({ status: 'exhausted', remainingUses });
    }
    return buildReadiness({ status: 'ready', remainingUses });
  }

  if (!isEmailOtpSession) {
    await restorePasskeyEd25519SessionBeforePlanning(args).catch((error) => {
      if (!args.operationLabel) return;
      console.warn(
        `[SigningEngine][near] ${args.operationLabel} sealed session restore failed before auth planning`,
        {
          nearAccountId: args.nearAccountId,
          sessionId: args.sessionId,
          error: error instanceof Error ? error.message : String(error || 'unknown error'),
        },
      );
    });
    const restoredCapability = await args.warmSessionReader
      .getEd25519CapabilityByThresholdSessionId(args.sessionId)
      .catch(() => null);
    if (restoredCapability?.record) {
      capability = restoredCapability;
      isEmailOtpSession = capability.record.source === 'email_otp';
    }
  }

  const status = await args.warmSessionReader.getEd25519SigningSessionStatusForSession({
    nearAccountId: args.nearAccountId,
    thresholdSessionId: args.sessionId,
  });
  if (hasSignableEd25519Record(capability)) {
    const remainingUses = resolveRemainingUses();
    if (remainingUses < normalizeRequiredSignatureUses(args.requiredSignatureUses)) {
      return buildReadiness({ status: 'exhausted', remainingUses });
    }
    return buildReadiness({ status: 'ready', remainingUses });
  }
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
    const remainingUses = Math.floor(Number(status.remainingUses) || 0);
    if (remainingUses < normalizeRequiredSignatureUses(args.requiredSignatureUses)) {
      return buildReadiness({ status: 'exhausted', remainingUses });
    }
    return buildReadiness({
      status: 'ready',
      remainingUses,
      expiresAtMs: Math.floor(Number(status.expiresAtMs) || resolveExpiresAtMs()),
    });
  }
  if (capability.state === 'missing') {
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

async function restorePasskeyEd25519SessionBeforePlanning(args: {
  warmSessionReader: NearWarmSessionReader;
  nearAccountId: string;
  capability: Awaited<
    ReturnType<WarmSessionCapabilityReader['getWarmSession']>
  >['capabilities']['ed25519'];
  sessionId: string;
}): Promise<void> {
  if (args.capability.prfClaim?.state === 'warm') return;
  const record = args.capability.record;
  if (!record || record.source === 'email_otp') return;
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
