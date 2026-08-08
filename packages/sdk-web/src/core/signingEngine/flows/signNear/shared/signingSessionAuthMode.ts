import type { SigningAuthPlan } from '@/core/signingEngine/stepUpConfirmation/types';
import { signingAuthPlanFromSigningSessionPlan } from '../../shared/signingConfirmation';
import {
  buildNearTransactionSigningLane,
  type NearTransactionSigningLane,
} from '@/core/signingEngine/session/operationState/lanes';
import type { ResolveSigningSessionAuthPlanFromReadinessResult } from '@/core/signingEngine/session/SigningSessionCoordinator';
import type { Ed25519SigningSessionReadiness } from '@/core/signingEngine/session/planning/planner';
import {
  SigningOperationIntent,
  SigningSessionIds,
  SigningSessionPlanKind,
} from '@/core/signingEngine/session/operationState/types';
import { emitSigningLaneResolutionTrace } from '@/core/signingEngine/session/operationState/trace';
import type { NearCommandSubject } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { SelectedEd25519Lane } from '@/core/signingEngine/session/identity/laneIdentity';
import type { NearEd25519YaoSigningPreparation } from '@/core/signingEngine/session/material/nearEd25519YaoSigningPreparation';
import type { ThresholdEd25519SessionId } from '@shared/utils/domainIds';

export const SIGNING_SESSION_AUTH_UNAVAILABLE_ERROR =
  'Threshold signing session authorization is unavailable';

export type NearSigningSessionAuthPlan = {
  thresholdSessionId: ThresholdEd25519SessionId;
  lane: NearTransactionSigningLane;
  signingAuthPlan: SigningAuthPlan;
  confirmationAuthPayload: { signingAuthPlan: SigningAuthPlan };
  warmSessionReady: boolean;
};

export type NearSigningSessionAuthContext = {
  thresholdSessionId: ThresholdEd25519SessionId;
  walletId: string;
  nearAccountId: string;
  lane: NearTransactionSigningLane;
  coordinatorInput: {
    lane: NearTransactionSigningLane;
    readiness: Ed25519SigningSessionReadiness;
    expiresAtMs: number;
    remainingUses: number;
    usesNeeded: number;
    forceFreshAuth: boolean;
  };
};

function requireSelectedLaneSubject(args: {
  commandSubject: NearCommandSubject;
  selectedLane: SelectedEd25519Lane;
}): {
  walletId: ReturnType<typeof toWalletId>;
  nearAccountId: string;
} {
  const signer = args.selectedLane.identity.signer;
  const walletId = toWalletId(args.commandSubject.walletSession.walletId);
  const nearAccountId = String(args.commandSubject.nearAccount.accountId);
  if (
    signer.account.wallet.walletId !== walletId ||
    String(signer.account.nearAccountId) !== nearAccountId
  ) {
    throw new Error('[SigningEngine][near] selected Ed25519 lane does not match command subject');
  }
  return { walletId, nearAccountId };
}

function buildPlanningLane(args: {
  selectedLane: SelectedEd25519Lane;
  preparation: NearEd25519YaoSigningPreparation;
}): NearTransactionSigningLane {
  const signer = args.selectedLane.identity.signer;
  const common = {
    walletId: signer.account.wallet.walletId,
    nearAccountId: signer.account.nearAccountId,
    nearEd25519SigningKeyId: signer.nearEd25519SigningKeyId,
    signerSlot: signer.signerSlot,
    walletSessionId: args.selectedLane.walletSessionId,
    quotaId: args.selectedLane.quotaId,
    thresholdSessionId: args.selectedLane.thresholdSessionId,
  };
  switch (args.selectedLane.auth.kind) {
    case 'passkey':
      return buildNearTransactionSigningLane({
        ...common,
        auth: args.selectedLane.auth,
        storageSource: 'login',
      });
    case 'email_otp': {
      const reusable = args.preparation.authorization.kind === 'authorized';
      return buildNearTransactionSigningLane({
        ...common,
        auth: args.selectedLane.auth,
        retention: reusable ? 'session' : 'single_use',
        sessionOrigin: reusable ? 'login' : 'per_operation',
      });
    }
    default:
      args.selectedLane.auth satisfies never;
      throw new Error('[SigningEngine][near] unsupported selected Ed25519 auth binding');
  }
}

function readinessFromPreparation(args: {
  selectedLane: SelectedEd25519Lane;
  preparation: NearEd25519YaoSigningPreparation;
  requiredSignatureUses: number;
}): {
  readiness: Ed25519SigningSessionReadiness;
  expiresAtMs: number;
  remainingUses: number;
  forceFreshAuth: boolean;
} {
  const thresholdSessionId = SigningSessionIds.thresholdEd25519Session(
    args.selectedLane.thresholdSessionId,
  );
  switch (args.preparation.authorization.kind) {
    case 'authorized': {
      const status = args.preparation.authorization.authorization.status;
      const remainingUses = status.remainingUses;
      const expiresAtMs = status.expiresAtMs;
      const statusKind =
        expiresAtMs <= Date.now()
          ? 'expired'
          : remainingUses < args.requiredSignatureUses
            ? 'exhausted'
            : 'ready';
      const readiness: Ed25519SigningSessionReadiness =
        statusKind === 'expired'
          ? {
              status: 'expired',
              curve: 'ed25519',
              thresholdSessionId,
              expiresAtMs,
            }
          : {
              status: statusKind,
              curve: 'ed25519',
              thresholdSessionId,
              remainingUses,
              expiresAtMs,
            };
      return {
        readiness,
        expiresAtMs,
        remainingUses,
        forceFreshAuth: statusKind !== 'ready',
      };
    }
    case 'authorization_required':
      return {
        readiness: {
          status: 'missing_session',
          curve: 'ed25519',
          thresholdSessionId,
        },
        expiresAtMs: 0,
        remainingUses: 0,
        forceFreshAuth: true,
      };
    default:
      args.preparation.authorization satisfies never;
      throw new Error('[SigningEngine][near] unsupported material authorization state');
  }
}

export function resolveNearSigningSessionAuthContext(args: {
  commandSubject: NearCommandSubject;
  selectedLane: SelectedEd25519Lane;
  preparation: NearEd25519YaoSigningPreparation;
  forceFreshAuth: boolean;
  requiredSignatureUses?: number;
}): NearSigningSessionAuthContext {
  const subject = requireSelectedLaneSubject(args);
  const requiredSignatureUses = Math.max(1, Math.floor(Number(args.requiredSignatureUses) || 1));
  const lane = buildPlanningLane(args);
  const resolved = readinessFromPreparation({
    selectedLane: args.selectedLane,
    preparation: args.preparation,
    requiredSignatureUses,
  });
  emitSigningLaneResolutionTrace('near', lane, { reason: 'near_threshold_auth_plan' });
  return {
    thresholdSessionId: SigningSessionIds.thresholdEd25519Session(
      args.selectedLane.thresholdSessionId,
    ),
    walletId: subject.walletId,
    nearAccountId: subject.nearAccountId,
    lane,
    coordinatorInput: {
      lane,
      readiness: resolved.readiness,
      expiresAtMs: resolved.expiresAtMs,
      remainingUses: resolved.remainingUses,
      usesNeeded: requiredSignatureUses,
      forceFreshAuth: args.forceFreshAuth || resolved.forceFreshAuth,
    },
  };
}

export function buildNearSigningSessionAuthPlan(args: {
  context: NearSigningSessionAuthContext;
  resolvedSigningSession: ResolveSigningSessionAuthPlanFromReadinessResult;
}): NearSigningSessionAuthPlan {
  const { thresholdSessionId, lane } = args.context;
  const resolvedSigningSession = args.resolvedSigningSession;
  const plan = resolvedSigningSession.signingSessionPlan;
  if (plan.kind === SigningSessionPlanKind.NotReady) {
    throw new Error(`[SigningEngine][near] signing session is not ready: ${plan.reason}`);
  }
  const signingAuthPlan = signingAuthPlanFromSigningSessionPlan({
    plan,
    accountId: String(lane.identity.signer.account.nearAccountId),
    intent: SigningOperationIntent.TransactionSign,
    curve: 'ed25519',
    expiresAtMs: resolvedSigningSession.expiresAtMs,
    remainingUses: resolvedSigningSession.remainingUses,
  });
  return {
    thresholdSessionId,
    lane,
    signingAuthPlan,
    confirmationAuthPayload: { signingAuthPlan },
    warmSessionReady: plan.kind === SigningSessionPlanKind.WarmSession,
  };
}
