import type { SensitiveOperationPolicy } from '@/core/types/seams';
import type {
  SelectedSigningSessionPlanningLane,
  SelectedEcdsaSigningSessionPlanningLane,
  SelectedEd25519SigningSessionPlanningLane,
  SigningLaneSummary,
  SigningPlanSummary,
  SigningSessionNotReadyReason,
  SigningSessionPlan,
  ThresholdEd25519SessionId,
} from '../operationState/types';
import {
  SigningKeyRefIntentKind,
  SigningSessionPlanKind,
  summarizeSigningLane,
  summarizeSigningSessionPlan,
} from '../operationState/types';
import { signingLaneAuthMethod } from '../identity/signingLaneAuthBinding';
import { mpcMaterialActivationRefsEqual } from '@shared/utils/domainIds';

type ReauthableNotReadyReason = Extract<
  SigningSessionNotReadyReason,
  'missing_session' | 'expired' | 'exhausted'
>;

type TerminalNotReadyReason = Extract<
  SigningSessionNotReadyReason,
  'auth_unavailable' | 'status_unavailable' | 'status_unknown'
>;

type SigningSessionReadinessState<TIdentity extends object> =
  | ({
      status: 'ready';
      remainingUses: number;
      expiresAtMs: number;
    } & TIdentity)
  | ({
      status: 'exhausted';
      remainingUses: number;
      expiresAtMs: number;
    } & TIdentity)
  | ({
      status: 'expired';
      expiresAtMs: number;
      remainingUses?: never;
    } & TIdentity)
  | ({
      status: Exclude<ReauthableNotReadyReason, 'expired' | 'exhausted'> | TerminalNotReadyReason;
      remainingUses?: never;
      expiresAtMs?: never;
    } & TIdentity);

export type Ed25519SigningSessionReadiness = SigningSessionReadinessState<{
  curve: 'ed25519';
  thresholdSessionId: ThresholdEd25519SessionId;
  materialActivation?: never;
  authorization?: never;
}>;

export type EcdsaSigningSessionReadiness = SigningSessionReadinessState<{
  curve: 'ecdsa';
  thresholdSessionId?: never;
  materialActivation: SelectedEcdsaSigningSessionPlanningLane['materialActivation'];
  authorization: SelectedEcdsaSigningSessionPlanningLane['authorization'];
}>;

export type SigningSessionReadiness = Ed25519SigningSessionReadiness | EcdsaSigningSessionReadiness;

type SigningSessionPlannerOptions = {
  forceFreshAuth?: boolean;
  sensitiveOperationPolicy?: SensitiveOperationPolicy | null;
};

export type SigningSessionPlannerInput =
  | (SigningSessionPlannerOptions & {
      lane: SelectedEd25519SigningSessionPlanningLane;
      readiness: Ed25519SigningSessionReadiness;
    })
  | (SigningSessionPlannerOptions & {
      lane: SelectedEcdsaSigningSessionPlanningLane;
      readiness: EcdsaSigningSessionReadiness;
    });

export type SigningPlannerDecisionTraceEvent = {
  event: 'signing_planner_decision';
  readinessStatus: SigningSessionReadiness['status'];
  forceFreshAuth: boolean;
  sensitiveOperationPolicy?: SensitiveOperationPolicy;
  plan: SigningPlanSummary;
  lane: SigningLaneSummary;
  reason?: SigningSessionNotReadyReason;
};

export function planSigningSession(input: SigningSessionPlannerInput): SigningSessionPlan {
  const lane = input.lane;
  const readiness = input.readiness;
  if (lane.curve !== readiness.curve) {
    throw new Error('[SigningSession] planner lane and readiness curves do not match');
  }
  if (lane.curve === 'ecdsa' && readiness.curve === 'ecdsa') {
    const laneAuthorization = lane.authorization;
    const readinessAuthorization = readiness.authorization;
    const laneSession = laneAuthorization.session;
    const readinessSession = readinessAuthorization.session;
    if (
      !mpcMaterialActivationRefsEqual(lane.materialActivation, readiness.materialActivation) ||
      laneAuthorization.selectedAuthority.authorityId !==
        readinessAuthorization.selectedAuthority.authorityId ||
      laneAuthorization.selectedAuthMethod.kind !==
        readinessAuthorization.selectedAuthMethod.kind ||
      laneAuthorization.selectedAuthMethod.walletAuthMethodId !==
        readinessAuthorization.selectedAuthMethod.walletAuthMethodId ||
      laneSession.walletId !== readinessSession.walletId ||
      laneSession.authorityId !== readinessSession.authorityId ||
      laneSession.authMethodId !== readinessSession.authMethodId ||
      laneSession.authorizationId !== readinessSession.authorizationId ||
      laneSession.quotaId !== readinessSession.quotaId ||
      laneSession.authorityDigestB64u !== readinessSession.authorityDigestB64u ||
      laneSession.authorityRevocationEpoch !== readinessSession.authorityRevocationEpoch ||
      laneAuthorization.operationCredential.walletSessionId !==
        readinessAuthorization.operationCredential.walletSessionId ||
      laneAuthorization.operationCredential.token !==
        readinessAuthorization.operationCredential.token
    ) {
      throw new Error('[SigningSession] planner ECDSA readiness authority does not match its lane');
    }
  }
  const policyBlock = getPolicyBlock(input);
  if (policyBlock) {
    return {
      kind: SigningSessionPlanKind.NotReady,
      lane,
      reason: policyBlock,
    };
  }

  const forceFreshAuth =
    input.forceFreshAuth ||
    input.sensitiveOperationPolicy === 'require_fresh_same_method' ||
    lane.retention === 'single_use';

  if (readiness.status === 'ready' && !forceFreshAuth) {
    if (lane.curve === 'ed25519' && readiness.curve === 'ed25519') {
      return {
        kind: SigningSessionPlanKind.WarmSession,
        lane,
        keyRef: {
          kind: SigningKeyRefIntentKind.Cached,
          curve: 'ed25519',
          thresholdSessionId: readiness.thresholdSessionId,
        },
      };
    }
    if (lane.curve !== 'ecdsa' || readiness.curve !== 'ecdsa') {
      throw new Error('[SigningSession] planner lane and readiness curves do not match');
    }
    return {
      kind: SigningSessionPlanKind.WarmSession,
      lane,
      keyRef: {
        kind: SigningKeyRefIntentKind.Cached,
        curve: 'ecdsa',
        materialActivation: readiness.materialActivation,
        authorization: readiness.authorization,
      },
    };
  }

  if (
    readiness.status === 'auth_unavailable' ||
    readiness.status === 'status_unavailable' ||
    readiness.status === 'status_unknown'
  ) {
    return {
      kind: SigningSessionPlanKind.NotReady,
      lane,
      reason: readiness.status,
    };
  }

  if (signingLaneAuthMethod(lane.auth) === 'email_otp') {
    return {
      kind: SigningSessionPlanKind.EmailOtpReauth,
      lane,
      challenge: {
        chainFamily: lane.chainFamily,
        lane,
      },
    };
  }

  if (lane.curve === 'ed25519' && readiness.curve === 'ed25519') {
    return {
      kind: SigningSessionPlanKind.PasskeyReauth,
      lane,
      reconnect: {
        lane,
        curve: 'ed25519',
        thresholdSessionId: readiness.thresholdSessionId,
      },
    };
  }
  if (lane.curve !== 'ecdsa' || readiness.curve !== 'ecdsa') {
    throw new Error('[SigningSession] planner lane and readiness curves do not match');
  }
  return {
    kind: SigningSessionPlanKind.PasskeyReauth,
    lane,
    reconnect: {
      lane,
      curve: 'ecdsa',
      materialActivation: readiness.materialActivation,
      authorization: readiness.authorization,
    },
  };
}

export function createSigningPlannerDecisionTraceEvent(
  input: SigningSessionPlannerInput,
  plan: SigningSessionPlan,
): SigningPlannerDecisionTraceEvent {
  return {
    event: 'signing_planner_decision',
    readinessStatus: input.readiness.status,
    forceFreshAuth: Boolean(input.forceFreshAuth),
    ...(input.sensitiveOperationPolicy
      ? { sensitiveOperationPolicy: input.sensitiveOperationPolicy }
      : {}),
    plan: summarizeSigningSessionPlan(plan),
    lane: summarizeSigningLane(input.lane),
    ...(plan.kind === SigningSessionPlanKind.NotReady ? { reason: plan.reason } : {}),
  };
}

function getPolicyBlock(
  input: SigningSessionPlannerInput,
): Extract<SigningSessionNotReadyReason, 'policy_blocked'> | null {
  if (signingLaneAuthMethod(input.lane.auth) !== 'email_otp') {
    return null;
  }

  if (
    input.sensitiveOperationPolicy === 'deny_email_otp' ||
    input.sensitiveOperationPolicy === 'require_passkey'
  ) {
    return 'policy_blocked';
  }

  return null;
}
