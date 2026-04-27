import type { SensitiveOperationPolicy } from '@/core/types/tatchi';
import type {
  BackingMaterialSessionId,
  SigningLaneContext,
  SigningLaneSummary,
  SigningPlanSummary,
  SigningSessionNotReadyReason,
  SigningSessionPlan,
  ThresholdSessionId,
} from './types';
import {
  SigningKeyRefIntentKind,
  SigningSessionPlanKind,
  summarizeSigningLane,
  summarizeSigningSessionPlan,
} from './types';

type ReauthableNotReadyReason = Extract<
  SigningSessionNotReadyReason,
  'missing_session' | 'expired' | 'exhausted'
>;

type TerminalNotReadyReason = Extract<
  SigningSessionNotReadyReason,
  'auth_unavailable' | 'status_unavailable'
>;

export type SigningSessionReadiness =
  | {
      status: 'ready';
      thresholdSessionId?: ThresholdSessionId;
      backingMaterialSessionId?: BackingMaterialSessionId;
    }
  | {
      status: ReauthableNotReadyReason | TerminalNotReadyReason;
      thresholdSessionId?: ThresholdSessionId;
      backingMaterialSessionId?: BackingMaterialSessionId;
    };

export type SigningSessionPlannerInput = {
  lane: SigningLaneContext;
  readiness: SigningSessionReadiness;
  forceFreshAuth?: boolean;
  sensitiveOperationPolicy?: SensitiveOperationPolicy | null;
};

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
  const { lane, readiness } = input;
  const policyBlock = getPolicyBlock(input);
  if (policyBlock) {
    return {
      kind: SigningSessionPlanKind.NotReady,
      lane,
      reason: policyBlock,
    };
  }

  const thresholdSessionId = readiness.thresholdSessionId || lane.thresholdSessionId;
  const forceFreshAuth =
    input.forceFreshAuth ||
    input.sensitiveOperationPolicy === 'require_fresh_same_method' ||
    lane.retention === 'single_use';

  if (readiness.status === 'ready' && !forceFreshAuth) {
    if (!thresholdSessionId) {
      return {
        kind: SigningSessionPlanKind.NotReady,
        lane,
        reason: 'missing_session',
      };
    }

    return {
      kind: SigningSessionPlanKind.WarmSession,
      lane,
      keyRef: {
        kind: SigningKeyRefIntentKind.Cached,
        thresholdSessionId,
      },
    };
  }

  if (readiness.status === 'auth_unavailable' || readiness.status === 'status_unavailable') {
    return {
      kind: SigningSessionPlanKind.NotReady,
      lane,
      reason: readiness.status,
    };
  }

  if (lane.authMethod === 'email_otp') {
    return {
      kind: SigningSessionPlanKind.EmailOtpReauth,
      lane,
      challenge: {
        chainFamily: lane.chainFamily,
        lane,
      },
    };
  }

  return {
    kind: SigningSessionPlanKind.PasskeyReauth,
    lane,
    reconnect: {
      lane,
      thresholdSessionId,
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
  if (input.lane.authMethod !== 'email_otp') {
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
