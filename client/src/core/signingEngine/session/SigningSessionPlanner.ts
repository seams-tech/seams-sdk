import type { SensitiveOperationPolicy } from '@/core/types/tatchi';
import type {
  BackingMaterialSessionId,
  SigningLaneContext,
  SigningLaneSummary,
  SigningPlanSummary,
  SigningSessionNotReadyReason,
  SigningSessionPlan,
  ThresholdSessionId,
} from './signingSessionTypes';
import {
  summarizeSigningLane,
  summarizeSigningSessionPlan,
} from './signingSessionTypes';

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

export type SigningSessionPlanner = {
  plan(input: SigningSessionPlannerInput): SigningSessionPlan;
};

export function createSigningSessionPlanner(args: {
  onTrace?: (event: SigningPlannerDecisionTraceEvent) => void;
} = {}): SigningSessionPlanner {
  return {
    plan(input) {
      const plan = planSigningSession(input);
      args.onTrace?.(createSigningPlannerDecisionTraceEvent(input, plan));
      return plan;
    },
  };
}

export function planSigningSession(input: SigningSessionPlannerInput): SigningSessionPlan {
  const { lane, readiness } = input;
  const policyBlock = getPolicyBlock(input);
  if (policyBlock) {
    return {
      kind: 'not_ready',
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
        kind: 'not_ready',
        lane,
        reason: 'missing_session',
      };
    }

    return {
      kind: 'warm_session',
      lane,
      keyRef: {
        kind: 'cached',
        thresholdSessionId,
      },
    };
  }

  if (readiness.status === 'auth_unavailable' || readiness.status === 'status_unavailable') {
    return {
      kind: 'not_ready',
      lane,
      reason: readiness.status,
    };
  }

  if (lane.authMethod === 'email_otp') {
    return {
      kind: 'email_otp_reauth',
      lane,
      challenge: {
        chainFamily: lane.chainFamily,
        lane,
      },
    };
  }

  return {
    kind: 'passkey_reauth',
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
    ...(plan.kind === 'not_ready' ? { reason: plan.reason } : {}),
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
