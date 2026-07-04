import type { SensitiveOperationPolicy } from '@shared/utils/signerDomain';
import type {
  SigningSessionBudgetStatusAuth,
  SigningSessionPreparedBudgetIdentity,
} from '../budget/budget';
import type {
  SigningPlannerDecisionTraceEvent,
  SigningSessionReadiness,
} from '../planning/planner';
import type {
  SigningAuthMethod,
  SigningChainFamily,
  SigningCurve,
  SelectedSigningSessionPlanningLane,
  SigningOperationContext,
  SigningSessionPlan,
} from './types';
import { signingLaneAuthMethod } from '../identity/signingLaneAuthBinding';

export type ThresholdSigningIntent =
  | {
      kind: 'transaction_sign';
      chain: SigningChainFamily;
      curve: SigningCurve;
      walletId: string;
      reason: string;
    }
  | {
      kind: 'key_export';
      curve: SigningCurve;
      walletId: string;
      reason: string;
      freshAuthRequired: true;
    };

export type ThresholdSigningReadinessInput = {
  readiness: SigningSessionReadiness;
  expiresAtMs?: number;
  remainingUses?: number;
  usesNeeded?: number;
  trustedStatusAuth?: SigningSessionBudgetStatusAuth;
};

export type ThresholdSigningOperationCoordinator = {
  resolveAuthPlanFromReadiness(
    input: {
      lane: SelectedSigningSessionPlanningLane;
      readiness: SigningSessionReadiness;
      expiresAtMs?: number;
      remainingUses?: number;
      usesNeeded?: number;
      trustedStatusAuth?: SigningSessionBudgetStatusAuth;
      forceFreshAuth?: boolean;
      sensitiveOperationPolicy?: SensitiveOperationPolicy | null;
      missingWhenExpiresAtMissing?: boolean;
    },
    onTrace?: (event: SigningPlannerDecisionTraceEvent) => void,
  ): Promise<{
    signingSessionPlan: SigningSessionPlan;
    readiness: SigningSessionReadiness;
    expiresAtMs: number;
    remainingUses: number;
  }>;
  prepareBudgetIdentity(input: {
    lane: SelectedSigningSessionPlanningLane;
    trustedStatusAuth?: SigningSessionBudgetStatusAuth;
    operationUsesNeeded?: number;
  }): Promise<SigningSessionPreparedBudgetIdentity>;
};

export type PreparedThresholdSigningOperation<
  TLane extends SelectedSigningSessionPlanningLane = SelectedSigningSessionPlanningLane,
  TMetadata extends object = Record<string, never>,
> = {
  intent: ThresholdSigningIntent;
  operation?: SigningOperationContext;
  lane: TLane;
  authMethod: SigningAuthMethod;
  signingSessionPlan: SigningSessionPlan;
  readiness: SigningSessionReadiness;
  expiresAtMs: number;
  remainingUses: number;
  trustedStatusAuth?: SigningSessionBudgetStatusAuth;
  availableLanesGeneration: number;
  metadata: TMetadata;
};

export type ThresholdSigningLifecycleAdapter<
  TLane extends SelectedSigningSessionPlanningLane = SelectedSigningSessionPlanningLane,
  TMetadata extends object = Record<string, never>,
> = {
  prepare(input: { intent: ThresholdSigningIntent; operation?: SigningOperationContext }): Promise<{
    lane: TLane;
    readiness: ThresholdSigningReadinessInput;
    availableLanesGeneration?: number;
    forceFreshAuth?: boolean;
    metadata?: TMetadata;
  }>;
};

export async function prepareThresholdSigningOperation<
  TLane extends SelectedSigningSessionPlanningLane,
  TMetadata extends object = Record<string, never>,
>(args: {
  intent: ThresholdSigningIntent;
  lifecycleAdapter: ThresholdSigningLifecycleAdapter<TLane, TMetadata>;
  coordinator: ThresholdSigningOperationCoordinator;
  operation?: SigningOperationContext;
  forceFreshAuth?: boolean;
  sensitiveOperationPolicy?: SensitiveOperationPolicy | null;
  missingWhenExpiresAtMissing?: boolean;
  onPlannerTrace?: (event: SigningPlannerDecisionTraceEvent) => void;
}): Promise<PreparedThresholdSigningOperation<TLane, TMetadata>> {
  const lifecycle = await args.lifecycleAdapter.prepare({
    intent: args.intent,
    ...(args.operation ? { operation: args.operation } : {}),
  });
  const coordinatorInput = {
    lane: lifecycle.lane,
    readiness: lifecycle.readiness.readiness,
    expiresAtMs: lifecycle.readiness.expiresAtMs,
    remainingUses: lifecycle.readiness.remainingUses,
    usesNeeded: lifecycle.readiness.usesNeeded,
    ...(lifecycle.readiness.trustedStatusAuth
      ? { trustedStatusAuth: lifecycle.readiness.trustedStatusAuth }
      : {}),
    forceFreshAuth: args.forceFreshAuth || lifecycle.forceFreshAuth,
    sensitiveOperationPolicy: args.sensitiveOperationPolicy,
    missingWhenExpiresAtMissing: args.missingWhenExpiresAtMissing,
  };
  const resolved = await args.coordinator.resolveAuthPlanFromReadiness(
    coordinatorInput,
    args.onPlannerTrace,
  );

  return {
    intent: args.intent,
    ...(args.operation ? { operation: args.operation } : {}),
    lane: lifecycle.lane,
    authMethod: signingLaneAuthMethod(lifecycle.lane.auth),
    signingSessionPlan: resolved.signingSessionPlan,
    readiness: resolved.readiness,
    expiresAtMs: resolved.expiresAtMs,
    remainingUses: resolved.remainingUses,
    ...(lifecycle.readiness.trustedStatusAuth
      ? { trustedStatusAuth: lifecycle.readiness.trustedStatusAuth }
      : {}),
    availableLanesGeneration: Math.max(0, Math.floor(Number(lifecycle.availableLanesGeneration) || 0)),
    metadata: (lifecycle.metadata || {}) as TMetadata,
  };
}
