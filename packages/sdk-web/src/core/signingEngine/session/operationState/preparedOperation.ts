import type { SensitiveOperationPolicy, SignerAuthMethod } from '@shared/utils/signerDomain';
import type { WalletSessionStatusIdentity } from '../lifecycle/walletSessionStatus';
import type {
  SigningPlannerDecisionTraceEvent,
  SigningSessionReadiness,
} from '../planning/planner';
import type {
  SigningChainFamily,
  SigningCurve,
  SelectedEd25519SigningSessionPlanningLane,
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
  trustedStatusAuth?: WalletSessionStatusIdentity;
};

export type ThresholdSigningOperationCoordinator = {
  resolveAuthPlanFromReadiness(
    input: {
      lane: SelectedSigningSessionPlanningLane;
      readiness: SigningSessionReadiness;
      expiresAtMs?: number;
      remainingUses?: number;
      usesNeeded?: number;
      trustedStatusAuth?: WalletSessionStatusIdentity;
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
};

export type PreparedThresholdSigningOperation<
  TLane extends SelectedSigningSessionPlanningLane = SelectedSigningSessionPlanningLane,
  TMetadata extends object = Record<string, never>,
> = {
  intent: ThresholdSigningIntent;
  operation?: SigningOperationContext;
  lane: TLane;
  authMethod: SignerAuthMethod;
  signingSessionPlan: SigningSessionPlan;
  readiness: SigningSessionReadiness;
  expiresAtMs: number;
  remainingUses: number;
  trustedStatusAuth?: WalletSessionStatusIdentity;
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
  if (lifecycle.lane.curve !== lifecycle.readiness.readiness.curve) {
    throw new Error('[SigningSession] prepared lane and readiness curves do not match');
  }
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
