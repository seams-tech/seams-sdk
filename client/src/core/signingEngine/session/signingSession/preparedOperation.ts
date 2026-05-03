import type { SensitiveOperationPolicy } from '@shared/utils/signerDomain';
import type { SigningSessionPreparedBudgetIdentity } from './budget';
import type {
  SigningPlannerDecisionTraceEvent,
  SigningSessionReadiness,
} from './planner';
import type {
  SigningAuthMethod,
  SigningChainFamily,
  SigningCurve,
  SigningLaneContext,
  SigningOperationContext,
  SigningSessionPlan,
} from './types';

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
  signingRootId?: string;
};

export type ThresholdSigningOperationCoordinator = {
  resolveAuthPlanFromReadiness(
    input: {
      lane: SigningLaneContext;
      readiness: SigningSessionReadiness;
      expiresAtMs?: number;
      remainingUses?: number;
      usesNeeded?: number;
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
    nearAccountId: string;
    lane: SigningLaneContext;
    operationUsesNeeded?: number;
  }): Promise<SigningSessionPreparedBudgetIdentity>;
};

export type PreparedThresholdSigningOperation<
  TLane extends SigningLaneContext = SigningLaneContext,
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
  snapshotGeneration: number;
  metadata: TMetadata;
};

export type ThresholdSigningLifecycleAdapter<
  TLane extends SigningLaneContext = SigningLaneContext,
  TMetadata extends object = Record<string, never>,
> = {
  prepare(input: {
    intent: ThresholdSigningIntent;
    operation?: SigningOperationContext;
  }): Promise<{
    lane: TLane;
    readiness: ThresholdSigningReadinessInput;
    snapshotGeneration?: number;
    forceFreshAuth?: boolean;
    metadata?: TMetadata;
  }>;
};

export type ThresholdCurveAdapter<TPrepared, TPayload, TResult> = {
  execute(prepared: TPrepared, payload: TPayload): Promise<TResult>;
};

export type ThresholdSigningFinalizationAdapter<TPrepared, TResult> = {
  recordSuccess?: (prepared: TPrepared, result: TResult) => Promise<void> | void;
  recordZeroSpend?: (prepared: TPrepared, result: TResult) => Promise<void> | void;
  cleanup?: (prepared: TPrepared, result: TResult) => Promise<void> | void;
};

export async function prepareThresholdSigningOperation<
  TLane extends SigningLaneContext,
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
    authMethod: lifecycle.lane.authMethod,
    signingSessionPlan: resolved.signingSessionPlan,
    readiness: resolved.readiness,
    expiresAtMs: resolved.expiresAtMs,
    remainingUses: resolved.remainingUses,
    snapshotGeneration: Math.max(0, Math.floor(Number(lifecycle.snapshotGeneration) || 0)),
    metadata: (lifecycle.metadata || {}) as TMetadata,
  };
}

export async function executePreparedThresholdSigning<TPrepared, TPayload, TResult>(
  prepared: TPrepared,
  payload: TPayload,
  adapter: ThresholdCurveAdapter<TPrepared, TPayload, TResult>,
): Promise<TResult> {
  return await adapter.execute(prepared, payload);
}

export async function finalizePreparedThresholdSigning<TPrepared, TResult>(
  prepared: TPrepared,
  result: TResult,
  finalization: ThresholdSigningFinalizationAdapter<TPrepared, TResult>,
): Promise<void> {
  if (
    typeof finalization.recordSuccess !== 'function' &&
    typeof finalization.recordZeroSpend !== 'function' &&
    typeof finalization.cleanup !== 'function'
  ) {
    throw new Error('[SigningSession] prepared signing finalization requires a real finalizer');
  }
  if (typeof finalization.recordSuccess === 'function') {
    await finalization.recordSuccess(prepared, result);
  } else {
    await finalization.recordZeroSpend?.(prepared, result);
  }
  await finalization.cleanup?.(prepared, result);
}
