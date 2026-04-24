import type {
  BackingMaterialSessionId,
  SigningLaneContext,
  SigningOperationContext,
  ThresholdSessionId,
  WalletSigningSpendPlan,
} from './signingSessionTypes';

export function buildWalletSigningSpendPlan(
  operation: SigningOperationContext,
  lane: SigningLaneContext,
  refs: {
    thresholdSessionId?: ThresholdSessionId;
    backingMaterialSessionId?: BackingMaterialSessionId;
  } = {},
): WalletSigningSpendPlan {
  return {
    operationId: operation.operationId,
    nearAccountId: lane.accountId,
    walletSigningSessionId: lane.walletSigningSessionId,
    lane,
    thresholdSessionIds: uniqueDefined([lane.thresholdSessionId, refs.thresholdSessionId]),
    backingMaterialSessionIds: uniqueDefined([
      lane.backingMaterialSessionId,
      refs.backingMaterialSessionId,
    ]),
    uses: 1,
    reason: operation.intent,
  };
}

function uniqueDefined<TValue extends string>(values: readonly (TValue | undefined)[]): TValue[] {
  const out: TValue[] = [];
  const seen = new Set<string>();

  for (const value of values) {
    if (!value || seen.has(value)) {
      continue;
    }
    seen.add(value);
    out.push(value);
  }

  return out;
}
