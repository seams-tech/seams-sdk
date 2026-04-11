import type { SigningAuthMode } from '@/core/signingEngine/touchConfirm/shared/confirmTypes';
import {
  THRESHOLD_SESSION_AUTH_UNAVAILABLE_ERROR,
  type WarmSessionEd25519SigningAuthPlan,
  type WarmSessionManager,
} from '@/core/signingEngine/session/WarmSessionManager';

export type NearThresholdSigningAuthPlan = {
  sessionId: string;
  signingAuthMode: SigningAuthMode;
  warmSessionReady: boolean;
};
export { THRESHOLD_SESSION_AUTH_UNAVAILABLE_ERROR };

export async function resolveNearThresholdSigningAuthPlan(args: {
  warmSessionManager: WarmSessionManager;
  nearAccountId: string;
  operationLabel: string;
  usesNeeded?: number;
}): Promise<NearThresholdSigningAuthPlan> {
  const plan: WarmSessionEd25519SigningAuthPlan =
    await args.warmSessionManager.resolveEd25519SigningAuthPlan({
      nearAccountId: args.nearAccountId,
      usesNeeded: args.usesNeeded,
      operationLabel: args.operationLabel,
    });
  return plan;
}
