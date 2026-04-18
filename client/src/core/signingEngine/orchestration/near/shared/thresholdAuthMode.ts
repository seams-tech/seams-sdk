import type { SigningAuthPlan } from '@/core/signingEngine/touchConfirm/shared/confirmTypes';
import {
  THRESHOLD_SESSION_AUTH_UNAVAILABLE_ERROR,
  type WarmSessionEd25519SigningAuthPlan,
  type WarmSessionManager,
} from '@/core/signingEngine/session/WarmSessionManager';

export type NearThresholdSigningAuthPlan = {
  sessionId: string;
  signingAuthPlan?: SigningAuthPlan;
  touchConfirmAuthPayload: { signingAuthPlan: SigningAuthPlan };
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
  return {
    ...plan,
    ...resolveSigningAuthPlanEnvelope(plan),
  };
}

function resolveSigningAuthPlanEnvelope(
  plan: WarmSessionEd25519SigningAuthPlan,
): Pick<NearThresholdSigningAuthPlan, 'signingAuthPlan' | 'touchConfirmAuthPayload'> {
  if (plan.kind === 'warmSession') {
    const signingAuthPlan: SigningAuthPlan = {
      kind: 'warmSession',
      method: plan.method,
      accountId: plan.accountId,
      intent: 'transaction_sign',
      curve: 'ed25519',
      sessionId: plan.sessionId,
      ...(plan.retention !== undefined ? { retention: plan.retention } : {}),
      expiresAtMs: plan.expiresAtMs,
      remainingUses: plan.remainingUses,
    };
    return {
      signingAuthPlan,
      touchConfirmAuthPayload: { signingAuthPlan },
    };
  }
  if (plan.kind === 'passkeyReauth') {
    const signingAuthPlan: SigningAuthPlan = {
      kind: 'passkeyReauth',
      method: 'passkey',
    };
    return {
      signingAuthPlan,
      touchConfirmAuthPayload: { signingAuthPlan },
    };
  }
  const signingAuthPlan: SigningAuthPlan = {
    kind: 'emailOtpReauth',
    method: 'email_otp',
  };
  return {
    signingAuthPlan,
    touchConfirmAuthPayload: { signingAuthPlan },
  };
}
