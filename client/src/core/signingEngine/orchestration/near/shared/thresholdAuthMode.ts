import type { SigningAuthMode } from '@/core/signingEngine/touchConfirm/shared/confirmTypes';
import type { ThresholdPrfFirstCachePeekPort } from '@/core/signingEngine/touchConfirm';
import {
  peekThresholdSigningSessionReadiness,
  requireThresholdSigningSessionId,
} from '@/core/signingEngine/orchestration/shared/thresholdSigningSessionPlanner';

export type NearThresholdSigningAuthPlan = {
  sessionId: string;
  signingAuthMode: SigningAuthMode;
  warmSessionReady: boolean;
};

export async function resolveNearThresholdSigningAuthPlan(args: {
  touchConfirm: ThresholdPrfFirstCachePeekPort;
  sessionId: unknown;
  nearAccountId: string;
  operationLabel: string;
  usesNeeded?: number;
}): Promise<NearThresholdSigningAuthPlan> {
  const sessionId = requireThresholdSigningSessionId(args.sessionId);
  const readiness = await peekThresholdSigningSessionReadiness({
    touchConfirm: args.touchConfirm,
    sessionId,
    usesNeeded: args.usesNeeded,
  });

  if (readiness.ok) {
    return {
      sessionId,
      signingAuthMode: 'warmSession',
      warmSessionReady: true,
    };
  }

  if (readiness.code !== 'not_found') {
    throw new Error(readiness.message);
  }

  console.warn(
    `[SigningEngine][near] ${args.operationLabel} warm session cache is unavailable; falling back to WebAuthn`,
    {
      nearAccountId: args.nearAccountId,
      sessionId,
      code: readiness.code,
    },
  );

  return {
    sessionId,
    signingAuthMode: 'webauthn',
    warmSessionReady: false,
  };
}
