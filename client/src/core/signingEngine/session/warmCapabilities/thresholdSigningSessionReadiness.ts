import {
  formatThresholdSigningSessionAvailabilityError,
  formatThresholdSigningSessionStatusError,
  requireThresholdSigningSessionId,
  THRESHOLD_SESSION_EXHAUSTED_ERROR,
  THRESHOLD_SESSION_MISSING_ERROR,
} from '@/core/signingEngine/session/warmCapabilities/statusReader';
import type { ThresholdWarmSessionStatusReader } from '@/core/signingEngine/session/warmCapabilities/types';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  WarmSessionStatusResult,
  WarmSessionStatusReader,
} from '@/core/signingEngine/uiConfirm/types';
import { normalizeBoundedPositiveInteger } from '@shared/utils/normalize';
export { THRESHOLD_SESSION_EXHAUSTED_ERROR, THRESHOLD_SESSION_MISSING_ERROR, requireThresholdSigningSessionId };

function toSessionId(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function toExhaustedWarmSessionStatusResult(): Extract<WarmSessionStatusResult, { ok: false }> {
  return {
    ok: false,
    code: 'exhausted',
    message: THRESHOLD_SESSION_EXHAUSTED_ERROR,
  };
}

function normalizeUsesNeeded(usesNeeded?: number): number {
  return normalizeBoundedPositiveInteger(usesNeeded, {
    fallback: 1,
    min: 1,
  });
}

export async function readThresholdSigningSessionReadiness(args: {
  touchConfirm: WarmSessionStatusReader;
  sessionId: string;
  usesNeeded?: number;
}): Promise<WarmSessionStatusResult> {
  const status = await args.touchConfirm.getWarmSessionStatus({
    sessionId: args.sessionId,
  });
  if (!status.ok) {
    if (
      status.code !== 'not_found' &&
      status.code !== 'expired' &&
      status.code !== 'exhausted'
    ) {
      return {
        ok: false,
        code: 'status_unavailable',
        message: formatThresholdSigningSessionAvailabilityError(status.code),
      };
    }
    return {
      ok: false,
      code: status.code,
      message: formatThresholdSigningSessionStatusError(status.code),
    };
  }

  if (status.remainingUses < normalizeUsesNeeded(args.usesNeeded)) {
    return toExhaustedWarmSessionStatusResult();
  }
  return status;
}

export async function isThresholdSigningSessionReady(args: {
  touchConfirm: WarmSessionStatusReader;
  sessionId: string;
  usesNeeded?: number;
}): Promise<boolean> {
  const sessionId = toSessionId(args.sessionId);
  if (!sessionId) return false;
  const status = await readThresholdSigningSessionReadiness({
    touchConfirm: args.touchConfirm,
    sessionId,
    usesNeeded: args.usesNeeded,
  });
  return status.ok;
}

export async function assertThresholdSigningSessionReady(args: {
  signingSessionCoordinator: Pick<ThresholdWarmSessionStatusReader, 'assertEcdsaSigningSessionReady'>;
  nearAccountId: string;
  chainTarget: ThresholdEcdsaChainTarget;
  sessionId: unknown;
  usesNeeded?: number;
}): Promise<Extract<WarmSessionStatusResult, { ok: true }>> {
  const thresholdSessionId = requireThresholdSigningSessionId(args.sessionId);
  return await args.signingSessionCoordinator.assertEcdsaSigningSessionReady({
    nearAccountId: args.nearAccountId,
    chainTarget: args.chainTarget,
    thresholdSessionId,
    usesNeeded: args.usesNeeded,
  });
}
