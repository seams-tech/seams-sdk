import type {
  WarmSessionStatusBatchReader,
  WarmSessionStatusReader,
} from '@/core/signingEngine/uiConfirm/uiConfirm.types';

type WarmClaimFixture =
  | {
      state: 'warm';
      remainingUses: number;
      expiresAtMs: number;
      prfFirstB64u?: string;
    }
  | {
      state: 'missing' | 'expired' | 'exhausted' | 'unavailable';
      message?: string;
      code?: string;
    };

function isWarmClaimFixture(
  claim: WarmClaimFixture,
): claim is Extract<WarmClaimFixture, { state: 'warm' }> {
  return claim.state === 'warm';
}

export function createWarmSessionStatusReader(
  claimsByThresholdSessionId: Record<string, WarmClaimFixture>,
): Pick<
  WarmSessionStatusReader & WarmSessionStatusBatchReader,
  'getWarmSessionStatus' | 'getWarmSessionStatuses'
> {
  const getWarmSessionStatus: WarmSessionStatusReader['getWarmSessionStatus'] = async ({
    thresholdSessionId,
  }) => {
    const claim = claimsByThresholdSessionId[String(thresholdSessionId || '').trim()];
    if (!claim || claim.state === 'missing') {
      return {
        ok: false as const,
        code: 'not_found',
        message: claim?.message || 'missing',
      };
    }
    if (claim.state === 'unavailable') {
      return {
        ok: false as const,
        code: claim.code || 'worker_error',
        message: claim.message || 'unavailable',
      };
    }
    if (claim.state === 'expired' || claim.state === 'exhausted') {
      return {
        ok: false as const,
        code: claim.state,
        message: claim.message || claim.state,
      };
    }
    if (!isWarmClaimFixture(claim)) {
      return {
        ok: false as const,
        code: 'not_found',
        message: claim.message || 'missing',
      };
    }
    return {
      ok: true as const,
      remainingUses: claim.remainingUses,
      expiresAtMs: claim.expiresAtMs,
    };
  };
  return {
    getWarmSessionStatus,
    getWarmSessionStatuses: async ({ thresholdSessionIds }) => ({
      results: await Promise.all(
        (Array.isArray(thresholdSessionIds) ? thresholdSessionIds : []).map(async (thresholdSessionId) => ({
          thresholdSessionId: String(thresholdSessionId || '').trim(),
          result: await getWarmSessionStatus({ thresholdSessionId: String(thresholdSessionId || '').trim() }),
        })),
      ),
    }),
  };
}
