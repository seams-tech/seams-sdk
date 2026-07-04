import type {
  WarmSessionMaterialClaimer,
  WarmSessionSealPersister,
  WarmSessionStatusBatchReader,
  WarmSessionStatusReader,
} from '@/core/signingEngine/uiConfirm/uiConfirm.types';
import type { WarmSessionSealAndPersistPayload } from '@/core/types/secure-confirm-worker';

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
  claimsBySessionId: Record<string, WarmClaimFixture>,
): Pick<
  WarmSessionStatusReader & WarmSessionStatusBatchReader,
  'getWarmSessionStatus' | 'getWarmSessionStatuses'
> {
  const getWarmSessionStatus: WarmSessionStatusReader['getWarmSessionStatus'] = async ({
    sessionId,
  }) => {
    const claim = claimsBySessionId[String(sessionId || '').trim()];
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
    getWarmSessionStatuses: async ({ sessionIds }) => ({
      results: await Promise.all(
        (Array.isArray(sessionIds) ? sessionIds : []).map(async (sessionId) => ({
          sessionId: String(sessionId || '').trim(),
          result: await getWarmSessionStatus({ sessionId: String(sessionId || '').trim() }),
        })),
      ),
    }),
  };
}

export function createWarmSessionUiConfirmFixture(args: {
  claimsBySessionId: Record<string, WarmClaimFixture>;
  sealAndPersistResultBySessionId?: Record<
    string,
    | {
        ok: true;
        sealedSecretB64u: string;
        keyVersion?: string;
        remainingUses: number;
        expiresAtMs: number;
      }
    | {
        ok: false;
        code: string;
        message: string;
      }
  >;
}) {
  const sealCalls: WarmSessionSealAndPersistPayload[] = [];
  const readStatus = createWarmSessionStatusReader(args.claimsBySessionId).getWarmSessionStatus;

  const touchConfirm: Pick<
    WarmSessionStatusReader & WarmSessionMaterialClaimer & WarmSessionSealPersister,
    'getWarmSessionStatus' | 'claimWarmSessionMaterial' | 'sealAndPersistWarmSessionMaterial'
  > = {
    getWarmSessionStatus: readStatus,
    claimWarmSessionMaterial: async ({ sessionId, uses }) => {
      const normalizedSessionId = String(sessionId || '').trim();
      const claim = args.claimsBySessionId[normalizedSessionId];
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

      const warmClaim = claim;
      const consumeUses = Math.max(1, Math.floor(Number(uses) || 1));
      if (warmClaim.remainingUses < consumeUses) {
        args.claimsBySessionId[normalizedSessionId] = { state: 'exhausted' };
        return {
          ok: false as const,
          code: 'exhausted',
          message: 'exhausted',
        };
      }

      warmClaim.remainingUses -= consumeUses;
      const remainingUses = warmClaim.remainingUses;
      const prfFirstB64u = String(
        warmClaim.prfFirstB64u || `prf-first:${normalizedSessionId}:${remainingUses}`,
      ).trim();
      if (remainingUses <= 0) {
        args.claimsBySessionId[normalizedSessionId] = { state: 'exhausted' };
      }
      return {
        ok: true as const,
        prfFirstB64u,
        remainingUses,
        expiresAtMs: claim.expiresAtMs,
      };
    },
    sealAndPersistWarmSessionMaterial: async (payload) => {
      sealCalls.push(payload);
      return (
        args.sealAndPersistResultBySessionId?.[String(payload.sessionId || '').trim()] || {
          ok: false as const,
          code: 'not_enabled',
          message: 'not enabled',
        }
      );
    },
  };

  return {
    claimsBySessionId: args.claimsBySessionId,
    sealCalls,
    touchConfirm,
  };
}
