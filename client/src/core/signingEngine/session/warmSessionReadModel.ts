import type { SigningSessionStatus } from '@/core/types/tatchi';
import type {
  WarmSessionStatusBatchReader,
  WarmSessionStatusReader,
  WarmSessionStatusResult,
} from '../touchConfirm';
import type {
  ThresholdSessionSealTransportAuthMaterial,
} from '../api/thresholdLifecycle/thresholdSessionStore';
import type {
  WarmSessionEd25519AuthMaterial,
  WarmSessionEcdsaAuthMaterial,
  WarmSessionEcdsaCapabilityState,
  WarmSessionEd25519CapabilityState,
  WarmSessionPrfClaim,
} from './warmSessionTypes';

export type WarmSessionReadPorts =
  | Partial<Pick<WarmSessionStatusReader & WarmSessionStatusBatchReader, 'getWarmSessionStatus' | 'getWarmSessionStatuses'>>
  | undefined;

export function reportWarmSessionAvailabilityFailure(args: {
  operation: 'status_read' | 'claim';
  sessionId: string;
  code?: string;
}): void {
  console.warn('[WarmSessionManager] warm-session availability failure', {
    operation: args.operation,
    sessionId: args.sessionId,
    code: String(args.code || 'worker_error').trim() || 'worker_error',
  });
}

export async function readWarmSessionClaim(
  touchConfirm: WarmSessionReadPorts,
  sessionIdRaw: string,
): Promise<WarmSessionPrfClaim | null> {
  const sessionId = String(sessionIdRaw || '').trim();
  if (!touchConfirm || !sessionId || typeof touchConfirm.getWarmSessionStatus !== 'function') {
    return null;
  }
  const status = await touchConfirm
    .getWarmSessionStatus({ sessionId })
    .catch(() => ({ ok: false as const, code: 'worker_error', message: 'worker_error' }));
  return toWarmSessionClaimFromStatusResult({ sessionId, status });
}

export function toWarmSessionClaimFromStatusResult(args: {
  sessionId: string;
  status: WarmSessionStatusResult;
}): WarmSessionPrfClaim {
  const sessionId = String(args.sessionId || '').trim();
  if (!args.status.ok) {
    if (args.status.code === 'expired') {
      return { state: 'expired', sessionId };
    }
    if (args.status.code === 'exhausted') {
      return { state: 'exhausted', sessionId };
    }
    if (args.status.code === 'not_found') {
      return { state: 'missing', sessionId };
    }
    reportWarmSessionAvailabilityFailure({
      operation: 'status_read',
      sessionId,
      code: args.status.code,
    });
    return {
      state: 'unavailable',
      sessionId,
      code: String(args.status.code || 'worker_error').trim() || 'worker_error',
    };
  }
  return {
    state: 'warm',
    sessionId,
    expiresAtMs: args.status.expiresAtMs,
    remainingUses: args.status.remainingUses,
  };
}

export async function readWarmSessionClaims(args: {
  touchConfirm: WarmSessionReadPorts;
  sessionIds: string[];
}): Promise<Map<string, WarmSessionPrfClaim | null>> {
  const normalizedSessionIds = Array.from(
    new Set(args.sessionIds.map((value) => String(value || '').trim()).filter(Boolean)),
  );
  const out = new Map<string, WarmSessionPrfClaim | null>();
  if (!normalizedSessionIds.length) {
    return out;
  }
  if (args.touchConfirm && typeof args.touchConfirm.getWarmSessionStatuses === 'function') {
    const batch = await args.touchConfirm.getWarmSessionStatuses({
      sessionIds: normalizedSessionIds,
    });
    for (const sessionId of normalizedSessionIds) {
      const matched = batch.results.find((entry) => entry.sessionId === sessionId);
      out.set(
        sessionId,
        matched ? toWarmSessionClaimFromStatusResult({ sessionId, status: matched.result }) : null,
      );
    }
    return out;
  }
  await Promise.all(
    normalizedSessionIds.map(async (sessionId) => {
      out.set(sessionId, await readWarmSessionClaim(args.touchConfirm, sessionId));
    }),
  );
  return out;
}

export function resolveEd25519AuthMaterial(
  record: WarmSessionEd25519CapabilityState['record'],
): WarmSessionEd25519AuthMaterial | null {
  if (!record) return null;
  const thresholdSessionJwt = String(record.thresholdSessionJwt || '').trim();
  return {
    capability: 'ed25519',
    record,
    ...(thresholdSessionJwt ? { thresholdSessionJwt } : {}),
    thresholdSessionJwtSource: thresholdSessionJwt ? 'ed25519' : 'none',
  };
}

export function resolveEcdsaAuthMaterial(
  record: WarmSessionEcdsaCapabilityState['record'],
): WarmSessionEcdsaAuthMaterial | null {
  if (!record) return null;
  const thresholdSessionJwt = String(record.thresholdSessionJwt || '').trim();
  return {
    capability: 'ecdsa',
    chain: record.chain,
    record,
    ...(thresholdSessionJwt ? { thresholdSessionJwt } : {}),
    thresholdSessionJwtSource: thresholdSessionJwt ? 'ecdsa' : 'none',
  };
}

export function deriveEd25519CapabilityState(args: {
  record: WarmSessionEd25519CapabilityState['record'];
  auth: WarmSessionEd25519AuthMaterial | null;
  prfClaim: WarmSessionPrfClaim | null;
}): WarmSessionEd25519CapabilityState['state'] {
  if (!args.record) return 'missing';
  if (
    !args.auth ||
    (args.record.thresholdSessionKind === 'jwt' && !args.auth.thresholdSessionJwt)
  ) {
    return 'auth_missing';
  }
  if (!args.prfClaim) return 'prf_missing';
  if (args.prfClaim.state === 'unavailable') return 'prf_unavailable';
  if (args.prfClaim.state !== 'warm') return 'prf_missing';
  return 'ready';
}

export function deriveEcdsaCapabilityState(args: {
  record: WarmSessionEcdsaCapabilityState['record'];
  auth: WarmSessionEcdsaAuthMaterial | null;
  prfClaim: WarmSessionPrfClaim | null;
  emailOtpAuthContext?: WarmSessionEcdsaCapabilityState['emailOtpAuthContext'];
}): WarmSessionEcdsaCapabilityState['state'] {
  if (!args.record) return 'missing';
  if (args.record.thresholdSessionKind === 'jwt' && (!args.auth || !args.auth.thresholdSessionJwt)) {
    return 'auth_missing';
  }
  if (
    args.record.source === 'email_otp' &&
    args.emailOtpAuthContext?.retention === 'single_use' &&
    Number(args.emailOtpAuthContext.consumedAtMs) > 0
  ) {
    return 'prf_missing';
  }
  if (!args.prfClaim) return 'prf_missing';
  if (args.prfClaim.state === 'unavailable') return 'prf_unavailable';
  if (args.prfClaim.state !== 'warm') return 'prf_missing';
  return 'ready';
}

export function hasSufficientWarmClaim(
  prfClaim: WarmSessionPrfClaim | null,
  usesNeededRaw: unknown,
): boolean {
  if (!prfClaim || prfClaim.state !== 'warm') return false;
  const remainingUses = Math.floor(Number(prfClaim.remainingUses) || 0);
  const usesNeeded = Math.floor(Number(usesNeededRaw) || 0);
  return remainingUses >= (usesNeeded > 0 ? usesNeeded : 1);
}

export function formatMissingWarmPrfMaterialError(args: {
  errorContext: string;
  code?: string;
}): Error {
  const suffix =
    typeof args.code === 'string' && args.code.trim() ? ` (${args.code.trim()})` : '';
  return new Error(`Missing warm PRF material for ${args.errorContext}${suffix}`);
}

export function formatWarmSessionClaimUnavailableError(args: {
  errorContext: string;
  code?: string;
}): Error {
  const suffix =
    typeof args.code === 'string' && args.code.trim() ? ` (${args.code.trim()})` : '';
  return new Error(`Warm-session claim unavailable for ${args.errorContext}${suffix}`);
}

export function toSigningSessionStatus(args: {
  sessionId: string;
  claim: WarmSessionPrfClaim | null;
}): SigningSessionStatus {
  const sessionId = String(args.sessionId || '').trim();
  const claim = args.claim;
  if (!claim) {
    return { sessionId, status: 'not_found' };
  }
  if (claim.state === 'unavailable') {
    return {
      sessionId,
      status: 'unavailable',
      statusCode: claim.code,
    };
  }
  if (claim.state === 'warm') {
    return {
      sessionId,
      status: 'active',
      remainingUses: claim.remainingUses,
      expiresAtMs: claim.expiresAtMs,
    };
  }
  return {
    sessionId,
    status:
      claim.state === 'expired'
        ? 'expired'
        : claim.state === 'exhausted'
          ? 'exhausted'
          : 'not_found',
  };
}

export function resolveEcdsaSealTransport(args: {
  record: WarmSessionEcdsaCapabilityState['record'];
  auth: WarmSessionEcdsaAuthMaterial | null;
  keyVersion?: string;
  shamirPrimeB64u?: string;
}): ThresholdSessionSealTransportAuthMaterial | null {
  if (!args.record) return null;
  const relayerUrl = String(args.record.relayerUrl || '').trim();
  if (!relayerUrl) return null;
  const keyVersion = String(args.keyVersion || '').trim();
  const shamirPrimeB64u = String(args.shamirPrimeB64u || '').trim();
  return {
    curve: 'ecdsa',
    relayerUrl,
    ...(String(args.auth?.thresholdSessionJwt || '').trim()
      ? { thresholdSessionJwt: String(args.auth?.thresholdSessionJwt || '').trim() }
      : {}),
    thresholdSessionJwtSource: args.auth?.thresholdSessionJwtSource || 'none',
    ...(keyVersion ? { keyVersion } : {}),
    ...(shamirPrimeB64u ? { shamirPrimeB64u } : {}),
  };
}
