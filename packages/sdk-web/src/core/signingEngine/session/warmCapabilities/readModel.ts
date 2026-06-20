import type {
  SigningSessionRetention,
  SigningSessionStatus,
  WalletAuthMethod,
} from '@/core/types/seams';
import type {
  WarmSessionStatusBatchReader,
  WarmSessionStatusReader,
  WarmSessionStatusResult,
} from '../../uiConfirm/uiConfirm.types';
import type { ThresholdSessionSealTransportAuthMaterial } from '../persistence/records';
import type {
  WarmSessionEd25519AuthMaterial,
  WarmSessionEcdsaAuthMaterial,
  WarmSessionEcdsaCapabilityState,
  WarmSessionEd25519CapabilityState,
  WarmSessionPrfClaim,
} from './types';
import {
  persistedWarmSessionRecordRequiresWalletSessionJwt,
  walletSessionJwtFromPersistedWarmSessionRecord,
} from './walletSessionAuthBoundary';
import {
  classifyRouterAbEcdsaHssPersistedSigningRecord,
  classifyRouterAbEd25519PersistedSigningRecord,
} from '../routerAbSigningWalletSession';

export type WarmSessionReadPortsInput =
  | Partial<
      Pick<
        WarmSessionStatusReader & WarmSessionStatusBatchReader,
        'getWarmSessionStatus' | 'getWarmSessionStatuses'
      >
    >
  | null
  | undefined;

export type WarmSessionReadPortsSingle = {
  statusPort: 'single';
  getWarmSessionStatus: WarmSessionStatusReader['getWarmSessionStatus'];
  getWarmSessionStatuses?: never;
};

export type WarmSessionReadPortsBatch = {
  statusPort: 'batch';
  getWarmSessionStatus?: never;
  getWarmSessionStatuses: WarmSessionStatusBatchReader['getWarmSessionStatuses'];
};

export type WarmSessionReadPortsSingleAndBatch = {
  statusPort: 'single_and_batch';
  getWarmSessionStatus: WarmSessionStatusReader['getWarmSessionStatus'];
  getWarmSessionStatuses: WarmSessionStatusBatchReader['getWarmSessionStatuses'];
};

export type WarmSessionReadPorts =
  | WarmSessionReadPortsSingle
  | WarmSessionReadPortsBatch
  | WarmSessionReadPortsSingleAndBatch;

export function normalizeWarmSessionReadPorts(
  ports: WarmSessionReadPortsInput,
): WarmSessionReadPorts | null {
  const getWarmSessionStatus =
    typeof ports?.getWarmSessionStatus === 'function'
      ? (args: Parameters<WarmSessionStatusReader['getWarmSessionStatus']>[0]) =>
          ports.getWarmSessionStatus!(args)
      : null;
  const getWarmSessionStatuses =
    typeof ports?.getWarmSessionStatuses === 'function'
      ? (args: Parameters<WarmSessionStatusBatchReader['getWarmSessionStatuses']>[0]) =>
          ports.getWarmSessionStatuses!(args)
      : null;
  if (getWarmSessionStatus && getWarmSessionStatuses) {
    return {
      statusPort: 'single_and_batch',
      getWarmSessionStatus,
      getWarmSessionStatuses,
    };
  }
  if (getWarmSessionStatus) {
    return {
      statusPort: 'single',
      getWarmSessionStatus,
    };
  }
  if (getWarmSessionStatuses) {
    return {
      statusPort: 'batch',
      getWarmSessionStatuses,
    };
  }
  return null;
}

export function reportWarmSessionAvailabilityFailure(args: {
  operation: 'status_read' | 'claim';
  sessionId: string;
  code?: string;
}): void {
  console.warn('[WarmSessionStore] warm-session availability failure', {
    operation: args.operation,
    sessionId: args.sessionId,
    code: String(args.code || 'worker_error').trim() || 'worker_error',
  });
}

export async function readWarmSessionClaim(
  touchConfirm: WarmSessionReadPorts | null,
  sessionIdRaw: string,
): Promise<WarmSessionPrfClaim | null> {
  const sessionId = String(sessionIdRaw || '').trim();
  if (!touchConfirm || !sessionId || touchConfirm.statusPort === 'batch') {
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
  touchConfirm: WarmSessionReadPorts | null;
  sessionIds: string[];
}): Promise<Map<string, WarmSessionPrfClaim | null>> {
  const normalizedSessionIds = Array.from(
    new Set(args.sessionIds.map((value) => String(value || '').trim()).filter(Boolean)),
  );
  const out = new Map<string, WarmSessionPrfClaim | null>();
  if (!normalizedSessionIds.length) {
    return out;
  }
  if (!args.touchConfirm) {
    for (const sessionId of normalizedSessionIds) {
      out.set(sessionId, null);
    }
    return out;
  }
  if (args.touchConfirm.statusPort !== 'single') {
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
  const walletSessionJwt = walletSessionJwtFromPersistedWarmSessionRecord(record);
  if (walletSessionJwt) {
    return {
      capability: 'ed25519',
      record,
      walletSessionJwt,
      walletSessionJwtSource: 'ed25519_record',
    };
  }
  return {
    capability: 'ed25519',
    record,
    walletSessionJwtSource: 'none',
  };
}

export function resolveEcdsaAuthMaterial(
  record: WarmSessionEcdsaCapabilityState['record'],
): WarmSessionEcdsaAuthMaterial | null {
  if (!record) return null;
  if (record.thresholdSessionKind !== 'jwt') {
    return {
      capability: 'ecdsa',
      state: 'unavailable',
      record,
      walletSessionJwtSource: 'none',
      unavailableReason: 'cookie_session',
    };
  }
  const walletSessionJwt = walletSessionJwtFromPersistedWarmSessionRecord(record);
  if (walletSessionJwt) {
    return {
      capability: 'ecdsa',
      state: 'ready',
      record,
      walletSessionJwt,
      walletSessionJwtSource: 'ecdsa_record',
    };
  }
  return {
    capability: 'ecdsa',
    state: 'unavailable',
    record,
    walletSessionJwtSource: 'none',
    unavailableReason: 'missing_wallet_session_jwt',
  };
}

export function deriveEd25519CapabilityState(args: {
  record: WarmSessionEd25519CapabilityState['record'];
  auth: WarmSessionEd25519AuthMaterial | null;
  prfClaim: WarmSessionPrfClaim | null;
}): WarmSessionEd25519CapabilityState['state'] {
  if (!args.record) return 'missing';
  if (!args.auth || !args.auth.walletSessionJwt) {
    return 'auth_missing';
  }
  if (
    args.record.source === 'email_otp' &&
    args.record.emailOtpAuthContext?.retention === 'single_use' &&
    Number(args.record.emailOtpAuthContext.consumedAtMs) > 0
  ) {
    return 'prf_missing';
  }
  const persistedState = classifyRouterAbEd25519PersistedSigningRecord(args.record);
  if (persistedState.kind === 'runtime_validated') {
    return 'ready';
  }
  if (
    persistedState.kind === 'non_signing' ||
    persistedState.reason === 'missing_wallet_session_jwt'
  ) {
    return 'auth_missing';
  }
  if (persistedState.kind === 'restore_available') return 'material_pending';
  if (persistedState.kind === 'invalid') return 'invalid';
  if (args.record.source !== 'email_otp') {
    if (!args.prfClaim || args.prfClaim.state === 'missing' || args.prfClaim.state === 'warm') {
      return 'material_pending';
    }
    return args.prfClaim.state === 'unavailable' ? 'prf_unavailable' : 'prf_missing';
  }
  if (!args.prfClaim) return 'prf_missing';
  switch (args.prfClaim.state) {
    case 'warm':
      return 'material_pending';
    case 'unavailable':
      return 'prf_unavailable';
    case 'missing':
    case 'expired':
    case 'exhausted':
      return 'prf_missing';
  }
}

export function deriveEcdsaCapabilityState(args: {
  record: WarmSessionEcdsaCapabilityState['record'];
  auth: WarmSessionEcdsaAuthMaterial | null;
  prfClaim: WarmSessionPrfClaim | null;
}): WarmSessionEcdsaCapabilityState['state'] {
  if (!args.record) return 'missing';
  const requiresWalletSessionJwt = persistedWarmSessionRecordRequiresWalletSessionJwt({
    capability: 'ecdsa',
    record: args.record,
  });
  if (requiresWalletSessionJwt && (!args.auth || args.auth.state === 'unavailable')) {
    return 'auth_missing';
  }
  if (
    args.record.source === 'email_otp' &&
    args.record.emailOtpAuthContext?.retention === 'single_use' &&
    Number(args.record.emailOtpAuthContext.consumedAtMs) > 0
  ) {
    return 'prf_missing';
  }
  if (!args.prfClaim) return 'prf_missing';
  if (args.prfClaim.state === 'unavailable') return 'prf_unavailable';
  if (args.prfClaim.state !== 'warm') return 'prf_missing';
  const persistedState = classifyRouterAbEcdsaHssPersistedSigningRecord(args.record);
  if (persistedState.kind === 'signable') return 'ready';
  if (
    persistedState.kind === 'non_signing' ||
    persistedState.reason === 'missing_wallet_session_jwt'
  ) {
    return 'auth_missing';
  }
  return 'material_pending';
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
  const suffix = typeof args.code === 'string' && args.code.trim() ? ` (${args.code.trim()})` : '';
  return new Error(`Missing warm PRF material for ${args.errorContext}${suffix}`);
}

export function formatWarmSessionClaimUnavailableError(args: {
  errorContext: string;
  code?: string;
}): Error {
  const suffix = typeof args.code === 'string' && args.code.trim() ? ` (${args.code.trim()})` : '';
  return new Error(`Warm-session claim unavailable for ${args.errorContext}${suffix}`);
}

export function toSigningSessionStatus(args: {
  sessionId: string;
  claim: WarmSessionPrfClaim | null;
  authMethod?: WalletAuthMethod | null;
  retention?: SigningSessionRetention | null;
}): SigningSessionStatus {
  const sessionId = String(args.sessionId || '').trim();
  const claim = args.claim;
  const metadata = {
    ...(args.authMethod ? { authMethod: args.authMethod } : {}),
    ...(args.retention ? { retention: args.retention } : {}),
  };
  if (!claim) {
    return { sessionId, status: 'not_found', ...metadata };
  }
  if (claim.state === 'unavailable') {
    return {
      sessionId,
      status: 'unavailable',
      statusCode: claim.code,
      ...metadata,
    };
  }
  if (claim.state === 'warm') {
    return {
      sessionId,
      status: 'active',
      ...metadata,
      remainingUses: claim.remainingUses,
      expiresAtMs: claim.expiresAtMs,
    };
  }
  return {
    sessionId,
    ...metadata,
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
  const signingGrantId = args.record.signingGrantId;
  const walletSessionJwt = String(args.auth?.walletSessionJwt || '').trim();
  const walletSessionJwtSource =
    args.auth?.walletSessionJwtSource === 'ecdsa_record' ? 'ecdsa' : 'none';
  return {
    curve: 'ecdsa',
    walletId: String(args.record.walletId),
    chainTarget: args.record.chainTarget,
    relayerUrl,
    ...(signingGrantId ? { signingGrantId } : {}),
    ...(walletSessionJwt
      ? { walletSessionJwt: walletSessionJwt }
      : {}),
    walletSessionJwtSource,
    ...(keyVersion ? { keyVersion } : {}),
    ...(shamirPrimeB64u ? { shamirPrimeB64u } : {}),
  };
}
