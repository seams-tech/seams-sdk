import { laneCandidateStateFromRuntimePolicy } from '../identity/laneIdentity';
import type { ActiveEvmFamilyWalletSessionAuthorization } from '../../flows/signEvmFamily/ecdsaSigningCapability';
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
import type { SigningSessionSealKeyVersion } from '../keyMaterialBrands';
import type {
  WarmSessionEd25519AuthMaterial,
  WarmSessionEcdsaCapabilityState,
  WarmSessionEd25519CapabilityState,
  WarmSessionPrfClaim,
} from './types';
import {
  emailOtpAuthContextConsumedAtMs,
  emailOtpAuthContextRetention,
} from '../identity/laneIdentity';
import type { ThresholdEcdsaEmailOtpAuthContext } from '../identity/laneIdentity';
import {
  classifyRouterAbEd25519PersistedSigningRecord,
  parseRouterAbEd25519WalletSessionAuthorityFromRecord,
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
  const authority = parseRouterAbEd25519WalletSessionAuthorityFromRecord(record);
  if (authority.ok) {
    return {
      capability: 'ed25519',
      record,
      walletSessionJwt: authority.value.auth.walletSessionJwt,
      walletSessionJwtSource: 'ed25519_record',
    };
  }
  return {
    capability: 'ed25519',
    record,
    walletSessionJwtSource: 'none',
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
  const ed25519EmailOtpAuthContext =
    args.record.source === 'email_otp' ? args.record.emailOtpAuthContext : null;
  if (
    ed25519EmailOtpAuthContext &&
    emailOtpAuthContextRetention(ed25519EmailOtpAuthContext) === 'single_use' &&
    Number(emailOtpAuthContextConsumedAtMs(ed25519EmailOtpAuthContext)) > 0
  ) {
    return 'prf_missing';
  }
  const persistedState = classifyRouterAbEd25519PersistedSigningRecord(args.record);
  if (persistedState.kind === 'ready') return 'ready';
  if (
    persistedState.kind === 'non_signing' ||
    persistedState.reason === 'missing_wallet_session_jwt'
  ) {
    return 'auth_missing';
  }
  if (persistedState.kind === 'invalid') return 'invalid';
  if (!args.prfClaim) return 'prf_missing';
  switch (args.prfClaim.state) {
    case 'unavailable':
      return 'prf_unavailable';
    case 'warm':
    case 'missing':
    case 'expired':
    case 'exhausted':
      return 'prf_missing';
  }
}

export function deriveEcdsaCapabilityState(args: {
  runtime: NonNullable<WarmSessionEcdsaCapabilityState['runtime']>;
  auth: ActiveEvmFamilyWalletSessionAuthorization | null;
  prfClaim: WarmSessionPrfClaim | null;
  emailOtpAuthContext?: ThresholdEcdsaEmailOtpAuthContext | null;
}): WarmSessionEcdsaCapabilityState['state'] {
  // The reusable Wallet Session authorization is the independent second proof:
  // without it the capability is not signable regardless of material, and no
  // SelectedEcdsaLane can exist.
  if (!args.auth) return 'authorization_required';
  // Allowance and expiry are classified by the shared Refactor 92 rule before
  // PRF state. An expired or exhausted session is an authorization state, not a
  // material one: the sealed material and its activation are untouched.
  const runtimeState = laneCandidateStateFromRuntimePolicy({
    remainingUses: args.runtime.remainingUses,
    expiresAtMs: args.runtime.expiresAtMs,
  });
  if (runtimeState === 'expired' || runtimeState === 'exhausted') {
    return 'authorization_required';
  }
  const ecdsaEmailOtpAuthContext = args.emailOtpAuthContext ?? null;
  if (
    ecdsaEmailOtpAuthContext &&
    emailOtpAuthContextRetention(ecdsaEmailOtpAuthContext) === 'single_use' &&
    Number(emailOtpAuthContextConsumedAtMs(ecdsaEmailOtpAuthContext)) > 0
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

/** Transport identity comes from the sealed runtime; the bearer proof comes from
 * the reusable Wallet Session. An Email-OTP-bound runtime has no standing
 * authorization of its own, so without a live Wallet Session there is nothing to
 * seal against and the transport is withheld rather than emitted unauthorized. */
export function resolveEcdsaSealTransport(args: {
  runtime: NonNullable<WarmSessionEcdsaCapabilityState['runtime']>;
  auth: ActiveEvmFamilyWalletSessionAuthorization | null;
  signingSessionSealKeyVersion?: SigningSessionSealKeyVersion;
  groupId?: string;
}): ThresholdSessionSealTransportAuthMaterial | null {
  const walletSessionJwt = String(args.auth?.projection.walletSessionJwt || '').trim();
  if (args.runtime.authBinding.kind === 'email_otp' && !walletSessionJwt) return null;
  const relayerUrl = String(args.runtime.relayerUrl || '').trim();
  if (!relayerUrl) return null;
  const groupId = String(args.groupId || '').trim();
  return {
    curve: 'ecdsa',
    walletId: String(args.runtime.walletId),
    chainTarget: args.runtime.chainTarget,
    relayerUrl,
    // No signingGrantId: a grant is a distinct identity and the authorization
    // boundary carries none. The Wallet Session is identified by its own JWT.
    ...(walletSessionJwt ? { walletSessionJwt } : {}),
    walletSessionJwtSource: walletSessionJwt ? 'ecdsa' : 'none',
    ...(args.signingSessionSealKeyVersion
      ? { signingSessionSealKeyVersion: args.signingSessionSealKeyVersion }
      : {}),
    ...(groupId ? { groupId } : {}),
  };
}
