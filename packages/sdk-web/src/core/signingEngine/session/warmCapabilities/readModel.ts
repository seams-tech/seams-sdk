import { laneCandidateStateFromRuntimePolicy } from '../identity/laneIdentity';
import type { ActiveEvmFamilyWalletSessionAuthorization } from '../material/ecdsaSigningCapability';
import type {
  SigningSessionRetention,
  SigningSessionStatus,
  SignerAuthMethod,
} from '@/core/types/seams';
import type {
  WarmSessionStatusBatchReader,
  WarmSessionStatusReader,
  WarmSessionStatusResult,
} from '../../uiConfirm/uiConfirm.types';
import type { EcdsaSealTransportAuthMaterial } from '../persistence/sealedSessionTransportAuth';
import type { SigningSessionSealKeyVersion } from '../keyMaterialBrands';
import type {
  WarmSessionEcdsaCapabilityState,
  WarmSessionEd25519CapabilityState,
  WarmSessionPrfClaim,
} from './types';
import {
  emailOtpAuthContextConsumedAtMs,
  emailOtpAuthContextRetention,
} from '../identity/laneIdentity';
import type { ThresholdEcdsaEmailOtpAuthContext } from '../identity/laneIdentity';
import type { ExactEd25519SealedSessionRuntime } from './ed25519SealedSessionRuntime';
import {
  walletSessionTokenForCurve,
  type ActiveWalletSessionAuthorizationProjection,
} from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';

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
  thresholdSessionId: string;
  code?: string;
}): void {
  console.warn('[WarmSessionStore] warm-session availability failure', {
    operation: args.operation,
    thresholdSessionId: args.thresholdSessionId,
    code: String(args.code || 'worker_error').trim() || 'worker_error',
  });
}

export async function readWarmSessionClaim(
  touchConfirm: WarmSessionReadPorts | null,
  thresholdSessionIdRaw: string,
): Promise<WarmSessionPrfClaim | null> {
  const thresholdSessionId = String(thresholdSessionIdRaw || '').trim();
  if (!touchConfirm || !thresholdSessionId || touchConfirm.statusPort === 'batch') {
    return null;
  }
  const status = await touchConfirm
    .getWarmSessionStatus({ thresholdSessionId })
    .catch(() => ({ ok: false as const, code: 'worker_error', message: 'worker_error' }));
  return toWarmSessionClaimFromStatusResult({ thresholdSessionId, status });
}

export function toWarmSessionClaimFromStatusResult(args: {
  thresholdSessionId: string;
  status: WarmSessionStatusResult;
}): WarmSessionPrfClaim {
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  if (!args.status.ok) {
    if (args.status.code === 'expired') {
      return { state: 'expired', thresholdSessionId };
    }
    if (args.status.code === 'exhausted') {
      return { state: 'exhausted', thresholdSessionId };
    }
    if (args.status.code === 'not_found') {
      return { state: 'missing', thresholdSessionId };
    }
    reportWarmSessionAvailabilityFailure({
      operation: 'status_read',
      thresholdSessionId,
      code: args.status.code,
    });
    return {
      state: 'unavailable',
      thresholdSessionId,
      code: String(args.status.code || 'worker_error').trim() || 'worker_error',
    };
  }
  return {
    state: 'warm',
    thresholdSessionId,
    expiresAtMs: args.status.expiresAtMs,
    remainingUses: args.status.remainingUses,
  };
}

export async function readWarmSessionClaims(args: {
  touchConfirm: WarmSessionReadPorts | null;
  thresholdSessionIds: string[];
}): Promise<Map<string, WarmSessionPrfClaim | null>> {
  const normalizedThresholdSessionIds = Array.from(
    new Set(args.thresholdSessionIds.map((value) => String(value || '').trim()).filter(Boolean)),
  );
  const out = new Map<string, WarmSessionPrfClaim | null>();
  if (!normalizedThresholdSessionIds.length) {
    return out;
  }
  if (!args.touchConfirm) {
    for (const thresholdSessionId of normalizedThresholdSessionIds) {
      out.set(thresholdSessionId, null);
    }
    return out;
  }
  if (args.touchConfirm.statusPort !== 'single') {
    const batch = await args.touchConfirm.getWarmSessionStatuses({
      thresholdSessionIds: normalizedThresholdSessionIds,
    });
    for (const thresholdSessionId of normalizedThresholdSessionIds) {
      const matched = batch.results.find(
        (entry) => entry.thresholdSessionId === thresholdSessionId,
      );
      out.set(
        thresholdSessionId,
        matched
          ? toWarmSessionClaimFromStatusResult({ thresholdSessionId, status: matched.result })
          : null,
      );
    }
    return out;
  }
  await Promise.all(
    normalizedThresholdSessionIds.map(async (thresholdSessionId) => {
      out.set(
        thresholdSessionId,
        await readWarmSessionClaim(args.touchConfirm, thresholdSessionId),
      );
    }),
  );
  return out;
}

export function deriveEd25519CapabilityState(args: {
  runtime: ExactEd25519SealedSessionRuntime;
  auth: ActiveWalletSessionAuthorizationProjection | null;
  prfClaim: WarmSessionPrfClaim | null;
}): WarmSessionEd25519CapabilityState['state'] {
  if (
    !args.auth ||
    String(args.auth.walletId) !== String(args.runtime.walletId) ||
    args.auth.authMethod !== args.runtime.factor.kind
  ) {
    return 'authorization_required';
  }
  const runtimeState = laneCandidateStateFromRuntimePolicy({
    remainingUses: args.runtime.remainingUses,
    expiresAtMs: args.runtime.expiresAtMs,
  });
  if (runtimeState === 'expired' || runtimeState === 'exhausted') {
    return 'authorization_required';
  }
  if (!args.prfClaim) return 'prf_missing';
  switch (args.prfClaim.state) {
    case 'unavailable':
      return 'prf_unavailable';
    case 'warm':
      return 'ready';
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
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext | null;
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
  const ecdsaEmailOtpAuthContext = args.emailOtpAuthContext;
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

export function toSigningSessionStatus(args: {
  sessionId: string;
  claim: WarmSessionPrfClaim | null;
  authMethod?: SignerAuthMethod | null;
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
 * the active Wallet Session. An Email-OTP-bound runtime has no standing
 * authorization of its own, so without a live Wallet Session there is nothing to
 * seal against and the transport is withheld rather than emitted unauthorized. */
export function resolveEcdsaSealTransport(args: {
  runtime: NonNullable<WarmSessionEcdsaCapabilityState['runtime']>;
  auth: ActiveEvmFamilyWalletSessionAuthorization | null;
  signingSessionSealKeyVersion?: SigningSessionSealKeyVersion;
  groupId?: string;
}): EcdsaSealTransportAuthMaterial | null {
  const walletSessionToken = args.auth
    ? walletSessionTokenForCurve(args.auth.projection, 'ecdsa')
    : null;
  if (!walletSessionToken) return null;
  const relayerUrl = String(args.runtime.relayerUrl || '').trim();
  if (!relayerUrl) return null;
  const groupId = String(args.groupId || '').trim();
  return {
    curve: 'ecdsa',
    walletId: String(args.runtime.walletId),
    chainTarget: args.runtime.chainTarget,
    relayerUrl,
    walletSessionToken,
    ...(args.signingSessionSealKeyVersion
      ? { signingSessionSealKeyVersion: args.signingSessionSealKeyVersion }
      : {}),
    ...(groupId ? { groupId } : {}),
  };
}
