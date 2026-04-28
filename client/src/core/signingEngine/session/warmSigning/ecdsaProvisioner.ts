import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type {
  ThresholdEcdsaSessionRecord,
  ThresholdEcdsaSessionStoreSource,
} from '../../api/thresholdLifecycle/thresholdSessionStore';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import type {
  ThresholdEcdsaActivationChain,
  ThresholdEcdsaSessionBootstrapResult,
} from '../../orchestration/thresholdActivation';
import { formatEmailOtpSensitiveOperationError } from '../signingSession/postSignPolicy';
import {
  emitWarmSessionTransition,
  summarizeWarmSessionTransition,
  type WarmSessionTransitionEvent,
} from './transitions';
import { resolveWarmEcdsaBootstrapRequestFromSession } from './ecdsaBootstrapRequest';
import { hasSufficientWarmClaim } from './readModel';
import type {
  WarmSessionEcdsaCapabilityState,
  WarmSessionEnvelope,
} from './types';
import type {
  ClaimWarmSessionPrfArgs,
  EnsureWarmEcdsaCapabilityReadyArgs,
  EnsureWarmEcdsaCapabilityReadyResult,
  ProvisionWarmEcdsaCapabilityArgs,
} from './types';
import { readWarmSessionEcdsaRecordByThresholdSessionId } from './store';

export type WarmSessionEcdsaProvisionerDeps = {
  getWarmSession: (nearAccountId: AccountId | string) => Promise<WarmSessionEnvelope>;
  listThresholdEcdsaKeyRefsForLookup?: (args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    source?: ThresholdEcdsaSessionStoreSource;
  }) => EcdsaKeyRefCandidate[];
  provisionThresholdEcdsaSession?: (
    args: ProvisionWarmEcdsaCapabilityArgs,
  ) => Promise<ThresholdEcdsaSessionBootstrapResult>;
  bootstrapThresholdEcdsaSession?: (args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
  }) => Promise<ThresholdEcdsaSessionBootstrapResult>;
  claimPrfFirstByThresholdSessionId?: (args: ClaimWarmSessionPrfArgs) => Promise<string>;
  onTransition?: (event: WarmSessionTransitionEvent) => void | Promise<void>;
};

export type WarmSessionEcdsaReconnectDeps = {
  getWarmSession: (nearAccountId: AccountId | string) => Promise<WarmSessionEnvelope>;
  listThresholdEcdsaKeyRefsForLookup?: (args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    source?: ThresholdEcdsaSessionStoreSource;
  }) => EcdsaKeyRefCandidate[];
  canProvisionEcdsaCapability: boolean;
  provisionEcdsaCapability: (
    args: ProvisionWarmEcdsaCapabilityArgs,
  ) => Promise<ThresholdEcdsaSessionBootstrapResult>;
  resolveCurrentEcdsaRecord: (args: {
    nearAccountId: AccountId;
    chain: ThresholdEcdsaActivationChain;
    source?: ThresholdEcdsaSessionStoreSource;
  }) => ThresholdEcdsaSessionRecord | null;
  readEcdsaCapabilityByThresholdSessionId: (
    thresholdSessionId: string,
  ) => Promise<WarmSessionEcdsaCapabilityState | null>;
  reconnectInFlightByCapability: Map<string, Promise<EnsureWarmEcdsaCapabilityReadyResult>>;
  onTransition?: (event: WarmSessionTransitionEvent) => void | Promise<void>;
};

function assertPersistedEcdsaWarmSessionRecord(args: {
  nearAccountId: AccountId;
  expectedSessionId: string;
  persistedSessionIdRaw: unknown;
  fallbackPersistedSessionIdRaw?: unknown;
}): void {
  const persistedSessionId = String(args.persistedSessionIdRaw || '').trim();
  if (persistedSessionId === args.expectedSessionId) {
    return;
  }
  const fallbackPersistedSessionId = String(args.fallbackPersistedSessionIdRaw || '').trim();
  throw new Error(
    `[WarmSessionStore] provisioned ECDSA capability was not persisted for ${args.nearAccountId} (expected sessionId=${args.expectedSessionId}, found=${persistedSessionId || fallbackPersistedSessionId || 'missing'})`,
  );
}

type EcdsaKeyRefCandidate = {
  source: ThresholdEcdsaSessionStoreSource;
  keyRef: ThresholdEcdsaSecp256k1KeyRef;
};

function readEcdsaKeyRefCandidates(
  deps: Pick<WarmSessionEcdsaProvisionerDeps, 'listThresholdEcdsaKeyRefsForLookup'>,
  args: {
    nearAccountId: AccountId;
    chain: ThresholdEcdsaActivationChain;
    source?: ThresholdEcdsaSessionStoreSource;
  },
): EcdsaKeyRefCandidate[] {
  if (typeof deps.listThresholdEcdsaKeyRefsForLookup !== 'function') return [];
  const candidates: EcdsaKeyRefCandidate[] = [];
  const seen = new Set<string>();
  let listed: EcdsaKeyRefCandidate[] = [];
  try {
    listed = deps.listThresholdEcdsaKeyRefsForLookup({
      nearAccountId: args.nearAccountId,
      chain: args.chain,
      ...(args.source ? { source: args.source } : {}),
    });
  } catch {
    return [];
  }
  for (const candidate of listed) {
    const source = candidate.source;
    const keyRef = candidate.keyRef;
    if (args.source && source !== args.source) continue;
    try {
      const key = [
        source,
        String(keyRef.thresholdSessionId || '').trim(),
        String(keyRef.ecdsaThresholdKeyId || '').trim(),
      ].join(':');
      if (seen.has(key)) continue;
      seen.add(key);
      candidates.push({ source, keyRef });
    } catch {}
  }
  return candidates;
}

export async function tryReuseReadyWarmEcdsaBootstrap(
  deps: WarmSessionEcdsaProvisionerDeps,
  args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    source?: ThresholdEcdsaSessionStoreSource;
  },
): Promise<ThresholdEcdsaSessionBootstrapResult | null> {
  const nearAccountId = toAccountId(args.nearAccountId);
  const keyRefCandidates = readEcdsaKeyRefCandidates(deps, {
    nearAccountId,
    chain: args.chain,
    ...(args.source ? { source: args.source } : {}),
  });
  if (!keyRefCandidates.length) return null;
  const warmSession = await deps.getWarmSession(nearAccountId);
  for (const candidate of keyRefCandidates) {
    const capability = getMatchingReadyEcdsaCapability({
      warmSession,
      chain: args.chain,
      keyRef: candidate.keyRef,
      usesNeeded: 1,
    });
    if (!capability) continue;
    const reusableBootstrap = buildReusableEcdsaBootstrapResult({
      keyRef: candidate.keyRef,
      capability,
      source: candidate.source,
    });
    if (reusableBootstrap) return reusableBootstrap;
  }
  return null;
}

export async function provisionWarmEcdsaCapability(
  deps: WarmSessionEcdsaProvisionerDeps,
  args: ProvisionWarmEcdsaCapabilityArgs,
): Promise<ThresholdEcdsaSessionBootstrapResult> {
  const nearAccountId = toAccountId(args.nearAccountId);
  const beforeWarmSession = await deps.getWarmSession(nearAccountId);
  const hasThresholdRouteAuth = Boolean(args.thresholdRouteAuth);
  const normalizedClientRootShare32 =
    args.clientRootShare32 instanceof Uint8Array ? args.clientRootShare32 : undefined;
  const normalizedClientRootShare32B64u = toOptionalNonEmptyString(args.clientRootShare32B64u);
  const normalizedSessionId = toOptionalNonEmptyString(args.sessionId);

  if (
    !hasThresholdRouteAuth &&
    !normalizedClientRootShare32 &&
    !normalizedClientRootShare32B64u &&
    !normalizedSessionId
  ) {
    const reusableBootstrap = await tryReuseReadyWarmEcdsaBootstrap(deps, {
      nearAccountId,
      chain: args.chain,
      source: args.source,
    });
    if (reusableBootstrap) {
      return reusableBootstrap;
    }
  }

  const resolvedBootstrapRequest = resolveWarmEcdsaBootstrapRequestFromSession({
    request: {
      nearAccountId,
      chain: args.chain,
      relayerUrl: args.relayerUrl,
      ecdsaThresholdKeyId: args.ecdsaThresholdKeyId,
      participantIds: args.participantIds,
      sessionKind: args.sessionKind,
      sessionId: args.sessionId,
      walletSigningSessionId: args.walletSigningSessionId,
      thresholdRouteAuth: args.thresholdRouteAuth,
      runtimePolicyScope: args.runtimePolicyScope,
      runtimeScopeBootstrap: args.runtimeScopeBootstrap,
      clientRootShare32: args.clientRootShare32,
      clientRootShare32B64u: args.clientRootShare32B64u,
      webauthnAuthentication: args.webauthnAuthentication,
    },
    warmSession: beforeWarmSession,
  });
  if (
    !resolvedBootstrapRequest.clientRootShare32 &&
    !resolvedBootstrapRequest.clientRootShare32B64u &&
    resolvedBootstrapRequest.thresholdRouteAuth &&
    resolvedBootstrapRequest.sessionId
  ) {
    if (typeof deps.claimPrfFirstByThresholdSessionId !== 'function') {
      throw new Error(
        '[WarmSessionStore] claimPrfFirstByThresholdSessionId is required for threshold-ecdsa authorization bootstrap',
      );
    }
    resolvedBootstrapRequest.clientRootShare32B64u = await deps.claimPrfFirstByThresholdSessionId({
      thresholdSessionId: resolvedBootstrapRequest.sessionId,
      errorContext: 'threshold-ecdsa authorization bootstrap',
      uses: 1,
      walletId: nearAccountId,
      authMethod: args.source === 'email_otp' ? 'email_otp' : 'passkey',
      curve: 'ecdsa',
      chain: args.chain,
      walletSigningSessionId: args.walletSigningSessionId,
    });
  }

  await args.beforeProvision?.();
  args.assertNotCancelled?.();

  const provisioned =
    typeof deps.provisionThresholdEcdsaSession === 'function'
      ? await deps.provisionThresholdEcdsaSession({
          ...args,
          ...resolvedBootstrapRequest,
        })
      : typeof deps.bootstrapThresholdEcdsaSession === 'function'
        ? await deps.bootstrapThresholdEcdsaSession({
            nearAccountId,
            chain: args.chain,
          })
        : null;

  if (!provisioned) {
    throw new Error(
      '[WarmSessionStore] provisionThresholdEcdsaSession is required to provision ECDSA capability',
    );
  }

  args.assertNotCancelled?.();

  const expectedSessionId = toOptionalNonEmptyString(
    provisioned.thresholdEcdsaKeyRef?.thresholdSessionId,
  );
  if (!expectedSessionId) {
    throw new Error(
      `[WarmSessionStore] provisioned ECDSA capability is missing thresholdSessionId for ${nearAccountId}`,
    );
  }

  const afterWarmSession = await deps.getWarmSession(nearAccountId);
  const persistedRecord = readWarmSessionEcdsaRecordByThresholdSessionId(expectedSessionId);
  assertPersistedEcdsaWarmSessionRecord({
    nearAccountId,
    expectedSessionId,
    persistedSessionIdRaw: persistedRecord?.thresholdSessionId,
    fallbackPersistedSessionIdRaw:
      afterWarmSession.capabilities.ecdsa[args.chain].record?.thresholdSessionId,
  });
  emitWarmSessionTransition({
    onTransition: deps.onTransition,
    event: {
      type: 'ecdsa_capability_provisioned',
      accountId: nearAccountId,
      chain: args.chain,
      thresholdSessionId: expectedSessionId,
      before: summarizeWarmSessionTransition(beforeWarmSession),
      after: summarizeWarmSessionTransition(afterWarmSession),
    },
  });
  return provisioned;
}

function buildEcdsaCapabilityInflightKey(args: {
  nearAccountId: AccountId;
  chain: ThresholdEcdsaActivationChain;
  usesNeeded?: number;
  keyRef: ThresholdEcdsaSecp256k1KeyRef | null;
}): string {
  const keyId = String(args.keyRef?.ecdsaThresholdKeyId || '').trim() || 'auto';
  const sessionId = String(args.keyRef?.thresholdSessionId || '').trim() || 'auto';
  const usesNeeded = Math.floor(Number(args.usesNeeded) || 0);
  return [
    String(args.nearAccountId),
    args.chain,
    String(usesNeeded > 0 ? usesNeeded : 1),
    keyId,
    sessionId,
  ].join('::');
}

export async function ensureWarmEcdsaCapabilityReady(
  deps: WarmSessionEcdsaReconnectDeps,
  args: EnsureWarmEcdsaCapabilityReadyArgs,
): Promise<EnsureWarmEcdsaCapabilityReadyResult> {
  const nearAccountId = toAccountId(args.nearAccountId);
  const warmSession = await deps.getWarmSession(nearAccountId);
  const keyRefCandidates: EcdsaKeyRefCandidate[] = args.keyRef
    ? [{ source: args.source || 'manual-bootstrap', keyRef: args.keyRef }]
    : readEcdsaKeyRefCandidates(deps, {
        nearAccountId,
        chain: args.chain,
        ...(args.source ? { source: args.source } : {}),
      });
  let keyRef: ThresholdEcdsaSecp256k1KeyRef | null = null;
  for (const candidate of keyRefCandidates) {
    const capability = getMatchingReadyEcdsaCapability({
      warmSession,
      chain: args.chain,
      keyRef: candidate.keyRef,
      usesNeeded: args.usesNeeded,
    });
    if (!capability) {
      keyRef ||= candidate.keyRef;
      continue;
    }
    return {
      keyRef: candidate.keyRef,
      warmSession,
      capability,
      reconnected: false,
    };
  }
  keyRef ||= keyRefCandidates[0]?.keyRef || null;

  for (const candidate of keyRefCandidates) {
    const keyRefSessionId = String(candidate.keyRef.thresholdSessionId || '').trim();
    if (!keyRefSessionId) continue;
    const directCapability = await deps.readEcdsaCapabilityByThresholdSessionId(keyRefSessionId);
    if (
      directCapability?.chain === args.chain &&
      directCapability.state === 'ready' &&
      hasSufficientWarmClaim(directCapability.prfClaim, args.usesNeeded)
    ) {
      return {
        keyRef: candidate.keyRef,
        warmSession,
        capability: directCapability,
        reconnected: false,
      };
    }
  }

  if (!deps.canProvisionEcdsaCapability) {
    throw new Error(
      '[WarmSessionStore] provisionThresholdEcdsaSession is required to reconnect ECDSA capability',
    );
  }
  if (typeof deps.listThresholdEcdsaKeyRefsForLookup !== 'function') {
    throw new Error(
      '[WarmSessionStore] listThresholdEcdsaKeyRefsForLookup is required to resolve ECDSA capability',
    );
  }

  const reconnectRecord = deps.resolveCurrentEcdsaRecord({
    nearAccountId,
    chain: args.chain,
    ...(args.source ? { source: args.source } : {}),
  });
  const secondaryRecord = args.source
    ? null
    : getPrimaryAndSecondaryEcdsaCapabilities({
        warmSession,
        chain: args.chain,
      }).secondary.record;
  const secondaryEmailOtpRecord = secondaryRecord?.source === 'email_otp' ? secondaryRecord : null;
  if (
    reconnectRecord?.source === 'email_otp' &&
    reconnectRecord.emailOtpAuthContext?.retention === 'single_use'
  ) {
    throw formatEmailOtpSensitiveOperationError({
      operationLabel: `${args.chain} signing`,
      mode: 'per_operation',
    });
  }
  if (
    !reconnectRecord &&
    secondaryEmailOtpRecord?.emailOtpAuthContext?.retention === 'single_use' &&
    Number(secondaryEmailOtpRecord.emailOtpAuthContext.consumedAtMs) > 0
  ) {
    throw formatEmailOtpSensitiveOperationError({
      operationLabel: `${args.chain} signing`,
      mode: 'per_operation',
    });
  }
  const inheritedEmailOtpRecord =
    reconnectRecord?.source === 'email_otp' ? reconnectRecord : secondaryEmailOtpRecord;

  const inflightKey = buildEcdsaCapabilityInflightKey({
    nearAccountId,
    chain: args.chain,
    usesNeeded: args.usesNeeded,
    keyRef,
  });
  let reconnectPromise = deps.reconnectInFlightByCapability.get(inflightKey);
  if (!reconnectPromise) {
    reconnectPromise = (async (): Promise<EnsureWarmEcdsaCapabilityReadyResult> => {
      const reconnectUses = Math.max(1, Math.floor(Number(args.usesNeeded) || 1));
      const provisioned = await deps.provisionEcdsaCapability({
        nearAccountId,
        chain: args.chain,
        source: inheritedEmailOtpRecord ? 'email_otp' : 'manual-bootstrap',
        ...(args.sessionId ? { sessionId: args.sessionId } : {}),
        ...(args.walletSigningSessionId
          ? { walletSigningSessionId: args.walletSigningSessionId }
          : {}),
        ...(args.clientRootShare32B64u ? { clientRootShare32B64u: args.clientRootShare32B64u } : {}),
        ...(args.webauthnAuthentication
          ? { webauthnAuthentication: args.webauthnAuthentication }
          : {}),
        ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
        ...(args.runtimeScopeBootstrap ? { runtimeScopeBootstrap: args.runtimeScopeBootstrap } : {}),
        ...(args.operationIntent ? { operationIntent: args.operationIntent } : {}),
        ...(inheritedEmailOtpRecord?.emailOtpAuthContext
          ? { emailOtpAuthContext: inheritedEmailOtpRecord.emailOtpAuthContext }
          : {}),
        remainingUses: reconnectUses,
        beforeProvision: args.beforeReconnect,
        assertNotCancelled: args.assertNotCancelled,
      });
      args.assertNotCancelled?.();

      const refreshedKeyRef = provisioned.thresholdEcdsaKeyRef;
      const refreshedWarmSession = await deps.getWarmSession(nearAccountId);
      let refreshedCapability = getMatchingReadyEcdsaCapability({
        warmSession: refreshedWarmSession,
        chain: args.chain,
        keyRef: refreshedKeyRef,
        usesNeeded: args.usesNeeded,
      });
      const refreshedSessionId = String(refreshedKeyRef?.thresholdSessionId || '').trim();
      if (!refreshedCapability && refreshedSessionId) {
        const directCapability =
          await deps.readEcdsaCapabilityByThresholdSessionId(refreshedSessionId);
        if (
          directCapability?.chain === args.chain &&
          directCapability.state === 'ready' &&
          hasSufficientWarmClaim(directCapability.prfClaim, args.usesNeeded)
        ) {
          refreshedCapability = directCapability;
        }
      }
      if (!refreshedKeyRef || !refreshedCapability) {
        throw new Error(
          '[WarmSessionStore] threshold ECDSA warm capability is not ready after reconnect',
        );
      }

      emitWarmSessionTransition({
        onTransition: deps.onTransition,
        event: {
          type: 'ecdsa_capability_reconnected',
          accountId: nearAccountId,
          chain: args.chain,
          thresholdSessionId: String(refreshedKeyRef.thresholdSessionId || '').trim(),
          before: summarizeWarmSessionTransition(warmSession),
          after: summarizeWarmSessionTransition(refreshedWarmSession),
        },
      });

      return {
        keyRef: refreshedKeyRef,
        warmSession: refreshedWarmSession,
        capability: refreshedCapability,
        reconnected: true,
      };
    })();
    deps.reconnectInFlightByCapability.set(inflightKey, reconnectPromise);
    void reconnectPromise.then(
      () => {
        if (deps.reconnectInFlightByCapability.get(inflightKey) === reconnectPromise) {
          deps.reconnectInFlightByCapability.delete(inflightKey);
        }
      },
      () => {
        if (deps.reconnectInFlightByCapability.get(inflightKey) === reconnectPromise) {
          deps.reconnectInFlightByCapability.delete(inflightKey);
        }
      },
    );
  }

  const reconnectedCapability = await reconnectPromise;
  args.assertNotCancelled?.();
  return reconnectedCapability;
}
export function getMatchingReadyEcdsaCapability(args: {
  warmSession: WarmSessionEnvelope;
  chain: ThresholdEcdsaActivationChain;
  keyRef: ThresholdEcdsaSecp256k1KeyRef | null;
  usesNeeded?: number;
}): WarmSessionEcdsaCapabilityState | null {
  const capability = args.warmSession.capabilities.ecdsa[args.chain];
  if (!args.keyRef || capability.state !== 'ready') return null;

  const recordSessionId = String(capability.record?.thresholdSessionId || '').trim();
  const keyRefSessionId = String(args.keyRef.thresholdSessionId || '').trim();
  if (!recordSessionId || !keyRefSessionId || recordSessionId !== keyRefSessionId) {
    return null;
  }

  const recordThresholdKeyId = String(capability.record?.ecdsaThresholdKeyId || '').trim();
  const keyRefThresholdKeyId = String(args.keyRef.ecdsaThresholdKeyId || '').trim();
  if (!recordThresholdKeyId || (keyRefThresholdKeyId && recordThresholdKeyId !== keyRefThresholdKeyId)) {
    return null;
  }

  if (!hasSufficientWarmClaim(capability.prfClaim, args.usesNeeded)) {
    return null;
  }

  return capability;
}

export function normalizeParticipantIds(participantIds: unknown): number[] | undefined {
  if (!Array.isArray(participantIds)) return undefined;
  const normalized = participantIds
    .map((value) => Number(value))
    .filter((value) => Number.isFinite(value));
  return normalized.length ? normalized : undefined;
}

export function toOptionalNonEmptyString(value: unknown): string | undefined {
  const normalized = String(value || '').trim();
  return normalized || undefined;
}

export function getEcdsaCapabilityCandidates(args: {
  warmSession: WarmSessionEnvelope;
  chain: ThresholdEcdsaActivationChain;
}): WarmSessionEcdsaCapabilityState[] {
  const primary = args.warmSession.capabilities.ecdsa[args.chain];
  const secondary =
    args.chain === 'tempo'
      ? args.warmSession.capabilities.ecdsa.evm
      : args.warmSession.capabilities.ecdsa.tempo;
  return primary === secondary ? [primary] : [primary, secondary];
}

export function getPrimaryAndSecondaryEcdsaCapabilities(args: {
  warmSession: WarmSessionEnvelope;
  chain: ThresholdEcdsaActivationChain;
}): {
  primary: WarmSessionEcdsaCapabilityState;
  secondary: WarmSessionEcdsaCapabilityState;
} {
  return {
    primary: args.warmSession.capabilities.ecdsa[args.chain],
    secondary:
      args.chain === 'tempo'
        ? args.warmSession.capabilities.ecdsa.evm
        : args.warmSession.capabilities.ecdsa.tempo,
  };
}

export function buildReusableEcdsaBootstrapResult(args: {
  keyRef: ThresholdEcdsaSecp256k1KeyRef;
  capability: WarmSessionEcdsaCapabilityState;
  source: 'login' | 'registration' | 'manual-bootstrap' | 'email_otp';
}): ThresholdEcdsaSessionBootstrapResult | null {
  const record = args.capability.record;
  const auth = args.capability.auth;
  const prfClaim = args.capability.prfClaim;
  if (!record || !auth || !prfClaim || prfClaim.state !== 'warm') return null;

  const clientVerifyingShareB64u = String(record.clientVerifyingShareB64u || '').trim();
  const relayerKeyId = String(record.relayerKeyId || '').trim();
  const sessionId = String(record.thresholdSessionId || '').trim();
  if (!clientVerifyingShareB64u || !relayerKeyId || !sessionId) return null;

  return {
    thresholdEcdsaKeyRef: {
      ...args.keyRef,
      relayerUrl: String(record.relayerUrl || args.keyRef.relayerUrl || '').trim(),
      ecdsaThresholdKeyId: String(
        record.ecdsaThresholdKeyId || args.keyRef.ecdsaThresholdKeyId || '',
      ).trim(),
      participantIds: record.participantIds,
      thresholdSessionKind: record.thresholdSessionKind,
      thresholdSessionId: sessionId,
      thresholdSessionJwt: String(
        auth.thresholdSessionJwt || args.keyRef.thresholdSessionJwt || '',
      ).trim(),
    },
    keygen: {
      ok: true,
      ecdsaThresholdKeyId: String(record.ecdsaThresholdKeyId || '').trim(),
      relayerKeyId,
      clientVerifyingShareB64u,
      ...(String(record.clientAdditiveShare32B64u || '').trim()
        ? { clientAdditiveShare32B64u: String(record.clientAdditiveShare32B64u || '').trim() }
        : {}),
      participantIds: record.participantIds,
      thresholdEcdsaPublicKeyB64u: record.thresholdEcdsaPublicKeyB64u,
      ethereumAddress: record.ethereumAddress,
      relayerVerifyingShareB64u: record.relayerVerifyingShareB64u,
    },
    session: {
      ok: true,
      sessionId,
      ...(String(auth.thresholdSessionJwt || '').trim()
        ? { jwt: String(auth.thresholdSessionJwt || '').trim() }
        : {}),
      expiresAtMs: prfClaim.expiresAtMs,
      remainingUses: prfClaim.remainingUses,
      clientVerifyingShareB64u,
    },
  };
}
