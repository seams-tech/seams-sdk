import type {
  WarmSessionStatusBatchReader,
  WarmSessionStatusReader,
} from '@/core/signingEngine/uiConfirm/types';
import type {
  WarmSessionMaterialClaimer,
  WarmSessionSealPersister,
} from '@/core/signingEngine/uiConfirm/types';
import type {
  ThresholdEcdsaSessionBootstrapResult,
  ThresholdEcdsaActivationChain,
} from '@/core/signingEngine/threshold/ecdsa/activation';
import type { EcdsaBootstrapRequest } from '@/core/signingEngine/session/passkey/ecdsaBootstrap';
import type { AccountId } from '@/core/types/accountIds';
import type { WarmSessionSealAndPersistPayload } from '@/core/types/secure-confirm-worker';
import {
  clearAllStoredThresholdEd25519SessionRecords,
  clearAllThresholdEcdsaSessionRecords,
  listThresholdEcdsaSessionRecordsForSubject,
  type ThresholdEcdsaSessionRecord,
  upsertStoredThresholdEd25519SessionRecord,
  upsertThresholdEcdsaSessionFromBootstrap,
  type ThresholdEcdsaKeyRefLookupResult,
  type ThresholdEcdsaSessionStoreDeps,
  type ThresholdEd25519SessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import type {
  ThresholdEcdsaEmailOtpAuthContext,
  ThresholdEcdsaSessionStoreSource,
} from '@/core/signingEngine/session/identity/laneIdentity';
import type { WarmSessionStatusResult } from '@/core/signingEngine/uiConfirm/types';
import {
  createWarmSessionCapabilityReader,
} from '@/core/signingEngine/session/warmCapabilities/capabilityReader';
import {
  buildEcdsaSessionProvisionPlan,
  buildEcdsaSessionIdentity,
  buildEcdsaSigningKeyContext,
  type EcdsaSessionProvisionPlan,
} from '@/core/signingEngine/session/warmCapabilities/ecdsaProvisionPlan';
import {
  ensureWarmEcdsaCapabilityReady,
  getPrimaryAndSecondaryEcdsaCapabilities,
  normalizeParticipantIds,
  toOptionalNonEmptyString,
  tryReuseReadyWarmEcdsaBootstrap,
} from '@/core/signingEngine/session/passkey/ecdsaProvisioner';
import { provisionWarmEd25519Capability } from '@/core/signingEngine/session/passkey/ed25519Provisioner';
import {
  applyWarmSessionEcdsaPostSignPolicy,
  assertWarmSessionEcdsaOperationAllowed,
} from '@/core/signingEngine/session/operationState/warmSessionPolicyAdapter';
import {
  createWarmSessionStatusReader as createCoreWarmSessionStatusReader,
} from '@/core/signingEngine/session/warmCapabilities/statusReader';
import { claimWarmSessionPrfFirst } from '@/core/signingEngine/session/passkey/prfClaim';
import { ensureEcdsaPrfSealPersisted } from '@/core/signingEngine/session/passkey/runtime';
import type {
  EnsureWarmEcdsaCapabilityReadyResult,
  ProvisionWarmEd25519CapabilityArgs,
  ProvisionWarmEd25519CapabilityResult,
} from '@/core/signingEngine/session/warmCapabilities/types';
import {
  thresholdEcdsaChainTargetFromChainFamily,
  toWalletSubjectId,
  type ThresholdEcdsaChainTarget,
  type WalletSubjectId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';

function testEcdsaChainId(chain: ThresholdEcdsaActivationChain): number {
  return chain === 'tempo' ? 42431 : 11155111;
}
export function testEcdsaChainTarget(
  chain: ThresholdEcdsaActivationChain,
): ThresholdEcdsaChainTarget {
  return thresholdEcdsaChainTargetFromChainFamily({
    chain,
    chainId: testEcdsaChainId(chain),
  });
}
import type { WarmSessionTransitionEvent } from '@/core/signingEngine/session/warmCapabilities/transitions';

type SessionStorageMock = {
  getItem: (key: string) => string | null;
  setItem: (key: string, value: string) => void;
  removeItem: (key: string) => void;
  clear: () => void;
};

export type WarmClaimFixture =
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

export function ensureWarmSessionTestStorage(): SessionStorageMock {
  const globalObj = globalThis as { sessionStorage?: SessionStorageMock };
  if (globalObj.sessionStorage) return globalObj.sessionStorage;

  const store = new Map<string, string>();
  const sessionStorage: SessionStorageMock = {
    getItem: (key) => (store.has(key) ? String(store.get(key)) : null),
    setItem: (key, value) => {
      store.set(String(key), String(value));
    },
    removeItem: (key) => {
      store.delete(String(key));
    },
    clear: () => {
      store.clear();
    },
  };
  globalObj.sessionStorage = sessionStorage;
  return sessionStorage;
}

export function createThresholdEcdsaStoreFixture(): ThresholdEcdsaSessionStoreDeps {
  return {
    recordsByLane: new Map(),
    exportArtifactsByLane: new Map(),
  };
}

export function resetWarmSessionFixtureState(deps: ThresholdEcdsaSessionStoreDeps): void {
  ensureWarmSessionTestStorage().clear();
  clearAllStoredThresholdEd25519SessionRecords();
  clearAllThresholdEcdsaSessionRecords(deps);
}

export function seedEd25519WarmSessionRecord(
  args: Partial<ThresholdEd25519SessionRecord> & {
    nearAccountId: string;
    thresholdSessionId: string;
  },
): ThresholdEd25519SessionRecord {
  const emailOtpAuthContext =
    args.emailOtpAuthContext ||
    (args.source === 'email_otp'
      ? ({
          policy: 'session',
          retention: 'session',
          reason: 'login',
          authMethod: 'email_otp',
        } satisfies ThresholdEcdsaEmailOtpAuthContext)
      : undefined);
  const record = upsertStoredThresholdEd25519SessionRecord({
    nearAccountId: args.nearAccountId,
    rpId: args.rpId || 'wallet.example.test',
    relayerUrl: args.relayerUrl || 'https://relay.example',
    relayerKeyId: args.relayerKeyId || 'rk-ed25519',
    participantIds: args.participantIds || [1, 2],
    ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
    ...(args.xClientBaseB64u ? { xClientBaseB64u: args.xClientBaseB64u } : {}),
    thresholdSessionKind: args.thresholdSessionKind || 'jwt',
    thresholdSessionId: args.thresholdSessionId,
    walletSigningSessionId:
      args.walletSigningSessionId || `wsess-${String(args.thresholdSessionId).trim()}`,
    ...(args.thresholdSessionAuthToken ? { thresholdSessionAuthToken: args.thresholdSessionAuthToken } : {}),
    expiresAtMs: args.expiresAtMs ?? Date.now() + 120_000,
    remainingUses: args.remainingUses ?? 7,
    ...(emailOtpAuthContext ? { emailOtpAuthContext } : {}),
    updatedAtMs: args.updatedAtMs ?? Date.now(),
    source: args.source || 'login',
  });
  if (!record) {
    throw new Error(`Failed to seed Ed25519 warm-session record for ${args.nearAccountId}`);
  }
  return record;
}

export function createThresholdEcdsaBootstrapFixture(args: {
  nearAccountId: string;
  chain: ThresholdEcdsaActivationChain;
  ecdsaThresholdKeyId?: string;
  sessionId?: string;
  sessionAuthToken?: string;
  sessionKind?: 'jwt' | 'cookie';
  relayerUrl?: string;
  relayerKeyId?: string;
  clientVerifyingShareB64u?: string;
  clientAdditiveShare32B64u?: string;
  participantIds?: number[];
  ethereumAddress?: string;
  walletSigningSessionId?: string;
  signingRootId?: string;
  signingRootVersion?: string;
}): ThresholdEcdsaSessionBootstrapResult {
  const chainLabel = args.chain;
  const ecdsaThresholdKeyId = String(
    args.ecdsaThresholdKeyId || `ek-${chainLabel}-1`,
  ).trim();
  const sessionId = String(args.sessionId || `sess-${chainLabel}-1`).trim();
  const sessionKind = args.sessionKind || 'jwt';
  const relayerUrl = String(args.relayerUrl || 'https://relay.example').trim();
  const relayerKeyId = String(args.relayerKeyId || `rk-${chainLabel}-1`).trim();
  const clientVerifyingShareB64u = String(
    args.clientVerifyingShareB64u || `cvs-${chainLabel}-1`,
  ).trim();
  const clientAdditiveShare32B64u = String(
    args.clientAdditiveShare32B64u || `cas-${chainLabel}-1`,
  ).trim();
  const participantIds = args.participantIds || [1, 2];
  const ethereumAddress = args.ethereumAddress || `0x${'11'.repeat(20)}`;
  const walletSigningSessionId = String(
    args.walletSigningSessionId || `wsess-${sessionId}`,
  ).trim();
  const signingRootId = String(args.signingRootId || 'sr-test:dev').trim();
  const signingRootVersion = String(args.signingRootVersion || 'default').trim();
  const chainTarget = thresholdEcdsaChainTargetFromChainFamily({
    chain: args.chain,
    chainId: testEcdsaChainId(args.chain),
  });
  const sessionAuthToken =
    sessionKind === 'jwt'
      ? toFixtureThresholdSessionAuthToken(
          String(args.sessionAuthToken || `jwt:${sessionId}`).trim(),
          {
            nearAccountId: args.nearAccountId,
            sessionId,
            walletSigningSessionId,
            relayerKeyId,
            ecdsaThresholdKeyId,
            participantIds,
            chainTarget,
          },
        )
      : '';

  return {
    thresholdEcdsaKeyRef: {
      type: 'threshold-ecdsa-secp256k1',
      userId: args.nearAccountId,
      subjectId: toWalletSubjectId(args.nearAccountId),
      chainTarget,
      relayerUrl,
      ecdsaThresholdKeyId,
      signingRootId,
      signingRootVersion,
      participantIds: [...participantIds],
      backendBinding: {
        relayerKeyId,
        clientVerifyingShareB64u,
        clientAdditiveShare32B64u,
      },
      thresholdSessionKind: sessionKind,
      thresholdSessionId: sessionId,
      walletSigningSessionId,
      ...(sessionAuthToken ? { thresholdSessionAuthToken: sessionAuthToken } : {}),
      ethereumAddress,
      thresholdEcdsaPublicKeyB64u: `pub-${chainLabel}-b64u`,
      relayerVerifyingShareB64u: `relayer-${chainLabel}-share-b64u`,
    },
    keygen: {
      ok: true,
      ecdsaThresholdKeyId,
      clientVerifyingShareB64u,
      relayerKeyId,
      participantIds: [...participantIds],
      ethereumAddress,
      thresholdEcdsaPublicKeyB64u: `pub-${chainLabel}-b64u`,
      relayerVerifyingShareB64u: `relayer-${chainLabel}-share-b64u`,
    },
    session: {
      ok: true,
      sessionId,
      walletSigningSessionId,
      expiresAtMs: Date.now() + 120_000,
      remainingUses: 5,
      ...(sessionAuthToken ? { jwt: sessionAuthToken } : {}),
      clientVerifyingShareB64u,
    },
  };
}

function toFixtureThresholdSessionAuthToken(
  token: string,
  args: {
    nearAccountId: string;
    sessionId: string;
    walletSigningSessionId: string;
    relayerKeyId: string;
    ecdsaThresholdKeyId: string;
    participantIds: number[];
    chainTarget: ThresholdEcdsaChainTarget;
  },
): string {
  if (token.split('.').length === 3) return token;
  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(
    JSON.stringify({
      sub: args.nearAccountId,
      walletId: args.nearAccountId,
      kind: 'threshold_ecdsa_session_v1',
      sessionId: args.sessionId,
      walletSigningSessionId: args.walletSigningSessionId,
      subjectId: args.nearAccountId,
      chainTarget: args.chainTarget,
      ecdsaThresholdKeyId: args.ecdsaThresholdKeyId,
      relayerKeyId: args.relayerKeyId,
      rpId: 'localhost',
      thresholdExpiresAtMs: Date.now() + 120_000,
      participantIds: args.participantIds,
    }),
  ).toString('base64url');
  return `${header}.${payload}.fixture`;
}

export function seedEcdsaWarmSessionRecord(
  deps: ThresholdEcdsaSessionStoreDeps,
  args: {
    nearAccountId: string;
    chain: ThresholdEcdsaActivationChain;
    source?: 'login' | 'registration' | 'manual-bootstrap' | 'email_otp';
    emailOtpAuthContext?: ThresholdEcdsaEmailOtpAuthContext;
    bootstrap?: ThresholdEcdsaSessionBootstrapResult;
    signingSessionSeal?: {
      keyVersion?: string;
      shamirPrimeB64u?: string;
    };
  },
) {
  const emailOtpAuthContext =
    args.emailOtpAuthContext ||
    (args.source === 'email_otp'
      ? ({
          policy: 'session',
          retention: 'session',
          reason: 'login',
          authMethod: 'email_otp',
        } satisfies ThresholdEcdsaEmailOtpAuthContext)
      : undefined);
  return upsertThresholdEcdsaSessionFromBootstrap(deps, {
    nearAccountId: args.nearAccountId,
    chainTarget: args.bootstrap?.thresholdEcdsaKeyRef.chainTarget || testEcdsaChainTarget(args.chain),
    bootstrap:
      args.bootstrap ||
      createThresholdEcdsaBootstrapFixture({
        nearAccountId: args.nearAccountId,
        chain: args.chain,
      }),
    source: args.source || 'login',
    ...(emailOtpAuthContext ? { emailOtpAuthContext } : {}),
    ...(args.signingSessionSeal ? { signingSessionSeal: args.signingSessionSeal } : {}),
  });
}

export function createWarmSessionStatusReader(
  claimsBySessionId: Record<string, WarmClaimFixture>,
): Pick<WarmSessionStatusReader & WarmSessionStatusBatchReader, 'getWarmSessionStatus' | 'getWarmSessionStatuses'> {
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
    WarmSessionStatusReader &
      WarmSessionMaterialClaimer &
      WarmSessionSealPersister,
    | 'getWarmSessionStatus'
    | 'claimWarmSessionMaterial'
    | 'sealAndPersistWarmSessionMaterial'
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

type WarmSessionTestServicesDeps = {
  touchConfirm?: Partial<
    Pick<
      WarmSessionStatusReader &
        WarmSessionStatusBatchReader &
        WarmSessionMaterialClaimer &
        WarmSessionSealPersister & {
          clearWarmSessionMaterial(args: { sessionId: string }): Promise<void>;
        },
      | 'getWarmSessionStatus'
      | 'getWarmSessionStatuses'
      | 'claimWarmSessionMaterial'
      | 'sealAndPersistWarmSessionMaterial'
      | 'clearWarmSessionMaterial'
    >
  >;
  clearThresholdEcdsaSessionRecordForLane?: (args: {
    subjectId: WalletSubjectId;
    chainTarget: ThresholdEcdsaChainTarget;
    source?: ThresholdEcdsaSessionStoreSource;
  }) => void;
  markThresholdEcdsaEmailOtpSessionConsumedForAccount?: (args: {
    nearAccountId: AccountId | string;
    chainTarget: ThresholdEcdsaChainTarget;
    uses?: number;
  }) => void;
  clearThresholdEcdsaSigningArtifactsForLane?: (args: {
    record: ThresholdEcdsaSessionRecord;
  }) => void | Promise<void>;
  listThresholdEcdsaSessionRecordsForSubject?: (args: {
    subjectId: WalletSubjectId;
  }) => ThresholdEcdsaSessionRecord[];
  getThresholdEcdsaSessionRecordByThresholdSessionId?: (
    thresholdSessionId: string,
  ) => ThresholdEcdsaSessionRecord | null;
  signingSessionSeal?: {
    keyVersion?: string;
    shamirPrimeB64u?: string;
  };
  getEmailOtpWarmSessionStatus?: (sessionId: string) => Promise<WarmSessionStatusResult>;
  listThresholdEcdsaKeyRefsForAccountTarget?: (args: {
    nearAccountId: AccountId | string;
    subjectId: WalletSubjectId;
    chainTarget: ThresholdEcdsaChainTarget;
    source?: ThresholdEcdsaSessionStoreSource;
  }) => ThresholdEcdsaKeyRefLookupResult[];
  provisionThresholdEcdsaSession?: (
    args: EcdsaBootstrapRequest,
  ) => Promise<ThresholdEcdsaSessionBootstrapResult>;
  provisionThresholdEd25519Session?: (
    args: ProvisionWarmEd25519CapabilityArgs,
  ) => Promise<ProvisionWarmEd25519CapabilityResult>;
  onTransition?: (event: WarmSessionTransitionEvent) => void | Promise<void>;
};

const emptyThresholdEcdsaStoreDeps = (): ThresholdEcdsaSessionStoreDeps => ({
  recordsByLane: new Map(),
  exportArtifactsByLane: new Map(),
});

function resolveTestEcdsaBootstrapArgs(args: {
  request: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    source?: ThresholdEcdsaSessionStoreSource;
  };
  warmSession: Awaited<ReturnType<ReturnType<typeof createWarmSessionCapabilityReader>['getWarmSession']>>;
}): EcdsaBootstrapRequest {
  const chainTarget = testEcdsaChainTarget(args.request.chain);
  const subjectId = toWalletSubjectId(args.request.nearAccountId);
  const { primary, secondary } = getPrimaryAndSecondaryEcdsaCapabilities({
    warmSession: args.warmSession,
    chainTarget,
  });
  const reusableWarmCapability = primary.prfClaim?.state === 'warm' ? primary : null;
  const preferredMetadataCapability = primary.record
    ? primary
    : secondary.record
      ? secondary
      : null;
  const participantIds =
    normalizeParticipantIds(primary.record?.participantIds) ||
    normalizeParticipantIds(secondary.record?.participantIds);
  const baseArgs = {
    nearAccountId: args.request.nearAccountId,
    subjectId,
    chainTarget,
    kind: 'reuse_warm_ecdsa_bootstrap' as const,
    ...(args.request.source ? { source: args.request.source } : {}),
    ...(preferredMetadataCapability?.record?.relayerUrl
      ? { relayerUrl: preferredMetadataCapability.record.relayerUrl }
      : {}),
    ...(primary.record?.ecdsaThresholdKeyId
      ? { ecdsaThresholdKeyId: primary.record.ecdsaThresholdKeyId }
      : secondary.record?.ecdsaThresholdKeyId
        ? { ecdsaThresholdKeyId: secondary.record.ecdsaThresholdKeyId }
        : {}),
    ...(participantIds ? { participantIds } : {}),
    sessionKind: primary.record?.thresholdSessionKind || secondary.record?.thresholdSessionKind || 'jwt',
  };

  const sessionId = toOptionalNonEmptyString(reusableWarmCapability?.record?.thresholdSessionId);
  const walletSigningSessionId = toOptionalNonEmptyString(
    reusableWarmCapability?.record?.walletSigningSessionId,
  );
  const thresholdSessionAuthToken = toOptionalNonEmptyString(
    reusableWarmCapability?.auth?.thresholdSessionAuthToken,
  );

  if (sessionId && walletSigningSessionId && thresholdSessionAuthToken) {
    return {
      ...baseArgs,
      kind: 'threshold_session_auth_reconnect_ecdsa_bootstrap',
      sessionKind: 'jwt',
      sessionIdentity: {
        thresholdSessionId: sessionId,
        walletSigningSessionId,
      },
      routeAuth: {
        kind: 'threshold_session',
        jwt: thresholdSessionAuthToken,
      },
    };
  }
  if (sessionId && walletSigningSessionId) {
    return {
      ...baseArgs,
      kind: 'passkey_cookie_reconnect_ecdsa_bootstrap',
      sessionKind: 'cookie',
      sessionIdentity: {
        thresholdSessionId: sessionId,
        walletSigningSessionId,
      },
    };
  }
  return baseArgs;
}

export function createWarmSessionTestServices(deps: WarmSessionTestServicesDeps = {}) {
  const reconnectInFlightByCapability = new Map<
    string,
    Promise<EnsureWarmEcdsaCapabilityReadyResult>
  >();
  const sealPersistInFlightBySessionId = new Map<string, Promise<void>>();
  const getEmailOtpWarmSessionStatus =
    deps.getEmailOtpWarmSessionStatus ||
    (async (sessionId: string): Promise<WarmSessionStatusResult> => {
      if (typeof deps.touchConfirm?.getWarmSessionStatus === 'function') {
        return await deps.touchConfirm.getWarmSessionStatus({ sessionId });
      }
      return {
        ok: false,
        code: 'not_found',
        message: 'Email OTP warm-session status reader is unavailable',
      };
    });
  const statusReader = createCoreWarmSessionStatusReader({
    touchConfirm: deps.touchConfirm,
    getEmailOtpWarmSessionStatus,
    listThresholdEcdsaSessionRecordsForSubject:
      deps.listThresholdEcdsaSessionRecordsForSubject ||
      ((args) => listThresholdEcdsaSessionRecordsForSubject(emptyThresholdEcdsaStoreDeps(), args)),
    getThresholdEcdsaSessionRecordByThresholdSessionId:
      deps.getThresholdEcdsaSessionRecordByThresholdSessionId,
  });
  const clearEcdsaEphemeralMaterial = async (args: {
    record: ThresholdEcdsaSessionRecord;
    thresholdSessionId?: string;
  }): Promise<void> => {
    const thresholdSessionId = String(args.thresholdSessionId || '').trim();
    if (typeof deps.clearThresholdEcdsaSigningArtifactsForLane === 'function') {
      await Promise.resolve(
        deps.clearThresholdEcdsaSigningArtifactsForLane({
          record: args.record,
        }),
      ).catch(() => undefined);
    }
    if (thresholdSessionId && typeof deps.touchConfirm?.clearWarmSessionMaterial === 'function') {
      await deps.touchConfirm
        .clearWarmSessionMaterial({ sessionId: thresholdSessionId })
        .catch(() => undefined);
    }
  };
  const capabilityReader = createWarmSessionCapabilityReader({
    touchConfirm: deps.touchConfirm,
    signingSessionSeal: deps.signingSessionSeal,
    getEmailOtpWarmSessionStatus,
    listThresholdEcdsaSessionRecordsForSubject:
      deps.listThresholdEcdsaSessionRecordsForSubject ||
      ((args) => listThresholdEcdsaSessionRecordsForSubject(emptyThresholdEcdsaStoreDeps(), args)),
    getThresholdEcdsaSessionRecordByThresholdSessionId:
      deps.getThresholdEcdsaSessionRecordByThresholdSessionId,
  });
  const getWarmSession = (nearAccountId: AccountId | string) =>
    capabilityReader.getWarmSession(nearAccountId);
  const claimPrfFirstByThresholdSessionId = (args: {
    thresholdSessionId: string;
    errorContext: string;
    uses?: number;
  }) =>
    claimWarmSessionPrfFirst({
      touchConfirm: deps.touchConfirm,
      thresholdSessionId: args.thresholdSessionId,
      errorContext: args.errorContext,
      uses: args.uses,
    });
  const provisionEcdsaCapability = async (args: EcdsaBootstrapRequest) => {
    const provisionThresholdEcdsaSession =
      deps.provisionThresholdEcdsaSession ||
      (async () => {
        throw new Error('provisionThresholdEcdsaSession test dependency is required');
      });
    const requiresClaim =
      args.kind === 'passkey_cookie_reconnect_ecdsa_bootstrap';
    if (!requiresClaim) {
      return await provisionThresholdEcdsaSession(args);
    }
    const clientRootShare32B64u = await claimPrfFirstByThresholdSessionId({
      kind: 'threshold_only_claim',
      thresholdSessionId: args.sessionIdentity.thresholdSessionId,
      errorContext: 'threshold-ecdsa restored-session bootstrap',
      uses: 1,
    });
    return await provisionThresholdEcdsaSession({
      ...args,
      kind: 'passkey_fresh_ecdsa_bootstrap',
      sessionKind: 'cookie',
      clientRootShare32B64u,
    });
  };

  return {
    getWarmSession,
    resolveEd25519RecordByThresholdSessionId:
      capabilityReader.resolveEd25519RecordByThresholdSessionId,
    resolveEcdsaRecordByThresholdSessionId:
      capabilityReader.resolveEcdsaRecordByThresholdSessionId,
    resolveEd25519AuthByThresholdSessionId:
      capabilityReader.resolveEd25519AuthByThresholdSessionId,
    resolveEcdsaAuthByThresholdSessionId: capabilityReader.resolveEcdsaAuthByThresholdSessionId,
    resolveEmailOtpSigningSessionAuthLane:
      capabilityReader.resolveEmailOtpSigningSessionAuthLane,
    getEd25519CapabilityByThresholdSessionId:
      capabilityReader.getEd25519CapabilityByThresholdSessionId,
    getEcdsaCapabilityByThresholdSessionId:
      capabilityReader.getEcdsaCapabilityByThresholdSessionId,
    resolveEcdsaSealTransportByThresholdSessionId:
      capabilityReader.resolveEcdsaSealTransportByThresholdSessionId,
    provisionEd25519Capability: (args: ProvisionWarmEd25519CapabilityArgs) =>
      provisionWarmEd25519Capability(
        {
          getWarmSession,
          provisionThresholdEd25519Session: deps.provisionThresholdEd25519Session,
          onTransition: deps.onTransition,
        },
        args,
      ),
    resolveEcdsaBootstrapRequest: async (args: {
      nearAccountId: AccountId | string;
      chain: ThresholdEcdsaActivationChain;
      source?: ThresholdEcdsaSessionStoreSource;
    }) =>
      resolveTestEcdsaBootstrapArgs({
        request: args,
        warmSession: await getWarmSession(args.nearAccountId),
      }),
    provisionEcdsaCapability,
    tryReuseReadyEcdsaBootstrap: (args: {
      nearAccountId: AccountId | string;
      chain: ThresholdEcdsaActivationChain;
      source?: ThresholdEcdsaSessionStoreSource;
    }) =>
      tryReuseReadyWarmEcdsaBootstrap(
        {
          getWarmSession,
          listThresholdEcdsaKeyRefsForAccountTarget: deps.listThresholdEcdsaKeyRefsForAccountTarget,
          provisionThresholdEcdsaSession:
            deps.provisionThresholdEcdsaSession ||
            (async () => {
              throw new Error('provisionThresholdEcdsaSession test dependency is required');
            }),
        },
        {
          ...args,
          subjectId: toWalletSubjectId(args.nearAccountId),
          chainTarget: testEcdsaChainTarget(args.chain),
        },
      ),
    ensureEcdsaCapabilityReady: (args: {
      nearAccountId: AccountId | string;
      chain: ThresholdEcdsaActivationChain;
      source?: ThresholdEcdsaSessionStoreSource;
      usesNeeded?: number;
      plan?: EcdsaSessionProvisionPlan;
      [key: string]: unknown;
    }) =>
      ensureWarmEcdsaCapabilityReady(
        {
          getWarmSession,
          listThresholdEcdsaKeyRefsForAccountTarget: deps.listThresholdEcdsaKeyRefsForAccountTarget,
          canProvisionEcdsaCapability:
            typeof deps.provisionThresholdEcdsaSession === 'function',
          provisionThresholdEcdsaSession:
            deps.provisionThresholdEcdsaSession ||
            (async () => {
              throw new Error('provisionThresholdEcdsaSession test dependency is required');
            }),
          resolveCurrentEcdsaRecord: (recordArgs) =>
            statusReader.resolveCurrentEcdsaRecord(recordArgs),
          readEcdsaCapabilityByThresholdSessionId:
            capabilityReader.getEcdsaCapabilityByThresholdSessionId,
          reconnectInFlightByCapability,
          onTransition: deps.onTransition,
        },
        {
          ...args,
          subjectId: toWalletSubjectId(args.nearAccountId),
          chainTarget: testEcdsaChainTarget(args.chain),
          plan:
            (args.plan as EcdsaSessionProvisionPlan | undefined) ||
            (() => {
              const chainTarget = testEcdsaChainTarget(args.chain);
              const subjectId = toWalletSubjectId(args.nearAccountId);
              const record = statusReader.resolveCurrentEcdsaRecord({
                nearAccountId: args.nearAccountId,
                chainTarget,
                ...(args.source ? { source: args.source } : {}),
              });
              const keyRefCandidate =
                deps.listThresholdEcdsaKeyRefsForAccountTarget?.({
                  nearAccountId: args.nearAccountId,
                  subjectId,
                  chainTarget,
                  ...(args.source ? { source: args.source } : {}),
                })[0]?.keyRef || null;
              const identity = buildEcdsaSessionIdentity({
                thresholdSessionId:
                  args.thresholdSessionId || keyRefCandidate?.thresholdSessionId || record?.thresholdSessionId,
                walletSigningSessionId:
                  args.walletSigningSessionId ||
                  keyRefCandidate?.walletSigningSessionId ||
                  record?.walletSigningSessionId,
              });
              const signingKeyContext = buildEcdsaSigningKeyContext({
                keyRef: keyRefCandidate,
                record,
              });
              return buildEcdsaSessionProvisionPlan({
                kind: args.clientRootShare32B64u
                  ? 'passkey_ecdsa_session_provision'
                  : 'ecdsa_session_reconnect',
                subjectId,
                chainTarget,
                sessionIdentity: identity,
                signingKeyContext,
                sessionBudgetUses: Number(args.sessionBudgetUses || 1),
                ...(args.clientRootShare32B64u
                  ? {
                      sessionKind:
                        record?.thresholdSessionKind || keyRefCandidate?.thresholdSessionKind || 'jwt',
                      clientRootShare32B64u: String(args.clientRootShare32B64u || ''),
                      webauthnAuthentication: {
                        id: 'test-credential',
                        rawId: 'test-raw-id',
                        type: 'public-key',
                        authenticatorAttachment: 'platform',
                        response: {
                          clientDataJSON: 'test-client-data',
                          authenticatorData: 'test-authenticator-data',
                          signature: 'test-signature',
                          userHandle: undefined,
                        },
                        clientExtensionResults: {
                          prf: {
                            results: {
                              first: String(args.clientRootShare32B64u || ''),
                              second: undefined,
                            },
                          },
                        },
                      },
                      ...(record?.runtimePolicyScope
                        ? { runtimePolicyScope: record.runtimePolicyScope }
                        : {}),
                    }
                  : {
                      reconnectMaterial:
                        keyRefCandidate && record
                          ? {
                              kind: 'record_and_key_ref' as const,
                              keyRef: keyRefCandidate,
                              record,
                            }
                          : record
                            ? {
                                kind: 'record_only' as const,
                                record,
                              }
                            : keyRefCandidate
                              ? {
                                  kind: 'key_ref_only' as const,
                                  keyRef: keyRefCandidate,
                                }
                              : (() => {
                                  throw new Error('ECDSA reconnect plan requires a record or key ref');
                                })(),
                    }),
              });
            })(),
          sessionBudgetUses: Number(args.sessionBudgetUses || 1),
        },
      ),
    assertEcdsaSigningSessionReady: statusReader.assertEcdsaSigningSessionReady,
    getEd25519SigningSessionStatus: statusReader.getEd25519SigningSessionStatus,
    getEd25519SigningSessionStatusForSession:
      statusReader.getEd25519SigningSessionStatusForSession,
    getEcdsaSigningSessionStatus: statusReader.getEcdsaSigningSessionStatus,
    listEcdsaSigningSessionStatuses: statusReader.listEcdsaSigningSessionStatuses,
    claimPrfFirstByThresholdSessionId,
    ensureEcdsaPrfSealPersistedByThresholdSessionId: (args: {
      chain?: ThresholdEcdsaActivationChain;
      thresholdSessionId: string;
      required?: boolean;
      errorContext?: string;
    }) =>
      ensureEcdsaPrfSealPersisted({
        touchConfirm: deps.touchConfirm,
        chainTarget: testEcdsaChainTarget(args.chain || 'evm'),
        thresholdSessionId: args.thresholdSessionId,
        required: args.required,
        errorContext: args.errorContext,
        sealPersistInFlightBySessionId,
        resolveSealTransport: capabilityReader.resolveEcdsaSealTransportByThresholdSessionId,
      }),
    applyEcdsaPostSignPolicy: (args: {
      nearAccountId: AccountId | string;
      chain: ThresholdEcdsaActivationChain;
      thresholdSessionId?: string;
      source?: ThresholdEcdsaSessionStoreSource;
      selectedRecord: ThresholdEcdsaSessionRecord;
    }) =>
      applyWarmSessionEcdsaPostSignPolicy(
        {
          getWarmSession,
          resolveCurrentEcdsaRecord: (recordArgs) =>
            statusReader.resolveCurrentEcdsaRecord(recordArgs),
          markEmailOtpSessionConsumed: deps.markThresholdEcdsaEmailOtpSessionConsumedForAccount,
          clearEcdsaEphemeralMaterial,
        },
        {
          ...args,
          chainTarget: testEcdsaChainTarget(args.chain),
        },
      ),
    assertEcdsaOperationAllowed: (args: {
      nearAccountId: AccountId | string;
      chain: ThresholdEcdsaActivationChain;
      thresholdSessionId?: string;
      operationLabel: string;
      source?: ThresholdEcdsaSessionStoreSource;
      [key: string]: unknown;
    }) =>
      assertWarmSessionEcdsaOperationAllowed(
        {
          getWarmSession,
          resolveCurrentEcdsaRecord: (recordArgs) =>
            statusReader.resolveCurrentEcdsaRecord(recordArgs),
        },
        {
          ...args,
          chainTarget: testEcdsaChainTarget(args.chain),
        },
      ),
  };
}
