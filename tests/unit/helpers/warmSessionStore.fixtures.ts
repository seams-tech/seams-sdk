import type {
  WarmSessionStatusBatchReader,
  WarmSessionStatusReader,
} from '@/core/signingEngine/touchConfirm';
import type {
  WarmSessionMaterialClaimer,
  WarmSessionSealPersister,
} from '@/core/signingEngine/touchConfirm';
import type {
  ThresholdEcdsaSessionBootstrapResult,
  ThresholdEcdsaActivationChain,
} from '@/core/signingEngine/orchestration/thresholdActivation';
import type { AccountId } from '@/core/types/accountIds';
import type { WarmSessionSealAndPersistPayload } from '@/core/types/secure-confirm-worker';
import {
  clearAllStoredThresholdEd25519SessionRecords,
  clearAllThresholdEcdsaSessionRecords,
  listConcreteThresholdEcdsaSessionRecordsForSubject,
  type ConcreteThresholdEcdsaSessionRecord,
  upsertStoredThresholdEd25519SessionRecord,
  upsertThresholdEcdsaSessionFromBootstrap,
  type ThresholdEcdsaEmailOtpAuthContext,
  type ThresholdEcdsaKeyRefLookupResult,
  type ThresholdEcdsaSessionRecord,
  type ThresholdEcdsaSessionStoreDeps,
  type ThresholdEcdsaSessionStoreSource,
  type ThresholdEd25519SessionRecord,
} from '@/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore';
import type { WarmSessionStatusResult } from '@/core/signingEngine/touchConfirm';
import {
  createWarmSessionCapabilityReader,
} from '@/core/signingEngine/session/warmSigning/capabilityReader';
import {
  ensureWarmEcdsaCapabilityReady,
  provisionWarmEcdsaCapability,
  tryReuseReadyWarmEcdsaBootstrap,
} from '@/core/signingEngine/session/warmSigning/ecdsaProvisioner';
import { provisionWarmEd25519Capability } from '@/core/signingEngine/session/warmSigning/ed25519Provisioner';
import {
  applyWarmSessionEcdsaPostSignPolicy,
  assertWarmSessionEcdsaOperationAllowed,
} from '@/core/signingEngine/session/warmSigning/postSignPolicyAdapter';
import {
  createWarmSessionStatusReader as createCoreWarmSessionStatusReader,
} from '@/core/signingEngine/session/warmSigning/statusReader';
import { resolveWarmEcdsaBootstrapRequestFromSession } from '@/core/signingEngine/session/warmSigning/ecdsaBootstrapRequest';
import {
  claimWarmSessionPrfFirst,
  ensureEcdsaPrfSealPersisted,
} from '@/core/signingEngine/session/warmSigning/runtime';
import type {
  EnsureWarmEcdsaCapabilityReadyResult,
  ProvisionWarmEcdsaCapabilityArgs,
  ProvisionWarmEd25519CapabilityArgs,
  ProvisionWarmEd25519CapabilityResult,
} from '@/core/signingEngine/session/warmSigning/types';
import {
  thresholdEcdsaChainTargetFromChainFamily,
  toWalletSubjectId,
  type ThresholdEcdsaChainTarget,
  type WalletSubjectId,
} from '@/core/signingEngine/session/signingSession/ecdsaChainTarget';

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
import type { WarmSessionTransitionEvent } from '@/core/signingEngine/session/warmSigning/transitions';

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
  const sessionAuthToken =
    sessionKind === 'jwt' ? String(args.sessionAuthToken || `jwt:${sessionId}`).trim() : '';
  const relayerUrl = String(args.relayerUrl || 'https://relay.example').trim();
  const relayerKeyId = String(args.relayerKeyId || `rk-${chainLabel}-1`).trim();
  const clientVerifyingShareB64u = String(
    args.clientVerifyingShareB64u || `cvs-${chainLabel}-1`,
  ).trim();
  const participantIds = args.participantIds || [1, 2];
  const ethereumAddress = args.ethereumAddress || `0x${'11'.repeat(20)}`;
  const walletSigningSessionId = String(
    args.walletSigningSessionId || `wsess-${sessionId}`,
  ).trim();
  const signingRootId = String(args.signingRootId || 'sr-test:dev').trim();
  const signingRootVersion = String(args.signingRootVersion || '').trim();

  return {
    thresholdEcdsaKeyRef: {
      type: 'threshold-ecdsa-secp256k1',
      userId: args.nearAccountId,
      subjectId: toWalletSubjectId(args.nearAccountId),
      chainTarget: thresholdEcdsaChainTargetFromChainFamily({
        chain: args.chain,
        chainId: testEcdsaChainId(args.chain),
      }),
      relayerUrl,
      ecdsaThresholdKeyId,
      signingRootId,
      ...(signingRootVersion ? { signingRootVersion } : {}),
      participantIds: [...participantIds],
      backendBinding: {
        relayerKeyId,
        clientVerifyingShareB64u,
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
    chain: args.chain,
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

export function createWarmSessionTouchConfirmFixture(args: {
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
    chain: ThresholdEcdsaActivationChain;
  }) => void;
  clearThresholdEcdsaSigningArtifactsForLane?: (args: {
    record: ThresholdEcdsaSessionRecord;
  }) => void | Promise<void>;
  listThresholdEcdsaSessionRecordsForLookup?: (args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
  }) => ThresholdEcdsaSessionRecord[];
  listConcreteThresholdEcdsaSessionRecordsForSubject?: (args: {
    subjectId: WalletSubjectId;
  }) => ConcreteThresholdEcdsaSessionRecord[];
  getThresholdEcdsaSessionRecordByThresholdSessionId?: (
    thresholdSessionId: string,
  ) => ThresholdEcdsaSessionRecord | null;
  signingSessionSeal?: {
    keyVersion?: string;
    shamirPrimeB64u?: string;
  };
  getEmailOtpWarmSessionStatus?: (sessionId: string) => Promise<WarmSessionStatusResult>;
  listThresholdEcdsaKeyRefsForLookup?: (args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    source?: ThresholdEcdsaSessionStoreSource;
  }) => ThresholdEcdsaKeyRefLookupResult[];
  provisionThresholdEcdsaSession?: (
    args: ProvisionWarmEcdsaCapabilityArgs,
  ) => Promise<ThresholdEcdsaSessionBootstrapResult>;
  bootstrapThresholdEcdsaSession?: (args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
  }) => Promise<ThresholdEcdsaSessionBootstrapResult>;
  provisionThresholdEd25519Session?: (
    args: ProvisionWarmEd25519CapabilityArgs,
  ) => Promise<ProvisionWarmEd25519CapabilityResult>;
  onTransition?: (event: WarmSessionTransitionEvent) => void | Promise<void>;
};

const emptyThresholdEcdsaStoreDeps = (): ThresholdEcdsaSessionStoreDeps => ({
  recordsByLane: new Map(),
  exportArtifactsByLane: new Map(),
});

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
    listThresholdEcdsaSessionRecordsForLookup: deps.listThresholdEcdsaSessionRecordsForLookup,
    listConcreteThresholdEcdsaSessionRecordsForSubject:
      deps.listConcreteThresholdEcdsaSessionRecordsForSubject ||
      ((args) => listConcreteThresholdEcdsaSessionRecordsForSubject(emptyThresholdEcdsaStoreDeps(), args)),
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
    listThresholdEcdsaSessionRecordsForLookup: deps.listThresholdEcdsaSessionRecordsForLookup,
    listConcreteThresholdEcdsaSessionRecordsForSubject:
      deps.listConcreteThresholdEcdsaSessionRecordsForSubject ||
      ((args) => listConcreteThresholdEcdsaSessionRecordsForSubject(emptyThresholdEcdsaStoreDeps(), args)),
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
  const provisionEcdsaCapability = (args: ProvisionWarmEcdsaCapabilityArgs) =>
    provisionWarmEcdsaCapability(
      {
        getWarmSession,
        listThresholdEcdsaKeyRefsForLookup: deps.listThresholdEcdsaKeyRefsForLookup,
        provisionThresholdEcdsaSession: deps.provisionThresholdEcdsaSession,
        bootstrapThresholdEcdsaSession: deps.bootstrapThresholdEcdsaSession,
        claimPrfFirstByThresholdSessionId,
        onTransition: deps.onTransition,
      },
      args,
    );

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
      [key: string]: unknown;
    }) =>
      resolveWarmEcdsaBootstrapRequestFromSession({
        request: { ...args, chainTarget: testEcdsaChainTarget(args.chain) },
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
          listThresholdEcdsaKeyRefsForLookup: deps.listThresholdEcdsaKeyRefsForLookup,
        },
        args,
      ),
    ensureEcdsaCapabilityReady: (args: {
      nearAccountId: AccountId | string;
      chain: ThresholdEcdsaActivationChain;
      source?: ThresholdEcdsaSessionStoreSource;
      usesNeeded?: number;
      [key: string]: unknown;
    }) =>
      ensureWarmEcdsaCapabilityReady(
        {
          getWarmSession,
          listThresholdEcdsaKeyRefsForLookup: deps.listThresholdEcdsaKeyRefsForLookup,
          canProvisionEcdsaCapability:
            typeof deps.bootstrapThresholdEcdsaSession === 'function' ||
            typeof deps.provisionThresholdEcdsaSession === 'function',
          provisionEcdsaCapability,
          resolveCurrentEcdsaRecord: (recordArgs) =>
            statusReader.resolveCurrentEcdsaRecord(recordArgs),
          readEcdsaCapabilityByThresholdSessionId:
            capabilityReader.getEcdsaCapabilityByThresholdSessionId,
          reconnectInFlightByCapability,
          onTransition: deps.onTransition,
        },
        {
          ...args,
          chainTarget: testEcdsaChainTarget(args.chain),
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
        args,
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
        args,
      ),
  };
}
