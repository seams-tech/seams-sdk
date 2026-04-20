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
import type { WarmSessionSealAndPersistPayload } from '@/core/types/secure-confirm-worker';
import {
  clearAllStoredThresholdEd25519SessionRecords,
  clearAllThresholdEcdsaSessionRecords,
  upsertStoredThresholdEd25519SessionRecord,
  upsertThresholdEcdsaSessionFromBootstrap,
  type ThresholdEcdsaEmailOtpAuthContext,
  type ThresholdEcdsaSessionStoreDeps,
  type ThresholdEd25519SessionRecord,
} from '@/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore';

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
    ...(args.walletSigningSessionId
      ? { walletSigningSessionId: args.walletSigningSessionId }
      : {}),
    ...(args.thresholdSessionJwt ? { thresholdSessionJwt: args.thresholdSessionJwt } : {}),
    expiresAtMs: args.expiresAtMs ?? Date.now() + 120_000,
    remainingUses: args.remainingUses ?? 7,
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
  sessionJwt?: string;
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
  const sessionJwt =
    sessionKind === 'jwt' ? String(args.sessionJwt || `jwt:${sessionId}`).trim() : '';
  const relayerUrl = String(args.relayerUrl || 'https://relay.example').trim();
  const relayerKeyId = String(args.relayerKeyId || `rk-${chainLabel}-1`).trim();
  const clientVerifyingShareB64u = String(
    args.clientVerifyingShareB64u || `cvs-${chainLabel}-1`,
  ).trim();
  const participantIds = args.participantIds || [1, 2];
  const ethereumAddress = args.ethereumAddress || `0x${'11'.repeat(20)}`;
  const walletSigningSessionId = String(args.walletSigningSessionId || '').trim();
  const signingRootId = String(args.signingRootId || 'sr-test:dev').trim();
  const signingRootVersion = String(args.signingRootVersion || '').trim();

  return {
    thresholdEcdsaKeyRef: {
      type: 'threshold-ecdsa-secp256k1',
      userId: args.nearAccountId,
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
      ...(walletSigningSessionId ? { walletSigningSessionId } : {}),
      ...(sessionJwt ? { thresholdSessionJwt: sessionJwt } : {}),
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
      ...(walletSigningSessionId ? { walletSigningSessionId } : {}),
      expiresAtMs: Date.now() + 120_000,
      remainingUses: 5,
      ...(sessionJwt ? { jwt: sessionJwt } : {}),
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
    ...(args.emailOtpAuthContext ? { emailOtpAuthContext: args.emailOtpAuthContext } : {}),
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
