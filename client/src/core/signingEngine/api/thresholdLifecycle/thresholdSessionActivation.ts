import type { UnifiedIndexedDBManager } from '@/core/indexedDB';
import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { TouchIdPrompt } from '../../signers/webauthn/prompt/touchIdPrompt';
import type { SignerWorkerManagerContext } from '../../workerManager';
import type { NearSigningKeyOps } from '../../interfaces/nearKeyOps';
import type { ThresholdPrfFirstCachePort } from '../../threshold/webauthn';
import { connectEd25519Session } from '../../threshold/workflows/connectEd25519Session';
import {
  activateEvmEcdsaSession,
  activateTempoEcdsaSession,
  activateThresholdKeyForChain,
  type ThresholdEcdsaActivationChain,
  type ThresholdEcdsaSessionBootstrapResult,
} from '../../orchestration/thresholdActivation';
import type { ThresholdEcdsaSmartAccountBootstrapInput } from './thresholdEcdsaBootstrapPersistence';
import type { ThresholdEcdsaSessionStoreSource } from './thresholdSessionStore';

export type ConnectEd25519SessionArgs = {
  nearAccountId: AccountId | string;
  relayerKeyId: string;
  participantIds?: number[];
  sessionKind?: 'jwt' | 'cookie';
  relayerUrl?: string;
  ttlMs?: number;
  remainingUses?: number;
  sessionId?: string;
};

export type BootstrapEcdsaSessionArgs = {
  nearAccountId: AccountId | string;
  chain?: ThresholdEcdsaActivationChain;
  source?: ThresholdEcdsaSessionStoreSource;
  relayerUrl?: string;
  participantIds?: number[];
  sessionKind?: 'jwt' | 'cookie';
  sessionId?: string;
  clientVerifyingShareB64u?: string;
  authorizationJwt?: string;
  ttlMs?: number;
  remainingUses?: number;
  smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
};

export type ThresholdSessionActivationDeps = {
  indexedDB: UnifiedIndexedDBManager;
  touchIdPrompt: Pick<
    TouchIdPrompt,
    'getRpId' | 'getAuthenticationCredentialsSerializedForChallengeB64u'
  >;
  signingKeyOps: Pick<NearSigningKeyOps, 'deriveThresholdEd25519ClientVerifyingShare'>;
  touchConfirm: ThresholdPrfFirstCachePort;
  getSignerWorkerContext: () => SignerWorkerManagerContext;
  getOrCreateActiveThresholdEd25519SessionId: (nearAccountId: AccountId) => string;
  setActiveThresholdEd25519SessionId: (
    nearAccountId: AccountId | string,
    sessionId: string,
  ) => void;
  getOrCreateActiveThresholdEcdsaSessionId: (
    nearAccountId: AccountId,
    chain: ThresholdEcdsaActivationChain,
  ) => string;
  setActiveThresholdEcdsaSessionId: (
    nearAccountId: AccountId | string,
    chain: ThresholdEcdsaActivationChain,
    sessionId: string,
  ) => void;
  defaultRelayerUrl: string;
  persistThresholdEcdsaBootstrapChainAccount: (args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
    deployment?: {
      deployed: boolean;
      deploymentTxHash?: string;
    };
  }) => Promise<void>;
  upsertThresholdEcdsaSessionFromBootstrap: (args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    source: ThresholdEcdsaSessionStoreSource;
  }) => void;
};

function resolveRelayerUrl(
  relayerUrlOverride: string | undefined,
  defaultRelayerUrl: string,
): string {
  const relayerUrl = String(relayerUrlOverride || defaultRelayerUrl || '').trim();
  if (!relayerUrl) {
    throw new Error('Missing relayer url (configs.network.relayer.url)');
  }
  return relayerUrl;
}

export async function connectEd25519SessionValue(
  deps: ThresholdSessionActivationDeps,
  args: ConnectEd25519SessionArgs,
): Promise<Awaited<ReturnType<typeof connectEd25519Session>>> {
  const nearAccountId = toAccountId(args.nearAccountId);
  const relayerUrl = resolveRelayerUrl(args.relayerUrl, deps.defaultRelayerUrl);
  const workerCtx = deps.getSignerWorkerContext();
  const requestedSessionId = String(args.sessionId || '').trim();
  const sessionId =
    requestedSessionId || deps.getOrCreateActiveThresholdEd25519SessionId(nearAccountId);
  const connected = await connectEd25519Session({
    indexedDB: deps.indexedDB,
    touchIdPrompt: deps.touchIdPrompt,
    signingKeyOps: deps.signingKeyOps,
    prfFirstCache: deps.touchConfirm,
    relayerUrl,
    relayerKeyId: args.relayerKeyId,
    nearAccountId,
    participantIds: args.participantIds,
    sessionKind: args.sessionKind,
    sessionId,
    ttlMs: args.ttlMs,
    remainingUses: args.remainingUses,
    workerCtx,
  });
  if (connected.ok) {
    const resolvedSessionId = String(connected.sessionId || sessionId).trim();
    if (resolvedSessionId) {
      deps.setActiveThresholdEd25519SessionId(nearAccountId, resolvedSessionId);
    }
  }
  return connected;
}

export async function bootstrapEcdsaSessionValue(
  deps: ThresholdSessionActivationDeps,
  args: BootstrapEcdsaSessionArgs,
): Promise<ThresholdEcdsaSessionBootstrapResult> {
  const nearAccountId = toAccountId(args.nearAccountId);
  const chain: ThresholdEcdsaActivationChain = args.chain || 'tempo';
  const relayerUrl = resolveRelayerUrl(args.relayerUrl, deps.defaultRelayerUrl);

  const signerWorkerCtx = deps.getSignerWorkerContext();
  const activationDeps = {
    indexedDB: deps.indexedDB,
    touchIdPrompt: deps.touchIdPrompt,
    prfFirstCache: deps.touchConfirm,
    workerCtx: signerWorkerCtx,
    getOrCreateActiveThresholdEcdsaSessionId: (
      accountId: AccountId,
      activationChain: ThresholdEcdsaActivationChain,
    ) =>
      deps.getOrCreateActiveThresholdEcdsaSessionId(accountId, activationChain),
  };

  const bootstrap = await activateThresholdKeyForChain({
    chain,
    adapters: {
      evm: (request) => activateEvmEcdsaSession(activationDeps, request),
      tempo: (request) => activateTempoEcdsaSession(activationDeps, request),
    },
    request: {
      nearAccountId,
      relayerUrl,
      participantIds: args.participantIds,
      sessionKind: args.sessionKind,
      sessionId: args.sessionId,
      clientVerifyingShareB64u: args.clientVerifyingShareB64u,
      authorizationJwt: args.authorizationJwt,
      ttlMs: args.ttlMs,
      remainingUses: args.remainingUses,
    },
  });

  const requestedThresholdSessionId = String(args.sessionId || '').trim();
  const canonicalThresholdSessionId = String(
    bootstrap.thresholdEcdsaKeyRef?.thresholdSessionId || '',
  ).trim();

  if (
    requestedThresholdSessionId &&
    canonicalThresholdSessionId &&
    requestedThresholdSessionId !== canonicalThresholdSessionId &&
    typeof deps.touchConfirm.transferPrfFirstForThresholdSession === 'function'
  ) {
    const transferred = await deps.touchConfirm.transferPrfFirstForThresholdSession({
      fromSessionId: requestedThresholdSessionId,
      toSessionId: canonicalThresholdSessionId,
    });

    if (!transferred.ok && typeof deps.touchConfirm.peekPrfFirstForThresholdSession === 'function') {
      const canonicalPeek = await deps.touchConfirm.peekPrfFirstForThresholdSession({
        sessionId: canonicalThresholdSessionId,
      });
      if (!canonicalPeek.ok && String(args.authorizationJwt || '').trim()) {
        throw new Error(
          `[SigningEngine] threshold PRF session transfer failed (${transferred.code}); reconnect threshold session via bootstrapEcdsaSession`,
        );
      }
    }
  }

  if (canonicalThresholdSessionId) {
    deps.setActiveThresholdEcdsaSessionId(nearAccountId, chain, canonicalThresholdSessionId);
  }

  await deps.persistThresholdEcdsaBootstrapChainAccount({
    nearAccountId,
    chain,
    bootstrap,
    smartAccount: args.smartAccount,
  });
  deps.upsertThresholdEcdsaSessionFromBootstrap({
    nearAccountId,
    chain,
    bootstrap,
    source: args.source || 'manual-bootstrap',
  });

  // Force PRF seal persistence during bootstrap/login using canonical transport data.
  // This avoids relying on lazy peek-only sealing and makes server apply-seal visible
  // during the login/bootstrap path.
  if (
    canonicalThresholdSessionId &&
    typeof deps.touchConfirm.persistPrfFirstSealForThresholdSession === 'function'
  ) {
    const persisted = await deps.touchConfirm.persistPrfFirstSealForThresholdSession({
      sessionId: canonicalThresholdSessionId,
      transport: {
        relayerUrl: String(
          bootstrap.thresholdEcdsaKeyRef?.relayerUrl || relayerUrl || '',
        ).trim(),
        thresholdSessionJwt: String(
          bootstrap.thresholdEcdsaKeyRef?.thresholdSessionJwt || bootstrap.session?.jwt || '',
        ).trim(),
      },
    });
    if (
      !persisted.ok &&
      persisted.code !== 'not_enabled' &&
      String(args.authorizationJwt || '').trim()
    ) {
      throw new Error(
        `[SigningEngine] threshold PRF seal persistence failed (${persisted.code}): ${persisted.message}`,
      );
    }
  }

  // Ensure PRF seal persistence happens during login/bootstrap as soon as canonical
  // threshold session metadata exists. Without this, sealing can still be deferred to
  // a later peek/sign path in partial implementations.
  if (
    canonicalThresholdSessionId &&
    typeof deps.touchConfirm.peekPrfFirstForThresholdSession === 'function'
  ) {
    await deps.touchConfirm
      .peekPrfFirstForThresholdSession({ sessionId: canonicalThresholdSessionId })
      .catch(() => undefined);
  }
  return bootstrap;
}
