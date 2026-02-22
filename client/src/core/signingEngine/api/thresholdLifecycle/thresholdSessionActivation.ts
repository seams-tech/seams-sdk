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
import type { ThresholdEcdsaSessionStoreSource } from './thresholdEcdsaSessionStore';

export type ConnectEd25519SessionArgs = {
  nearAccountId: AccountId | string;
  relayerKeyId: string;
  participantIds?: number[];
  sessionKind?: 'jwt' | 'cookie';
  relayerUrl?: string;
  ttlMs?: number;
  remainingUses?: number;
};

export type BootstrapEcdsaSessionArgs = {
  nearAccountId: AccountId | string;
  chain?: ThresholdEcdsaActivationChain;
  source?: ThresholdEcdsaSessionStoreSource;
  relayerUrl?: string;
  participantIds?: number[];
  sessionKind?: 'jwt' | 'cookie';
  ttlMs?: number;
  remainingUses?: number;
  smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
};

export type ThresholdSessionActivationDeps = {
  indexedDB: UnifiedIndexedDBManager;
  touchIdPrompt: Pick<TouchIdPrompt, 'getRpId' | 'getAuthenticationCredentialsSerializedForChallengeB64u'>;
  signingKeyOps: Pick<NearSigningKeyOps, 'deriveThresholdEd25519ClientVerifyingShare'>;
  touchConfirmManager: ThresholdPrfFirstCachePort;
  getSignerWorkerContext: () => SignerWorkerManagerContext;
  getOrCreateActiveSigningSessionId: (nearAccountId: AccountId) => string;
  defaultRelayerUrl: string;
  persistThresholdEcdsaBootstrapChainAccount: (args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
  }) => Promise<void>;
  upsertThresholdEcdsaSessionFromBootstrap: (args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    source: ThresholdEcdsaSessionStoreSource;
  }) => void;
};

function resolveRelayerUrl(relayerUrlOverride: string | undefined, defaultRelayerUrl: string): string {
  const relayerUrl = String(relayerUrlOverride || defaultRelayerUrl || '').trim();
  if (!relayerUrl) {
    throw new Error('Missing relayer url (configs.relayer.url)');
  }
  return relayerUrl;
}

export async function connectEd25519SessionValue(
  deps: ThresholdSessionActivationDeps,
  args: ConnectEd25519SessionArgs,
): Promise<Awaited<ReturnType<typeof connectEd25519Session>>> {
  const nearAccountId = toAccountId(args.nearAccountId);
  const relayerUrl = resolveRelayerUrl(args.relayerUrl, deps.defaultRelayerUrl);
  const sessionId = deps.getOrCreateActiveSigningSessionId(nearAccountId);
  return await connectEd25519Session({
    indexedDB: deps.indexedDB,
    touchIdPrompt: deps.touchIdPrompt,
    signingKeyOps: deps.signingKeyOps,
    prfFirstCache: deps.touchConfirmManager,
    relayerUrl,
    relayerKeyId: args.relayerKeyId,
    nearAccountId,
    participantIds: args.participantIds,
    sessionKind: args.sessionKind,
    sessionId,
    ttlMs: args.ttlMs,
    remainingUses: args.remainingUses,
  });
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
    prfFirstCache: deps.touchConfirmManager,
    workerCtx: signerWorkerCtx,
    getOrCreateActiveSigningSessionId: deps.getOrCreateActiveSigningSessionId,
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
      ttlMs: args.ttlMs,
      remainingUses: args.remainingUses,
    },
  });

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
  return bootstrap;
}
