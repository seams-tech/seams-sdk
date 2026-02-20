import type { UnifiedIndexedDBManager } from '@/core/indexedDB';
import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { SecureConfirmWorkerManager } from '../../secureConfirm';
import type { TouchIdPrompt } from '../../signers/webauthn/prompt/touchIdPrompt';
import type { SignerWorkerManagerContext } from '../../workerManager';
import type { NearSigningKeyOps } from '../../interfaces/nearKeyOps';
import { connectEd25519Session } from '../../threshold/workflows/connectEd25519Session';
import {
  activateEvmEcdsaSession,
  activateTempoEcdsaSession,
  activateThresholdKeyForChain,
  type ThresholdEcdsaActivationChain,
  type ThresholdEcdsaSessionBootstrapResult,
} from '../../orchestration/thresholdActivation';
import type { ThresholdEcdsaSmartAccountBootstrapInput } from './thresholdEcdsaBootstrapPersistence';

type PutPrfFirstForThresholdSessionArgs = Parameters<
  SecureConfirmWorkerManager['putPrfFirstForThresholdSession']
>[0];

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
  secureConfirmWorkerManager: Pick<
    SecureConfirmWorkerManager,
    'putPrfFirstForThresholdSession'
  >;
  getSignerWorkerContext: () => SignerWorkerManagerContext;
  getOrCreateActiveSigningSessionId: (nearAccountId: AccountId) => string;
  defaultRelayerUrl: string;
  persistThresholdEcdsaBootstrapChainAccount: (args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
  }) => Promise<void>;
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
    prfFirstCache: {
      putPrfFirstForThresholdSession: (params: PutPrfFirstForThresholdSessionArgs) =>
        deps.secureConfirmWorkerManager.putPrfFirstForThresholdSession(params),
    },
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
    prfFirstCache: {
      putPrfFirstForThresholdSession: (params: PutPrfFirstForThresholdSessionArgs) =>
        deps.secureConfirmWorkerManager.putPrfFirstForThresholdSession(params),
    },
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
  return bootstrap;
}
