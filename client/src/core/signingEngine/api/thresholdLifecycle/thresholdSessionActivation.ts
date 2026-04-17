import type { UnifiedIndexedDBManager } from '@/core/indexedDB';
import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { TouchIdPrompt } from '../../signers/webauthn/prompt/touchIdPrompt';
import type { SignerWorkerManagerContext } from '../../workerManager';
import type { WarmSessionMaterialPort } from '../../threshold/webauthn';
import {
  activateEvmEcdsaSession,
  activateTempoEcdsaSession,
  activateThresholdKeyForChain,
  type ThresholdEcdsaActivationChain,
  type ThresholdEcdsaSessionBootstrapResult,
} from '../../orchestration/thresholdActivation';
import type { ThresholdEcdsaSmartAccountBootstrapInput } from './thresholdEcdsaBootstrapPersistence';
import type {
  ThresholdEcdsaEmailOtpAuthContext,
  ThresholdEcdsaSessionStoreSource,
} from './thresholdSessionStore';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import type { ThresholdRuntimePolicyScope } from '../../threshold/session/sessionPolicy';

export type BootstrapEcdsaSessionArgs = {
  nearAccountId: AccountId | string;
  chain?: ThresholdEcdsaActivationChain;
  source?: ThresholdEcdsaSessionStoreSource;
  emailOtpAuthContext?: ThresholdEcdsaEmailOtpAuthContext;
  relayerUrl?: string;
  ecdsaThresholdKeyId?: string;
  participantIds?: number[];
  sessionKind?: 'jwt' | 'cookie';
  sessionId?: string;
  clientRootShare32?: Uint8Array;
  clientRootShare32B64u?: string;
  authorizationJwt?: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  runtimeScopeBootstrap?: {
    environmentId: string;
    publishableKey: string;
  };
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
  touchConfirm: WarmSessionMaterialPort;
  getSignerWorkerContext: () => SignerWorkerManagerContext;
  getOrCreateActiveThresholdEcdsaSessionId: (
    nearAccountId: AccountId,
    chain: ThresholdEcdsaActivationChain,
  ) => string;
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
    emailOtpAuthContext?: ThresholdEcdsaEmailOtpAuthContext;
  }) => void;
};

function requireCanonicalThresholdEcdsaKeyRefIdentity(
  keyRef: ThresholdEcdsaSecp256k1KeyRef,
): ThresholdEcdsaSecp256k1KeyRef & { ecdsaThresholdKeyId: string } {
  const ecdsaThresholdKeyId = String(keyRef.ecdsaThresholdKeyId || '').trim();
  if (!ecdsaThresholdKeyId) {
    throw new Error(
      '[SigningEngine] threshold-ecdsa bootstrap did not provide canonical ecdsaThresholdKeyId',
    );
  }
  return {
    ...keyRef,
    ecdsaThresholdKeyId,
  };
}

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
    ) => deps.getOrCreateActiveThresholdEcdsaSessionId(accountId, activationChain),
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
      ecdsaThresholdKeyId: args.ecdsaThresholdKeyId,
      participantIds: args.participantIds,
      sessionKind: args.sessionKind,
      sessionId: args.sessionId,
      clientRootShare32: args.clientRootShare32,
      clientRootShare32B64u: args.clientRootShare32B64u,
      authorizationJwt: args.authorizationJwt,
      runtimePolicyScope: args.runtimePolicyScope,
      runtimeScopeBootstrap: args.runtimeScopeBootstrap,
      ttlMs: args.ttlMs,
      remainingUses: args.remainingUses,
    },
  });
  const thresholdEcdsaKeyRef = requireCanonicalThresholdEcdsaKeyRefIdentity(
    bootstrap.thresholdEcdsaKeyRef,
  );
  const canonicalBootstrap: ThresholdEcdsaSessionBootstrapResult = {
    ...bootstrap,
    thresholdEcdsaKeyRef,
  };

  await deps.persistThresholdEcdsaBootstrapChainAccount({
    nearAccountId,
    chain,
    bootstrap: canonicalBootstrap,
    smartAccount: args.smartAccount,
  });
  deps.upsertThresholdEcdsaSessionFromBootstrap({
    nearAccountId,
    chain,
    bootstrap: canonicalBootstrap,
    source: args.source || 'manual-bootstrap',
    ...(args.emailOtpAuthContext ? { emailOtpAuthContext: args.emailOtpAuthContext } : {}),
  });
  return canonicalBootstrap;
}
