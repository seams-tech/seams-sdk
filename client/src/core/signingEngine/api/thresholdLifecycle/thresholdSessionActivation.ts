import type { UnifiedIndexedDBManager } from '@/core/indexedDB';
import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { TouchIdPrompt } from '../../signers/webauthn/prompt/touchIdPrompt';
import type { SignerWorkerManagerContext } from '../../workerManager';
import type { WarmSessionMaterialPort } from '../../threshold/webauthn';
import {
  activateEcdsaSession,
  type ThresholdEcdsaChainTarget,
  type ThresholdEcdsaSessionBootstrapResult,
} from '../../orchestration/thresholdActivation';
import type { ThresholdEcdsaSmartAccountBootstrapInput } from './thresholdEcdsaBootstrapPersistence';
import type {
  ThresholdEcdsaEmailOtpAuthContext,
  ThresholdEcdsaSessionStoreSource,
} from './thresholdSessionStore';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import type { ThresholdRuntimePolicyScope } from '../../threshold/session/sessionPolicy';
import type { ThresholdEcdsaHssRouteAuth } from '@/core/rpcClients/relayer/thresholdEcdsa';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type { SigningOperationIntent } from '../../session/signingSession/types';
import type { WalletSubjectId } from '../../session/signingSession/ecdsaChainTarget';

export type BootstrapEcdsaSessionArgs = {
  nearAccountId: AccountId | string;
  subjectId: WalletSubjectId;
  chainTarget: ThresholdEcdsaChainTarget;
  source?: ThresholdEcdsaSessionStoreSource;
  emailOtpAuthContext?: ThresholdEcdsaEmailOtpAuthContext;
  relayerUrl?: string;
  ecdsaThresholdKeyId?: string;
  participantIds?: number[];
  sessionKind?: 'jwt' | 'cookie';
  sessionId?: string;
  walletSigningSessionId?: string;
  clientRootShare32?: Uint8Array;
  clientRootShare32B64u?: string;
  webauthnAuthentication?: WebAuthnAuthenticationCredential;
  operationIntent?: SigningOperationIntent;
  thresholdRouteAuth?: ThresholdEcdsaHssRouteAuth;
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
    chainTarget: ThresholdEcdsaChainTarget,
  ) => string;
  defaultRelayerUrl: string;
  persistThresholdEcdsaBootstrapChainAccount: (args: {
    nearAccountId: AccountId | string;
    chainTarget: ThresholdEcdsaChainTarget;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
    deployment?: {
      deployed: boolean;
      deploymentTxHash?: string;
    };
  }) => Promise<void>;
  upsertThresholdEcdsaSessionFromBootstrap: (args: {
    nearAccountId: AccountId | string;
    chainTarget: ThresholdEcdsaChainTarget;
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
  const chainTarget = args.chainTarget;
  const relayerUrl = resolveRelayerUrl(args.relayerUrl, deps.defaultRelayerUrl);

  const signerWorkerCtx = deps.getSignerWorkerContext();
  const activationDeps = {
    indexedDB: deps.indexedDB,
    touchIdPrompt: deps.touchIdPrompt,
    prfFirstCache: deps.touchConfirm,
    workerCtx: signerWorkerCtx,
    getOrCreateActiveThresholdEcdsaSessionId: (
      accountId: AccountId,
      target: ThresholdEcdsaChainTarget,
    ) => deps.getOrCreateActiveThresholdEcdsaSessionId(accountId, target),
  };

  const bootstrap = await activateEcdsaSession(activationDeps, {
    nearAccountId,
    subjectId: args.subjectId,
    chainTarget,
    relayerUrl,
    ecdsaThresholdKeyId: args.ecdsaThresholdKeyId,
    participantIds: args.participantIds,
    sessionKind: args.sessionKind,
    sessionId: args.sessionId,
    walletSigningSessionId: args.walletSigningSessionId,
    clientRootShare32: args.clientRootShare32,
    clientRootShare32B64u: args.clientRootShare32B64u,
    webauthnAuthentication: args.webauthnAuthentication,
    thresholdRouteAuth: args.thresholdRouteAuth,
    runtimePolicyScope: args.runtimePolicyScope,
    runtimeScopeBootstrap: args.runtimeScopeBootstrap,
    ttlMs: args.ttlMs,
    remainingUses: args.remainingUses,
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
    chainTarget,
    bootstrap: canonicalBootstrap,
    smartAccount: args.smartAccount,
  });
  deps.upsertThresholdEcdsaSessionFromBootstrap({
    nearAccountId,
    chainTarget,
    bootstrap: canonicalBootstrap,
    source: args.source || 'manual-bootstrap',
    ...(args.emailOtpAuthContext ? { emailOtpAuthContext: args.emailOtpAuthContext } : {}),
  });
  return canonicalBootstrap;
}
