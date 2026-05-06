import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { ThresholdEcdsaSecp256k1KeyRef } from '@/core/signingEngine/interfaces/signing';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type {
  ThresholdIndexedDbPort,
  WarmSessionMaterialWriter,
  ThresholdWebAuthnPromptPort,
} from '@/core/signingEngine/threshold/webauthn';
import { bootstrapEcdsaSession } from '@/core/signingEngine/threshold/workflows/bootstrapEcdsaSession';
import type { connectEcdsaSession } from '@/core/signingEngine/threshold/workflows/connectEcdsaSession';
import type { keygenEcdsa } from '@/core/signingEngine/threshold/workflows/keygenEcdsa';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/session/sessionPolicy';
import type { ThresholdEcdsaHssRouteAuth } from '@/core/rpcClients/relayer/thresholdEcdsa';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import {
  type WalletSubjectId,
  type EvmEip155ChainTarget,
  type TempoChainTarget,
  type ThresholdEcdsaChainTarget as CanonicalThresholdEcdsaChainTarget,
} from '@/core/signingEngine/session/signingSession/ecdsaChainTarget';

export type ThresholdEcdsaEvmChainTarget = EvmEip155ChainTarget;
export type ThresholdEcdsaTempoChainTarget = TempoChainTarget;
export type ThresholdEcdsaChainTarget = CanonicalThresholdEcdsaChainTarget;

export const TEMPO_TESTNET_CHAIN_ID = 42431;
export const TEMPO_ECDSA_CHAIN_TARGET: ThresholdEcdsaTempoChainTarget = {
  kind: 'tempo',
  chainId: TEMPO_TESTNET_CHAIN_ID,
  networkSlug: 'tempo-moderato',
};

export type EcdsaKeygenResult = Awaited<ReturnType<typeof keygenEcdsa>>;
export type EcdsaSessionResult = Awaited<ReturnType<typeof connectEcdsaSession>>;
export type EcdsaKeygenSuccess = EcdsaKeygenResult & { ok: true };
export type EcdsaSessionSuccess = EcdsaSessionResult & { ok: true };

export type ThresholdEcdsaSessionBootstrapResult = {
  thresholdEcdsaKeyRef: ThresholdEcdsaSecp256k1KeyRef;
  keygen: EcdsaKeygenSuccess;
  session: EcdsaSessionSuccess & { walletSigningSessionId: string };
};

export type ActivateEcdsaSessionDeps = {
  indexedDB: ThresholdIndexedDbPort;
  touchIdPrompt: ThresholdWebAuthnPromptPort;
  prfFirstCache: WarmSessionMaterialWriter;
  workerCtx: WorkerOperationContext;
  getOrCreateActiveThresholdEcdsaSessionId: (
    nearAccountId: AccountId,
    chainTarget: ThresholdEcdsaChainTarget,
  ) => string;
};

export type ActivateEcdsaSessionRequest = {
  nearAccountId: AccountId | string;
  subjectId: WalletSubjectId;
  chainTarget: ThresholdEcdsaChainTarget;
  relayerUrl: string;
  ecdsaThresholdKeyId?: string;
  participantIds?: number[];
  sessionKind?: 'jwt' | 'cookie';
  sessionId?: string;
  walletSigningSessionId?: string;
  clientRootShare32?: Uint8Array;
  clientRootShare32B64u?: string;
  webauthnAuthentication?: WebAuthnAuthenticationCredential;
  thresholdRouteAuth?: ThresholdEcdsaHssRouteAuth;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  runtimeScopeBootstrap?: {
    environmentId: string;
    publishableKey: string;
  };
  ttlMs?: number;
  remainingUses?: number;
};

export async function activateEcdsaSession(
  deps: ActivateEcdsaSessionDeps,
  args: ActivateEcdsaSessionRequest,
): Promise<ThresholdEcdsaSessionBootstrapResult> {
  const nearAccountId = toAccountId(args.nearAccountId);
  const subjectId = args.subjectId;
  const chainTarget = args.chainTarget;

  const requestedSessionId = String(args.sessionId || '').trim();
  const requestedWalletSigningSessionId = String(args.walletSigningSessionId || '').trim();
  const requestedEcdsaThresholdKeyId = String(args.ecdsaThresholdKeyId || '').trim();
  const baseBootstrapArgs = {
    indexedDB: deps.indexedDB,
    touchIdPrompt: deps.touchIdPrompt,
    prfFirstCache: deps.prfFirstCache,
    relayerUrl: args.relayerUrl,
    chainTarget,
    chainId: chainTarget.chainId,
    userId: nearAccountId,
    subjectId,
    participantIds: args.participantIds,
    sessionKind: args.sessionKind,
    clientRootShare32: args.clientRootShare32,
    clientRootShare32B64u: args.clientRootShare32B64u,
    webauthnAuthentication: args.webauthnAuthentication,
    runtimePolicyScope: args.runtimePolicyScope,
    runtimeScopeBootstrap: args.runtimeScopeBootstrap,
    ttlMs: args.ttlMs,
    remainingUses: args.remainingUses,
    workerCtx: deps.workerCtx,
  };
  const bootstrap = args.thresholdRouteAuth
    ? await bootstrapEcdsaSession({
        ...baseBootstrapArgs,
        bootstrapAuth: args.thresholdRouteAuth,
        ecdsaThresholdKeyId: requestedEcdsaThresholdKeyId,
        sessionId: requestedSessionId,
        walletSigningSessionId: requestedWalletSigningSessionId,
      })
    : await bootstrapEcdsaSession({
        ...baseBootstrapArgs,
        ...(requestedEcdsaThresholdKeyId
          ? { ecdsaThresholdKeyId: requestedEcdsaThresholdKeyId }
          : {}),
        sessionId:
          requestedSessionId ||
          deps.getOrCreateActiveThresholdEcdsaSessionId(nearAccountId, chainTarget),
        ...(requestedWalletSigningSessionId
          ? { walletSigningSessionId: requestedWalletSigningSessionId }
          : {}),
      });
  if (!bootstrap.ok) {
    throw new Error(bootstrap.message || bootstrap.code || 'threshold-ecdsa bootstrap failed');
  }

  const ecdsaThresholdKeyId = String(bootstrap.ecdsaThresholdKeyId || '').trim();
  if (!ecdsaThresholdKeyId) {
    throw new Error('threshold-ecdsa bootstrap returned empty ecdsaThresholdKeyId');
  }

  const relayerKeyId = String(bootstrap.relayerKeyId || '').trim();
  if (!relayerKeyId) {
    throw new Error('threshold-ecdsa bootstrap returned empty relayerKeyId');
  }

  const clientVerifyingShareB64u = String(bootstrap.clientVerifyingShareB64u || '').trim();
  if (!clientVerifyingShareB64u) {
    throw new Error('threshold-ecdsa bootstrap returned empty clientVerifyingShareB64u');
  }
  const clientAdditiveShare32B64u = String(bootstrap.clientAdditiveShare32B64u || '').trim();
  if (!clientAdditiveShare32B64u) {
    throw new Error('threshold-ecdsa bootstrap returned empty clientAdditiveShare32B64u');
  }

  const sessionId = String(bootstrap.sessionId || '').trim();
  if (!sessionId) {
    throw new Error('threshold-ecdsa bootstrap returned empty sessionId');
  }
  const walletSigningSessionId = String(bootstrap.walletSigningSessionId || '').trim();
  if (!walletSigningSessionId) {
    throw new Error('threshold-ecdsa bootstrap returned empty walletSigningSessionId');
  }
  const participantIds = normalizeThresholdEd25519ParticipantIds(
    Array.isArray(args.participantIds) ? args.participantIds : bootstrap.participantIds,
  );
  if (!participantIds) {
    throw new Error('threshold-ecdsa bootstrap returned empty participantIds');
  }
  const signingRootId = String(bootstrap.signingRootId || '').trim();
  if (!signingRootId) {
    throw new Error('threshold-ecdsa bootstrap returned empty signingRootId');
  }
  const signingRootVersion = String(bootstrap.signingRootVersion || '').trim();

  const keygen: EcdsaKeygenSuccess = {
    ok: true,
    keygenSessionId: bootstrap.keygenSessionId,
    rpId: bootstrap.rpId,
    clientVerifyingShareB64u,
    ...(clientAdditiveShare32B64u ? { clientAdditiveShare32B64u } : {}),
    relayerKeyId,
    thresholdEcdsaPublicKeyB64u: bootstrap.thresholdEcdsaPublicKeyB64u,
    ethereumAddress: bootstrap.ethereumAddress,
    relayerVerifyingShareB64u: bootstrap.relayerVerifyingShareB64u,
    participantIds,
    ...(typeof bootstrap.chainId === 'number' ? { chainId: bootstrap.chainId } : {}),
    ...(typeof bootstrap.factory === 'string' ? { factory: bootstrap.factory } : {}),
    ...(typeof bootstrap.entryPoint === 'string' ? { entryPoint: bootstrap.entryPoint } : {}),
    ...(typeof bootstrap.salt === 'string' ? { salt: bootstrap.salt } : {}),
    ...(typeof bootstrap.counterfactualAddress === 'string'
      ? { counterfactualAddress: bootstrap.counterfactualAddress }
      : {}),
    ...(bootstrap.code ? { code: bootstrap.code } : {}),
    ...(bootstrap.message ? { message: bootstrap.message } : {}),
  };

  const session: EcdsaSessionSuccess & { walletSigningSessionId: string } = {
    ok: true,
    sessionId,
    walletSigningSessionId,
    expiresAtMs: bootstrap.expiresAtMs,
    remainingUses: bootstrap.remainingUses,
    jwt: bootstrap.jwt,
    clientVerifyingShareB64u,
    ...(bootstrap.code ? { code: bootstrap.code } : {}),
    ...(bootstrap.message ? { message: bootstrap.message } : {}),
  };

  const thresholdEcdsaKeyRef: ThresholdEcdsaSecp256k1KeyRef = {
    type: 'threshold-ecdsa-secp256k1',
    userId: nearAccountId,
    subjectId,
    chainTarget,
    relayerUrl: args.relayerUrl,
    ecdsaThresholdKeyId,
    signingRootId,
    ...(signingRootVersion ? { signingRootVersion } : {}),
    backendBinding: {
      relayerKeyId,
      clientVerifyingShareB64u,
      ...(clientAdditiveShare32B64u ? { clientAdditiveShare32B64u } : {}),
    },
    participantIds,
    ...(typeof bootstrap.thresholdEcdsaPublicKeyB64u === 'string' && bootstrap.thresholdEcdsaPublicKeyB64u.trim()
      ? { thresholdEcdsaPublicKeyB64u: bootstrap.thresholdEcdsaPublicKeyB64u.trim() }
      : {}),
    ...(typeof bootstrap.ethereumAddress === 'string' && bootstrap.ethereumAddress.trim()
      ? { ethereumAddress: bootstrap.ethereumAddress.trim() }
      : {}),
    ...(typeof bootstrap.relayerVerifyingShareB64u === 'string' &&
    bootstrap.relayerVerifyingShareB64u.trim()
      ? { relayerVerifyingShareB64u: bootstrap.relayerVerifyingShareB64u.trim() }
      : {}),
    thresholdSessionKind: args.sessionKind || 'jwt',
    thresholdSessionId: sessionId,
    walletSigningSessionId,
    ...(typeof session.jwt === 'string' && session.jwt.trim()
      ? { thresholdSessionJwt: session.jwt.trim() }
      : {}),
  };

  return {
    thresholdEcdsaKeyRef,
    keygen: keygen as EcdsaKeygenSuccess,
    session,
  };
}
