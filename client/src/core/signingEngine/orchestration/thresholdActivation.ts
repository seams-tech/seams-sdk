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
import type { AppOrThresholdSessionAuth } from '@shared/utils/sessionTokens';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';

export type ThresholdKeyActivationChain = 'near' | 'evm' | 'tempo';

export type ThresholdKeyActivationAdapter<Request = unknown, Result = unknown> = (
  request: Request,
) => Promise<Result>;

export type ThresholdKeyActivationAdaptersForChain<
  Chain extends ThresholdKeyActivationChain,
  Request,
  Result,
> = Record<Chain, ThresholdKeyActivationAdapter<Request, Result>> &
  Partial<
    Record<
      Exclude<ThresholdKeyActivationChain, Chain>,
      ThresholdKeyActivationAdapter<unknown, unknown>
    >
  >;

export async function activateThresholdKeyForChain<
  Chain extends ThresholdKeyActivationChain,
  Request,
  Result,
>(args: {
  chain: Chain;
  request: Request;
  adapters: ThresholdKeyActivationAdaptersForChain<Chain, Request, Result>;
}): Promise<Result> {
  const adapter = args.adapters[args.chain];
  if (typeof adapter !== 'function') {
    throw new Error(
      `[activation] missing threshold-key activation adapter for chain: ${args.chain}`,
    );
  }

  return await (adapter as ThresholdKeyActivationAdapter<Request, Result>)(args.request);
}

export type ThresholdEcdsaActivationChain = 'evm' | 'tempo';

export type EcdsaKeygenResult = Awaited<ReturnType<typeof keygenEcdsa>>;
export type EcdsaSessionResult = Awaited<ReturnType<typeof connectEcdsaSession>>;
export type EcdsaKeygenSuccess = EcdsaKeygenResult & { ok: true };
export type EcdsaSessionSuccess = EcdsaSessionResult & { ok: true };

export type ThresholdEcdsaSessionBootstrapResult = {
  thresholdEcdsaKeyRef: ThresholdEcdsaSecp256k1KeyRef;
  keygen: EcdsaKeygenSuccess;
  session: EcdsaSessionSuccess & { walletSigningSessionId?: string };
};

export type ActivateEcdsaSessionDeps = {
  indexedDB: ThresholdIndexedDbPort;
  touchIdPrompt: ThresholdWebAuthnPromptPort;
  prfFirstCache: WarmSessionMaterialWriter;
  workerCtx: WorkerOperationContext;
  getOrCreateActiveThresholdEcdsaSessionId: (
    nearAccountId: AccountId,
    chain: 'tempo' | 'evm',
  ) => string;
};

export type ActivateEcdsaSessionRequest = {
  nearAccountId: AccountId | string;
  relayerUrl: string;
  ecdsaThresholdKeyId?: string;
  participantIds?: number[];
  sessionKind?: 'jwt' | 'cookie';
  sessionId?: string;
  walletSigningSessionId?: string;
  clientRootShare32?: Uint8Array;
  clientRootShare32B64u?: string;
  webauthnAuthentication?: WebAuthnAuthenticationCredential;
  thresholdRouteAuth?: AppOrThresholdSessionAuth;
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
  args: ActivateEcdsaSessionRequest & { chain: 'tempo' | 'evm' },
): Promise<ThresholdEcdsaSessionBootstrapResult> {
  const nearAccountId = toAccountId(args.nearAccountId);

  const bootstrap = await bootstrapEcdsaSession({
    indexedDB: deps.indexedDB,
    touchIdPrompt: deps.touchIdPrompt,
    prfFirstCache: deps.prfFirstCache,
    relayerUrl: args.relayerUrl,
    userId: nearAccountId,
    ecdsaThresholdKeyId: args.ecdsaThresholdKeyId,
    participantIds: args.participantIds,
    sessionKind: args.sessionKind,
    sessionId:
      String(args.sessionId || '').trim() ||
      deps.getOrCreateActiveThresholdEcdsaSessionId(nearAccountId, args.chain),
    walletSigningSessionId: args.walletSigningSessionId,
    clientRootShare32: args.clientRootShare32,
    clientRootShare32B64u: args.clientRootShare32B64u,
    webauthnAuthentication: args.webauthnAuthentication,
    bootstrapAuth: args.thresholdRouteAuth,
    runtimePolicyScope: args.runtimePolicyScope,
    runtimeScopeBootstrap: args.runtimeScopeBootstrap,
    ttlMs: args.ttlMs,
    remainingUses: args.remainingUses,
    workerCtx: deps.workerCtx,
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

  const session: EcdsaSessionSuccess = {
    ok: true,
    sessionId,
    ...(walletSigningSessionId ? { walletSigningSessionId } : {}),
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
    ...(walletSigningSessionId ? { walletSigningSessionId } : {}),
    ...(typeof session.jwt === 'string' && session.jwt.trim()
      ? { thresholdSessionJwt: session.jwt.trim() }
      : {}),
  };

  return {
    thresholdEcdsaKeyRef,
    keygen: keygen as EcdsaKeygenSuccess,
    session: session as EcdsaSessionSuccess,
  };
}

export async function activateEvmEcdsaSession(
  deps: ActivateEcdsaSessionDeps,
  args: ActivateEcdsaSessionRequest,
): Promise<ThresholdEcdsaSessionBootstrapResult> {
  return await activateEcdsaSession(deps, { ...args, chain: 'evm' });
}

export async function activateTempoEcdsaSession(
  deps: ActivateEcdsaSessionDeps,
  args: ActivateEcdsaSessionRequest,
): Promise<ThresholdEcdsaSessionBootstrapResult> {
  return await activateEcdsaSession(deps, { ...args, chain: 'tempo' });
}
