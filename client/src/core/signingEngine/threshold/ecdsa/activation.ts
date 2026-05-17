import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { ThresholdEcdsaSecp256k1KeyRef } from '@/core/signingEngine/interfaces/signing';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type {
  ThresholdIndexedDbPort,
  ThresholdWebAuthnPromptPort,
} from '@/core/signingEngine/threshold/crypto/webauthn';
import { bootstrapEcdsaSession } from '@/core/signingEngine/threshold/ecdsa/bootstrapSession';
import type { connectEcdsaSession } from '@/core/signingEngine/threshold/ecdsa/connectSession';
import type { keygenEcdsa } from '@/core/signingEngine/threshold/ecdsa/keygen';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import type { ThresholdEcdsaHssRouteAuth } from '@/core/rpcClients/relayer/thresholdEcdsa';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import {
  thresholdEcdsaChainTargetKey,
  type WalletSubjectId,
  type EvmEip155ChainTarget,
  type TempoChainTarget,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  EvmFamilyEcdsaKeyIdentity,
  EvmFamilyEcdsaSessionLanePolicy,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import { deriveEvmFamilyKeyFingerprint } from '../../session/identity/evmFamilyEcdsaIdentity';
import type { ExistingEcdsaBootstrapKeyIntent } from '../../session/passkey/ecdsaBootstrap';

export type ThresholdEcdsaEvmChainTarget = EvmEip155ChainTarget;
export type ThresholdEcdsaTempoChainTarget = TempoChainTarget;
export type ThresholdEcdsaActivationChain = ThresholdEcdsaChainTarget['kind'];

export const STALE_ECDSA_KEY_IDENTITY_ERROR_CODE = 'stale_ecdsa_key_identity' as const;

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
  session: EcdsaSessionSuccess & {
    sessionId: string;
    walletSigningSessionId: string;
    expiresAtMs: number;
    remainingUses: number;
  };
};

export type ThresholdEcdsaSessionActivationResult = ThresholdEcdsaSessionBootstrapResult & {
  clientRootShare32B64u: string;
};

export type ActivateEcdsaSessionDeps = {
  indexedDB: ThresholdIndexedDbPort;
  touchIdPrompt: ThresholdWebAuthnPromptPort;
  workerCtx: WorkerOperationContext;
  getOrCreateActiveThresholdEcdsaSessionId: (
    walletId: AccountId,
    chainTarget: ThresholdEcdsaChainTarget,
  ) => string;
};

type ActivateEcdsaSessionRequestCommon = {
  relayerUrl: string;
  clientRootShare32?: Uint8Array;
  clientRootShare32B64u?: string;
  webauthnAuthentication?: WebAuthnAuthenticationCredential;
  runtimeScopeBootstrap?: {
    environmentId: string;
    publishableKey: string;
  };
};

type ActivateEcdsaRegistrationSessionPlan = {
  kind: 'requested_session';
  sessionKind: 'jwt' | 'cookie';
  sessionId: string;
  walletSigningSessionId: string;
};

type ActivateEcdsaRegistrationRequest = ActivateEcdsaSessionRequestCommon & {
  kind: 'registration_bootstrap';
  walletId: AccountId | string;
  subjectId: WalletSubjectId;
  chainTarget: ThresholdEcdsaChainTarget;
  keyIntent?: ExistingEcdsaBootstrapKeyIntent;
  sessionPlan?: ActivateEcdsaRegistrationSessionPlan;
  thresholdSessionAuth?: ThresholdEcdsaHssRouteAuth;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  ttlMs?: number;
  remainingUses?: number;
  key?: never;
  lanePolicy?: never;
  ecdsaThresholdKeyId?: never;
  participantIds?: never;
  sessionKind?: never;
  sessionId?: never;
  walletSigningSessionId?: never;
};

type ActivateEcdsaExistingSessionRequest = ActivateEcdsaSessionRequestCommon & {
  kind: 'session_bootstrap';
  key: EvmFamilyEcdsaKeyIdentity;
  lanePolicy: EvmFamilyEcdsaSessionLanePolicy;
  thresholdSessionAuth: ThresholdEcdsaHssRouteAuth;
  walletId?: never;
  subjectId?: never;
  chainTarget?: never;
  ecdsaThresholdKeyId?: never;
  participantIds?: never;
  sessionKind?: never;
  sessionId?: never;
  walletSigningSessionId?: never;
  runtimePolicyScope?: never;
  ttlMs?: never;
  remainingUses?: never;
};

export type ActivateEcdsaSessionRequest =
  | ActivateEcdsaRegistrationRequest
  | ActivateEcdsaExistingSessionRequest;

function isStaleEcdsaIntegratedKeyBootstrapFailure(args: {
  code?: unknown;
  message?: unknown;
}): boolean {
  const code = String(args.code || '').trim();
  const message = String(args.message || '')
    .trim()
    .toLowerCase();
  return (
    code === 'stale_session_state' &&
    message.includes('threshold-ecdsa bootstrap') &&
    message.includes('client verifying share') &&
    message.includes('integrated key record')
  );
}

function createThresholdEcdsaBootstrapFailure(args: {
  code?: unknown;
  message?: unknown;
}): Error & { code: string } {
  const message = String(args.message || args.code || 'threshold-ecdsa bootstrap failed').trim();
  const code = isStaleEcdsaIntegratedKeyBootstrapFailure(args)
    ? STALE_ECDSA_KEY_IDENTITY_ERROR_CODE
    : String(args.code || 'threshold_ecdsa_bootstrap_failed').trim() ||
      'threshold_ecdsa_bootstrap_failed';
  const error = new Error(message || 'threshold-ecdsa bootstrap failed') as Error & {
    code: string;
  };
  error.code = code;
  return error;
}

function inferThresholdEcdsaBootstrapAuthMethod(
  args: ActivateEcdsaSessionRequest,
): 'passkey' | 'email_otp' | 'unknown' {
  if (args.webauthnAuthentication) return 'passkey';
  if ('thresholdSessionAuth' in args && args.thresholdSessionAuth) return 'email_otp';
  return 'unknown';
}

function normalizeExactActivationOwnerAddress(value: unknown, field: string): string {
  const normalized = String(value || '').trim().toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(normalized)) {
    throw new Error(`threshold-ecdsa exact activation returned invalid ${field}`);
  }
  return normalized;
}

function resolveExactActivationOwnerAddress(args: {
  key: EvmFamilyEcdsaKeyIdentity;
  bootstrapOwnerAddress: unknown;
}): string {
  const trustedOwnerAddress = normalizeExactActivationOwnerAddress(
    args.bootstrapOwnerAddress,
    'server owner address',
  );
  const expectedOwnerAddress = normalizeExactActivationOwnerAddress(
    args.key.thresholdOwnerAddress,
    'key owner address',
  );
  if (trustedOwnerAddress !== expectedOwnerAddress) {
    throw new Error(
      'threshold-ecdsa exact activation owner address mismatches server bootstrap result',
    );
  }
  return trustedOwnerAddress;
}

export async function activateEcdsaSession(
  deps: ActivateEcdsaSessionDeps,
  args: ActivateEcdsaSessionRequest,
): Promise<ThresholdEcdsaSessionActivationResult> {
  const exactActivation = args.kind === 'session_bootstrap';
  const walletId = toAccountId(exactActivation ? String(args.key.walletId) : args.walletId);
  const subjectId = exactActivation ? args.key.subjectId : args.subjectId;
  const chainTarget = exactActivation ? args.lanePolicy.chainTarget : args.chainTarget;

  const requestedSessionId = String(
    exactActivation ? args.lanePolicy.thresholdSessionId : args.sessionPlan?.sessionId || '',
  ).trim();
  const requestedWalletSigningSessionId = String(
    exactActivation
      ? args.lanePolicy.walletSigningSessionId
      : args.sessionPlan?.walletSigningSessionId || '',
  ).trim();
  const requestedEcdsaThresholdKeyId = String(
    exactActivation ? args.key.ecdsaThresholdKeyId : args.keyIntent?.ecdsaThresholdKeyId || '',
  ).trim();
  const baseBootstrapArgs = {
    indexedDB: deps.indexedDB,
    touchIdPrompt: deps.touchIdPrompt,
    relayerUrl: args.relayerUrl,
    chainTarget,
    chainId: chainTarget.chainId,
    userId: walletId,
    subjectId,
    participantIds: exactActivation
      ? undefined
      : args.keyIntent
        ? [...args.keyIntent.participantIds]
        : undefined,
    sessionKind: exactActivation
      ? args.lanePolicy.thresholdSessionKind
      : args.sessionPlan?.sessionKind,
    clientRootShare32: args.clientRootShare32,
    clientRootShare32B64u: args.clientRootShare32B64u,
    webauthnAuthentication: args.webauthnAuthentication,
    runtimePolicyScope: exactActivation ? undefined : args.runtimePolicyScope,
    runtimeScopeBootstrap: args.runtimeScopeBootstrap,
    ttlMs: exactActivation ? undefined : args.ttlMs,
    remainingUses: exactActivation ? undefined : args.remainingUses,
    workerCtx: deps.workerCtx,
  };
  const bootstrapRequestSummary = {
    walletId,
    subjectId,
    chainTarget,
    targetKey: thresholdEcdsaChainTargetKey(chainTarget),
    operationId: requestedSessionId || null,
    authMethod: inferThresholdEcdsaBootstrapAuthMethod(args),
    ...(exactActivation ? { evmFamilyKeyFingerprint: deriveEvmFamilyKeyFingerprint(args.key) } : {}),
    chainTargetKey: thresholdEcdsaChainTargetKey(chainTarget),
    ecdsaThresholdKeyId: requestedEcdsaThresholdKeyId || null,
    walletSigningSessionId: requestedWalletSigningSessionId || null,
    thresholdSessionId: requestedSessionId || null,
    budgetProjectionVersion: undefined,
    freshAuthRetrySideEffectState: 'not_applicable',
    hasRequestedEcdsaThresholdKeyId: Boolean(requestedEcdsaThresholdKeyId),
    requestedSessionId: requestedSessionId || null,
    requestedWalletSigningSessionId: requestedWalletSigningSessionId || null,
    sessionKind: exactActivation
      ? args.lanePolicy.thresholdSessionKind
      : args.sessionPlan?.sessionKind || 'jwt',
    authKind: args.thresholdSessionAuth?.kind || 'none',
    hasClientRootShare32B64u: Boolean(String(args.clientRootShare32B64u || '').trim()),
    hasWebAuthnAuthentication: Boolean(args.webauthnAuthentication),
  };
  let bootstrap: Awaited<ReturnType<typeof bootstrapEcdsaSession>>;
  try {
    if (
      !exactActivation &&
      args.thresholdSessionAuth &&
      requestedEcdsaThresholdKeyId &&
      requestedSessionId &&
      requestedWalletSigningSessionId
    ) {
      throw new Error(
        'Threshold ECDSA session bootstrap requires shared key identity and lane policy',
      );
    }
    bootstrap = exactActivation
      ? await bootstrapEcdsaSession({
          ...baseBootstrapArgs,
          bootstrapAuth: args.thresholdSessionAuth,
          key: args.key,
          lanePolicy: args.lanePolicy,
        })
      : args.thresholdSessionAuth
        ? await bootstrapEcdsaSession({
            ...baseBootstrapArgs,
            bootstrapAuth: args.thresholdSessionAuth,
          })
      : await bootstrapEcdsaSession({
          ...baseBootstrapArgs,
          ...(requestedEcdsaThresholdKeyId
            ? { ecdsaThresholdKeyId: requestedEcdsaThresholdKeyId }
            : {}),
          sessionId:
            requestedSessionId ||
            deps.getOrCreateActiveThresholdEcdsaSessionId(walletId, chainTarget),
          ...(requestedWalletSigningSessionId
            ? { walletSigningSessionId: requestedWalletSigningSessionId }
            : {}),
        });
  } catch (error: unknown) {
    try {
      console.warn('[threshold-ecdsa][bootstrap][exception]', {
        ...bootstrapRequestSummary,
        message: error instanceof Error ? error.message : String(error),
      });
    } catch {}
    throw error;
  }
  if (!bootstrap.ok) {
    try {
      console.warn('[threshold-ecdsa][bootstrap][failure]', {
        ...bootstrapRequestSummary,
        code: bootstrap.code || '',
        message: bootstrap.message || '',
      });
    } catch {}
    throw createThresholdEcdsaBootstrapFailure({
      code: bootstrap.code,
      message: bootstrap.message,
    });
  }

  const ecdsaThresholdKeyId = String(
    exactActivation ? args.key.ecdsaThresholdKeyId : bootstrap.ecdsaThresholdKeyId || '',
  ).trim();
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
  const clientRootShare32B64u = String(bootstrap.clientRootShare32B64u || '').trim();
  if (!clientRootShare32B64u) {
    throw new Error('threshold-ecdsa bootstrap returned empty clientRootShare32B64u');
  }

  const sessionId = String(bootstrap.sessionId || '').trim();
  if (!sessionId) {
    throw new Error('threshold-ecdsa bootstrap returned empty sessionId');
  }
  const walletSigningSessionId = String(bootstrap.walletSigningSessionId || '').trim();
  if (!walletSigningSessionId) {
    throw new Error('threshold-ecdsa bootstrap returned empty walletSigningSessionId');
  }
  const expiresAtMs = Number(bootstrap.expiresAtMs);
  if (!Number.isFinite(expiresAtMs)) {
    throw new Error('threshold-ecdsa bootstrap returned invalid expiresAtMs');
  }
  const remainingUses = Number(bootstrap.remainingUses);
  if (!Number.isFinite(remainingUses)) {
    throw new Error('threshold-ecdsa bootstrap returned invalid remainingUses');
  }
    const participantIds = exactActivation
    ? args.key.participantIds.map((participantId) => Number(participantId))
    : normalizeThresholdEd25519ParticipantIds(
        Array.isArray(args.keyIntent?.participantIds)
          ? args.keyIntent.participantIds
          : bootstrap.participantIds,
      );
  if (!participantIds) {
    throw new Error('threshold-ecdsa bootstrap returned empty participantIds');
  }
  const signingRootId = String(
    exactActivation ? args.key.signingRootId : bootstrap.signingRootId || '',
  ).trim();
  if (!signingRootId) {
    throw new Error('threshold-ecdsa bootstrap returned empty signingRootId');
  }
  const signingRootVersion = String(
    exactActivation ? args.key.signingRootVersion : bootstrap.signingRootVersion || '',
  ).trim();
  const thresholdOwnerAddress = exactActivation
    ? resolveExactActivationOwnerAddress({
        key: args.key,
        bootstrapOwnerAddress: bootstrap.ethereumAddress,
      })
    : String(bootstrap.ethereumAddress || '').trim();

  const keygen: EcdsaKeygenSuccess = {
    ok: true,
    keygenSessionId: bootstrap.keygenSessionId,
    rpId: bootstrap.rpId,
    ecdsaThresholdKeyId,
    clientVerifyingShareB64u,
    ...(clientAdditiveShare32B64u ? { clientAdditiveShare32B64u } : {}),
    relayerKeyId,
    thresholdEcdsaPublicKeyB64u: bootstrap.thresholdEcdsaPublicKeyB64u,
    ...(thresholdOwnerAddress ? { ethereumAddress: thresholdOwnerAddress } : {}),
    relayerVerifyingShareB64u: bootstrap.relayerVerifyingShareB64u,
    participantIds,
    ...(typeof bootstrap.chainId === 'number' ? { chainId: bootstrap.chainId } : {}),
    ...(bootstrap.code ? { code: bootstrap.code } : {}),
    ...(bootstrap.message ? { message: bootstrap.message } : {}),
  };

  const session: ThresholdEcdsaSessionBootstrapResult['session'] = {
    ok: true,
    sessionId,
    walletSigningSessionId,
    expiresAtMs,
    remainingUses,
    jwt: bootstrap.jwt,
    clientVerifyingShareB64u,
    ...(bootstrap.code ? { code: bootstrap.code } : {}),
    ...(bootstrap.message ? { message: bootstrap.message } : {}),
  };

  const thresholdEcdsaKeyRef: ThresholdEcdsaSecp256k1KeyRef = {
    type: 'threshold-ecdsa-secp256k1',
    userId: walletId,
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
    ...(thresholdOwnerAddress ? { ethereumAddress: thresholdOwnerAddress } : {}),
    ...(typeof bootstrap.relayerVerifyingShareB64u === 'string' &&
    bootstrap.relayerVerifyingShareB64u.trim()
      ? { relayerVerifyingShareB64u: bootstrap.relayerVerifyingShareB64u.trim() }
      : {}),
    thresholdSessionKind: exactActivation
      ? args.lanePolicy.thresholdSessionKind
      : args.sessionPlan?.sessionKind || 'jwt',
    thresholdSessionId: sessionId,
    walletSigningSessionId,
    ...(typeof session.jwt === 'string' && session.jwt.trim()
      ? { thresholdSessionAuthToken: session.jwt.trim() }
      : {}),
  };

  return {
    clientRootShare32B64u,
    thresholdEcdsaKeyRef,
    keygen: keygen as EcdsaKeygenSuccess,
    session,
  };
}
