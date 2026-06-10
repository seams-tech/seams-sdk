import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { EcdsaRoleLocalAuthMethod, EmailOtpWorkerIssuedSessionHandle } from '@/core/platform';
import type { ThresholdEcdsaSecp256k1KeyRef } from '@/core/signingEngine/interfaces/signing';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type {
  ThresholdCredentialStorePort,
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
  type EvmEip155ChainTarget,
  type TempoChainTarget,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  EvmFamilyEcdsaKeyHandle,
  EvmFamilyEcdsaKeyIdentity,
  EvmFamilyEcdsaSessionLanePolicy,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import { deriveEvmFamilyKeyFingerprint } from '../../session/identity/evmFamilyEcdsaIdentity';
import type { ExistingEcdsaBootstrapKeyIntent } from '../../session/passkey/ecdsaBootstrap';
import {
  buildEcdsaRoleLocalEmailOtpAuthMethod,
  buildEcdsaRoleLocalPasskeyAuthMethod,
  buildEcdsaRoleLocalReadyRecord,
} from '../../session/persistence/ecdsaRoleLocalRecords';

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

function buildWalletBudgetProjectionVersion(args: {
  walletSigningSessionId: string;
  expiresAtMs: number;
  remainingUses: number;
}): string {
  return [
    'wallet-budget',
    args.walletSigningSessionId,
    args.expiresAtMs,
    Math.max(0, Math.floor(Number(args.remainingUses) || 0)),
  ].join(':');
}

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
    projectionVersion?: string;
  };
  passkeyPrfFirstB64u?: string;
  passkeyCredentialIdB64u?: string;
};

export type ThresholdEcdsaSessionActivationResult = ThresholdEcdsaSessionBootstrapResult;

export type ActivateEcdsaSessionDeps = {
  credentialStore: ThresholdCredentialStorePort;
  touchIdPrompt: ThresholdWebAuthnPromptPort;
  workerCtx: WorkerOperationContext;
  getOrCreateActiveThresholdEcdsaSessionId: (
    walletId: AccountId,
    chainTarget: ThresholdEcdsaChainTarget,
  ) => string;
};

type EmailOtpEcdsaBootstrapWorkerHandle = Extract<
  EmailOtpWorkerIssuedSessionHandle,
  { action: 'threshold_ecdsa_bootstrap' }
>;

type ActivateEcdsaPasskeyPromptAuth = {
  authKind: 'passkey_prompt';
  passkeyPrfFirst32?: never;
  passkeyPrfFirstB64u?: never;
  passkeyCredentialIdB64u?: never;
  emailOtpWorkerSessionHandle?: never;
  webauthnAuthentication?: never;
};

type ActivateEcdsaPasskeyWebAuthnAuth = {
  authKind: 'passkey_webauthn';
  webauthnAuthentication: WebAuthnAuthenticationCredential;
  passkeyPrfFirst32?: never;
  passkeyPrfFirstB64u?: never;
  passkeyCredentialIdB64u?: never;
  emailOtpWorkerSessionHandle?: never;
};

type ActivateEcdsaPasskeyWebAuthnPrfB64uAuth = {
  authKind: 'passkey_webauthn_prf_b64u';
  webauthnAuthentication: WebAuthnAuthenticationCredential;
  passkeyPrfFirstB64u: string;
  passkeyPrfFirst32?: never;
  passkeyCredentialIdB64u?: never;
  emailOtpWorkerSessionHandle?: never;
};

type ActivateEcdsaPasskeyPrfB64uAuth = {
  authKind: 'passkey_prf_b64u';
  passkeyPrfFirstB64u: string;
  passkeyCredentialIdB64u: string;
  passkeyPrfFirst32?: never;
  emailOtpWorkerSessionHandle?: never;
  webauthnAuthentication?: never;
};

type ActivateEcdsaPasskeyPrfBytesAuth = {
  authKind: 'passkey_prf_bytes';
  passkeyPrfFirst32: Uint8Array;
  passkeyCredentialIdB64u: string;
  passkeyPrfFirstB64u?: never;
  emailOtpWorkerSessionHandle?: never;
  webauthnAuthentication?: never;
};

type ActivateEcdsaEmailOtpAuth = {
  authKind: 'email_otp';
  emailOtpWorkerSessionHandle: EmailOtpEcdsaBootstrapWorkerHandle;
  passkeyPrfFirst32?: never;
  passkeyPrfFirstB64u?: never;
  passkeyCredentialIdB64u?: never;
  webauthnAuthentication?: never;
};

export type ActivateEcdsaSessionAuth =
  | ActivateEcdsaPasskeyPromptAuth
  | ActivateEcdsaPasskeyWebAuthnAuth
  | ActivateEcdsaPasskeyWebAuthnPrfB64uAuth
  | ActivateEcdsaPasskeyPrfB64uAuth
  | ActivateEcdsaPasskeyPrfBytesAuth
  | ActivateEcdsaEmailOtpAuth;

type ActivateEcdsaSessionRequestCommon = {
  relayerUrl: string;
  requestId?: string;
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

type ActivateEcdsaRegistrationRequestBase = ActivateEcdsaSessionRequestCommon & {
  kind: 'key_enrollment_bootstrap';
  walletId: AccountId | string;
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

type ActivateEcdsaExistingSessionRequestBase = ActivateEcdsaSessionRequestCommon & {
  kind: 'session_bootstrap';
  keyHandle: EvmFamilyEcdsaKeyHandle;
  key: EvmFamilyEcdsaKeyIdentity;
  lanePolicy: EvmFamilyEcdsaSessionLanePolicy;
  thresholdSessionAuth?: ThresholdEcdsaHssRouteAuth;
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

type ActivateEcdsaRegistrationRequest = ActivateEcdsaRegistrationRequestBase &
  ActivateEcdsaSessionAuth;

type ActivateEcdsaExistingSessionRequest = ActivateEcdsaExistingSessionRequestBase &
  ActivateEcdsaSessionAuth;

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
  switch (args.authKind) {
    case 'email_otp':
      return 'email_otp';
    case 'passkey_prompt':
    case 'passkey_webauthn':
    case 'passkey_webauthn_prf_b64u':
    case 'passkey_prf_b64u':
    case 'passkey_prf_bytes':
      return 'passkey';
  }
  args satisfies never;
  return 'unknown';
}

function normalizeExactActivationOwnerAddress(value: unknown, field: string): string {
  const normalized = String(value || '')
    .trim()
    .toLowerCase();
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

function credentialIdB64uFromAuthenticationCredential(
  credential: WebAuthnAuthenticationCredential,
): string {
  const credentialIdB64u = String(credential.rawId || credential.id || '').trim();
  if (!credentialIdB64u) {
    throw new Error('threshold-ecdsa passkey activation requires credential id');
  }
  return credentialIdB64u;
}

type EcdsaActivationRoleLocalAuthMethodInput =
  | {
      kind: 'email_otp';
      emailOtpWorkerSessionHandle: EmailOtpEcdsaBootstrapWorkerHandle;
    }
  | {
      kind: 'passkey';
      credentialIdB64u: string;
      rpId: string;
    };

type BootstrapEcdsaSessionSuccess = Extract<
  Awaited<ReturnType<typeof bootstrapEcdsaSession>>,
  { ok: true }
>;

function roleLocalAuthMethodForActivation(
  args: EcdsaActivationRoleLocalAuthMethodInput,
): EcdsaRoleLocalAuthMethod {
  switch (args.kind) {
    case 'email_otp':
      return buildEcdsaRoleLocalEmailOtpAuthMethod({
        authSubjectId: args.emailOtpWorkerSessionHandle.authSubjectId,
      });
    case 'passkey':
      return buildEcdsaRoleLocalPasskeyAuthMethod({
        credentialIdB64u: args.credentialIdB64u,
        rpId: args.rpId,
      });
  }
  args satisfies never;
  throw new Error('threshold-ecdsa activation received unsupported role-local auth method');
}

function roleLocalAuthMethodInputForActivation(args: {
  request: ActivateEcdsaSessionRequest;
  bootstrap: BootstrapEcdsaSessionSuccess;
  rpId: string;
}): EcdsaActivationRoleLocalAuthMethodInput {
  switch (args.request.authKind) {
    case 'email_otp':
      return {
        kind: 'email_otp',
        emailOtpWorkerSessionHandle: args.request.emailOtpWorkerSessionHandle,
      };
    case 'passkey_webauthn':
    case 'passkey_webauthn_prf_b64u':
      return {
        kind: 'passkey',
        credentialIdB64u: credentialIdB64uFromAuthenticationCredential(
          args.request.webauthnAuthentication,
        ),
        rpId: args.rpId,
      };
    case 'passkey_prompt':
    case 'passkey_prf_b64u':
    case 'passkey_prf_bytes':
      break;
  }
  if (args.bootstrap.secretSourceKind === 'passkey') {
    return {
      kind: 'passkey',
      credentialIdB64u: args.bootstrap.passkeyCredentialIdB64u,
      rpId: args.rpId,
    };
  }
  if (args.bootstrap.secretSourceKind === 'email_otp') {
    throw new Error('threshold-ecdsa email OTP activation requires worker session handle');
  }
  args.bootstrap satisfies never;
  throw new Error('threshold-ecdsa activation could not resolve role-local auth method');
}

function bootstrapSecretSourceArgsForActivation(
  args: ActivateEcdsaSessionRequest,
):
  | ActivateEcdsaPasskeyPromptAuth
  | ActivateEcdsaPasskeyWebAuthnAuth
  | ActivateEcdsaPasskeyWebAuthnPrfB64uAuth
  | ActivateEcdsaPasskeyPrfB64uAuth
  | ActivateEcdsaPasskeyPrfBytesAuth
  | ActivateEcdsaEmailOtpAuth {
  switch (args.authKind) {
    case 'email_otp':
      return {
        authKind: 'email_otp',
        emailOtpWorkerSessionHandle: args.emailOtpWorkerSessionHandle,
      };
    case 'passkey_webauthn':
      return {
        authKind: 'passkey_webauthn',
        webauthnAuthentication: args.webauthnAuthentication,
      };
    case 'passkey_webauthn_prf_b64u':
      return {
        authKind: 'passkey_webauthn_prf_b64u',
        webauthnAuthentication: args.webauthnAuthentication,
        passkeyPrfFirstB64u: args.passkeyPrfFirstB64u,
      };
    case 'passkey_prf_b64u':
      return {
        authKind: 'passkey_prf_b64u',
        passkeyPrfFirstB64u: args.passkeyPrfFirstB64u,
        passkeyCredentialIdB64u: args.passkeyCredentialIdB64u,
      };
    case 'passkey_prf_bytes':
      return {
        authKind: 'passkey_prf_bytes',
        passkeyPrfFirst32: args.passkeyPrfFirst32,
        passkeyCredentialIdB64u: args.passkeyCredentialIdB64u,
      };
    case 'passkey_prompt':
      return { authKind: 'passkey_prompt' };
  }
  args satisfies never;
  return { authKind: 'passkey_prompt' };
}

export async function activateEcdsaSession(
  deps: ActivateEcdsaSessionDeps,
  args: ActivateEcdsaSessionRequest,
): Promise<ThresholdEcdsaSessionActivationResult> {
  const exactActivation = args.kind === 'session_bootstrap';
  const walletId = toAccountId(exactActivation ? String(args.key.walletId) : args.walletId);
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
    exactActivation ? '' : args.keyIntent?.ecdsaThresholdKeyId || '',
  ).trim();
  const bootstrapSecretSourceArgs = bootstrapSecretSourceArgsForActivation(args);
  const baseBootstrapArgs = {
    credentialStore: deps.credentialStore,
    touchIdPrompt: deps.touchIdPrompt,
    relayerUrl: args.relayerUrl,
    chainTarget,
    userId: walletId,
    participantIds: exactActivation
      ? undefined
      : args.keyIntent
        ? [...args.keyIntent.participantIds]
        : undefined,
    sessionKind: exactActivation
      ? args.lanePolicy.thresholdSessionKind
      : args.sessionPlan?.sessionKind,
    ...bootstrapSecretSourceArgs,
    requestId: args.requestId,
    runtimePolicyScope: exactActivation ? undefined : args.runtimePolicyScope,
    runtimeScopeBootstrap: args.runtimeScopeBootstrap,
    ttlMs: exactActivation ? undefined : args.ttlMs,
    remainingUses: exactActivation ? undefined : args.remainingUses,
    workerCtx: deps.workerCtx,
  };
  const bootstrapRequestSummary = {
    walletId,
    chainTarget,
    targetKey: thresholdEcdsaChainTargetKey(chainTarget),
    operationId: requestedSessionId || null,
    authMethod: inferThresholdEcdsaBootstrapAuthMethod(args),
    ...(exactActivation
      ? {
          evmFamilyKeyFingerprint: deriveEvmFamilyKeyFingerprint(args.key),
          keyHandle: args.keyHandle,
        }
      : {}),
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
    hasPasskeyPrfFirstB64u:
      args.authKind === 'passkey_prf_b64u' || args.authKind === 'passkey_webauthn_prf_b64u'
        ? Boolean(String(args.passkeyPrfFirstB64u || '').trim())
        : false,
    hasWebAuthnAuthentication:
      args.authKind === 'passkey_webauthn' || args.authKind === 'passkey_webauthn_prf_b64u',
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
          keyHandle: args.keyHandle,
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
  const keyHandle = String(bootstrap.keyHandle || '').trim();

  const relayerKeyId = String(bootstrap.relayerKeyId || '').trim();
  if (!relayerKeyId) {
    throw new Error('threshold-ecdsa bootstrap returned empty relayerKeyId');
  }

  const clientVerifyingShareB64u = String(bootstrap.clientVerifyingShareB64u || '').trim();
  if (!clientVerifyingShareB64u) {
    throw new Error('threshold-ecdsa bootstrap returned empty clientVerifyingShareB64u');
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
  const ecdsaRoleLocalReadyRecord = bootstrap.ecdsaHssRoleLocalClientState
    ? buildEcdsaRoleLocalReadyRecord({
        stateBlob: bootstrap.ecdsaHssRoleLocalClientState.stateBlob,
        publicFacts: bootstrap.ecdsaHssRoleLocalClientState.publicFacts,
        authMethod: roleLocalAuthMethodForActivation(
          roleLocalAuthMethodInputForActivation({
            request: args,
            bootstrap,
            rpId: String(bootstrap.rpId || '').trim(),
          }),
        ),
      })
    : undefined;
  if (!ecdsaRoleLocalReadyRecord) {
    throw new Error('threshold-ecdsa bootstrap returned empty role-local ready record');
  }

  const keygen: EcdsaKeygenSuccess = {
    ok: true,
    keygenSessionId: bootstrap.keygenSessionId,
    rpId: bootstrap.rpId,
    ...(keyHandle ? { keyHandle } : {}),
    ecdsaThresholdKeyId,
    clientVerifyingShareB64u,
    relayerKeyId,
    thresholdEcdsaPublicKeyB64u: bootstrap.thresholdEcdsaPublicKeyB64u,
    ...(thresholdOwnerAddress ? { ethereumAddress: thresholdOwnerAddress } : {}),
    relayerVerifyingShareB64u: bootstrap.relayerVerifyingShareB64u,
    participantIds,
    chainId: bootstrap.chainId,
  };

  const session: ThresholdEcdsaSessionBootstrapResult['session'] = {
    ok: true,
    sessionId,
    walletSigningSessionId,
    expiresAtMs,
    remainingUses,
    projectionVersion: buildWalletBudgetProjectionVersion({
      walletSigningSessionId,
      expiresAtMs,
      remainingUses,
    }),
    jwt: bootstrap.jwt,
    clientVerifyingShareB64u,
  };

  const thresholdEcdsaKeyRef: ThresholdEcdsaSecp256k1KeyRef = {
    type: 'threshold-ecdsa-secp256k1',
    userId: walletId,
    chainTarget,
    relayerUrl: args.relayerUrl,
    ...(bootstrap.keyHandle ? { keyHandle: bootstrap.keyHandle } : {}),
    ecdsaThresholdKeyId,
    signingRootId,
    ...(signingRootVersion ? { signingRootVersion } : {}),
    backendBinding: {
      materialKind: 'role_local_ready_state_blob',
      relayerKeyId,
      clientVerifyingShareB64u,
      stateBlob: ecdsaRoleLocalReadyRecord.stateBlob,
      ecdsaRoleLocalReadyRecord,
    },
    participantIds,
    ...(typeof bootstrap.thresholdEcdsaPublicKeyB64u === 'string' &&
    bootstrap.thresholdEcdsaPublicKeyB64u.trim()
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

  const activationResultBase = {
    thresholdEcdsaKeyRef,
    keygen: keygen as EcdsaKeygenSuccess,
    session,
  };
  if (bootstrap.secretSourceKind === 'passkey') {
    return {
      ...activationResultBase,
      passkeyPrfFirstB64u: bootstrap.passkeyPrfFirstB64u,
      passkeyCredentialIdB64u: bootstrap.passkeyCredentialIdB64u,
    };
  }
  return activationResultBase;
}
