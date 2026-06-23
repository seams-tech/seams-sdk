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
import type { RouterAbNormalSigningConfig } from '@/core/types/seams';
import { base64UrlEncode } from '@shared/utils/base64';
import {
  thresholdEcdsaChainTargetKey,
  toWalletId,
  type EvmEip155ChainTarget,
  type TempoChainTarget,
  type ThresholdEcdsaChainTarget,
  type WalletId,
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
import {
  parseEcdsaClientVerifyingShareB64u,
  parseEcdsaKeyHandle,
  parseEcdsaRelayerKeyId,
  parseEcdsaThresholdKeyId,
} from '../../session/keyMaterialBrands';
import { buildEcdsaRoleLocalSigningMaterialHandle } from '../../session/identity/ecdsaHssSigningMaterialHandle';
import { storeEcdsaRoleLocalSigningMaterialWasm } from '../crypto/hssClientSignerWasm';
import { hexToBytes } from '../../chains/evm/bytes';
import { fetchRouterAbPublicKeysetV2 } from '@/core/rpcClients/relayer/routerAbPublicKeyset';
import {
  ROUTER_AB_ECDSA_HSS_KEY_SCOPE_V1,
  ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_STATE_KIND_V1,
  parseRouterAbEcdsaHssNormalSigningStateV1,
  routerAbEcdsaHssActiveStateSessionId,
  verifyRouterAbEcdsaHssNormalSigningScopeContextBindingV1,
  type RouterAbEcdsaHssNormalSigningStateV1,
} from '@shared/utils/routerAbEcdsaHss';

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
  signingGrantId: string;
  expiresAtMs: number;
  remainingUses: number;
}): string {
  return [
    'wallet-budget',
    args.signingGrantId,
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
    thresholdSessionId: string;
    signingGrantId: string;
    expiresAtMs: number;
    remainingUses: number;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
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
  routerAbNormalSigning: RouterAbNormalSigningConfig;
  getOrCreateActiveThresholdEcdsaSessionId: (
    walletId: WalletId,
    chainTarget: ThresholdEcdsaChainTarget,
  ) => string;
};

type EmailOtpEcdsaBootstrapWorkerHandle = Extract<
  EmailOtpWorkerIssuedSessionHandle,
  { action: 'threshold_ecdsa_bootstrap' }
>;

function assertNeverRouterAbNormalSigningConfig(value: never): never {
  throw new Error(`Unexpected Router A/B normal-signing config branch: ${String(value)}`);
}

function encodeEthereumAddress20B64u(address: string): string {
  const bytes = hexToBytes(address);
  if (bytes.length !== 20) {
    throw new Error('Router A/B ECDSA-HSS normal-signing state requires a 20-byte owner address');
  }
  return base64UrlEncode(bytes);
}

async function buildRouterAbEcdsaHssNormalSigningState(args: {
  config: RouterAbNormalSigningConfig;
  relayerUrl: string;
  walletId: WalletId;
  rpId: string;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  contextBinding32B64u: string;
  clientPublicKey33B64u: string;
  serverPublicKey33B64u: string;
  thresholdPublicKey33B64u: string;
  ethereumAddress: string;
  clientShareRetryCounter: number;
  serverShareRetryCounter: number;
  activationEpoch: string;
}): Promise<RouterAbEcdsaHssNormalSigningStateV1> {
  switch (args.config.mode) {
    case 'disabled':
      throw new Error('Router A/B ECDSA-HSS normal signing must be enabled for activation');
    case 'enabled': {
      const keyset = await fetchRouterAbPublicKeysetV2({ relayerUrl: args.relayerUrl });
      const state = parseRouterAbEcdsaHssNormalSigningStateV1({
        kind: ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_STATE_KIND_V1,
        scope: {
          context: {
            wallet_id: String(args.walletId),
            rp_id: args.rpId,
            key_scope: ROUTER_AB_ECDSA_HSS_KEY_SCOPE_V1,
            ecdsa_threshold_key_id: args.ecdsaThresholdKeyId,
            signing_root_id: args.signingRootId,
            signing_root_version: args.signingRootVersion,
            key_purpose: 'evm-signing',
            key_version: 'v1',
          },
          public_identity: {
            context_binding_b64u: args.contextBinding32B64u,
            client_public_key33_b64u: args.clientPublicKey33B64u,
            server_public_key33_b64u: args.serverPublicKey33B64u,
            threshold_public_key33_b64u: args.thresholdPublicKey33B64u,
            ethereum_address20_b64u: encodeEthereumAddress20B64u(args.ethereumAddress),
            client_share_retry_counter: args.clientShareRetryCounter,
            server_share_retry_counter: args.serverShareRetryCounter,
          },
          signing_worker: {
            server_id: args.config.signingWorkerId,
            key_epoch: keyset.signing_worker_server_output_hpke.key_epoch,
            recipient_encryption_key: keyset.signing_worker_server_output_hpke.public_key,
          },
          activation_epoch: args.activationEpoch,
        },
      });
      if (!state) {
        throw new Error('Router A/B ECDSA-HSS normal-signing state could not be built');
      }
      await verifyRouterAbEcdsaHssNormalSigningScopeContextBindingV1(state.scope);
      return state;
    }
    default:
      return assertNeverRouterAbNormalSigningConfig(args.config);
  }
}

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
  sessionKind: 'jwt';
  sessionId: string;
  signingGrantId: string;
};

type ActivateEcdsaRegistrationRequestBase = ActivateEcdsaSessionRequestCommon & {
  kind: 'key_enrollment_bootstrap';
  walletId: WalletId | string;
  chainTarget: ThresholdEcdsaChainTarget;
  keyIntent?: ExistingEcdsaBootstrapKeyIntent;
  sessionPlan?: ActivateEcdsaRegistrationSessionPlan;
  walletSessionRouteAuth?: ThresholdEcdsaHssRouteAuth;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  ttlMs?: number;
  remainingUses?: number;
  key?: never;
  lanePolicy?: never;
  ecdsaThresholdKeyId?: never;
  participantIds?: never;
  sessionKind?: never;
  sessionId?: never;
  signingGrantId?: never;
};

type ActivateEcdsaExistingSessionRequestBase = ActivateEcdsaSessionRequestCommon & {
  kind: 'session_bootstrap';
  keyHandle: EvmFamilyEcdsaKeyHandle;
  key: EvmFamilyEcdsaKeyIdentity;
  lanePolicy: EvmFamilyEcdsaSessionLanePolicy;
  walletSessionRouteAuth?: ThresholdEcdsaHssRouteAuth;
  walletId?: never;
  subjectId?: never;
  chainTarget?: never;
  ecdsaThresholdKeyId?: never;
  participantIds?: never;
  sessionKind?: never;
  sessionId?: never;
  signingGrantId?: never;
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

function createStaleEcdsaKeyIdentityError(message: string): Error & {
  code: typeof STALE_ECDSA_KEY_IDENTITY_ERROR_CODE;
} {
  const error = new Error(message) as Error & {
    code: typeof STALE_ECDSA_KEY_IDENTITY_ERROR_CODE;
  };
  error.code = STALE_ECDSA_KEY_IDENTITY_ERROR_CODE;
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
    throw createStaleEcdsaKeyIdentityError(
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
  const walletId = toWalletId(exactActivation ? String(args.key.walletId) : args.walletId);
  const chainTarget = exactActivation ? args.lanePolicy.chainTarget : args.chainTarget;

  const requestedSessionId = String(
    exactActivation ? args.lanePolicy.thresholdSessionId : args.sessionPlan?.sessionId || '',
  ).trim();
  const requestedSigningGrantId = String(
    exactActivation
      ? args.lanePolicy.signingGrantId
      : args.sessionPlan?.signingGrantId || '',
  ).trim();
  const requestedEcdsaThresholdKeyId = String(
    exactActivation ? '' : args.keyIntent?.ecdsaThresholdKeyId || '',
  ).trim();
  const resolvedSessionKind = exactActivation
    ? args.lanePolicy.thresholdSessionKind
    : args.sessionPlan?.sessionKind || 'jwt';
  if (resolvedSessionKind !== 'jwt') {
    throw new Error('Threshold ECDSA activation requires JWT Wallet Session state');
  }
  if (deps.routerAbNormalSigning.mode !== 'enabled') {
    throw new Error('Router A/B ECDSA-HSS normal signing must be enabled for activation');
  }
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
    sessionKind: resolvedSessionKind,
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
    signingGrantId: requestedSigningGrantId || null,
    thresholdSessionId: requestedSessionId || null,
    budgetProjectionVersion: undefined,
    freshAuthRetrySideEffectState: 'not_applicable',
    hasRequestedEcdsaThresholdKeyId: Boolean(requestedEcdsaThresholdKeyId),
    requestedSessionId: requestedSessionId || null,
    requestedSigningGrantId: requestedSigningGrantId || null,
    sessionKind: exactActivation
      ? args.lanePolicy.thresholdSessionKind
      : args.sessionPlan?.sessionKind || 'jwt',
    authKind: args.walletSessionRouteAuth?.kind || 'none',
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
      args.walletSessionRouteAuth &&
      requestedEcdsaThresholdKeyId &&
      requestedSessionId &&
      requestedSigningGrantId
    ) {
      throw new Error(
        'Threshold ECDSA session bootstrap requires shared key identity and lane policy',
      );
    }
    bootstrap = exactActivation
      ? await bootstrapEcdsaSession({
          ...baseBootstrapArgs,
          bootstrapAuth: args.walletSessionRouteAuth,
          keyHandle: args.keyHandle,
          key: args.key,
          lanePolicy: args.lanePolicy,
        })
      : args.walletSessionRouteAuth
        ? await bootstrapEcdsaSession({
            ...baseBootstrapArgs,
            bootstrapAuth: args.walletSessionRouteAuth,
          })
        : await bootstrapEcdsaSession({
            ...baseBootstrapArgs,
            ...(requestedEcdsaThresholdKeyId
              ? { ecdsaThresholdKeyId: requestedEcdsaThresholdKeyId }
              : {}),
            sessionId:
              requestedSessionId ||
              deps.getOrCreateActiveThresholdEcdsaSessionId(walletId, chainTarget),
            ...(requestedSigningGrantId
              ? { signingGrantId: requestedSigningGrantId }
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

  const ecdsaThresholdKeyIdRaw = String(
    exactActivation ? args.key.ecdsaThresholdKeyId : bootstrap.ecdsaThresholdKeyId || '',
  ).trim();
  if (!ecdsaThresholdKeyIdRaw) {
    throw new Error('threshold-ecdsa bootstrap returned empty ecdsaThresholdKeyId');
  }
  const ecdsaThresholdKeyId = parseEcdsaThresholdKeyId(ecdsaThresholdKeyIdRaw);
  const keyHandleRaw = String(bootstrap.keyHandle || '').trim();
  const keyHandle = parseEcdsaKeyHandle(keyHandleRaw);

  const relayerKeyIdRaw = String(bootstrap.relayerKeyId || '').trim();
  if (!relayerKeyIdRaw) {
    throw new Error('threshold-ecdsa bootstrap returned empty relayerKeyId');
  }
  const relayerKeyId = parseEcdsaRelayerKeyId(relayerKeyIdRaw);

  const clientVerifyingShareB64uRaw = String(bootstrap.clientVerifyingShareB64u || '').trim();
  if (!clientVerifyingShareB64uRaw) {
    throw new Error('threshold-ecdsa bootstrap returned empty clientVerifyingShareB64u');
  }
  const clientVerifyingShareB64u = parseEcdsaClientVerifyingShareB64u(
    clientVerifyingShareB64uRaw,
  );

  const sessionId = String(bootstrap.sessionId || '').trim();
  if (!sessionId) {
    throw new Error('threshold-ecdsa bootstrap returned empty sessionId');
  }
  const signingGrantId = String(bootstrap.signingGrantId || '').trim();
  if (!signingGrantId) {
    throw new Error('threshold-ecdsa bootstrap returned empty signingGrantId');
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
  const routerAbEcdsaHssNormalSigning = await buildRouterAbEcdsaHssNormalSigningState({
    config: deps.routerAbNormalSigning,
    relayerUrl: args.relayerUrl,
    walletId,
    rpId: String(bootstrap.rpId || '').trim(),
    ecdsaThresholdKeyId,
    signingRootId: bootstrap.signingRootId,
    signingRootVersion: bootstrap.signingRootVersion,
    contextBinding32B64u: ecdsaRoleLocalReadyRecord.publicFacts.contextBinding32B64u,
    clientPublicKey33B64u: ecdsaRoleLocalReadyRecord.publicFacts.hssClientSharePublicKey33B64u,
    serverPublicKey33B64u: ecdsaRoleLocalReadyRecord.publicFacts.relayerPublicKey33B64u,
    thresholdPublicKey33B64u: ecdsaRoleLocalReadyRecord.publicFacts.groupPublicKey33B64u,
    ethereumAddress: thresholdOwnerAddress,
    clientShareRetryCounter: bootstrap.clientShareRetryCounter,
    serverShareRetryCounter: bootstrap.relayerShareRetryCounter,
    activationEpoch: sessionId,
  });
  const roleLocalMaterialHandle = buildEcdsaRoleLocalSigningMaterialHandle({
    thresholdSessionId: sessionId,
    signingGrantId,
    keyHandle,
    routerAbStateSessionId: routerAbEcdsaHssActiveStateSessionId(
      routerAbEcdsaHssNormalSigning,
    ),
    chainTarget,
    clientVerifyingShareB64u,
    ecdsaThresholdKeyId,
    participantIds,
    relayerKeyId,
  });
  const storedRoleLocalMaterial = await storeEcdsaRoleLocalSigningMaterialWasm({
    materialHandle: roleLocalMaterialHandle.materialHandle,
    bindingDigest: roleLocalMaterialHandle.bindingDigest,
    stateBlob: ecdsaRoleLocalReadyRecord.stateBlob,
    workerCtx: deps.workerCtx,
  });
  if (
    storedRoleLocalMaterial.materialHandle !== roleLocalMaterialHandle.materialHandle ||
    storedRoleLocalMaterial.bindingDigest !== roleLocalMaterialHandle.bindingDigest
  ) {
    throw new Error('threshold-ecdsa role-local worker material handle mismatch');
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
    thresholdSessionId: sessionId,
    signingGrantId,
    expiresAtMs,
    remainingUses,
    ...(bootstrap.runtimePolicyScope ? { runtimePolicyScope: bootstrap.runtimePolicyScope } : {}),
    projectionVersion: buildWalletBudgetProjectionVersion({
      signingGrantId,
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
    backendBinding: {
      materialKind: 'role_local_worker_handle',
      relayerKeyId,
      clientVerifyingShareB64u,
      roleLocalMaterialHandle,
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
    signingGrantId,
    routerAbEcdsaHssNormalSigning,
    ...(typeof session.jwt === 'string' && session.jwt.trim()
      ? { walletSessionJwt: session.jwt.trim() }
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
