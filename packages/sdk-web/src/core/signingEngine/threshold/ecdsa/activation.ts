import {
  buildEcdsaRoleLocalEmailOtpAuthMethod,
  buildEcdsaRoleLocalPasskeyAuthMethod,
  buildEcdsaRoleLocalPublicFacts,
  type EcdsaRoleLocalAuthMethod,
  type EcdsaRoleLocalPublicFacts,
  type EmailOtpWorkerIssuedSessionHandle,
} from '@/core/platform';
import type { FinalizeRouterAbEcdsaRecoveryActivationResultV1 } from '../../workerManager/ecdsaClientWorkerChannels';
import type { ThresholdEcdsaSecp256k1KeyRef } from '@/core/signingEngine/interfaces/signing';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type {
  ThresholdCredentialStorePort,
  ThresholdWebAuthnPromptPort,
} from '@/core/signingEngine/threshold/crypto/webauthn';
import { bootstrapEcdsaSession } from '@/core/signingEngine/threshold/ecdsa/bootstrapSession';
import type { BootstrapEcdsaSessionResult } from '@/core/signingEngine/threshold/ecdsa/bootstrapSession';
import type { connectEcdsaSession } from '@/core/signingEngine/threshold/ecdsa/connectSession';
import type { keygenEcdsa } from '@/core/signingEngine/threshold/ecdsa/keygen';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import type { ThresholdEcdsaDerivationRouteAuth } from '@/core/rpcClients/relayer/thresholdEcdsa';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type { RouterAbNormalSigningConfig } from '@/core/types/seams';
import { base64UrlEncode } from '@shared/utils/base64';
import {
  parseSdkEcdsaDerivationSigningRootId,
  parseSdkEcdsaDerivationSigningRootVersion,
} from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';
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
import {
  deriveEvmFamilyKeyFingerprint,
  deriveEvmFamilySigningKeySlotIdFromRuntimePolicyScope,
  toEvmFamilyEcdsaKeyHandle,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import type { ExistingEcdsaBootstrapKeyIntent } from '../../session/passkey/ecdsaBootstrap';
import {
  parseEcdsaClientVerifyingShareB64u,
  parseEcdsaKeyHandle,
  parseEcdsaRelayerKeyId,
  parseEcdsaThresholdKeyId,
} from '../../session/keyMaterialBrands';
import { buildEcdsaRoleLocalSigningMaterialHandle } from '../../session/identity/ecdsaDerivationSigningMaterialHandle';
import { storeEcdsaRoleLocalSigningMaterialWasm } from '../crypto/ecdsaDerivationClientWasm';
import { hexToBytes } from '../../chains/evm/bytes';
import { fetchRouterAbPublicKeysetV2 } from '@/core/rpcClients/relayer/routerAbPublicKeyset';
import {
  ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1,
  parseRouterAbEcdsaDerivationNormalSigningStateV1,
  routerAbEcdsaDerivationStableKeyContextFromSdkFactsV1,
  routerAbEcdsaDerivationActiveStateSessionId,
  verifyRouterAbEcdsaDerivationNormalSigningScopeContextBindingV1,
  type RouterAbEcdsaDerivationPublicCapabilityV1,
  type RouterAbEcdsaDerivationNormalSigningStateV1,
} from '@shared/utils/routerAbEcdsaDerivation';

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

export type ThresholdEcdsaExplicitKeyExportActivationResult = {
  kind: 'explicit_key_export_ecdsa_activation_result';
  purpose: 'explicit_key_export';
  material: {
    walletId: WalletId;
    evmFamilySigningKeySlotId: string;
    chainTarget: ThresholdEcdsaChainTarget;
    relayerUrl: string;
    keyHandle: EvmFamilyEcdsaKeyHandle;
    ecdsaThresholdKeyId: string;
    relayerKeyId: string;
    clientVerifyingShareB64u: string;
    participantIds: readonly number[];
    thresholdEcdsaPublicKeyB64u: string;
    ethereumAddress: string;
    relayerVerifyingShareB64u: string;
    thresholdSessionId: string;
    signingGrantId: string;
    expiresAtMs: number;
    remainingUses: number;
    walletSessionJwt: string;
    roleLocalMaterial:
      FinalizeRouterAbEcdsaRecoveryActivationResultV1['roleLocalMaterial'];
    publicFacts: EcdsaRoleLocalPublicFacts;
  };
  passkeyPrfFirstB64u: string;
  passkeyCredentialIdB64u: string;
};

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
    throw new Error(
      'Router A/B ECDSA derivation normal-signing state requires a 20-byte owner address',
    );
  }
  return base64UrlEncode(bytes);
}

async function buildRouterAbEcdsaDerivationNormalSigningState(args: {
  config: RouterAbNormalSigningConfig;
  relayerUrl: string;
  walletId: WalletId;
  evmFamilySigningKeySlotId: string;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  contextBinding32B64u: string;
  derivationClientSharePublicKey33B64u: string;
  serverPublicKey33B64u: string;
  thresholdPublicKey33B64u: string;
  ethereumAddress: string;
  clientShareRetryCounter: number;
  serverShareRetryCounter: number;
  activationEpoch: string;
}): Promise<RouterAbEcdsaDerivationNormalSigningStateV1> {
  switch (args.config.mode) {
    case 'disabled':
      throw new Error('Router A/B ECDSA derivation normal signing must be enabled for activation');
    case 'enabled': {
      const keyset = await fetchRouterAbPublicKeysetV2({ relayerUrl: args.relayerUrl });
      const context = await routerAbEcdsaDerivationStableKeyContextFromSdkFactsV1({
        walletId: toWalletId(args.walletId),
        ecdsaThresholdKeyId: parseEcdsaThresholdKeyId(args.ecdsaThresholdKeyId),
        signingRootId: parseSdkEcdsaDerivationSigningRootId(args.signingRootId),
        signingRootVersion: parseSdkEcdsaDerivationSigningRootVersion(args.signingRootVersion),
      });
      const state = parseRouterAbEcdsaDerivationNormalSigningStateV1({
        kind: ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1,
        scope: {
          wallet_key_id: args.evmFamilySigningKeySlotId,
          wallet_id: String(args.walletId),
          ecdsa_threshold_key_id: args.ecdsaThresholdKeyId,
          signing_root_id: args.signingRootId,
          signing_root_version: args.signingRootVersion,
          context,
          public_identity: {
            context_binding_b64u: args.contextBinding32B64u,
            derivation_client_share_public_key33_b64u: args.derivationClientSharePublicKey33B64u,
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
        throw new Error('Router A/B ECDSA derivation normal-signing state could not be built');
      }
      await verifyRouterAbEcdsaDerivationNormalSigningScopeContextBindingV1(state.scope);
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
    projectEnvironmentId: string;
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
  purpose: 'transaction_signing';
  walletId: WalletId | string;
  chainTarget: ThresholdEcdsaChainTarget;
  keyIntent?: ExistingEcdsaBootstrapKeyIntent;
  sessionPlan?: ActivateEcdsaRegistrationSessionPlan;
  walletSessionRouteAuth?: ThresholdEcdsaDerivationRouteAuth;
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
  publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
  walletSessionRouteAuth?: ThresholdEcdsaDerivationRouteAuth;
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
  ActivateEcdsaSessionAuth & { purpose: 'transaction_signing' };

export type ActivateExplicitKeyExportEcdsaSessionRequest = ActivateEcdsaExistingSessionRequestBase &
  ActivateEcdsaPasskeyWebAuthnPrfB64uAuth & {
    purpose: 'explicit_key_export';
  };

export type ActivateEcdsaSessionRequest =
  | ActivateEcdsaRegistrationRequest
  | ActivateEcdsaExistingSessionRequest;

type ActivateEcdsaSessionByPurposeRequest =
  | ActivateEcdsaSessionRequest
  | ActivateExplicitKeyExportEcdsaSessionRequest;

function requireStrictEcdsaRouteAuth(
  auth: ThresholdEcdsaDerivationRouteAuth | undefined,
): Extract<ThresholdEcdsaDerivationRouteAuth, { kind: 'app_session' | 'wallet_session' }> {
  if (!auth) {
    throw new Error('Strict ECDSA session bootstrap requires app or Wallet Session authority');
  }
  switch (auth.kind) {
    case 'app_session':
    case 'wallet_session':
      return auth;
    case 'bootstrap_grant':
    case 'publishable_key':
      throw new Error('Strict ECDSA session bootstrap requires app or Wallet Session authority');
  }
  auth satisfies never;
  throw new Error('Strict ECDSA session bootstrap authority is invalid');
}

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
  args: ActivateEcdsaSessionByPurposeRequest,
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

function roleLocalAuthMethodForActivation(args: {
  request: ActivateEcdsaSessionByPurposeRequest;
  bootstrap: Extract<BootstrapEcdsaSessionResult, { ok: true }>;
}): EcdsaRoleLocalAuthMethod {
  switch (args.bootstrap.secretSourceKind) {
    case 'passkey':
      return buildEcdsaRoleLocalPasskeyAuthMethod({
        credentialIdB64u: args.bootstrap.passkeyCredentialIdB64u,
        rpId: args.bootstrap.rpId,
      });
    case 'email_otp':
      if (args.request.authKind !== 'email_otp') {
        throw new Error('Email OTP ECDSA bootstrap requires Email OTP auth material');
      }
      return buildEcdsaRoleLocalEmailOtpAuthMethod({
        authSubjectId: args.request.emailOtpWorkerSessionHandle.authSubjectId,
      });
  }
}

function resolveEcdsaActivationWalletKeyId(args: ActivateEcdsaSessionByPurposeRequest): string {
  if (args.kind === 'session_bootstrap') {
    return String(args.key.evmFamilySigningKeySlotId);
  }
  if (!args.runtimePolicyScope) {
    throw new Error(
      'Threshold ECDSA activation requires runtimePolicyScope to derive signing key slot id',
    );
  }
  return String(
    deriveEvmFamilySigningKeySlotIdFromRuntimePolicyScope({
      walletId: args.walletId,
      runtimePolicyScope: args.runtimePolicyScope,
    }),
  );
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

type BootstrapEcdsaSessionSuccess = Extract<
  Awaited<ReturnType<typeof bootstrapEcdsaSession>>,
  { ok: true }
>;

function bootstrapSecretSourceArgsForActivation(
  args: ActivateEcdsaSessionByPurposeRequest,
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

async function activateEcdsaSessionByPurpose(
  deps: ActivateEcdsaSessionDeps,
  args: ActivateEcdsaSessionByPurposeRequest,
): Promise<
  ThresholdEcdsaSessionActivationResult | ThresholdEcdsaExplicitKeyExportActivationResult
> {
  const exactActivation = args.kind === 'session_bootstrap';
  const walletId = toWalletId(exactActivation ? String(args.key.walletId) : args.walletId);
  const chainTarget = exactActivation ? args.lanePolicy.chainTarget : args.chainTarget;

  const requestedSessionId = String(
    exactActivation ? args.lanePolicy.thresholdSessionId : args.sessionPlan?.sessionId || '',
  ).trim();
  const requestedSigningGrantId = String(
    exactActivation ? args.lanePolicy.signingGrantId : args.sessionPlan?.signingGrantId || '',
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
    throw new Error('Router A/B ECDSA derivation normal signing must be enabled for activation');
  }
  const evmFamilySigningKeySlotId = resolveEcdsaActivationWalletKeyId(args);
  const bootstrapSecretSourceArgs = bootstrapSecretSourceArgsForActivation(args);
  const baseBootstrapArgs = {
    credentialStore: deps.credentialStore,
    touchIdPrompt: deps.touchIdPrompt,
    relayerUrl: args.relayerUrl,
    chainTarget,
    userId: walletId,
    evmFamilySigningKeySlotId,
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
          credentialStore: deps.credentialStore,
          touchIdPrompt: deps.touchIdPrompt,
          relayerUrl: args.relayerUrl,
          chainTarget,
          userId: walletId,
          sessionKind: resolvedSessionKind,
          requestId: args.requestId,
          runtimeScopeBootstrap: args.runtimeScopeBootstrap,
          workerCtx: deps.workerCtx,
          ...bootstrapSecretSourceArgs,
          bootstrapAuth: requireStrictEcdsaRouteAuth(args.walletSessionRouteAuth),
          keyHandle: args.keyHandle,
          key: args.key,
          lanePolicy: args.lanePolicy,
          publicCapability: args.publicCapability,
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
            ...(requestedSigningGrantId ? { signingGrantId: requestedSigningGrantId } : {}),
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
  const clientVerifyingShareB64u = parseEcdsaClientVerifyingShareB64u(clientVerifyingShareB64uRaw);

  const sessionId = String(bootstrap.sessionId || '').trim();
  if (!sessionId) {
    throw new Error('threshold-ecdsa bootstrap returned empty sessionId');
  }
  const signingGrantId = String(bootstrap.signingGrantId || '').trim();
  if (!signingGrantId) {
    throw new Error('threshold-ecdsa bootstrap returned empty signingGrantId');
  }
  const walletSessionJwt = String(bootstrap.jwt || '').trim();
  if (!walletSessionJwt) {
    throw new Error('threshold-ecdsa bootstrap returned empty Wallet Session JWT');
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
  const strictRoleLocalPublicFacts =
    bootstrap.bootstrapKind === 'strict_post_registration'
      ? buildEcdsaRoleLocalPublicFacts({
          walletId,
          evmFamilySigningKeySlotId: bootstrap.evmFamilySigningKeySlotId,
          chainTarget,
          keyHandle,
          ecdsaThresholdKeyId,
          signingRootId: bootstrap.signingRootId,
          signingRootVersion: bootstrap.signingRootVersion,
          applicationBindingDigestB64u:
            bootstrap.roleLocalActivation.publicCapability.context
              .application_binding_digest_b64u,
          clientParticipantId: 1,
          relayerParticipantId: 2,
          participantIds,
          contextBinding32B64u:
            bootstrap.roleLocalActivation.publicFacts.contextBinding32B64u,
          derivationClientSharePublicKey33B64u:
            bootstrap.roleLocalActivation.publicFacts.derivationClientSharePublicKey33B64u,
          relayerPublicKey33B64u:
            bootstrap.roleLocalActivation.publicFacts.relayerPublicKey33B64u,
          groupPublicKey33B64u:
            bootstrap.roleLocalActivation.publicFacts.groupPublicKey33B64u,
          ethereumAddress: bootstrap.roleLocalActivation.publicFacts.ethereumAddress,
          publicCapability: bootstrap.roleLocalActivation.publicCapability,
        })
      : null;
  const roleLocalPublicFacts = strictRoleLocalPublicFacts;
  if (!roleLocalPublicFacts) {
    throw new Error('threshold-ecdsa bootstrap returned empty role-local public facts');
  }
  if (args.purpose === 'explicit_key_export') {
    if (bootstrap.secretSourceKind !== 'passkey') {
      throw new Error('Explicit ECDSA key export activation requires passkey material');
    }
    return {
      kind: 'explicit_key_export_ecdsa_activation_result',
      purpose: 'explicit_key_export',
      material: {
        walletId,
        evmFamilySigningKeySlotId: String(bootstrap.evmFamilySigningKeySlotId || '').trim(),
        chainTarget,
        relayerUrl: args.relayerUrl,
        keyHandle: toEvmFamilyEcdsaKeyHandle(keyHandle),
        ecdsaThresholdKeyId,
        relayerKeyId,
        clientVerifyingShareB64u,
        participantIds,
        thresholdEcdsaPublicKeyB64u: String(bootstrap.thresholdEcdsaPublicKeyB64u || '').trim(),
        ethereumAddress: thresholdOwnerAddress,
        relayerVerifyingShareB64u: String(bootstrap.relayerVerifyingShareB64u || '').trim(),
        thresholdSessionId: sessionId,
        signingGrantId,
        expiresAtMs,
        remainingUses,
        walletSessionJwt,
        roleLocalMaterial: bootstrap.roleLocalActivation.roleLocalMaterial,
        publicFacts: roleLocalPublicFacts,
      },
      passkeyPrfFirstB64u: bootstrap.passkeyPrfFirstB64u,
      passkeyCredentialIdB64u: bootstrap.passkeyCredentialIdB64u,
    };
  }
  const routerAbEcdsaDerivationNormalSigning = bootstrap.routerAbEcdsaDerivationNormalSigning;
  const roleLocalMaterialHandle = {
    kind: 'role_local_worker_session' as const,
    materialHandle: bootstrap.roleLocalActivation.roleLocalMaterial.materialHandle,
    bindingDigest: bootstrap.roleLocalActivation.roleLocalMaterial.bindingDigest,
    durableMaterialRef: bootstrap.roleLocalActivation.roleLocalMaterial.durableMaterialRef,
  };
  const roleLocalAuthMethod = roleLocalAuthMethodForActivation({
    request: args,
    bootstrap,
  });

  const keygen: EcdsaKeygenSuccess = {
    ok: true,
    keygenSessionId: bootstrap.keygenSessionId,
    evmFamilySigningKeySlotId: bootstrap.evmFamilySigningKeySlotId,
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
    jwt: walletSessionJwt,
    clientVerifyingShareB64u,
  };

  const thresholdEcdsaKeyRef: ThresholdEcdsaSecp256k1KeyRef = {
    type: 'threshold-ecdsa-secp256k1',
    userId: walletId,
    evmFamilySigningKeySlotId: bootstrap.evmFamilySigningKeySlotId,
    chainTarget,
    relayerUrl: args.relayerUrl,
    ...(bootstrap.keyHandle ? { keyHandle: bootstrap.keyHandle } : {}),
    ecdsaThresholdKeyId,
    backendBinding: {
      materialKind: 'role_local_worker_handle',
      relayerKeyId,
      clientVerifyingShareB64u,
      roleLocalMaterialHandle,
      publicFacts: roleLocalPublicFacts,
      authMethod: roleLocalAuthMethod,
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
    routerAbEcdsaDerivationNormalSigning,
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

export async function activateEcdsaSession(
  deps: ActivateEcdsaSessionDeps,
  args: ActivateEcdsaSessionRequest,
): Promise<ThresholdEcdsaSessionActivationResult> {
  const result = await activateEcdsaSessionByPurpose(deps, args);
  if ('purpose' in result) {
    throw new Error('Transaction ECDSA activation returned explicit export material');
  }
  return result;
}

export async function activateExplicitKeyExportEcdsaSession(
  deps: ActivateEcdsaSessionDeps,
  args: ActivateExplicitKeyExportEcdsaSessionRequest,
): Promise<ThresholdEcdsaExplicitKeyExportActivationResult> {
  const result = await activateEcdsaSessionByPurpose(deps, args);
  if (!('purpose' in result)) {
    throw new Error('Explicit ECDSA key export activation returned transaction material');
  }
  return result;
}
