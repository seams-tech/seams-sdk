import {
  buildEcdsaRoleLocalEmailOtpAuthMethod,
  buildEcdsaRoleLocalPasskeyAuthMethod,
  buildEcdsaRoleLocalPublicFacts,
  type EcdsaRoleLocalAuthMethod,
  type EcdsaRoleLocalPublicFacts,
} from '@/core/platform';
import type { EmailOtpWorkerIssuedSessionHandle } from '@/core/platform';
import type { ThresholdEcdsaSecp256k1KeyRef } from '@/core/signingEngine/interfaces/signing';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type {
  ThresholdCredentialStorePort,
  ThresholdWebAuthnPromptPort,
} from '@/core/signingEngine/threshold/crypto/webauthn';
import { bootstrapEcdsaSession } from '@/core/signingEngine/threshold/ecdsa/bootstrapSession';
import type { BootstrapEcdsaSessionResult } from '@/core/signingEngine/threshold/ecdsa/bootstrapSession';
import { type ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import type { ThresholdEcdsaDerivationRouteAuth } from '@/core/rpcClients/relayer/thresholdEcdsa';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type { RouterAbNormalSigningConfig } from '@/core/types/seams';
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
  EvmFamilyEcdsaActivationLanePolicy,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import {
  deriveEvmFamilyKeyFingerprint,
  toEvmFamilyEcdsaKeyHandle,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import {
  parseEcdsaClientVerifyingShareB64u,
  parseEcdsaKeyHandle,
  parseEcdsaRelayerKeyId,
  parseEcdsaThresholdKeyId,
} from '../../session/keyMaterialBrands';
import { buildEcdsaRoleLocalSigningMaterialHandle } from '../../session/identity/ecdsaDerivationSigningMaterialHandle';
import { storeEcdsaRoleLocalSigningMaterialWasm } from '../crypto/ecdsaDerivationClientWasm';
import {
  type RouterAbEcdsaDerivationPublicCapabilityV1,
  type RouterAbEcdsaDerivationNormalSigningStateV1,
  type RouterAbEcdsaPostRegistrationSessionActivationResponseV1,
  type RouterAbEcdsaOperationStepUpPreparationV1Wire,
  parseRouterAbEcdsaOperationStepUpPreparationV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import type {
  CapabilityGrantId,
  MpcWalletSigningQuotaId,
  SeamsSessionId,
  WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import { parseCapabilityGrantId } from '@shared/authorization/capabilityKinds';
import {
  requireAppSessionJwt,
  type AppSessionJwtAuth,
  type CookieSessionAuth,
} from '@shared/utils/sessionTokens';
import type { PersistedEcdsaRoleLocalMaterial } from '../../session/material/ecdsaRoleLocalMaterialResolver';

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

export type ThresholdEcdsaBootstrapKeyRef = Omit<
  ThresholdEcdsaSecp256k1KeyRef,
  | 'keyHandle'
  | 'backendBinding'
  | 'participantIds'
  | 'thresholdEcdsaPublicKeyB64u'
  | 'ethereumAddress'
  | 'relayerVerifyingShareB64u'
> & {
  keyHandle: string;
  backendBinding: NonNullable<ThresholdEcdsaSecp256k1KeyRef['backendBinding']>;
  participantIds: number[];
  thresholdEcdsaPublicKeyB64u: string;
  ethereumAddress: string;
  relayerVerifyingShareB64u: string;
};

export type ThresholdEcdsaSessionBootstrapResult = {
  thresholdEcdsaKeyRef: ThresholdEcdsaBootstrapKeyRef;
  session: {
    ok: true;
    thresholdSessionId: string;
    signingGrantId: string;
    authorizationSessionId: SeamsSessionId;
    walletSessionId: WalletSessionId;
    quotaId: MpcWalletSigningQuotaId;
    expiresAtMs: number;
    remainingUses: number;
    runtimePolicyScope: ThresholdRuntimePolicyScope;
    jwt: string;
    clientVerifyingShareB64u: string;
  };
  passkeyPrfFirstB64u?: string;
  passkeyCredentialIdB64u?: string;
};

export type EcdsaExplicitExportSessionAuth = AppSessionJwtAuth | CookieSessionAuth;

export type EcdsaExplicitExportOperationAuthorization = {
  readonly kind: 'operation_step_up';
  readonly grantId: CapabilityGrantId;
  readonly operation: RouterAbEcdsaOperationStepUpPreparationV1Wire;
  readonly sessionAuth: EcdsaExplicitExportSessionAuth;
  readonly expiresAtMs: number;
  readonly quotaUse: 'none';
};

export type ThresholdEcdsaExplicitKeyExportActivationResult = {
  kind: 'explicit_key_export_ecdsa_activation_result';
  purpose: 'explicit_key_export';
  material: {
    readonly kind: 'auth_neutral_ecdsa_export_material_v1';
    readonly relayerUrl: string;
    readonly persistedMaterial: PersistedEcdsaRoleLocalMaterial;
  };
  authorization: EcdsaExplicitExportOperationAuthorization;
};

export type ActivateEcdsaSessionDeps = {
  credentialStore: ThresholdCredentialStorePort;
  touchIdPrompt: ThresholdWebAuthnPromptPort;
  workerCtx: WorkerOperationContext;
  routerAbNormalSigning: RouterAbNormalSigningConfig;
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
    projectEnvironmentId: string;
    publishableKey: string;
  };
};

type ActivateEcdsaExistingSessionRequestBase = ActivateEcdsaSessionRequestCommon & {
  kind: 'session_bootstrap';
  keyHandle: EvmFamilyEcdsaKeyHandle;
  key: EvmFamilyEcdsaKeyIdentity;
  lanePolicy: EvmFamilyEcdsaActivationLanePolicy;
  publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
  existingRoleLocalMaterial: PersistedEcdsaRoleLocalMaterial;
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

export type ActivateEcdsaExistingSessionRequest = ActivateEcdsaExistingSessionRequestBase &
  ActivateEcdsaSessionAuth & { purpose: 'transaction_signing' } & (
    | {
        preauthorizedSessionActivation: RouterAbEcdsaPostRegistrationSessionActivationResponseV1;
        walletSessionRouteAuth?: never;
      }
    | {
        preauthorizedSessionActivation?: never;
      }
  );

export type ActivateExplicitKeyExportEcdsaSessionRequest = {
  readonly purpose: 'explicit_key_export';
  readonly relayerUrl: string;
  readonly existingRoleLocalMaterial: PersistedEcdsaRoleLocalMaterial;
  readonly authorization: EcdsaExplicitExportOperationAuthorization;
};

function requireStrictEcdsaRouteAuth(
  auth: ThresholdEcdsaDerivationRouteAuth | undefined,
): Extract<ThresholdEcdsaDerivationRouteAuth, { kind: 'wallet_session' }> {
  if (!auth) {
    throw new Error('Strict ECDSA session bootstrap requires Wallet Session authority');
  }
  switch (auth.kind) {
    case 'wallet_session':
      return auth;
    case 'app_session':
    case 'publishable_key':
      throw new Error('Strict ECDSA session bootstrap requires Wallet Session authority');
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
  args: ActivateEcdsaExistingSessionRequest,
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
  request: ActivateEcdsaExistingSessionRequest;
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

function bootstrapSecretSourceArgsForActivation(
  args: ActivateEcdsaExistingSessionRequest,
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
  args: ActivateEcdsaExistingSessionRequest,
): Promise<ThresholdEcdsaSessionBootstrapResult> {
  const walletId = toWalletId(String(args.key.walletId));
  const chainTarget = args.lanePolicy.chainTarget;
  const requestedSessionId = String(args.lanePolicy.thresholdSessionId).trim();
  const requestedSigningGrantId =
    'signingGrantId' in args.lanePolicy ? String(args.lanePolicy.signingGrantId || '').trim() : '';
  const resolvedSessionKind = args.lanePolicy.thresholdSessionKind;
  if (resolvedSessionKind !== 'jwt') {
    throw new Error('Threshold ECDSA activation requires JWT Wallet Session state');
  }
  if (deps.routerAbNormalSigning.mode !== 'enabled') {
    throw new Error('Router A/B ECDSA derivation normal signing must be enabled for activation');
  }
  const bootstrapSecretSourceArgs = bootstrapSecretSourceArgsForActivation(args);
  const bootstrapRequestSummary = {
    walletId,
    chainTarget,
    targetKey: thresholdEcdsaChainTargetKey(chainTarget),
    operationId: requestedSessionId || null,
    authMethod: inferThresholdEcdsaBootstrapAuthMethod(args),
    evmFamilyKeyFingerprint: deriveEvmFamilyKeyFingerprint(args.key),
    keyHandle: args.keyHandle,
    chainTargetKey: thresholdEcdsaChainTargetKey(chainTarget),
    ecdsaThresholdKeyId: String(args.key.ecdsaThresholdKeyId),
    signingGrantId: requestedSigningGrantId || null,
    thresholdSessionId: requestedSessionId || null,
    freshAuthRetrySideEffectState: 'not_applicable',
    hasRequestedEcdsaThresholdKeyId: true,
    requestedSessionId: requestedSessionId || null,
    requestedSigningGrantId: requestedSigningGrantId || null,
    sessionKind: args.lanePolicy.thresholdSessionKind,
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
    bootstrap = await bootstrapEcdsaSession({
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
      ...('preauthorizedSessionActivation' in args && args.preauthorizedSessionActivation
        ? { sessionActivation: args.preauthorizedSessionActivation }
        : { bootstrapAuth: requireStrictEcdsaRouteAuth(args.walletSessionRouteAuth) }),
      keyHandle: args.keyHandle,
      key: args.key,
      lanePolicy: args.lanePolicy,
      publicCapability: args.publicCapability,
      existingRoleLocalMaterial: args.existingRoleLocalMaterial,
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

  const ecdsaThresholdKeyIdRaw = String(args.key.ecdsaThresholdKeyId).trim();
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
  const participantIds = args.key.participantIds.map((participantId) => Number(participantId));
  if (!participantIds) {
    throw new Error('threshold-ecdsa bootstrap returned empty participantIds');
  }
  const thresholdOwnerAddress = resolveExactActivationOwnerAddress({
    key: args.key,
    bootstrapOwnerAddress: bootstrap.ethereumAddress,
  });
  const roleLocalPublicFacts = buildEcdsaRoleLocalPublicFacts({
    walletId,
    chainTarget,
    keyHandle,
    ecdsaThresholdKeyId,
    signingRootId: bootstrap.signingRootId,
    signingRootVersion: bootstrap.signingRootVersion,
    applicationBindingDigestB64u:
      bootstrap.roleLocalActivation.publicCapability.context.application_binding_digest_b64u,
    clientParticipantId: 1,
    relayerParticipantId: 2,
    participantIds,
    contextBinding32B64u: bootstrap.roleLocalActivation.publicFacts.contextBinding32B64u,
    derivationClientSharePublicKey33B64u:
      bootstrap.roleLocalActivation.publicFacts.derivationClientSharePublicKey33B64u,
    relayerPublicKey33B64u: bootstrap.roleLocalActivation.publicFacts.relayerPublicKey33B64u,
    groupPublicKey33B64u: bootstrap.roleLocalActivation.publicFacts.groupPublicKey33B64u,
    ethereumAddress: bootstrap.roleLocalActivation.publicFacts.ethereumAddress,
    publicCapability: bootstrap.roleLocalActivation.publicCapability,
  });
  const routerAbEcdsaDerivationNormalSigning = bootstrap.routerAbEcdsaDerivationNormalSigning;
  const roleLocalMaterialHandle = bootstrap.roleLocalActivation.roleLocalMaterial;
  const roleLocalAuthMethod = roleLocalAuthMethodForActivation({
    request: args,
    bootstrap,
  });

  const session: ThresholdEcdsaSessionBootstrapResult['session'] = {
    ok: true,
    thresholdSessionId: sessionId,
    signingGrantId,
    authorizationSessionId: bootstrap.authorizationSessionId,
    walletSessionId: bootstrap.walletSessionId,
    quotaId: bootstrap.quotaId,
    expiresAtMs,
    remainingUses,
    runtimePolicyScope: bootstrap.runtimePolicyScope,
    jwt: walletSessionJwt,
    clientVerifyingShareB64u,
  };

  const thresholdEcdsaKeyRef: ThresholdEcdsaBootstrapKeyRef = {
    type: 'threshold-ecdsa-secp256k1',
    userId: walletId,
    chainTarget,
    relayerUrl: args.relayerUrl,
    keyHandle,
    ecdsaThresholdKeyId,
    backendBinding: {
      materialKind: 'role_local_worker_handle',
      relayerKeyId,
      clientVerifyingShareB64u,
      roleLocalMaterialHandle,
      roleLocalMaterialRef: bootstrap.roleLocalActivation.roleLocalMaterialRef,
      publicFacts: roleLocalPublicFacts,
      authMethod: roleLocalAuthMethod,
    },
    participantIds,
    thresholdEcdsaPublicKeyB64u: bootstrap.thresholdEcdsaPublicKeyB64u,
    ethereumAddress: thresholdOwnerAddress,
    relayerVerifyingShareB64u: bootstrap.relayerVerifyingShareB64u,
    routerAbEcdsaDerivationNormalSigning,
  };

  const activationResultBase = {
    thresholdEcdsaKeyRef,
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
  args: ActivateEcdsaExistingSessionRequest,
): Promise<ThresholdEcdsaSessionBootstrapResult> {
  return await activateEcdsaSessionByPurpose(deps, args);
}

function normalizeEcdsaExplicitExportAuthorization(
  authorization: EcdsaExplicitExportOperationAuthorization,
): EcdsaExplicitExportOperationAuthorization {
  const grantId = parseCapabilityGrantId(authorization.grantId);
  if (!grantId.ok) throw new Error(grantId.error.message);
  const expiresAtMs = Math.floor(Number(authorization.expiresAtMs));
  const operation = parseRouterAbEcdsaOperationStepUpPreparationV1(authorization.operation);
  if (operation.operation_kind !== 'evm.export_key') {
    throw new Error('ECDSA explicit export operation kind is invalid');
  }
  if (!Number.isSafeInteger(expiresAtMs) || expiresAtMs <= Date.now()) {
    throw new Error('ECDSA explicit export operation grant expiry is invalid');
  }
  switch (authorization.sessionAuth.kind) {
    case 'app_session':
      return {
        kind: 'operation_step_up',
        grantId: grantId.value,
        operation,
        sessionAuth: {
          kind: 'app_session',
          jwt: requireAppSessionJwt(authorization.sessionAuth.jwt),
        },
        expiresAtMs,
        quotaUse: 'none',
      };
    case 'cookie':
      return {
        kind: 'operation_step_up',
        grantId: grantId.value,
        operation,
        sessionAuth: { kind: 'cookie' },
        expiresAtMs,
        quotaUse: 'none',
      };
  }
}

export async function activateExplicitKeyExportEcdsaSession(
  args: ActivateExplicitKeyExportEcdsaSessionRequest,
): Promise<ThresholdEcdsaExplicitKeyExportActivationResult> {
  const relayerUrl = String(args.relayerUrl || '').trim();
  if (!relayerUrl) {
    throw new Error('ECDSA explicit export relayer URL is required');
  }
  return {
    kind: 'explicit_key_export_ecdsa_activation_result',
    purpose: 'explicit_key_export',
    material: {
      kind: 'auth_neutral_ecdsa_export_material_v1',
      relayerUrl,
      persistedMaterial: args.existingRoleLocalMaterial,
    },
    authorization: normalizeEcdsaExplicitExportAuthorization(args.authorization),
  };
}
