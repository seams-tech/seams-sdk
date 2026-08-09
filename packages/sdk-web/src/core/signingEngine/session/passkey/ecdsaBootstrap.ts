import type { EmailOtpWorkerIssuedSessionHandle } from '@/core/platform';
import type { RouterAbNormalSigningConfig } from '@/core/types/seams';
import type { TouchIdPrompt } from '../../stepUpConfirmation/passkeyPrompt/touchIdPrompt';
import type { SignerWorkerManagerContext } from '../../workerManager/SignerWorkerManager';
import type {
  ThresholdCredentialStorePort,
  ThresholdWarmSessionMaterialPort,
} from '../../threshold/crypto/webauthn';
import {
  activateEcdsaSession,
  activateExplicitKeyExportEcdsaSession,
  type ActivateExplicitKeyExportEcdsaSessionRequest,
  type ActivateEcdsaSessionAuth,
  type ActivateEcdsaExistingSessionRequest,
  type EcdsaExplicitExportOperationAuthorization,
  type ThresholdEcdsaExplicitKeyExportActivationResult,
  type ThresholdEcdsaSessionBootstrapResult,
} from '../../threshold/ecdsa/activation';
import type {
  ThresholdEcdsaEmailOtpAuthContext,
  ThresholdEcdsaSessionStoreSource,
} from '../identity/laneIdentity';
import type { ThresholdRuntimePolicyScope } from '../../threshold/sessionPolicy';
import type { ThresholdEcdsaDerivationRouteAuth } from '@/core/rpcClients/relayer/thresholdEcdsa';
import type { AppOrWalletSessionAuth } from '@shared/utils/sessionTokens';
import type { WalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import { SigningSessionIds, type SigningOperationIntent } from '../operationState/types';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildEcdsaSessionIdentity,
  type EcdsaSessionIdentity,
} from '../warmCapabilities/ecdsaProvisionPlan';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import {
  toEvmFamilyEcdsaKeyHandle,
  toRpId,
  type EvmFamilyEcdsaKeyHandle,
  type EvmFamilyEcdsaKeyIdentity,
  type EvmFamilyEcdsaActivationLanePolicy,
} from '../identity/evmFamilyEcdsaIdentity';
import type { PasskeyEcdsaReadyPersistInput } from '../warmCapabilities/persistencePorts';
import { SIGNER_AUTH_METHODS, SIGNER_SOURCES } from '@shared/utils/signerDomain';
import type { ThresholdEcdsaBootstrapSignerAuth } from '../warmCapabilities/ecdsaBootstrapPersistence';
import type {
  RouterAbEcdsaDerivationPublicCapabilityV1,
  RouterAbEcdsaPostRegistrationSessionActivationResponseV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import { requireRouterAbEcdsaDerivationNormalSigningStateV1 } from '@shared/utils/routerAbEcdsaDerivation';
import type { SealedSigningSessionEcdsaRestoreMetadata } from '@shared/utils/signingSessionSeal';
import type { ThresholdEcdsaBackendBinding } from '@/core/signingEngine/interfaces/signing';
import type { PersistedEcdsaRoleLocalMaterial } from '../material/ecdsaRoleLocalMaterialResolver';
import { walletSessionAuthorizations } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import { persistActiveWalletSessionAuthorizationFromEcdsaBootstrap } from '../persistence/walletSessionAuthorizationProjection';

export type ExistingEcdsaBootstrapKeyIntent = {
  kind: 'existing_ecdsa_key';
  ecdsaThresholdKeyId: string;
  participantIds: readonly number[];
};

type EcdsaBootstrapRequestCommon = {
  source?: ThresholdEcdsaSessionStoreSource;
  relayerUrl?: string;
  operationIntent?: SigningOperationIntent;
  requestId?: string;
  beforeAuthorizationPersistence?: () => Promise<void>;
  runtimeScopeBootstrap?: {
    projectEnvironmentId: string;
    publishableKey: string;
  };
};

type EcdsaBootstrapTargetIdentity = {
  walletId: WalletId | string;
  subjectId?: never;
  chainTarget: ThresholdEcdsaChainTarget;
  key?: never;
  lanePolicy?: never;
  publicCapability?: never;
};

type EcdsaBootstrapExactIdentity = {
  keyHandle: EvmFamilyEcdsaKeyHandle | string;
  key: EvmFamilyEcdsaKeyIdentity;
  lanePolicy: EvmFamilyEcdsaActivationLanePolicy;
  publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
  existingRoleLocalMaterial: PersistedEcdsaRoleLocalMaterial;
  walletId?: never;
  subjectId?: never;
  chainTarget?: never;
  keyIntent?: never;
  sessionKind?: never;
  sessionIdentity?: never;
  runtimePolicyScope?: never;
  ttlMs?: never;
  remainingUses?: never;
};

type EcdsaBootstrapRegistrationPolicy = {
  keyIntent?: ExistingEcdsaBootstrapKeyIntent;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  ttlMs?: number;
  remainingUses?: number;
};

type EcdsaBootstrapExactRequestBase = EcdsaBootstrapRequestCommon & EcdsaBootstrapExactIdentity;

type EmailOtpEcdsaBootstrapWorkerHandle = Extract<
  EmailOtpWorkerIssuedSessionHandle,
  { action: 'threshold_ecdsa_bootstrap' }
>;

type PasskeyPromptBootstrapAuth = {
  passkeyPrfFirstB64u?: never;
  passkeyCredentialIdB64u?: never;
  webauthnAuthentication?: never;
};

type PasskeyWebAuthnBootstrapAuth = {
  webauthnAuthentication: WebAuthnAuthenticationCredential;
  passkeyPrfFirstB64u?: never;
  passkeyCredentialIdB64u?: never;
};

type PasskeyWebAuthnPrfBootstrapAuth = {
  webauthnAuthentication: WebAuthnAuthenticationCredential;
  passkeyPrfFirstB64u: string;
  passkeyCredentialIdB64u?: never;
};

type PasskeyPrfCredentialBootstrapAuth = {
  passkeyPrfFirstB64u: string;
  passkeyCredentialIdB64u: string;
  webauthnAuthentication?: never;
};

export type ReuseWarmEcdsaBootstrapRequest = EcdsaBootstrapRequestCommon &
  EcdsaBootstrapTargetIdentity &
  EcdsaBootstrapRegistrationPolicy & {
    kind: 'reuse_warm_ecdsa_bootstrap';
    subjectId?: never;
    sessionKind?: never;
    sessionIdentity?: never;
    passkeyPrfFirstB64u?: never;
    routeAuth?: never;
    webauthnAuthentication?: never;
    emailOtpAuthContext?: never;
  };

type PasskeyFreshEcdsaBootstrapExactRequestBase = EcdsaBootstrapExactRequestBase & {
  kind: 'passkey_fresh_ecdsa_bootstrap';
  emailOtpAuthContext?: never;
};

type PasskeyFreshEcdsaBootstrapExactRequest =
  | (PasskeyFreshEcdsaBootstrapExactRequestBase & {
      routeAuth?: AppOrWalletSessionAuth;
    } & PasskeyWebAuthnPrfBootstrapAuth)
  | (PasskeyFreshEcdsaBootstrapExactRequestBase & {
      routeAuth?: AppOrWalletSessionAuth;
    } & PasskeyWebAuthnBootstrapAuth)
  | (PasskeyFreshEcdsaBootstrapExactRequestBase & {
      routeAuth: AppOrWalletSessionAuth;
    } & PasskeyPrfCredentialBootstrapAuth)
  | (PasskeyFreshEcdsaBootstrapExactRequestBase & {
      routeAuth: AppOrWalletSessionAuth;
    } & PasskeyPromptBootstrapAuth)
  | (PasskeyFreshEcdsaBootstrapExactRequestBase & {
      routeAuth?: never;
    } & PasskeyPrfCredentialBootstrapAuth)
  | (PasskeyFreshEcdsaBootstrapExactRequestBase & {
      routeAuth?: never;
    } & PasskeyPromptBootstrapAuth);

type EcdsaExplicitExportBootstrapRequestBase = {
  readonly relayerUrl?: string;
  readonly existingRoleLocalMaterial: PersistedEcdsaRoleLocalMaterial;
  readonly authorization: EcdsaExplicitExportOperationAuthorization;
};

export type PasskeyEcdsaExportBootstrapRequest = EcdsaExplicitExportBootstrapRequestBase & {
  kind: 'passkey_ecdsa_export_bootstrap';
  purpose: 'explicit_key_export';
};

export type PasskeyPreauthorizedEcdsaBootstrapRequest = EcdsaBootstrapExactRequestBase &
  PasskeyPrfCredentialBootstrapAuth & {
    kind: 'passkey_preauthorized_ecdsa_bootstrap';
    sessionActivation: RouterAbEcdsaPostRegistrationSessionActivationResponseV1;
    routeAuth?: never;
    emailOtpAuthContext?: never;
  };

export type WalletSessionReconnectEcdsaBootstrapRequest = EcdsaBootstrapExactRequestBase & {
  kind: 'wallet_session_reconnect_ecdsa_bootstrap';
  routeAuth: Extract<AppOrWalletSessionAuth, { kind: 'wallet_session' }>;
  passkeyCredentialIdB64u: string;
  webauthnAuthentication?: never;
  passkeyPrfFirstB64u: string;
  emailOtpAuthContext?: never;
};

type EmailOtpEcdsaBootstrapRequestBase = EcdsaBootstrapExactRequestBase & {
  kind: 'email_otp_ecdsa_bootstrap';
  source: 'email_otp';
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  emailOtpWorkerSessionHandle: EmailOtpEcdsaBootstrapWorkerHandle;
  passkeyPrfFirstB64u?: never;
  webauthnAuthentication?: never;
};

export type EmailOtpEcdsaBootstrapRequest = EmailOtpEcdsaBootstrapRequestBase &
  (
    | {
        routeAuth?: AppOrWalletSessionAuth;
        sessionActivation?: never;
      }
    | {
        sessionActivation: RouterAbEcdsaPostRegistrationSessionActivationResponseV1;
        routeAuth?: never;
      }
  );

export type EmailOtpEcdsaExplicitExportBootstrapRequest =
  EcdsaExplicitExportBootstrapRequestBase & {
    kind: 'email_otp_ecdsa_export_bootstrap';
    purpose: 'explicit_key_export';
  };

export type EmailOtpEcdsaExplicitExportBootstrapResult =
  ThresholdEcdsaExplicitKeyExportActivationResult;

export type EcdsaBootstrapRequest =
  | ReuseWarmEcdsaBootstrapRequest
  | PasskeyFreshEcdsaBootstrapExactRequest
  | PasskeyPreauthorizedEcdsaBootstrapRequest
  | WalletSessionReconnectEcdsaBootstrapRequest
  | EmailOtpEcdsaBootstrapRequest;

export type PasskeyEcdsaBootstrapRequest =
  | Extract<EcdsaBootstrapRequest, { kind: 'passkey_fresh_ecdsa_bootstrap' }>
  | Extract<EcdsaBootstrapRequest, { kind: 'passkey_preauthorized_ecdsa_bootstrap' }>
  | Extract<EcdsaBootstrapRequest, { kind: 'wallet_session_reconnect_ecdsa_bootstrap' }>;

export type WalletSessionActivationDeps = {
  credentialStore: ThresholdCredentialStorePort;
  touchIdPrompt: Pick<
    TouchIdPrompt,
    'getRpId' | 'getAuthenticationCredentialsSerializedForChallengeB64u'
  >;
  touchConfirm: ThresholdWarmSessionMaterialPort;
  getSignerWorkerContext: () => SignerWorkerManagerContext;
  routerAbNormalSigning: RouterAbNormalSigningConfig;
  getOrCreateActiveThresholdEcdsaSessionId: (
    walletId: WalletId,
    chainTarget: ThresholdEcdsaChainTarget,
  ) => string;
  defaultRelayerUrl: string;
  persistThresholdEcdsaBootstrapForWalletTarget: (args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    signerAuth: ThresholdEcdsaBootstrapSignerAuth;
  }) => Promise<void>;
};

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

export type PasskeyEcdsaRestoreSource = Exclude<
  SealedSigningSessionEcdsaRestoreMetadata['source'],
  'email_otp'
>;

type PasskeyRoleLocalBackendBinding = Extract<
  ThresholdEcdsaBackendBinding,
  { materialKind: 'role_local_worker_handle' | 'role_local_durable_sealed_ref' }
>;

export function requirePasskeyEcdsaRestoreSource(
  source: ThresholdEcdsaSessionStoreSource | undefined,
): PasskeyEcdsaRestoreSource {
  switch (source) {
    case 'login':
    case 'registration':
    case 'manual-bootstrap':
      return source;
    case undefined:
    case 'email_otp':
      throw new Error(
        '[SigningEngine][ecdsa] passkey ECDSA bootstrap is missing an exact restore source',
      );
  }
}

export function requirePasskeyEcdsaBootstrapRequest(
  request: EcdsaBootstrapRequest,
): PasskeyEcdsaBootstrapRequest {
  switch (request.kind) {
    case 'passkey_fresh_ecdsa_bootstrap':
    case 'passkey_preauthorized_ecdsa_bootstrap':
    case 'wallet_session_reconnect_ecdsa_bootstrap':
      return request;
    case 'reuse_warm_ecdsa_bootstrap':
    case 'email_otp_ecdsa_bootstrap':
      throw new Error('[SigningEngine][ecdsa] exact Passkey ECDSA bootstrap request is required');
  }
  request satisfies never;
  throw new Error('[SigningEngine][ecdsa] unsupported ECDSA bootstrap request');
}

function passkeyRoleLocalBackendBinding(
  binding: ThresholdEcdsaBackendBinding,
): PasskeyRoleLocalBackendBinding {
  switch (binding.materialKind) {
    case 'role_local_worker_handle':
    case 'role_local_durable_sealed_ref':
      return binding;
    case 'email_otp_worker_handle':
    case 'role_local_ready_state_blob':
    case 'role_local_durable_public_anchor':
    case 'metadata_only':
      throw new Error(
        '[SigningEngine][ecdsa] passkey ECDSA bootstrap is missing durable role-local material',
      );
  }
}

export function requirePasskeyEcdsaCredentialIdFromBootstrap(
  bootstrap: ThresholdEcdsaSessionBootstrapResult,
): string {
  const credentialId = String(bootstrap.passkeyCredentialIdB64u || '').trim();
  if (credentialId) return credentialId;
  throw new Error(
    '[SigningEngine][ecdsa] passkey ECDSA bootstrap is missing an exact credential id',
  );
}

export function buildPasskeyEcdsaRestoreMetadataFromBootstrap(args: {
  request: PasskeyEcdsaBootstrapRequest;
  authority: WalletAuthAuthorityRef;
  source: PasskeyEcdsaRestoreSource;
  rpId: ReturnType<typeof toRpId>;
  credentialIdB64u: string;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
}): Exclude<SealedSigningSessionEcdsaRestoreMetadata, { source: 'email_otp' }> {
  if (
    String(args.request.key.walletId) !== String(args.authority.walletId) ||
    String(args.request.existingRoleLocalMaterial.authority.authorityDigest) !==
      String(args.authority.authorityDigest)
  ) {
    throw new Error(
      '[SigningEngine][ecdsa] passkey ECDSA restore authority does not bind the key identity',
    );
  }
  const binding = passkeyRoleLocalBackendBinding(
    args.bootstrap.thresholdEcdsaKeyRef.backendBinding,
  );
  const keyRef = args.bootstrap.thresholdEcdsaKeyRef;
  const publicFacts = binding.publicFacts;
  return {
    chainTarget: keyRef.chainTarget,
    signingRootId: String(publicFacts.signingRootId),
    signingRootVersion: String(publicFacts.signingRootVersion),
    source: args.source,
    authority: args.authority,
    roleLocalMaterialRef: binding.roleLocalMaterialRef,
    rpId: args.rpId,
    credentialIdB64u: args.credentialIdB64u,
    keyHandle: String(keyRef.keyHandle),
    ecdsaThresholdKeyId: String(keyRef.ecdsaThresholdKeyId),
    ethereumAddress: String(keyRef.ethereumAddress),
    relayerKeyId: String(binding.relayerKeyId),
    clientVerifyingShareB64u: String(binding.clientVerifyingShareB64u),
    thresholdEcdsaPublicKeyB64u: String(keyRef.thresholdEcdsaPublicKeyB64u),
    participantIds: [...keyRef.participantIds],
    runtimePolicyScope: args.bootstrap.session.runtimePolicyScope,
    routerAbEcdsaDerivationNormalSigning: requireRouterAbEcdsaDerivationNormalSigningStateV1(
      keyRef.routerAbEcdsaDerivationNormalSigning,
    ),
    publicCapability: publicFacts.publicCapability,
  };
}

function hasExactEcdsaBootstrapIdentity(
  request: EcdsaBootstrapRequest,
): request is Extract<EcdsaBootstrapRequest, { key: EvmFamilyEcdsaKeyIdentity }> {
  return (
    'key' in request &&
    Boolean(request.key) &&
    'keyHandle' in request &&
    Boolean(String(request.keyHandle || '').trim())
  );
}

export function ecdsaBootstrapWalletId(request: EcdsaBootstrapRequest): WalletId | string {
  return hasExactEcdsaBootstrapIdentity(request) ? request.key.walletId : request.walletId;
}

export function ecdsaBootstrapChainTarget(
  request: EcdsaBootstrapRequest,
): ThresholdEcdsaChainTarget {
  return hasExactEcdsaBootstrapIdentity(request)
    ? request.lanePolicy.chainTarget
    : request.chainTarget;
}

function passkeyEcdsaBootstrapCredential(
  request: EcdsaBootstrapRequest,
): WebAuthnAuthenticationCredential | null {
  return request.kind === 'passkey_fresh_ecdsa_bootstrap' &&
    'webauthnAuthentication' in request &&
    request.webauthnAuthentication
    ? request.webauthnAuthentication
    : null;
}

export function resolvePasskeyEcdsaBootstrapPersistenceSource(args: {
  request: EcdsaBootstrapRequest;
  thresholdSessionId: ReturnType<typeof SigningSessionIds.thresholdEcdsaSession>;
}): PasskeyEcdsaReadyPersistInput['persistenceSource'] | null {
  const credential = passkeyEcdsaBootstrapCredential(args.request);
  if (credential) {
    const credentialIdB64u = String(credential.rawId || credential.id || '').trim();
    if (!credentialIdB64u) {
      throw new Error('[SigningEngine][ecdsa] passkey ECDSA persistence requires credential id');
    }
    return {
      kind: 'fresh_webauthn',
      credentialIdB64u,
    };
  }
  switch (args.request.kind) {
    case 'wallet_session_reconnect_ecdsa_bootstrap':
      return {
        kind: 'session_reconnect',
        restoredThresholdSessionId: args.thresholdSessionId,
      };
    case 'reuse_warm_ecdsa_bootstrap':
    case 'passkey_fresh_ecdsa_bootstrap':
    case 'passkey_preauthorized_ecdsa_bootstrap':
    case 'email_otp_ecdsa_bootstrap':
      return null;
  }
  args.request satisfies never;
  return null;
}

function ecdsaBootstrapSignerAuth(
  request: EcdsaBootstrapRequest,
): ThresholdEcdsaBootstrapSignerAuth {
  if (request.kind === 'email_otp_ecdsa_bootstrap') {
    return {
      authMethod: SIGNER_AUTH_METHODS.emailOtp,
      signerSource: SIGNER_SOURCES.emailOtpRegistration,
    };
  }
  return {
    authMethod: SIGNER_AUTH_METHODS.passkey,
    signerSource: SIGNER_SOURCES.passkeyRegistration,
  };
}

function toActivateEcdsaSessionRequest(
  request: Exclude<EcdsaBootstrapRequest, ReuseWarmEcdsaBootstrapRequest>,
  relayerUrl: string,
): ActivateEcdsaExistingSessionRequest {
  const passkeyFreshActivationAuth = (
    passkeyRequest: Extract<EcdsaBootstrapRequest, { kind: 'passkey_fresh_ecdsa_bootstrap' }>,
  ): ActivateEcdsaSessionAuth => {
    if ('webauthnAuthentication' in passkeyRequest && passkeyRequest.webauthnAuthentication) {
      const passkeyPrfFirstB64u = String(passkeyRequest.passkeyPrfFirstB64u || '').trim();
      if (passkeyPrfFirstB64u) {
        return {
          authKind: 'passkey_webauthn_prf_b64u',
          webauthnAuthentication: passkeyRequest.webauthnAuthentication,
          passkeyPrfFirstB64u,
        };
      }
      return {
        authKind: 'passkey_webauthn',
        webauthnAuthentication: passkeyRequest.webauthnAuthentication,
      };
    }

    const passkeyPrfFirstB64u = String(
      'passkeyPrfFirstB64u' in passkeyRequest ? passkeyRequest.passkeyPrfFirstB64u : '',
    ).trim();
    if (passkeyPrfFirstB64u) {
      const passkeyCredentialIdB64u = String(
        'passkeyCredentialIdB64u' in passkeyRequest ? passkeyRequest.passkeyCredentialIdB64u : '',
      ).trim();
      if (!passkeyCredentialIdB64u) {
        throw new Error('[SigningEngine][ecdsa] passkey PRF bootstrap requires credential id');
      }
      return {
        authKind: 'passkey_prf_b64u',
        passkeyPrfFirstB64u,
        passkeyCredentialIdB64u,
      };
    }

    return { authKind: 'passkey_prompt' };
  };

  const exactSessionRequest = (
    exactRequest: Extract<EcdsaBootstrapRequest, { key: EvmFamilyEcdsaKeyIdentity }>,
    walletSessionRouteAuth: ThresholdEcdsaDerivationRouteAuth | undefined,
    auth: ActivateEcdsaSessionAuth,
  ): ActivateEcdsaExistingSessionRequest => {
    return {
      kind: 'session_bootstrap',
      purpose: 'transaction_signing' as const,
      relayerUrl,
      keyHandle: toEvmFamilyEcdsaKeyHandle(exactRequest.keyHandle),
      key: exactRequest.key,
      lanePolicy: exactRequest.lanePolicy,
      publicCapability: exactRequest.publicCapability,
      existingRoleLocalMaterial: exactRequest.existingRoleLocalMaterial,
      ...(exactRequest.requestId ? { requestId: exactRequest.requestId } : {}),
      ...auth,
      ...(walletSessionRouteAuth ? { walletSessionRouteAuth } : {}),
      runtimeScopeBootstrap: exactRequest.runtimeScopeBootstrap,
    };
  };
  const preauthorizedExactSessionRequest = (
    exactRequest: PasskeyPreauthorizedEcdsaBootstrapRequest,
  ): ActivateEcdsaExistingSessionRequest => ({
    kind: 'session_bootstrap',
    purpose: 'transaction_signing',
    relayerUrl,
    keyHandle: toEvmFamilyEcdsaKeyHandle(exactRequest.keyHandle),
    key: exactRequest.key,
    lanePolicy: exactRequest.lanePolicy,
    publicCapability: exactRequest.publicCapability,
    existingRoleLocalMaterial: exactRequest.existingRoleLocalMaterial,
    ...(exactRequest.requestId ? { requestId: exactRequest.requestId } : {}),
    authKind: 'passkey_prf_b64u',
    passkeyPrfFirstB64u: exactRequest.passkeyPrfFirstB64u,
    passkeyCredentialIdB64u: exactRequest.passkeyCredentialIdB64u,
    preauthorizedSessionActivation: exactRequest.sessionActivation,
    runtimeScopeBootstrap: exactRequest.runtimeScopeBootstrap,
  });
  switch (request.kind) {
    case 'passkey_fresh_ecdsa_bootstrap': {
      return exactSessionRequest(request, request.routeAuth, passkeyFreshActivationAuth(request));
    }
    case 'passkey_preauthorized_ecdsa_bootstrap': {
      return preauthorizedExactSessionRequest(request);
    }
    case 'wallet_session_reconnect_ecdsa_bootstrap': {
      const passkeyCredentialIdB64u = String(request.passkeyCredentialIdB64u || '').trim();
      if (!passkeyCredentialIdB64u) {
        throw new Error(
          '[SigningEngine][ecdsa] Wallet Session reconnect bootstrap requires credential id',
        );
      }
      return exactSessionRequest(request, request.routeAuth, {
        authKind: 'passkey_prf_b64u',
        passkeyPrfFirstB64u: request.passkeyPrfFirstB64u,
        passkeyCredentialIdB64u,
      });
    }
    case 'email_otp_ecdsa_bootstrap': {
      const auth = {
        authKind: 'email_otp' as const,
        emailOtpWorkerSessionHandle: request.emailOtpWorkerSessionHandle,
      };
      return request.sessionActivation
        ? {
            kind: 'session_bootstrap',
            purpose: 'transaction_signing',
            relayerUrl,
            keyHandle: toEvmFamilyEcdsaKeyHandle(request.keyHandle),
            key: request.key,
            lanePolicy: request.lanePolicy,
            publicCapability: request.publicCapability,
            existingRoleLocalMaterial: request.existingRoleLocalMaterial,
            ...(request.requestId ? { requestId: request.requestId } : {}),
            ...auth,
            preauthorizedSessionActivation: request.sessionActivation,
            runtimeScopeBootstrap: request.runtimeScopeBootstrap,
          }
        : exactSessionRequest(request, request.routeAuth, auth);
    }
  }
  request satisfies never;
  throw new Error('[SigningEngine][ecdsa] unsupported ECDSA bootstrap request');
}

function toActivateExplicitKeyExportEcdsaSessionRequest(
  request: PasskeyEcdsaExportBootstrapRequest,
  relayerUrl: string,
): ActivateExplicitKeyExportEcdsaSessionRequest {
  return {
    purpose: 'explicit_key_export',
    relayerUrl,
    existingRoleLocalMaterial: request.existingRoleLocalMaterial,
    authorization: request.authorization,
  };
}

function toActivateEmailOtpExplicitExportBootstrapSessionRequest(
  request: EmailOtpEcdsaExplicitExportBootstrapRequest,
  relayerUrl: string,
): ActivateExplicitKeyExportEcdsaSessionRequest {
  return {
    purpose: 'explicit_key_export',
    relayerUrl,
    existingRoleLocalMaterial: request.existingRoleLocalMaterial,
    authorization: request.authorization,
  };
}

export async function bootstrapEcdsaSessionValue(
  deps: WalletSessionActivationDeps,
  request: EcdsaBootstrapRequest,
): Promise<ThresholdEcdsaSessionBootstrapResult> {
  if (request.kind === 'reuse_warm_ecdsa_bootstrap') {
    throw new Error(
      '[SigningEngine][ecdsa] reuse_warm bootstrap must resolve an existing exact material request before activation',
    );
  }
  const authority = request.existingRoleLocalMaterial.authority;
  const walletId = toWalletId(ecdsaBootstrapWalletId(request));
  const chainTarget = ecdsaBootstrapChainTarget(request);
  const relayerUrl = resolveRelayerUrl(request.relayerUrl, deps.defaultRelayerUrl);

  const signerWorkerCtx = deps.getSignerWorkerContext();
  const activationDeps = {
    credentialStore: deps.credentialStore,
    touchIdPrompt: deps.touchIdPrompt,
    workerCtx: signerWorkerCtx,
    routerAbNormalSigning: deps.routerAbNormalSigning,
    getOrCreateActiveThresholdEcdsaSessionId: (
      activeWalletId: WalletId,
      target: ThresholdEcdsaChainTarget,
    ) => deps.getOrCreateActiveThresholdEcdsaSessionId(activeWalletId, target),
  };

  const activation = await activateEcdsaSession(
    activationDeps,
    toActivateEcdsaSessionRequest(request, relayerUrl),
  );
  const walletSessionJwt = String(activation.session.jwt || '').trim();
  const transport = {
    curve: 'ecdsa' as const,
    walletId: String(authority.walletId),
    chainTarget,
    relayerUrl,
    walletSessionJwt,
  };
  const canonicalBootstrap = activation;

  const signerAuth = ecdsaBootstrapSignerAuth(request);
  const thresholdSessionId = SigningSessionIds.thresholdEcdsaSession(
    activation.session.thresholdSessionId,
  );
  const passkeyPersistenceSource = resolvePasskeyEcdsaBootstrapPersistenceSource({
    request,
    thresholdSessionId,
  });
  let readyPersistenceInput: PasskeyEcdsaReadyPersistInput | null = null;
  if (request.kind !== 'email_otp_ecdsa_bootstrap' && passkeyPersistenceSource) {
    const passkeyPrfFirstB64u = String(activation.passkeyPrfFirstB64u || '').trim();
    if (!passkeyPrfFirstB64u) {
      throw new Error('[SigningEngine][ecdsa] passkey ECDSA bootstrap returned empty PRF.first');
    }
    const passkeyRequest = requirePasskeyEcdsaBootstrapRequest(request);
    const ecdsaRestore = buildPasskeyEcdsaRestoreMetadataFromBootstrap({
      request: passkeyRequest,
      authority: passkeyRequest.existingRoleLocalMaterial.authority,
      source: requirePasskeyEcdsaRestoreSource(passkeyRequest.source),
      rpId: toRpId(deps.touchIdPrompt.getRpId()),
      credentialIdB64u: requirePasskeyEcdsaCredentialIdFromBootstrap(canonicalBootstrap),
      bootstrap: canonicalBootstrap,
    });
    readyPersistenceInput = {
      authMethod: 'passkey',
      curve: 'ecdsa',
      walletId: toWalletId(ecdsaRestore.authority.walletId),
      chainTarget,
      walletSessionId: activation.session.walletSessionId,
      quotaId: activation.session.quotaId,
      thresholdSessionId,
      persistenceSource: passkeyPersistenceSource,
      passkeyPrfSealMaterial: {
        kind: 'ecdsa_prf_first',
        passkeyPrfFirstB64u,
        transport: {
          ...transport,
          authMethod: 'passkey',
          ecdsaRestore,
        },
      },
    };
  }
  await deps.persistThresholdEcdsaBootstrapForWalletTarget({
    walletId,
    chainTarget,
    bootstrap: canonicalBootstrap,
    signerAuth,
  });
  if (readyPersistenceInput) {
    await deps.touchConfirm.putWarmSessionMaterial({
      thresholdSessionId: readyPersistenceInput.thresholdSessionId,
      prfFirstB64u: readyPersistenceInput.passkeyPrfSealMaterial.passkeyPrfFirstB64u,
      expiresAtMs: Number(activation.session.expiresAtMs),
      remainingUses: Number(activation.session.remainingUses),
      transport: readyPersistenceInput.passkeyPrfSealMaterial.transport,
    });
  }
  // Combined unlock overlaps both curves, then commits their shared authorization in curve order.
  await request.beforeAuthorizationPersistence?.();
  await persistActiveWalletSessionAuthorizationFromEcdsaBootstrap(walletSessionAuthorizations, {
    walletId,
    authority,
    authMethod: signerAuth.authMethod,
    bootstrap: canonicalBootstrap,
  });
  return canonicalBootstrap;
}

export async function bootstrapExplicitKeyExportEcdsaSessionValue(
  deps: Pick<WalletSessionActivationDeps, 'defaultRelayerUrl'>,
  request: PasskeyEcdsaExportBootstrapRequest,
): Promise<ThresholdEcdsaExplicitKeyExportActivationResult> {
  const relayerUrl = resolveRelayerUrl(request.relayerUrl, deps.defaultRelayerUrl);
  return await activateExplicitKeyExportEcdsaSession(
    toActivateExplicitKeyExportEcdsaSessionRequest(request, relayerUrl),
  );
}

export async function bootstrapEmailOtpExplicitExportEcdsaSessionValue(
  deps: Pick<WalletSessionActivationDeps, 'defaultRelayerUrl'>,
  request: EmailOtpEcdsaExplicitExportBootstrapRequest,
): Promise<EmailOtpEcdsaExplicitExportBootstrapResult> {
  const relayerUrl = resolveRelayerUrl(request.relayerUrl, deps.defaultRelayerUrl);
  return await activateExplicitKeyExportEcdsaSession(
    toActivateEmailOtpExplicitExportBootstrapSessionRequest(request, relayerUrl),
  );
}
