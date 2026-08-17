import type { EmailOtpWorkerIssuedSessionHandle } from '@/core/platform';
import type { RouterAbNormalSigningConfig } from '@/core/types/seams';
import type { TouchIdPrompt } from '../../stepUpConfirmation/passkeyPrompt/touchIdPrompt';
import type { SignerWorkerManagerContext } from '../../workerManager/SignerWorkerManager';
import type {
  ThresholdCredentialStorePort,
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
import type { WalletSessionRouteAuth } from '@shared/utils/sessionTokens';
import type { SigningOperationIntent } from '../operationState/types';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildEcdsaSessionIdentity,
  type EcdsaSessionIdentity,
} from '../warmCapabilities/ecdsaProvisionPlan';
import {
  toEvmFamilyEcdsaKeyHandle,
  type EvmFamilyEcdsaKeyHandle,
  type EvmFamilyEcdsaKeyIdentity,
  type EvmFamilyEcdsaActivationLanePolicy,
} from '../identity/evmFamilyEcdsaIdentity';
import { SIGNER_AUTH_METHODS, SIGNER_SOURCES } from '@shared/utils/signerDomain';
import type { ThresholdEcdsaBootstrapSignerAuth } from '../warmCapabilities/ecdsaBootstrapPersistence';
import type {
  RouterAbEcdsaDerivationPublicCapabilityV1,
  RouterAbEcdsaPostRegistrationSessionActivationResponseV1,
} from '@shared/utils/routerAbEcdsaDerivation';
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

type PasskeyCredentialBootstrapAuth = {
  passkeyPrfFirstB64u?: never;
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

type PasskeyFreshEcdsaBootstrapExactRequest = PasskeyFreshEcdsaBootstrapExactRequestBase &
  PasskeyCredentialBootstrapAuth & {
    routeAuth: WalletSessionRouteAuth;
  };

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
  PasskeyCredentialBootstrapAuth & {
    kind: 'passkey_preauthorized_ecdsa_bootstrap';
    sessionActivation: RouterAbEcdsaPostRegistrationSessionActivationResponseV1;
    routeAuth?: never;
    emailOtpAuthContext?: never;
  };

export type WalletSessionReconnectEcdsaBootstrapRequest = EcdsaBootstrapExactRequestBase & {
  kind: 'wallet_session_reconnect_ecdsa_bootstrap';
  routeAuth: Extract<
    WalletSessionRouteAuth,
    { kind: 'opaque_wallet_session' }
  >;
  passkeyCredentialIdB64u: string;
  webauthnAuthentication?: never;
  passkeyPrfFirstB64u?: never;
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
        routeAuth?: WalletSessionRouteAuth;
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

export type WalletSessionActivationDeps = {
  credentialStore: ThresholdCredentialStorePort;
  touchIdPrompt: Pick<
    TouchIdPrompt,
    'getRpId' | 'getAuthenticationCredentialsSerializedForChallengeB64u'
  >;
  getSignerWorkerContext: () => SignerWorkerManagerContext;
  routerAbNormalSigning: RouterAbNormalSigningConfig;
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
    authKind: 'passkey',
    passkeyCredentialIdB64u: exactRequest.passkeyCredentialIdB64u,
    preauthorizedSessionActivation: exactRequest.sessionActivation,
    runtimeScopeBootstrap: exactRequest.runtimeScopeBootstrap,
  });
  switch (request.kind) {
    case 'passkey_fresh_ecdsa_bootstrap': {
      return exactSessionRequest(request, request.routeAuth, {
        authKind: 'passkey',
        passkeyCredentialIdB64u: request.passkeyCredentialIdB64u,
      });
    }
    case 'passkey_preauthorized_ecdsa_bootstrap': {
      return preauthorizedExactSessionRequest(request);
    }
    case 'wallet_session_reconnect_ecdsa_bootstrap': {
      return exactSessionRequest(request, request.routeAuth, {
        authKind: 'passkey',
        passkeyCredentialIdB64u: request.passkeyCredentialIdB64u,
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
    touchIdPrompt: deps.touchIdPrompt,
    workerCtx: signerWorkerCtx,
    routerAbNormalSigning: deps.routerAbNormalSigning,
  };

  const activation = await activateEcdsaSession(
    activationDeps,
    toActivateEcdsaSessionRequest(request, relayerUrl),
  );
  const canonicalBootstrap = activation;

  const signerAuth = ecdsaBootstrapSignerAuth(request);
  await deps.persistThresholdEcdsaBootstrapForWalletTarget({
    walletId,
    chainTarget,
    bootstrap: canonicalBootstrap,
    signerAuth,
  });
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
