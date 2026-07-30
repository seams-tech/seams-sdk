import type {
  EmailOtpWorkerIssuedSessionHandle,
} from '@/core/platform';
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
  type ActivateEcdsaSessionRequest,
  type EcdsaExplicitExportOperationAuthorization,
  type ThresholdEcdsaExplicitKeyExportActivationResult,
  type ThresholdEcdsaSessionBootstrapResult,
} from '../../threshold/ecdsa/activation';
import type {
  ThresholdEcdsaEmailOtpAuthContext,
  ThresholdEcdsaSessionStoreSource,
} from '../identity/laneIdentity';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
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
import { parseEcdsaThresholdKeyId } from '../keyMaterialBrands';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import {
  toEvmFamilyEcdsaKeyHandle,
  type EvmFamilyEcdsaKeyHandle,
  type EvmFamilyEcdsaKeyIdentity,
  type EvmFamilyEcdsaSessionLanePolicy,
} from '../identity/evmFamilyEcdsaIdentity';
import type { PasskeyEcdsaReadyPersistInput } from '../warmCapabilities/persistencePorts';
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
  lanePolicy: EvmFamilyEcdsaSessionLanePolicy;
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

type PasskeyFreshBootstrapRouteAuth = AppOrWalletSessionAuth;

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
      routeAuth?: PasskeyFreshBootstrapRouteAuth;
    } & PasskeyWebAuthnPrfBootstrapAuth)
  | (PasskeyFreshEcdsaBootstrapExactRequestBase & {
      routeAuth?: PasskeyFreshBootstrapRouteAuth;
    } & PasskeyWebAuthnBootstrapAuth)
  | (PasskeyFreshEcdsaBootstrapExactRequestBase & {
      routeAuth: PasskeyFreshBootstrapRouteAuth;
    } & PasskeyPrfCredentialBootstrapAuth)
  | (PasskeyFreshEcdsaBootstrapExactRequestBase & {
      routeAuth: PasskeyFreshBootstrapRouteAuth;
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

export type PasskeyEcdsaExportBootstrapRequest =
  EcdsaExplicitExportBootstrapRequestBase & {
    kind: 'passkey_ecdsa_export_bootstrap';
    purpose: 'explicit_key_export';
  };

export type PasskeyExchangeEcdsaBootstrapRequest = EcdsaBootstrapExactRequestBase &
  PasskeyPrfCredentialBootstrapAuth & {
    kind: 'passkey_exchange_ecdsa_bootstrap';
    sessionActivation: RouterAbEcdsaPostRegistrationSessionActivationResponseV1;
    routeAuth?: never;
    emailOtpAuthContext?: never;
  };

export type WalletSessionReconnectEcdsaBootstrapRequest = EcdsaBootstrapExactRequestBase & {
  kind: 'wallet_session_reconnect_ecdsa_bootstrap';
  routeAuth: AppOrWalletSessionAuth;
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
  | PasskeyExchangeEcdsaBootstrapRequest
  | WalletSessionReconnectEcdsaBootstrapRequest
  | EmailOtpEcdsaBootstrapRequest;

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

function requireCanonicalThresholdEcdsaKeyRefIdentity(
  keyRef: ThresholdEcdsaSecp256k1KeyRef,
): ThresholdEcdsaSecp256k1KeyRef {
  const ecdsaThresholdKeyIdRaw = String(keyRef.ecdsaThresholdKeyId || '').trim();
  if (!ecdsaThresholdKeyIdRaw) {
    throw new Error(
      '[SigningEngine] threshold-ecdsa bootstrap did not provide canonical ecdsaThresholdKeyId',
    );
  }
  const ecdsaThresholdKeyId = parseEcdsaThresholdKeyId(ecdsaThresholdKeyIdRaw);
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

function ecdsaBootstrapSessionIdentityFromLanePolicy(
  lanePolicy: EvmFamilyEcdsaSessionLanePolicy,
): EcdsaSessionIdentity {
  return buildEcdsaSessionIdentity({
    thresholdSessionId: lanePolicy.thresholdSessionId,
    signingGrantId: lanePolicy.signingGrantId,
  });
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
    case 'passkey_exchange_ecdsa_bootstrap':
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
): ActivateEcdsaSessionRequest {
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
  ): ActivateEcdsaSessionRequest => {
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
    exactRequest: PasskeyExchangeEcdsaBootstrapRequest,
  ): ActivateEcdsaSessionRequest => ({
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
    case 'passkey_exchange_ecdsa_bootstrap': {
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
    walletId: String(walletId),
    chainTarget,
    relayerUrl,
    signingGrantId: activation.session.signingGrantId,
    walletSessionJwt,
  };
  const thresholdEcdsaKeyRef = requireCanonicalThresholdEcdsaKeyRefIdentity(
    activation.thresholdEcdsaKeyRef,
  );
  const canonicalBootstrap: ThresholdEcdsaSessionBootstrapResult = {
    ...activation,
    thresholdEcdsaKeyRef,
  };

  const signerAuth = ecdsaBootstrapSignerAuth(request);
  await deps.persistThresholdEcdsaBootstrapForWalletTarget({
    walletId,
    chainTarget,
    bootstrap: canonicalBootstrap,
    signerAuth,
  });
  await persistActiveWalletSessionAuthorizationFromEcdsaBootstrap(walletSessionAuthorizations, {
    walletId,
    authority,
    authMethod: signerAuth.authMethod,
    bootstrap: canonicalBootstrap,
  });
  const thresholdSessionId = SigningSessionIds.thresholdEcdsaSession(
    activation.session.thresholdSessionId,
  );
  const passkeyPersistenceSource = resolvePasskeyEcdsaBootstrapPersistenceSource({
    request,
    thresholdSessionId,
  });
  if (request.kind !== 'email_otp_ecdsa_bootstrap' && passkeyPersistenceSource) {
    const passkeyPrfFirstB64u = String(activation.passkeyPrfFirstB64u || '').trim();
    if (!passkeyPrfFirstB64u) {
      throw new Error('[SigningEngine][ecdsa] passkey ECDSA bootstrap returned empty PRF.first');
    }
    const readyPersistenceInput: PasskeyEcdsaReadyPersistInput = {
      authMethod: 'passkey',
      curve: 'ecdsa',
      walletId,
      chainTarget,
      signingGrantId: SigningSessionIds.signingGrant(activation.session.signingGrantId),
      thresholdSessionId,
      persistenceSource: passkeyPersistenceSource,
      passkeyPrfSealMaterial: {
        kind: 'ecdsa_prf_first',
        passkeyPrfFirstB64u,
        transport,
      },
    };
    await deps.touchConfirm.putWarmSessionMaterial({
      sessionId: readyPersistenceInput.thresholdSessionId,
      prfFirstB64u: readyPersistenceInput.passkeyPrfSealMaterial.passkeyPrfFirstB64u,
      expiresAtMs: Number(activation.session.expiresAtMs),
      remainingUses: Number(activation.session.remainingUses),
      transport: readyPersistenceInput.passkeyPrfSealMaterial.transport,
    });
  }
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
