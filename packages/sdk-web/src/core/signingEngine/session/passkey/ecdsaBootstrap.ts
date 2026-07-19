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
  type ActivateEcdsaSessionRequest,
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
import type { RouterAbEcdsaDerivationPublicCapabilityV1 } from '@shared/utils/routerAbEcdsaDerivation';
import type { PersistedEcdsaRoleLocalMaterial } from '../persistence/records';

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

type EcdsaBootstrapTargetRequestBase = EcdsaBootstrapRequestCommon &
  EcdsaBootstrapTargetIdentity &
  EcdsaBootstrapRegistrationPolicy;

type EcdsaBootstrapExactRequestBase = EcdsaBootstrapRequestCommon & EcdsaBootstrapExactIdentity;

type PasskeyFreshBootstrapRouteAuth = AppOrWalletSessionAuth;

type EmailOtpBootstrapRouteAuth = ThresholdEcdsaDerivationRouteAuth;
export type WalletSessionReconnectEcdsaBootstrapRouteAuth = AppOrWalletSessionAuth;

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

export type EcdsaBootstrapSessionIdentityInput = {
  thresholdSessionId: EcdsaSessionIdentity['thresholdSessionId'] | string;
  signingGrantId: EcdsaSessionIdentity['signingGrantId'] | string;
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

type PasskeyFreshEcdsaBootstrapTargetRequestBase = EcdsaBootstrapTargetRequestBase & {
  kind: 'passkey_fresh_ecdsa_bootstrap';
  sessionIdentity: EcdsaBootstrapSessionIdentityInput;
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

export type PasskeyEcdsaExportBootstrapRequest = Omit<
  PasskeyFreshEcdsaBootstrapExactRequestBase,
  'kind'
> &
  PasskeyWebAuthnPrfBootstrapAuth & {
    kind: 'passkey_ecdsa_export_bootstrap';
    purpose: 'explicit_key_export';
    routeAuth: PasskeyFreshBootstrapRouteAuth;
  };

export type PasskeyFreshEcdsaBootstrapRequest =
  | PasskeyFreshEcdsaBootstrapExactRequest
  | (PasskeyFreshEcdsaBootstrapTargetRequestBase & {
      sessionKind: 'jwt';
      routeAuth: PasskeyFreshBootstrapRouteAuth;
    } & PasskeyPromptBootstrapAuth)
  | (PasskeyFreshEcdsaBootstrapTargetRequestBase & {
      sessionKind: 'jwt';
      routeAuth: PasskeyFreshBootstrapRouteAuth;
    } & PasskeyPrfCredentialBootstrapAuth)
  | (PasskeyFreshEcdsaBootstrapTargetRequestBase & {
      sessionKind: 'jwt';
      routeAuth: PasskeyFreshBootstrapRouteAuth;
    } & PasskeyWebAuthnPrfBootstrapAuth)
  | (PasskeyFreshEcdsaBootstrapTargetRequestBase & {
      sessionKind: 'jwt';
      routeAuth: PasskeyFreshBootstrapRouteAuth;
    } & PasskeyWebAuthnBootstrapAuth)
  | (PasskeyFreshEcdsaBootstrapTargetRequestBase & {
      sessionKind: 'jwt';
      routeAuth?: never;
    } & PasskeyWebAuthnPrfBootstrapAuth)
  | (PasskeyFreshEcdsaBootstrapTargetRequestBase & {
      sessionKind: 'jwt';
      routeAuth?: never;
    } & PasskeyWebAuthnBootstrapAuth);

export type WalletSessionReconnectEcdsaBootstrapRequest = EcdsaBootstrapExactRequestBase & {
  kind: 'wallet_session_reconnect_ecdsa_bootstrap';
  routeAuth: WalletSessionReconnectEcdsaBootstrapRouteAuth;
  passkeyCredentialIdB64u: string;
  webauthnAuthentication?: never;
  passkeyPrfFirstB64u: string;
  emailOtpAuthContext?: never;
};

export type EmailOtpEcdsaBootstrapRequest =
  | (EcdsaBootstrapTargetRequestBase & {
      kind: 'email_otp_ecdsa_bootstrap';
      source: 'email_otp';
      sessionKind: 'jwt';
      sessionIdentity: EcdsaBootstrapSessionIdentityInput;
      emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
      emailOtpWorkerSessionHandle: EmailOtpEcdsaBootstrapWorkerHandle;
      passkeyPrfFirstB64u?: never;
      webauthnAuthentication?: never;
      routeAuth?: EmailOtpBootstrapRouteAuth;
    })
  | (EcdsaBootstrapExactRequestBase & {
      kind: 'email_otp_ecdsa_bootstrap';
      source: 'email_otp';
      emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
      emailOtpWorkerSessionHandle: EmailOtpEcdsaBootstrapWorkerHandle;
      passkeyPrfFirstB64u?: never;
      webauthnAuthentication?: never;
      routeAuth?: AppOrWalletSessionAuth;
    });

export type EcdsaBootstrapRequest =
  | ReuseWarmEcdsaBootstrapRequest
  | PasskeyFreshEcdsaBootstrapRequest
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
  upsertThresholdEcdsaSessionFromBootstrap: (
    args:
      | {
          walletId: WalletId;
          chainTarget: ThresholdEcdsaChainTarget;
          bootstrap: ThresholdEcdsaSessionBootstrapResult;
          source: 'email_otp';
          hasEmailOtpAuthContext: true;
          emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
        }
      | {
          walletId: WalletId;
          chainTarget: ThresholdEcdsaChainTarget;
          bootstrap: ThresholdEcdsaSessionBootstrapResult;
          source: Exclude<ThresholdEcdsaSessionStoreSource, 'email_otp'>;
          hasEmailOtpAuthContext: false;
          emailOtpAuthContext?: never;
        },
  ) => void;
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
  request: EcdsaBootstrapRequest,
  relayerUrl: string,
): ActivateEcdsaSessionRequest {
  const registrationBase = (
    targetRequest: Extract<EcdsaBootstrapRequest, { walletId: WalletId | string }>,
  ) => {
    const sessionPlan =
      'sessionIdentity' in targetRequest && targetRequest.sessionIdentity
        ? {
            kind: 'requested_session' as const,
            sessionKind: targetRequest.sessionKind,
            sessionId: buildEcdsaSessionIdentity(targetRequest.sessionIdentity).thresholdSessionId,
            signingGrantId: buildEcdsaSessionIdentity(targetRequest.sessionIdentity).signingGrantId,
          }
        : undefined;
    return {
      kind: 'key_enrollment_bootstrap' as const,
      purpose: 'transaction_signing' as const,
      walletId: targetRequest.walletId,
      chainTarget: targetRequest.chainTarget,
      relayerUrl,
      ...(targetRequest.keyIntent ? { keyIntent: targetRequest.keyIntent } : {}),
      ...(sessionPlan ? { sessionPlan } : {}),
      runtimePolicyScope: targetRequest.runtimePolicyScope,
      runtimeScopeBootstrap: targetRequest.runtimeScopeBootstrap,
      ttlMs: targetRequest.ttlMs,
      remainingUses: targetRequest.remainingUses,
    };
  };

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
  switch (request.kind) {
    case 'reuse_warm_ecdsa_bootstrap':
      return {
        ...registrationBase(request),
        authKind: 'passkey_prompt',
      };
    case 'passkey_fresh_ecdsa_bootstrap': {
      if (hasExactEcdsaBootstrapIdentity(request)) {
        return exactSessionRequest(request, request.routeAuth, passkeyFreshActivationAuth(request));
      }
      const passkeyFreshIdentity = buildEcdsaSessionIdentity(request.sessionIdentity);
      const routeAuth = 'routeAuth' in request && request.routeAuth ? request.routeAuth : undefined;
      return {
        ...registrationBase(request),
        sessionPlan: {
          kind: 'requested_session' as const,
          sessionKind: request.sessionKind,
          sessionId: passkeyFreshIdentity.thresholdSessionId,
          signingGrantId: passkeyFreshIdentity.signingGrantId,
        },
        ...passkeyFreshActivationAuth(request),
        ...(routeAuth ? { walletSessionRouteAuth: routeAuth } : {}),
      };
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
      if (hasExactEcdsaBootstrapIdentity(request)) {
        return exactSessionRequest(request, request.routeAuth, {
          authKind: 'email_otp',
          emailOtpWorkerSessionHandle: request.emailOtpWorkerSessionHandle,
        });
      }
      const emailOtpIdentity = buildEcdsaSessionIdentity(request.sessionIdentity);
      return {
        ...registrationBase(request),
        sessionPlan: {
          kind: 'requested_session' as const,
          sessionKind: request.sessionKind,
          sessionId: emailOtpIdentity.thresholdSessionId,
          signingGrantId: emailOtpIdentity.signingGrantId,
        },
        authKind: 'email_otp',
        emailOtpWorkerSessionHandle: request.emailOtpWorkerSessionHandle,
        walletSessionRouteAuth: request.routeAuth,
      };
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
    kind: 'session_bootstrap',
    purpose: 'explicit_key_export',
    relayerUrl,
    keyHandle: toEvmFamilyEcdsaKeyHandle(request.keyHandle),
    key: request.key,
    lanePolicy: request.lanePolicy,
    publicCapability: request.publicCapability,
    existingRoleLocalMaterial: request.existingRoleLocalMaterial,
    requestId: request.requestId,
    authKind: 'passkey_webauthn_prf_b64u',
    webauthnAuthentication: request.webauthnAuthentication,
    passkeyPrfFirstB64u: request.passkeyPrfFirstB64u,
    walletSessionRouteAuth: request.routeAuth,
    runtimeScopeBootstrap: request.runtimeScopeBootstrap,
  };
}

async function normalizeRuntimeEcdsaBootstrapRequest(
  deps: WalletSessionActivationDeps,
  request: EcdsaBootstrapRequest,
): Promise<EcdsaBootstrapRequest> {
  if (request.kind !== 'wallet_session_reconnect_ecdsa_bootstrap') {
    return request;
  }

  const providedPasskeyPrfFirstB64u = String(request.passkeyPrfFirstB64u || '').trim();
  if (providedPasskeyPrfFirstB64u) {
    return {
      ...request,
      passkeyPrfFirstB64u: providedPasskeyPrfFirstB64u,
    };
  }

  const sessionIdentity = ecdsaBootstrapSessionIdentityFromLanePolicy(request.lanePolicy);
  const claimedMaterial =
    typeof deps.touchConfirm.claimWarmSessionMaterial === 'function'
      ? await deps.touchConfirm.claimWarmSessionMaterial({
          sessionId: sessionIdentity.thresholdSessionId,
          uses: 1,
        })
      : null;
  const claimedPasskeyPrfFirstB64u = String(claimedMaterial?.prfFirstB64u || '').trim();
  if (claimedMaterial?.ok && claimedPasskeyPrfFirstB64u) {
    return {
      ...request,
      passkeyPrfFirstB64u: claimedPasskeyPrfFirstB64u,
    };
  }

  throw new Error(
    '[SigningEngine][ecdsa] threshold-session reconnect bootstrap requires passkeyPrfFirstB64u from the primed signing session',
  );
}

export async function bootstrapEcdsaSessionValue(
  deps: WalletSessionActivationDeps,
  request: EcdsaBootstrapRequest,
): Promise<ThresholdEcdsaSessionBootstrapResult> {
  const normalizedRequest = await normalizeRuntimeEcdsaBootstrapRequest(deps, request);
  const walletId = toWalletId(ecdsaBootstrapWalletId(normalizedRequest));
  const chainTarget = ecdsaBootstrapChainTarget(normalizedRequest);
  const relayerUrl = resolveRelayerUrl(normalizedRequest.relayerUrl, deps.defaultRelayerUrl);

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
    toActivateEcdsaSessionRequest(normalizedRequest, relayerUrl),
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

  await deps.persistThresholdEcdsaBootstrapForWalletTarget({
    walletId,
    chainTarget,
    bootstrap: canonicalBootstrap,
    signerAuth: ecdsaBootstrapSignerAuth(normalizedRequest),
  });
  if (normalizedRequest.kind === 'email_otp_ecdsa_bootstrap') {
    deps.upsertThresholdEcdsaSessionFromBootstrap({
      walletId,
      chainTarget,
      bootstrap: canonicalBootstrap,
      source: normalizedRequest.source,
      hasEmailOtpAuthContext: true,
      emailOtpAuthContext: normalizedRequest.emailOtpAuthContext,
    });
  } else {
    const source =
      normalizedRequest.source === 'email_otp'
        ? 'manual-bootstrap'
        : normalizedRequest.source || 'manual-bootstrap';
    deps.upsertThresholdEcdsaSessionFromBootstrap({
      walletId,
      chainTarget,
      bootstrap: canonicalBootstrap,
      source,
      hasEmailOtpAuthContext: false,
    });
  }
  const thresholdSessionId = SigningSessionIds.thresholdEcdsaSession(
    activation.session.thresholdSessionId,
  );
  const passkeyPersistenceSource = resolvePasskeyEcdsaBootstrapPersistenceSource({
    request: normalizedRequest,
    thresholdSessionId,
  });
  if (normalizedRequest.kind !== 'email_otp_ecdsa_bootstrap' && passkeyPersistenceSource) {
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
  deps: WalletSessionActivationDeps,
  request: PasskeyEcdsaExportBootstrapRequest,
): Promise<ThresholdEcdsaExplicitKeyExportActivationResult> {
  const relayerUrl = resolveRelayerUrl(request.relayerUrl, deps.defaultRelayerUrl);
  const activation = await activateExplicitKeyExportEcdsaSession(
    {
      credentialStore: deps.credentialStore,
      touchIdPrompt: deps.touchIdPrompt,
      workerCtx: deps.getSignerWorkerContext(),
      routerAbNormalSigning: deps.routerAbNormalSigning,
      getOrCreateActiveThresholdEcdsaSessionId: deps.getOrCreateActiveThresholdEcdsaSessionId,
    },
    toActivateExplicitKeyExportEcdsaSessionRequest(request, relayerUrl),
  );
  return activation;
}
