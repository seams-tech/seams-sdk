import type { UnifiedIndexedDBManager } from '@/core/indexedDB';
import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { TouchIdPrompt } from '../../stepUpConfirmation/passkeyPrompt/touchIdPrompt';
import type { SignerWorkerManagerContext } from '../../workerManager/SignerWorkerManager';
import type { ThresholdWarmSessionMaterialPort } from '../../threshold/crypto/webauthn';
import {
  activateEcdsaSession,
  type ActivateEcdsaSessionRequest,
  type ThresholdEcdsaSessionBootstrapResult,
} from '../../threshold/ecdsa/activation';
import type {
  ThresholdEcdsaEmailOtpAuthContext,
  ThresholdEcdsaSessionStoreSource,
} from '../identity/laneIdentity';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import type {
  ThresholdRuntimePolicyScope,
  ThresholdSessionKind,
} from '../../threshold/sessionPolicy';
import type { ThresholdEcdsaHssRouteAuth } from '@/core/rpcClients/relayer/thresholdEcdsa';
import type { AppOrThresholdSessionAuth, AppSessionJwtAuth } from '@shared/utils/sessionTokens';
import type { SigningOperationIntent } from '../operationState/types';
import type {
  ThresholdEcdsaChainTarget,
  WalletSubjectId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildEcdsaSessionIdentity,
  type EcdsaSessionIdentity,
} from '../warmCapabilities/ecdsaProvisionPlan';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type {
  EvmFamilyEcdsaKeyIdentity,
  EvmFamilyEcdsaSessionLanePolicy,
} from '../identity/evmFamilyEcdsaIdentity';

export type ExistingEcdsaBootstrapKeyIntent = {
  kind: 'existing_ecdsa_key';
  ecdsaThresholdKeyId: string;
  participantIds: readonly number[];
};

type EcdsaBootstrapRequestCommon = {
  source?: ThresholdEcdsaSessionStoreSource;
  relayerUrl?: string;
  operationIntent?: SigningOperationIntent;
  runtimeScopeBootstrap?: {
    environmentId: string;
    publishableKey: string;
  };
};

type EcdsaBootstrapTargetIdentity = {
  walletId: AccountId | string;
  subjectId: WalletSubjectId;
  chainTarget: ThresholdEcdsaChainTarget;
  key?: never;
  lanePolicy?: never;
};

type EcdsaBootstrapExactIdentity = {
  key: EvmFamilyEcdsaKeyIdentity;
  lanePolicy: EvmFamilyEcdsaSessionLanePolicy;
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

type PasskeyFreshBootstrapRouteAuth =
  | AppSessionJwtAuth
  | { kind: 'bootstrap_grant'; token: string }
  | { kind: 'publishable_key'; token: string }
  | { kind: 'registration_continuation'; token: string };

type EmailOtpBootstrapRouteAuth = Exclude<ThresholdEcdsaHssRouteAuth, { kind: 'cookie' }>;

export type EcdsaBootstrapSessionIdentityInput = {
  thresholdSessionId: EcdsaSessionIdentity['thresholdSessionId'] | string;
  walletSigningSessionId: EcdsaSessionIdentity['walletSigningSessionId'] | string;
};

export type ReuseWarmEcdsaBootstrapRequest = EcdsaBootstrapTargetRequestBase & {
  kind: 'reuse_warm_ecdsa_bootstrap';
  sessionKind?: never;
  sessionIdentity?: never;
  clientRootShare32B64u?: never;
  routeAuth?: never;
  webauthnAuthentication?: never;
  emailOtpAuthContext?: never;
};

type PasskeyFreshEcdsaBootstrapTargetRequestBase = EcdsaBootstrapTargetRequestBase & {
  kind: 'passkey_fresh_ecdsa_bootstrap';
  sessionIdentity: EcdsaBootstrapSessionIdentityInput;
  clientRootShare32B64u: string;
  emailOtpAuthContext?: never;
};

type PasskeyFreshEcdsaBootstrapExactRequest = EcdsaBootstrapExactRequestBase & {
  kind: 'passkey_fresh_ecdsa_bootstrap';
  routeAuth: PasskeyFreshBootstrapRouteAuth;
  clientRootShare32B64u: string;
  webauthnAuthentication?: WebAuthnAuthenticationCredential;
  emailOtpAuthContext?: never;
};

export type PasskeyFreshEcdsaBootstrapRequest =
  | PasskeyFreshEcdsaBootstrapExactRequest
  | (PasskeyFreshEcdsaBootstrapTargetRequestBase & {
      sessionKind: 'jwt';
      routeAuth: PasskeyFreshBootstrapRouteAuth;
      webauthnAuthentication?: never;
    })
  | (PasskeyFreshEcdsaBootstrapTargetRequestBase & {
      sessionKind: 'jwt';
      webauthnAuthentication: WebAuthnAuthenticationCredential;
      routeAuth?: never;
    })
  | (PasskeyFreshEcdsaBootstrapTargetRequestBase & {
      sessionKind: Extract<ThresholdSessionKind, 'cookie'>;
      routeAuth?: never;
      webauthnAuthentication?: never;
    })
  | (PasskeyFreshEcdsaBootstrapTargetRequestBase & {
      sessionKind: Extract<ThresholdSessionKind, 'cookie'>;
      webauthnAuthentication: WebAuthnAuthenticationCredential;
      routeAuth?: never;
    });

export type PasskeyCookieReconnectEcdsaBootstrapRequest = EcdsaBootstrapTargetRequestBase & {
  kind: 'passkey_cookie_reconnect_ecdsa_bootstrap';
  sessionKind: 'cookie';
  sessionIdentity: EcdsaBootstrapSessionIdentityInput;
  routeAuth?: never;
  webauthnAuthentication?: never;
  clientRootShare32B64u?: never;
  emailOtpAuthContext?: never;
};

export type ThresholdSessionAuthReconnectEcdsaBootstrapRequest = EcdsaBootstrapExactRequestBase & {
  kind: 'threshold_session_auth_reconnect_ecdsa_bootstrap';
  routeAuth: ThresholdEcdsaHssRouteAuth;
  webauthnAuthentication?: never;
  clientRootShare32B64u: string;
  emailOtpAuthContext?: never;
};

export type EmailOtpEcdsaBootstrapRequest =
  | (EcdsaBootstrapTargetRequestBase & {
      kind: 'email_otp_ecdsa_bootstrap';
      source: 'email_otp';
      sessionKind: ThresholdSessionKind;
      sessionIdentity: EcdsaBootstrapSessionIdentityInput;
      emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
      clientRootShare32B64u: string;
      webauthnAuthentication?: never;
      routeAuth?: EmailOtpBootstrapRouteAuth;
    })
  | (EcdsaBootstrapExactRequestBase & {
      kind: 'email_otp_ecdsa_bootstrap';
      source: 'email_otp';
      emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
      clientRootShare32B64u: string;
      webauthnAuthentication?: never;
      routeAuth: EmailOtpBootstrapRouteAuth;
    });

export type EcdsaBootstrapRequest =
  | ReuseWarmEcdsaBootstrapRequest
  | PasskeyFreshEcdsaBootstrapRequest
  | PasskeyCookieReconnectEcdsaBootstrapRequest
  | ThresholdSessionAuthReconnectEcdsaBootstrapRequest
  | EmailOtpEcdsaBootstrapRequest;

export type ThresholdSessionActivationDeps = {
  indexedDB: UnifiedIndexedDBManager;
  touchIdPrompt: Pick<
    TouchIdPrompt,
    'getRpId' | 'getAuthenticationCredentialsSerializedForChallengeB64u'
  >;
  touchConfirm: ThresholdWarmSessionMaterialPort;
  getSignerWorkerContext: () => SignerWorkerManagerContext;
  getOrCreateActiveThresholdEcdsaSessionId: (
    walletId: AccountId,
    chainTarget: ThresholdEcdsaChainTarget,
  ) => string;
  defaultRelayerUrl: string;
  persistThresholdEcdsaBootstrapForWalletTarget: (args: {
    walletId: AccountId | string;
    chainTarget: ThresholdEcdsaChainTarget;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
  }) => Promise<void>;
  upsertThresholdEcdsaSessionFromBootstrap: (
    args:
      | {
          walletId: AccountId | string;
          chainTarget: ThresholdEcdsaChainTarget;
          bootstrap: ThresholdEcdsaSessionBootstrapResult;
          source: ThresholdEcdsaSessionStoreSource;
          hasEmailOtpAuthContext: true;
          emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
        }
      | {
          walletId: AccountId | string;
          chainTarget: ThresholdEcdsaChainTarget;
          bootstrap: ThresholdEcdsaSessionBootstrapResult;
          source: ThresholdEcdsaSessionStoreSource;
          hasEmailOtpAuthContext: false;
          emailOtpAuthContext?: never;
        },
  ) => void;
};

function requireCanonicalThresholdEcdsaKeyRefIdentity(
  keyRef: ThresholdEcdsaSecp256k1KeyRef,
): ThresholdEcdsaSecp256k1KeyRef & { ecdsaThresholdKeyId: string } {
  const ecdsaThresholdKeyId = String(keyRef.ecdsaThresholdKeyId || '').trim();
  if (!ecdsaThresholdKeyId) {
    throw new Error(
      '[SigningEngine] threshold-ecdsa bootstrap did not provide canonical ecdsaThresholdKeyId',
    );
  }
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
  return 'key' in request && Boolean(request.key);
}

export function ecdsaBootstrapWalletId(request: EcdsaBootstrapRequest): AccountId | string {
  return hasExactEcdsaBootstrapIdentity(request) ? request.key.walletId : request.walletId;
}

export function ecdsaBootstrapSubjectId(request: EcdsaBootstrapRequest): WalletSubjectId {
  return hasExactEcdsaBootstrapIdentity(request) ? request.key.subjectId : request.subjectId;
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
    walletSigningSessionId: lanePolicy.walletSigningSessionId,
  });
}

function toActivateEcdsaSessionRequest(
  request: EcdsaBootstrapRequest,
  relayerUrl: string,
): ActivateEcdsaSessionRequest {
  const registrationBase = (
    targetRequest: Extract<EcdsaBootstrapRequest, { walletId: AccountId | string }>,
  ): Extract<ActivateEcdsaSessionRequest, { kind: 'registration_bootstrap' }> => {
    const sessionPlan =
      'sessionIdentity' in targetRequest && targetRequest.sessionIdentity
        ? {
            kind: 'requested_session' as const,
            sessionKind: targetRequest.sessionKind,
            sessionId: buildEcdsaSessionIdentity(targetRequest.sessionIdentity).thresholdSessionId,
            walletSigningSessionId: buildEcdsaSessionIdentity(targetRequest.sessionIdentity)
              .walletSigningSessionId,
          }
        : undefined;
    return {
      kind: 'registration_bootstrap',
      walletId: targetRequest.walletId,
      subjectId: targetRequest.subjectId,
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
  const exactSessionRequest = (
    exactRequest: Extract<EcdsaBootstrapRequest, { key: EvmFamilyEcdsaKeyIdentity }>,
    thresholdSessionAuth: ThresholdEcdsaHssRouteAuth,
    clientRootShare32B64u: string,
    webauthnAuthentication: WebAuthnAuthenticationCredential | undefined,
  ): ActivateEcdsaSessionRequest => {
    return {
      kind: 'session_bootstrap',
      relayerUrl,
      key: exactRequest.key,
      lanePolicy: exactRequest.lanePolicy,
      clientRootShare32B64u,
      ...(webauthnAuthentication ? { webauthnAuthentication } : {}),
      thresholdSessionAuth,
      runtimeScopeBootstrap: exactRequest.runtimeScopeBootstrap,
    };
  };
  switch (request.kind) {
    case 'reuse_warm_ecdsa_bootstrap':
      return registrationBase(request);
    case 'passkey_fresh_ecdsa_bootstrap': {
      if (hasExactEcdsaBootstrapIdentity(request)) {
        return exactSessionRequest(
          request,
          request.routeAuth,
          request.clientRootShare32B64u,
          request.webauthnAuthentication,
        );
      }
      const passkeyFreshIdentity = buildEcdsaSessionIdentity(request.sessionIdentity);
      const routeAuth = 'routeAuth' in request && request.routeAuth ? request.routeAuth : undefined;
      const webauthnAuthentication =
        'webauthnAuthentication' in request && request.webauthnAuthentication
          ? request.webauthnAuthentication
          : undefined;
      return {
        ...registrationBase(request),
        sessionPlan: {
          kind: 'requested_session' as const,
          sessionKind: request.sessionKind,
          sessionId: passkeyFreshIdentity.thresholdSessionId,
          walletSigningSessionId: passkeyFreshIdentity.walletSigningSessionId,
        },
        clientRootShare32B64u: request.clientRootShare32B64u,
        ...(routeAuth ? { thresholdSessionAuth: routeAuth } : {}),
        ...(webauthnAuthentication ? { webauthnAuthentication } : {}),
      };
    }
    case 'passkey_cookie_reconnect_ecdsa_bootstrap': {
      const cookieReconnectIdentity = buildEcdsaSessionIdentity(request.sessionIdentity);
      return {
        ...registrationBase(request),
        sessionPlan: {
          kind: 'requested_session' as const,
          sessionKind: request.sessionKind,
          sessionId: cookieReconnectIdentity.thresholdSessionId,
          walletSigningSessionId: cookieReconnectIdentity.walletSigningSessionId,
        },
      };
    }
    case 'threshold_session_auth_reconnect_ecdsa_bootstrap': {
      return exactSessionRequest(request, request.routeAuth, request.clientRootShare32B64u, undefined);
    }
    case 'email_otp_ecdsa_bootstrap': {
      if (hasExactEcdsaBootstrapIdentity(request)) {
        return exactSessionRequest(
          request,
          request.routeAuth,
          request.clientRootShare32B64u,
          undefined,
        );
      }
      const emailOtpIdentity = buildEcdsaSessionIdentity(request.sessionIdentity);
      return {
        ...registrationBase(request),
        sessionPlan: {
          kind: 'requested_session' as const,
          sessionKind: request.sessionKind,
          sessionId: emailOtpIdentity.thresholdSessionId,
          walletSigningSessionId: emailOtpIdentity.walletSigningSessionId,
        },
        clientRootShare32B64u: request.clientRootShare32B64u,
        thresholdSessionAuth: request.routeAuth,
      };
    }
  }
  request satisfies never;
  throw new Error('[SigningEngine][ecdsa] unsupported ECDSA bootstrap request');
}

async function normalizeRuntimeEcdsaBootstrapRequest(
  deps: ThresholdSessionActivationDeps,
  request: EcdsaBootstrapRequest,
): Promise<EcdsaBootstrapRequest> {
  if (request.kind !== 'threshold_session_auth_reconnect_ecdsa_bootstrap') {
    return request;
  }

  const providedClientRootShare32B64u = String(request.clientRootShare32B64u || '').trim();
  if (providedClientRootShare32B64u) {
    return {
      ...request,
      clientRootShare32B64u: providedClientRootShare32B64u,
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
  const claimedClientRootShare32B64u = String(claimedMaterial?.prfFirstB64u || '').trim();
  if (claimedMaterial?.ok && claimedClientRootShare32B64u) {
    return {
      ...request,
      clientRootShare32B64u: claimedClientRootShare32B64u,
    };
  }

  throw new Error(
    '[SigningEngine][ecdsa] threshold-session reconnect bootstrap requires clientRootShare32B64u from the primed signing session',
  );
}

export async function bootstrapEcdsaSessionValue(
  deps: ThresholdSessionActivationDeps,
  request: EcdsaBootstrapRequest,
): Promise<ThresholdEcdsaSessionBootstrapResult> {
  const normalizedRequest = await normalizeRuntimeEcdsaBootstrapRequest(deps, request);
  const walletId = toAccountId(ecdsaBootstrapWalletId(normalizedRequest));
  const chainTarget = ecdsaBootstrapChainTarget(normalizedRequest);
  const relayerUrl = resolveRelayerUrl(normalizedRequest.relayerUrl, deps.defaultRelayerUrl);

  const signerWorkerCtx = deps.getSignerWorkerContext();
  const activationDeps = {
    indexedDB: deps.indexedDB,
    touchIdPrompt: deps.touchIdPrompt,
    workerCtx: signerWorkerCtx,
    getOrCreateActiveThresholdEcdsaSessionId: (
      activeWalletId: AccountId,
      target: ThresholdEcdsaChainTarget,
    ) => deps.getOrCreateActiveThresholdEcdsaSessionId(activeWalletId, target),
  };

  const activation = await activateEcdsaSession(
    activationDeps,
    toActivateEcdsaSessionRequest(normalizedRequest, relayerUrl),
  );
  await deps.touchConfirm
    .putWarmSessionMaterial({
      sessionId: activation.session.sessionId,
      prfFirstB64u: activation.clientRootShare32B64u,
      expiresAtMs: Number(activation.session.expiresAtMs),
      remainingUses: Number(activation.session.remainingUses),
      transport: {
        curve: 'ecdsa',
        walletId: String(walletId),
        chainTarget,
        relayerUrl,
        walletSigningSessionId: activation.session.walletSigningSessionId,
        ...(typeof activation.session.jwt === 'string' && activation.session.jwt.trim()
          ? { thresholdSessionAuthToken: activation.session.jwt.trim() }
          : {}),
      },
    })
    .catch(() => undefined);
  const { clientRootShare32B64u: _clientRootShare32B64u, ...bootstrap } = activation;
  const thresholdEcdsaKeyRef = requireCanonicalThresholdEcdsaKeyRefIdentity(
    bootstrap.thresholdEcdsaKeyRef,
  );
  const canonicalBootstrap: ThresholdEcdsaSessionBootstrapResult = {
    ...bootstrap,
    thresholdEcdsaKeyRef,
  };

  await deps.persistThresholdEcdsaBootstrapForWalletTarget({
    walletId,
    chainTarget,
    bootstrap: canonicalBootstrap,
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
    deps.upsertThresholdEcdsaSessionFromBootstrap({
      walletId,
      chainTarget,
      bootstrap: canonicalBootstrap,
      source: normalizedRequest.source || 'manual-bootstrap',
      hasEmailOtpAuthContext: false,
    });
  }
  return canonicalBootstrap;
}
