import type { UnifiedIndexedDBManager } from '@/core/indexedDB';
import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { TouchIdPrompt } from '../../stepUpConfirmation/passkeyPrompt/touchIdPrompt';
import type { SignerWorkerManagerContext } from '../../workerManager/SignerWorkerManager';
import type { ThresholdWarmSessionMaterialPort } from '../../threshold/crypto/webauthn';
import {
  activateEcdsaSession,
  type ThresholdEcdsaSessionBootstrapResult,
} from '../../threshold/ecdsa/activation';
import type { ThresholdEcdsaSmartAccountBootstrapInput } from '../warmCapabilities/ecdsaBootstrapPersistence';
export type { ThresholdEcdsaSmartAccountBootstrapInput } from '../warmCapabilities/ecdsaBootstrapPersistence';
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
import type {
  AppOrThresholdSessionAuth,
  AppSessionJwtAuth,
} from '@shared/utils/sessionTokens';
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

type EcdsaBootstrapRequestBase = {
  walletId: AccountId | string;
  subjectId: WalletSubjectId;
  chainTarget: ThresholdEcdsaChainTarget;
  source?: ThresholdEcdsaSessionStoreSource;
  relayerUrl?: string;
  ecdsaThresholdKeyId?: string;
  participantIds?: number[];
  operationIntent?: SigningOperationIntent;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  runtimeScopeBootstrap?: {
    environmentId: string;
    publishableKey: string;
  };
  ttlMs?: number;
  remainingUses?: number;
  smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
};

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

export type ReuseWarmEcdsaBootstrapRequest = EcdsaBootstrapRequestBase & {
  kind: 'reuse_warm_ecdsa_bootstrap';
  sessionKind?: never;
  sessionIdentity?: never;
  clientRootShare32B64u?: never;
  routeAuth?: never;
  webauthnAuthentication?: never;
  emailOtpAuthContext?: never;
};

type PasskeyFreshEcdsaBootstrapRequestBase = EcdsaBootstrapRequestBase & {
  kind: 'passkey_fresh_ecdsa_bootstrap';
  sessionIdentity: EcdsaBootstrapSessionIdentityInput;
  clientRootShare32B64u: string;
  emailOtpAuthContext?: never;
};

export type PasskeyFreshEcdsaBootstrapRequest =
  | (PasskeyFreshEcdsaBootstrapRequestBase & {
      sessionKind: 'jwt';
      routeAuth: PasskeyFreshBootstrapRouteAuth;
      webauthnAuthentication?: never;
    })
  | (PasskeyFreshEcdsaBootstrapRequestBase & {
      sessionKind: 'jwt';
      webauthnAuthentication: WebAuthnAuthenticationCredential;
      routeAuth?: never;
    })
  | (PasskeyFreshEcdsaBootstrapRequestBase & {
      sessionKind: Extract<ThresholdSessionKind, 'cookie'>;
      routeAuth?: never;
      webauthnAuthentication?: never;
    })
  | (PasskeyFreshEcdsaBootstrapRequestBase & {
      sessionKind: Extract<ThresholdSessionKind, 'cookie'>;
      webauthnAuthentication: WebAuthnAuthenticationCredential;
      routeAuth?: never;
    });

export type PasskeyCookieReconnectEcdsaBootstrapRequest =
  EcdsaBootstrapRequestBase & {
  kind: 'passkey_cookie_reconnect_ecdsa_bootstrap';
  sessionKind: 'cookie';
  sessionIdentity: EcdsaBootstrapSessionIdentityInput;
  routeAuth?: never;
  webauthnAuthentication?: never;
  clientRootShare32B64u?: never;
  emailOtpAuthContext?: never;
};

export type ThresholdSessionAuthReconnectEcdsaBootstrapRequest =
  EcdsaBootstrapRequestBase & {
    kind: 'threshold_session_auth_reconnect_ecdsa_bootstrap';
    sessionKind: 'jwt';
    sessionIdentity: EcdsaBootstrapSessionIdentityInput;
    routeAuth: AppOrThresholdSessionAuth;
    webauthnAuthentication?: never;
    clientRootShare32B64u: string;
    emailOtpAuthContext?: never;
  };

export type EmailOtpEcdsaBootstrapRequest = EcdsaBootstrapRequestBase & {
  kind: 'email_otp_ecdsa_bootstrap';
  source: 'email_otp';
  sessionKind: ThresholdSessionKind;
  sessionIdentity: EcdsaBootstrapSessionIdentityInput;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  clientRootShare32B64u: string;
  webauthnAuthentication?: never;
  routeAuth?: EmailOtpBootstrapRouteAuth;
};

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
    smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
    deployment?: {
      deployed: boolean;
      deploymentTxHash?: string;
    };
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

function toActivateEcdsaSessionRequest(
  request: EcdsaBootstrapRequest,
  relayerUrl: string,
) {
  const base = {
    walletId: request.walletId,
    subjectId: request.subjectId,
    chainTarget: request.chainTarget,
    relayerUrl,
    ecdsaThresholdKeyId: request.ecdsaThresholdKeyId,
    participantIds: request.participantIds ? [...request.participantIds] : undefined,
    runtimePolicyScope: request.runtimePolicyScope,
    runtimeScopeBootstrap: request.runtimeScopeBootstrap,
    ttlMs: request.ttlMs,
    remainingUses: request.remainingUses,
  };
  switch (request.kind) {
    case 'reuse_warm_ecdsa_bootstrap':
      return base;
    case 'passkey_fresh_ecdsa_bootstrap': {
      const passkeyFreshIdentity = buildEcdsaSessionIdentity(request.sessionIdentity);
      return {
        ...base,
        sessionKind: request.sessionKind,
        sessionId: passkeyFreshIdentity.thresholdSessionId,
        walletSigningSessionId: passkeyFreshIdentity.walletSigningSessionId,
        clientRootShare32B64u: request.clientRootShare32B64u,
        ...('routeAuth' in request && request.routeAuth
          ? { thresholdSessionAuth: request.routeAuth }
          : {}),
        ...('webauthnAuthentication' in request && request.webauthnAuthentication
          ? { webauthnAuthentication: request.webauthnAuthentication }
          : {}),
      };
    }
    case 'passkey_cookie_reconnect_ecdsa_bootstrap': {
      const cookieReconnectIdentity = buildEcdsaSessionIdentity(request.sessionIdentity);
      return {
        ...base,
        sessionKind: request.sessionKind,
        sessionId: cookieReconnectIdentity.thresholdSessionId,
        walletSigningSessionId: cookieReconnectIdentity.walletSigningSessionId,
      };
    }
    case 'threshold_session_auth_reconnect_ecdsa_bootstrap': {
      const thresholdReconnectIdentity = buildEcdsaSessionIdentity(request.sessionIdentity);
      return {
        ...base,
        sessionKind: request.sessionKind,
        sessionId: thresholdReconnectIdentity.thresholdSessionId,
        walletSigningSessionId: thresholdReconnectIdentity.walletSigningSessionId,
        clientRootShare32B64u: request.clientRootShare32B64u,
        thresholdSessionAuth: request.routeAuth,
      };
    }
    case 'email_otp_ecdsa_bootstrap': {
      const emailOtpIdentity = buildEcdsaSessionIdentity(request.sessionIdentity);
      return {
        ...base,
        sessionKind: request.sessionKind,
        sessionId: emailOtpIdentity.thresholdSessionId,
        walletSigningSessionId: emailOtpIdentity.walletSigningSessionId,
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

  const sessionIdentity = buildEcdsaSessionIdentity(request.sessionIdentity);
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
      sessionIdentity,
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
  const walletId = toAccountId(normalizedRequest.walletId);
  const chainTarget = normalizedRequest.chainTarget;
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
  await deps.touchConfirm.putWarmSessionMaterial({
    sessionId: activation.session.sessionId,
    prfFirstB64u: activation.clientRootShare32B64u,
    expiresAtMs: Number(activation.session.expiresAtMs),
    remainingUses: Number(activation.session.remainingUses),
    transport: {
      curve: 'ecdsa',
      chainTarget,
      relayerUrl,
      walletSigningSessionId: activation.session.walletSigningSessionId,
      ...(typeof activation.session.jwt === 'string' && activation.session.jwt.trim()
        ? { thresholdSessionAuthToken: activation.session.jwt.trim() }
        : {}),
    },
  }).catch(() => undefined);
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
    smartAccount: normalizedRequest.smartAccount,
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
