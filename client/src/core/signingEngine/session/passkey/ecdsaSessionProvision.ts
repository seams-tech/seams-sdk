import { toAccountId } from '@/core/types/accountIds';
import type { ThresholdSessionSealTransportAuthMaterial } from '../persistence/records';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  bootstrapEcdsaSessionValue,
  ecdsaBootstrapChainTarget,
  ecdsaBootstrapWalletId,
  type EcdsaBootstrapRequest,
  type ThresholdSessionActivationDeps,
} from './ecdsaBootstrap';
import { withThresholdEcdsaBootstrapQueue } from '../warmCapabilities/ecdsaBootstrapQueue';
import { ensureEcdsaPrfSealPersisted, type WarmSessionSealPersistPorts } from './runtime';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type {
  ThresholdEcdsaEmailOtpAuthContext,
  ThresholdEcdsaSessionStoreSource,
} from '../identity/laneIdentity';
import type {
  EvmFamilyEcdsaKeyIdentity,
  EvmFamilyEcdsaSessionLanePolicy,
} from '../identity/evmFamilyEcdsaIdentity';
import type { SigningOperationIntent } from '../operationState/types';
import type {
  EcdsaSessionIdentity,
  VerifiedEcdsaThresholdSessionAuth,
} from '../warmCapabilities/ecdsaProvisionPlan';
import type {
  ThresholdRuntimePolicyScope,
  ThresholdSessionKind,
} from '../../threshold/sessionPolicy';

export type ProvisionThresholdEcdsaSessionDeps = {
  queueByWallet: Map<string, Promise<void>>;
  activationDeps: ThresholdSessionActivationDeps;
  touchConfirm: WarmSessionSealPersistPorts;
  resolveSealTransport: (args: {
    thresholdSessionId: string;
    chainTarget: ThresholdEcdsaChainTarget;
  }) => ThresholdSessionSealTransportAuthMaterial | null;
};

export type ThresholdEcdsaActivationPolicy =
  | { kind: 'default_policy' }
  | { kind: 'scoped_policy'; scope: ThresholdRuntimePolicyScope };

export type ThresholdEcdsaActivationRuntimeScopeBootstrap = {
  environmentId: string;
  publishableKey: string;
};

type ThresholdEcdsaActivationRequestSharedFields = {
  relayerUrl: string;
  source: ThresholdEcdsaSessionStoreSource;
  sessionBudgetUses: number;
  runtimePolicy: ThresholdEcdsaActivationPolicy;
  runtimeScopeBootstrap?: ThresholdEcdsaActivationRuntimeScopeBootstrap;
  operationIntent?: SigningOperationIntent;
  ttlMs?: number;
};

type ThresholdEcdsaActivationRequestIdentityFields = {
  key: EvmFamilyEcdsaKeyIdentity;
  lanePolicy: EvmFamilyEcdsaSessionLanePolicy;
  walletId?: never;
  subjectId?: never;
  chainTarget?: never;
  ecdsaThresholdKeyId?: never;
  participantIds?: never;
};

type ThresholdEcdsaActivationRequestCommon = ThresholdEcdsaActivationRequestSharedFields &
  ThresholdEcdsaActivationRequestIdentityFields;

export type ThresholdEcdsaPasskeyActivationRequest = ThresholdEcdsaActivationRequestCommon & {
  kind: 'passkey_ecdsa_activation';
  sessionIdentity: EcdsaSessionIdentity;
  sessionKind: ThresholdSessionKind;
  clientRootShare32B64u: string;
  webauthnAuthentication: WebAuthnAuthenticationCredential;
  thresholdSessionAuth?: never;
  emailOtpAuthContext?: never;
};

export type ThresholdEcdsaEmailOtpActivationRequest = ThresholdEcdsaActivationRequestCommon & {
  kind: 'email_otp_ecdsa_activation';
  sessionIdentity: EcdsaSessionIdentity;
  sessionKind: ThresholdSessionKind;
  clientRootShare32B64u: string;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  webauthnAuthentication?: never;
  thresholdSessionAuth?: never;
};

export type ThresholdEcdsaThresholdSessionAuthReconnectRequest =
  ThresholdEcdsaActivationRequestCommon & {
    kind: 'threshold_session_auth_reconnect';
    sessionIdentity: EcdsaSessionIdentity;
    sessionKind: 'jwt';
    thresholdSessionAuth: VerifiedEcdsaThresholdSessionAuth;
    clientRootShare32B64u: string;
    webauthnAuthentication?: never;
    emailOtpAuthContext?: never;
  };

export type ThresholdEcdsaCookieReconnectRequest = ThresholdEcdsaActivationRequestCommon & {
  kind: 'cookie_reconnect';
  sessionIdentity: EcdsaSessionIdentity;
  sessionKind: 'cookie';
  thresholdSessionAuth?: never;
  webauthnAuthentication?: never;
  clientRootShare32B64u?: never;
  emailOtpAuthContext?: never;
};

export type ThresholdEcdsaActivationRequest =
  | ThresholdEcdsaPasskeyActivationRequest
  | ThresholdEcdsaEmailOtpActivationRequest
  | ThresholdEcdsaThresholdSessionAuthReconnectRequest
  | ThresholdEcdsaCookieReconnectRequest;

type BuildThresholdEcdsaActivationRequestCommon = ThresholdEcdsaActivationRequestCommon;

type BuildPasskeyEcdsaActivationArgs = BuildThresholdEcdsaActivationRequestCommon & {
  sessionIdentity: EcdsaSessionIdentity;
  sessionKind: ThresholdSessionKind;
  clientRootShare32B64u: string;
  webauthnAuthentication: WebAuthnAuthenticationCredential;
  thresholdSessionAuth?: never;
  emailOtpAuthContext?: never;
};

type BuildEmailOtpSessionBootstrapEcdsaActivationArgs =
  BuildThresholdEcdsaActivationRequestCommon & {
    sessionIdentity: EcdsaSessionIdentity;
    sessionKind: ThresholdSessionKind;
    clientRootShare32B64u: string;
    emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext & { retention: 'session' };
    webauthnAuthentication?: never;
    thresholdSessionAuth?: never;
  };

type BuildEmailOtpPerOperationReauthEcdsaActivationArgs =
  BuildThresholdEcdsaActivationRequestCommon & {
    sessionIdentity: EcdsaSessionIdentity;
    sessionKind: ThresholdSessionKind;
    clientRootShare32B64u: string;
    emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext & { retention: 'single_use' };
    webauthnAuthentication?: never;
    thresholdSessionAuth?: never;
  };

type BuildThresholdSessionReconnectEcdsaActivationArgs =
  BuildThresholdEcdsaActivationRequestCommon & {
    sessionIdentity: EcdsaSessionIdentity;
    sessionKind: 'jwt';
    thresholdSessionAuth: VerifiedEcdsaThresholdSessionAuth;
    clientRootShare32B64u: string;
    webauthnAuthentication?: never;
    emailOtpAuthContext?: never;
  };

type BuildCookieReconnectEcdsaActivationArgs = BuildThresholdEcdsaActivationRequestCommon & {
  sessionIdentity: EcdsaSessionIdentity;
  sessionKind: 'cookie';
  thresholdSessionAuth?: never;
  webauthnAuthentication?: never;
  clientRootShare32B64u?: never;
  emailOtpAuthContext?: never;
};

function applyOptionalActivationFields<T extends ThresholdEcdsaActivationRequest>(
  request: T,
  args: BuildThresholdEcdsaActivationRequestCommon,
): T {
  if (args.runtimeScopeBootstrap) {
    request.runtimeScopeBootstrap = args.runtimeScopeBootstrap;
  }
  if (args.operationIntent) {
    request.operationIntent = args.operationIntent;
  }
  if (typeof args.ttlMs === 'number') {
    request.ttlMs = args.ttlMs;
  }
  return request;
}

function buildPasskeyEcdsaActivationRequest(
  args: BuildPasskeyEcdsaActivationArgs,
): ThresholdEcdsaPasskeyActivationRequest {
  const request: ThresholdEcdsaPasskeyActivationRequest = {
    kind: 'passkey_ecdsa_activation',
    key: args.key,
    lanePolicy: args.lanePolicy,
    source: args.source,
    relayerUrl: args.relayerUrl,
    sessionIdentity: args.sessionIdentity,
    sessionKind: args.sessionKind,
    sessionBudgetUses: args.sessionBudgetUses,
    runtimePolicy: args.runtimePolicy,
    clientRootShare32B64u: args.clientRootShare32B64u,
    webauthnAuthentication: args.webauthnAuthentication,
  };
  return applyOptionalActivationFields(request, args);
}

export function buildPasskeyRegistrationEcdsaActivation(
  args: BuildPasskeyEcdsaActivationArgs,
): ThresholdEcdsaPasskeyActivationRequest {
  return buildPasskeyEcdsaActivationRequest(args);
}

export function buildPasskeyReconnectEcdsaActivation(
  args: BuildPasskeyEcdsaActivationArgs,
): ThresholdEcdsaPasskeyActivationRequest {
  return buildPasskeyEcdsaActivationRequest(args);
}

function buildEmailOtpEcdsaActivationRequest(
  args:
    | BuildEmailOtpSessionBootstrapEcdsaActivationArgs
    | BuildEmailOtpPerOperationReauthEcdsaActivationArgs,
): ThresholdEcdsaEmailOtpActivationRequest {
  const request: ThresholdEcdsaEmailOtpActivationRequest = {
    kind: 'email_otp_ecdsa_activation',
    key: args.key,
    lanePolicy: args.lanePolicy,
    source: args.source,
    relayerUrl: args.relayerUrl,
    sessionIdentity: args.sessionIdentity,
    sessionKind: args.sessionKind,
    sessionBudgetUses: args.sessionBudgetUses,
    runtimePolicy: args.runtimePolicy,
    clientRootShare32B64u: args.clientRootShare32B64u,
    emailOtpAuthContext: args.emailOtpAuthContext,
  };
  return applyOptionalActivationFields(request, args);
}

export function buildEmailOtpSessionBootstrapEcdsaActivation(
  args: BuildEmailOtpSessionBootstrapEcdsaActivationArgs,
): ThresholdEcdsaEmailOtpActivationRequest {
  return buildEmailOtpEcdsaActivationRequest(args);
}

export function buildEmailOtpPerOperationReauthEcdsaActivation(
  args: BuildEmailOtpPerOperationReauthEcdsaActivationArgs,
): ThresholdEcdsaEmailOtpActivationRequest {
  return buildEmailOtpEcdsaActivationRequest(args);
}

export function buildThresholdSessionReconnectEcdsaActivation(
  args: BuildThresholdSessionReconnectEcdsaActivationArgs,
): ThresholdEcdsaThresholdSessionAuthReconnectRequest {
  const request: ThresholdEcdsaThresholdSessionAuthReconnectRequest = {
    kind: 'threshold_session_auth_reconnect',
    key: args.key,
    lanePolicy: args.lanePolicy,
    source: args.source,
    relayerUrl: args.relayerUrl,
    sessionIdentity: args.sessionIdentity,
    sessionKind: 'jwt',
    sessionBudgetUses: args.sessionBudgetUses,
    runtimePolicy: args.runtimePolicy,
    clientRootShare32B64u: args.clientRootShare32B64u,
    thresholdSessionAuth: args.thresholdSessionAuth,
  };
  return applyOptionalActivationFields(request, args);
}

export function buildCookieReconnectEcdsaActivation(
  args: BuildCookieReconnectEcdsaActivationArgs,
): ThresholdEcdsaCookieReconnectRequest {
  const request: ThresholdEcdsaCookieReconnectRequest = {
    kind: 'cookie_reconnect',
    key: args.key,
    lanePolicy: args.lanePolicy,
    source: args.source,
    relayerUrl: args.relayerUrl,
    sessionIdentity: args.sessionIdentity,
    sessionKind: 'cookie',
    sessionBudgetUses: args.sessionBudgetUses,
    runtimePolicy: args.runtimePolicy,
  };
  return applyOptionalActivationFields(request, args);
}

export function buildEcdsaExportActivation(
  args: BuildPasskeyEcdsaActivationArgs,
): ThresholdEcdsaPasskeyActivationRequest {
  return buildPasskeyEcdsaActivationRequest(args);
}

function toOptionalRuntimePolicyScope(
  policy: ThresholdEcdsaActivationPolicy,
): ThresholdRuntimePolicyScope | undefined {
  switch (policy.kind) {
    case 'default_policy':
      return undefined;
    case 'scoped_policy':
      return policy.scope;
  }
  policy satisfies never;
  throw new Error('[SigningEngine][ecdsa] unsupported ECDSA activation policy');
}

function applyCommonActivationRequestFields<T extends EcdsaBootstrapRequest>(
  args: T,
  request: ThresholdEcdsaActivationRequest,
): T {
  if (request.runtimeScopeBootstrap) {
    args.runtimeScopeBootstrap = request.runtimeScopeBootstrap;
  }
  if (request.operationIntent) {
    args.operationIntent = request.operationIntent;
  }
  const runtimePolicyScope = toOptionalRuntimePolicyScope(request.runtimePolicy);
  if ('walletId' in args) {
    if (typeof request.ttlMs === 'number') {
      args.ttlMs = request.ttlMs;
    }
    if (runtimePolicyScope) {
      args.runtimePolicyScope = runtimePolicyScope;
    }
  }
  return args;
}

function toBootstrapEcdsaSessionRequest(
  request: ThresholdEcdsaActivationRequest,
): EcdsaBootstrapRequest {
  const walletId = request.key.walletId;
  const subjectId = request.key.subjectId;
  const chainTarget = request.lanePolicy.chainTarget;
  const ecdsaThresholdKeyId = String(request.key.ecdsaThresholdKeyId);
  const participantIds = request.key.participantIds.map((participantId) => Number(participantId));
  const keyIntent = {
    kind: 'existing_ecdsa_key' as const,
    ecdsaThresholdKeyId,
    participantIds,
  };
  switch (request.kind) {
    case 'passkey_ecdsa_activation':
      if (request.sessionKind === 'cookie') {
        return applyCommonActivationRequestFields(
          {
            kind: 'passkey_fresh_ecdsa_bootstrap',
            walletId,
            subjectId,
            chainTarget,
            source: request.source,
            relayerUrl: request.relayerUrl,
            keyIntent,
            sessionKind: 'cookie',
            sessionIdentity: request.sessionIdentity,
            remainingUses: request.sessionBudgetUses,
            clientRootShare32B64u: request.clientRootShare32B64u,
            webauthnAuthentication: request.webauthnAuthentication,
          },
          request,
        );
      }
      return applyCommonActivationRequestFields(
        {
          kind: 'passkey_fresh_ecdsa_bootstrap',
          walletId,
          subjectId,
          chainTarget,
          source: request.source,
          relayerUrl: request.relayerUrl,
          keyIntent,
          sessionKind: 'jwt',
          sessionIdentity: request.sessionIdentity,
          remainingUses: request.sessionBudgetUses,
          clientRootShare32B64u: request.clientRootShare32B64u,
          webauthnAuthentication: request.webauthnAuthentication,
        },
        request,
      );
    case 'email_otp_ecdsa_activation':
      return applyCommonActivationRequestFields(
        {
          kind: 'email_otp_ecdsa_bootstrap',
          walletId,
          subjectId,
          chainTarget,
          source: 'email_otp',
          relayerUrl: request.relayerUrl,
          keyIntent,
          sessionKind: request.sessionKind,
          sessionIdentity: request.sessionIdentity,
          remainingUses: request.sessionBudgetUses,
          clientRootShare32B64u: request.clientRootShare32B64u,
          emailOtpAuthContext: request.emailOtpAuthContext,
        },
        request,
      );
    case 'threshold_session_auth_reconnect':
      return applyCommonActivationRequestFields(
        {
          kind: 'threshold_session_auth_reconnect_ecdsa_bootstrap',
          source: request.source,
          relayerUrl: request.relayerUrl,
          key: request.key,
          lanePolicy: request.lanePolicy,
          clientRootShare32B64u: request.clientRootShare32B64u,
          routeAuth: {
            kind: 'threshold_session',
            jwt: request.thresholdSessionAuth.thresholdSessionAuthToken,
          },
        },
        request,
      );
    case 'cookie_reconnect':
      return applyCommonActivationRequestFields(
        {
          kind: 'passkey_cookie_reconnect_ecdsa_bootstrap',
          walletId,
          subjectId,
            chainTarget,
            source: request.source,
            relayerUrl: request.relayerUrl,
            keyIntent,
            sessionKind: request.sessionKind,
            sessionIdentity: request.sessionIdentity,
          remainingUses: request.sessionBudgetUses,
        },
        request,
      );
  }
  request satisfies never;
  throw new Error('[SigningEngine][ecdsa] unsupported activation request');
}

export async function provisionThresholdEcdsaSessionFromBootstrapArgs(
  deps: ProvisionThresholdEcdsaSessionDeps,
  request: EcdsaBootstrapRequest,
): Promise<ThresholdEcdsaSessionBootstrapResult> {
  const walletId = toAccountId(ecdsaBootstrapWalletId(request));
  const chainTarget = ecdsaBootstrapChainTarget(request);
  return await withThresholdEcdsaBootstrapQueue(deps.queueByWallet, walletId, async () => {
    const bootstrap = await bootstrapEcdsaSessionValue(deps.activationDeps, request);
    const thresholdSessionId = String(
      bootstrap.thresholdEcdsaKeyRef.thresholdSessionId || '',
    ).trim();
    if (thresholdSessionId) {
      await ensureEcdsaPrfSealPersisted({
        touchConfirm: deps.touchConfirm,
        chainTarget,
        thresholdSessionId,
        required: request.kind === 'threshold_session_auth_reconnect_ecdsa_bootstrap',
        errorContext: 'threshold-ecdsa bootstrap seal persistence',
        sealPersistInFlightBySessionId: new Map(),
        resolveSealTransport: deps.resolveSealTransport,
      });
    }
    return bootstrap;
  });
}

export async function provisionThresholdEcdsaSession(
  deps: ProvisionThresholdEcdsaSessionDeps,
  request: ThresholdEcdsaActivationRequest,
): Promise<ThresholdEcdsaSessionBootstrapResult> {
  const bootstrapRequest = toBootstrapEcdsaSessionRequest(request);
  return await provisionThresholdEcdsaSessionFromBootstrapArgs(deps, bootstrapRequest);
}
