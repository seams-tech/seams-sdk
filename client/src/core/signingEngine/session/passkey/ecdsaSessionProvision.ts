import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { ThresholdSessionSealTransportAuthMaterial } from '../persistence/records';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  bootstrapEcdsaSessionValue,
  type EcdsaBootstrapRequest,
  type ThresholdEcdsaSmartAccountBootstrapInput,
  type ThresholdSessionActivationDeps,
} from './ecdsaBootstrap';
import { withThresholdEcdsaBootstrapQueue } from '../warmCapabilities/ecdsaBootstrapQueue';
import {
  ensureEcdsaPrfSealPersisted,
  type WarmSessionSealPersistPorts,
} from './runtime';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type { ThresholdEcdsaEmailOtpAuthContext, ThresholdEcdsaSessionStoreSource } from '../identity/laneIdentity';
import type { SigningOperationIntent } from '../operationState/types';
import type {
  EcdsaSessionIdentity,
  VerifiedEcdsaThresholdSessionAuth,
} from '../warmCapabilities/ecdsaProvisionPlan';
import type { ThresholdRuntimePolicyScope, ThresholdSessionKind } from '../../threshold/sessionPolicy';
import type { WalletSubjectId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

export type ProvisionThresholdEcdsaSessionDeps = {
  queueByAccount: Map<string, Promise<void>>;
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

type ThresholdEcdsaActivationRequestCommon = {
  nearAccountId: AccountId | string;
  subjectId: WalletSubjectId;
  chainTarget: ThresholdEcdsaChainTarget;
  relayerUrl: string;
  source: ThresholdEcdsaSessionStoreSource;
  ecdsaThresholdKeyId: string;
  participantIds: readonly number[];
  sessionBudgetUses: number;
  runtimePolicy: ThresholdEcdsaActivationPolicy;
  runtimeScopeBootstrap?: ThresholdEcdsaActivationRuntimeScopeBootstrap;
  operationIntent?: SigningOperationIntent;
  ttlMs?: number;
  smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
};

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
    webauthnAuthentication?: never;
    clientRootShare32B64u?: never;
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
  if (typeof request.ttlMs === 'number') {
    args.ttlMs = request.ttlMs;
  }
  if (request.smartAccount) {
    args.smartAccount = request.smartAccount;
  }
  const runtimePolicyScope = toOptionalRuntimePolicyScope(request.runtimePolicy);
  if (runtimePolicyScope) {
    args.runtimePolicyScope = runtimePolicyScope;
  }
  return args;
}

function toBootstrapEcdsaSessionRequest(
  request: ThresholdEcdsaActivationRequest,
): EcdsaBootstrapRequest {
  switch (request.kind) {
    case 'passkey_ecdsa_activation':
      if (request.sessionKind === 'cookie') {
        return applyCommonActivationRequestFields(
          {
            kind: 'passkey_fresh_ecdsa_bootstrap',
            nearAccountId: request.nearAccountId,
            subjectId: request.subjectId,
            chainTarget: request.chainTarget,
            source: request.source,
            relayerUrl: request.relayerUrl,
            ecdsaThresholdKeyId: request.ecdsaThresholdKeyId,
            participantIds: [...request.participantIds],
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
          nearAccountId: request.nearAccountId,
          subjectId: request.subjectId,
          chainTarget: request.chainTarget,
          source: request.source,
          relayerUrl: request.relayerUrl,
          ecdsaThresholdKeyId: request.ecdsaThresholdKeyId,
          participantIds: [...request.participantIds],
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
          nearAccountId: request.nearAccountId,
          subjectId: request.subjectId,
          chainTarget: request.chainTarget,
          source: 'email_otp',
          relayerUrl: request.relayerUrl,
          ecdsaThresholdKeyId: request.ecdsaThresholdKeyId,
          participantIds: [...request.participantIds],
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
          nearAccountId: request.nearAccountId,
          subjectId: request.subjectId,
          chainTarget: request.chainTarget,
          source: request.source,
          relayerUrl: request.relayerUrl,
          ecdsaThresholdKeyId: request.ecdsaThresholdKeyId,
          participantIds: [...request.participantIds],
          sessionKind: request.sessionKind,
          sessionIdentity: request.sessionIdentity,
          remainingUses: request.sessionBudgetUses,
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
          nearAccountId: request.nearAccountId,
          subjectId: request.subjectId,
          chainTarget: request.chainTarget,
          source: request.source,
          relayerUrl: request.relayerUrl,
          ecdsaThresholdKeyId: request.ecdsaThresholdKeyId,
          participantIds: [...request.participantIds],
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
  const nearAccountId = toAccountId(request.nearAccountId);
  return await withThresholdEcdsaBootstrapQueue(deps.queueByAccount, nearAccountId, async () => {
    const bootstrap = await bootstrapEcdsaSessionValue(deps.activationDeps, request);
    const thresholdSessionId = String(bootstrap.thresholdEcdsaKeyRef.thresholdSessionId || '').trim();
    if (thresholdSessionId) {
      await ensureEcdsaPrfSealPersisted({
        touchConfirm: deps.touchConfirm,
        chainTarget: request.chainTarget,
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
