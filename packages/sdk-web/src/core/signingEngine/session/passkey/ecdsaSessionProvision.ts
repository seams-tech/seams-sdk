import type { ThresholdSessionSealTransportAuthMaterial } from '../persistence/records';
import type { EmailOtpWorkerIssuedSessionHandle } from '@/core/platform';
import {
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  bootstrapEcdsaSessionValue,
  ecdsaBootstrapWalletId,
  type EcdsaBootstrapRequest,
  type WalletSessionActivationDeps,
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
  EvmFamilyEcdsaWalletKey,
  EvmFamilyEcdsaSessionLanePolicy,
} from '../identity/evmFamilyEcdsaIdentity';
import {
  evmFamilyEcdsaWalletKeyToIdentity,
  toEvmFamilyEcdsaKeyHandle,
  toRpId,
} from '../identity/evmFamilyEcdsaIdentity';
import {
  buildEvmFamilyEcdsaSignerBinding,
  exactEcdsaSigningLaneIdentity,
  type ExactEcdsaSigningLaneIdentity,
} from '../identity/exactSigningLaneIdentity';
import type { SigningOperationIntent } from '../operationState/types';
import type { SigningLaneAuthBinding } from '../identity/signingLaneAuthBinding';
import type {
  EcdsaSessionIdentity,
  VerifiedEcdsaWalletSessionAuth,
} from '../warmCapabilities/ecdsaProvisionPlan';
import type {
  ThresholdRuntimePolicyScope,
  ThresholdSessionKind,
} from '../../threshold/sessionPolicy';

export type ProvisionThresholdEcdsaSessionDeps = {
  queueByWallet: Map<string, Promise<void>>;
  activationDeps: WalletSessionActivationDeps;
  touchConfirm: WarmSessionSealPersistPorts;
  resolveSealTransport: (args: {
    lane: ExactEcdsaSigningLaneIdentity;
  }) => ThresholdSessionSealTransportAuthMaterial | null;
};

export type ThresholdEcdsaActivationPolicy =
  | { kind: 'default_policy' }
  | { kind: 'scoped_policy'; scope: ThresholdRuntimePolicyScope };

export type ThresholdEcdsaActivationRuntimeScopeBootstrap = {
  environmentId: string;
  publishableKey: string;
};

type EmailOtpEcdsaBootstrapWorkerHandle = Extract<
  EmailOtpWorkerIssuedSessionHandle,
  { action: 'threshold_ecdsa_bootstrap' }
>;

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
  walletKey: EvmFamilyEcdsaWalletKey;
  lanePolicy: EvmFamilyEcdsaSessionLanePolicy;
  keyHandle?: never;
  key?: never;
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
  sessionKind: 'jwt';
  requestId: string;
  passkeyPrfFirstB64u: string;
  webauthnAuthentication: WebAuthnAuthenticationCredential;
  walletSessionRouteAuth?: never;
  emailOtpAuthContext?: never;
};

export type ThresholdEcdsaEmailOtpActivationRequest = ThresholdEcdsaActivationRequestCommon & {
  kind: 'email_otp_ecdsa_activation';
  sessionIdentity: EcdsaSessionIdentity;
  sessionKind: 'jwt';
  emailOtpWorkerSessionHandle: EmailOtpEcdsaBootstrapWorkerHandle;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  passkeyPrfFirstB64u?: never;
  webauthnAuthentication?: never;
  walletSessionRouteAuth?: never;
};

export type ThresholdEcdsaWalletSessionReconnectRequest =
  ThresholdEcdsaActivationRequestCommon & {
    kind: 'wallet_session_reconnect';
    sessionIdentity: EcdsaSessionIdentity;
    sessionKind: 'jwt';
    walletSessionAuth: VerifiedEcdsaWalletSessionAuth;
    passkeyPrfFirstB64u: string;
    passkeyCredentialIdB64u: string;
    webauthnAuthentication?: never;
    emailOtpAuthContext?: never;
  };

export type ThresholdEcdsaActivationRequest =
  | ThresholdEcdsaPasskeyActivationRequest
  | ThresholdEcdsaEmailOtpActivationRequest
  | ThresholdEcdsaWalletSessionReconnectRequest;

type BuildThresholdEcdsaActivationRequestCommon = ThresholdEcdsaActivationRequestCommon;

type BuildPasskeyEcdsaActivationArgs = BuildThresholdEcdsaActivationRequestCommon & {
  sessionIdentity: EcdsaSessionIdentity;
  sessionKind: 'jwt';
  requestId: string;
  passkeyPrfFirstB64u: string;
  webauthnAuthentication: WebAuthnAuthenticationCredential;
  walletSessionRouteAuth?: never;
  emailOtpAuthContext?: never;
};

type BuildEmailOtpSessionBootstrapEcdsaActivationArgs =
  BuildThresholdEcdsaActivationRequestCommon & {
    sessionIdentity: EcdsaSessionIdentity;
    sessionKind: 'jwt';
    emailOtpWorkerSessionHandle: EmailOtpEcdsaBootstrapWorkerHandle;
    emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext & { retention: 'session' };
    passkeyPrfFirstB64u?: never;
    webauthnAuthentication?: never;
    walletSessionRouteAuth?: never;
  };

type BuildEmailOtpPerOperationReauthEcdsaActivationArgs =
  BuildThresholdEcdsaActivationRequestCommon & {
    sessionIdentity: EcdsaSessionIdentity;
    sessionKind: 'jwt';
    emailOtpWorkerSessionHandle: EmailOtpEcdsaBootstrapWorkerHandle;
    emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext & { retention: 'single_use' };
    passkeyPrfFirstB64u?: never;
    webauthnAuthentication?: never;
    walletSessionRouteAuth?: never;
  };

type BuildWalletSessionReconnectEcdsaActivationArgs =
  BuildThresholdEcdsaActivationRequestCommon & {
    sessionIdentity: EcdsaSessionIdentity;
    sessionKind: 'jwt';
    walletSessionAuth: VerifiedEcdsaWalletSessionAuth;
    passkeyPrfFirstB64u: string;
    passkeyCredentialIdB64u: string;
    webauthnAuthentication?: never;
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
    walletKey: args.walletKey,
    lanePolicy: args.lanePolicy,
    source: args.source,
    relayerUrl: args.relayerUrl,
    sessionIdentity: args.sessionIdentity,
    sessionKind: args.sessionKind,
    sessionBudgetUses: args.sessionBudgetUses,
    requestId: args.requestId,
    runtimePolicy: args.runtimePolicy,
    passkeyPrfFirstB64u: args.passkeyPrfFirstB64u,
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
    walletKey: args.walletKey,
    lanePolicy: args.lanePolicy,
    source: args.source,
    relayerUrl: args.relayerUrl,
    sessionIdentity: args.sessionIdentity,
    sessionKind: args.sessionKind,
    sessionBudgetUses: args.sessionBudgetUses,
    runtimePolicy: args.runtimePolicy,
    emailOtpWorkerSessionHandle: args.emailOtpWorkerSessionHandle,
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

export function buildWalletSessionReconnectEcdsaActivation(
  args: BuildWalletSessionReconnectEcdsaActivationArgs,
): ThresholdEcdsaWalletSessionReconnectRequest {
  const request: ThresholdEcdsaWalletSessionReconnectRequest = {
    kind: 'wallet_session_reconnect',
    walletKey: args.walletKey,
    lanePolicy: args.lanePolicy,
    source: args.source,
    relayerUrl: args.relayerUrl,
    sessionIdentity: args.sessionIdentity,
    sessionKind: 'jwt',
    sessionBudgetUses: args.sessionBudgetUses,
    runtimePolicy: args.runtimePolicy,
    passkeyPrfFirstB64u: args.passkeyPrfFirstB64u,
    passkeyCredentialIdB64u: args.passkeyCredentialIdB64u,
    walletSessionAuth: args.walletSessionAuth,
  };
  return applyOptionalActivationFields(request, args);
}

export function shouldEnsurePasskeyEcdsaSealAfterProvision(
  request: EcdsaBootstrapRequest,
): boolean {
  return request.kind !== 'email_otp_ecdsa_bootstrap';
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

export type EcdsaBootstrapLifecycleCommand =
  | {
      kind: 'passkey_existing_session_activation';
      request: ThresholdEcdsaPasskeyActivationRequest;
    }
  | {
      kind: 'email_otp_existing_session_activation';
      request: ThresholdEcdsaEmailOtpActivationRequest;
    }
  | {
      kind: 'wallet_session_existing_session_reconnect';
      request: ThresholdEcdsaWalletSessionReconnectRequest;
    };

function toEcdsaBootstrapLifecycleCommand(
  request: ThresholdEcdsaActivationRequest,
): EcdsaBootstrapLifecycleCommand {
  switch (request.kind) {
    case 'passkey_ecdsa_activation':
      return { kind: 'passkey_existing_session_activation', request };
    case 'email_otp_ecdsa_activation':
      return { kind: 'email_otp_existing_session_activation', request };
    case 'wallet_session_reconnect':
      return { kind: 'wallet_session_existing_session_reconnect', request };
  }
  request satisfies never;
  throw new Error('[SigningEngine][ecdsa] unsupported activation request');
}

function toBootstrapEcdsaSessionRequest(
  request: ThresholdEcdsaActivationRequest,
): EcdsaBootstrapRequest {
  const command = toEcdsaBootstrapLifecycleCommand(request);
  switch (command.kind) {
    case 'passkey_existing_session_activation':
      return applyCommonActivationRequestFields(
        {
          kind: 'passkey_fresh_ecdsa_bootstrap',
          keyHandle: command.request.walletKey.keyHandle,
          key: evmFamilyEcdsaWalletKeyToIdentity(command.request.walletKey),
          lanePolicy: command.request.lanePolicy,
          source: command.request.source,
          relayerUrl: command.request.relayerUrl,
          requestId: command.request.requestId,
          passkeyPrfFirstB64u: command.request.passkeyPrfFirstB64u,
          webauthnAuthentication: command.request.webauthnAuthentication,
        },
        command.request,
      );
    case 'email_otp_existing_session_activation':
      return applyCommonActivationRequestFields(
        {
          kind: 'email_otp_ecdsa_bootstrap',
          keyHandle: command.request.walletKey.keyHandle,
          key: evmFamilyEcdsaWalletKeyToIdentity(command.request.walletKey),
          lanePolicy: command.request.lanePolicy,
          source: 'email_otp',
          relayerUrl: command.request.relayerUrl,
          emailOtpWorkerSessionHandle: command.request.emailOtpWorkerSessionHandle,
          emailOtpAuthContext: command.request.emailOtpAuthContext,
        },
        command.request,
      );
    case 'wallet_session_existing_session_reconnect':
      return applyCommonActivationRequestFields(
        {
          kind: 'wallet_session_reconnect_ecdsa_bootstrap',
          source: command.request.source,
          relayerUrl: command.request.relayerUrl,
          keyHandle: command.request.walletKey.keyHandle,
          key: evmFamilyEcdsaWalletKeyToIdentity(command.request.walletKey),
          lanePolicy: command.request.lanePolicy,
          passkeyPrfFirstB64u: command.request.passkeyPrfFirstB64u,
          passkeyCredentialIdB64u: command.request.passkeyCredentialIdB64u,
          routeAuth: {
            kind: 'wallet_session',
            jwt: command.request.walletSessionAuth.walletSessionJwt,
          },
        },
        command.request,
      );
  }
  command satisfies never;
  throw new Error('[SigningEngine][ecdsa] unsupported activation request');
}

type ExactIdentityEcdsaBootstrapRequest = Extract<
  EcdsaBootstrapRequest,
  { key: ReturnType<typeof evmFamilyEcdsaWalletKeyToIdentity> }
>;

function exactEcdsaBootstrapRequest(
  request: EcdsaBootstrapRequest,
): ExactIdentityEcdsaBootstrapRequest | null {
  if (!('key' in request) || !request.key) return null;
  if (!('keyHandle' in request) || !request.keyHandle) return null;
  if (!('lanePolicy' in request) || !request.lanePolicy) return null;
  return request;
}

function passkeyCredentialIdFromBootstrapRequest(request: EcdsaBootstrapRequest): string {
  if ('passkeyCredentialIdB64u' in request) {
    const credentialId = String(request.passkeyCredentialIdB64u || '').trim();
    if (credentialId) return credentialId;
  }
  if ('webauthnAuthentication' in request && request.webauthnAuthentication) {
    return String(
      request.webauthnAuthentication.rawId || request.webauthnAuthentication.id || '',
    ).trim();
  }
  return '';
}

function exactEcdsaBootstrapAuthBinding(args: {
  deps: ProvisionThresholdEcdsaSessionDeps;
  request: EcdsaBootstrapRequest;
}): SigningLaneAuthBinding | null {
  if (args.request.kind === 'email_otp_ecdsa_bootstrap') {
    const providerSubjectId = String(args.request.emailOtpAuthContext.authSubjectId || '').trim();
    return providerSubjectId
      ? {
          kind: 'email_otp',
          providerSubjectId,
        }
      : null;
  }
  const rpId = String(args.deps.activationDeps.touchIdPrompt.getRpId() || '').trim();
  const credentialIdB64u = passkeyCredentialIdFromBootstrapRequest(args.request);
  if (!rpId || !credentialIdB64u) return null;
  return {
    kind: 'passkey',
    rpId: toRpId(rpId),
    credentialIdB64u,
  };
}

function exactEcdsaSealLaneFromBootstrap(args: {
  deps: ProvisionThresholdEcdsaSessionDeps;
  request: EcdsaBootstrapRequest;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
}): ExactEcdsaSigningLaneIdentity | null {
  const exactRequest = exactEcdsaBootstrapRequest(args.request);
  if (!exactRequest) return null;
  const auth = exactEcdsaBootstrapAuthBinding({
    deps: args.deps,
    request: args.request,
  });
  if (!auth) return null;
  const thresholdSessionId = String(
    args.bootstrap.thresholdEcdsaKeyRef.thresholdSessionId ||
      args.bootstrap.session.thresholdSessionId ||
      exactRequest.lanePolicy.thresholdSessionId,
  ).trim();
  const signingGrantId = String(
    args.bootstrap.thresholdEcdsaKeyRef.signingGrantId ||
      args.bootstrap.session.signingGrantId ||
      exactRequest.lanePolicy.signingGrantId,
  ).trim();
  if (!thresholdSessionId || !signingGrantId) return null;
  return exactEcdsaSigningLaneIdentity({
    signer: buildEvmFamilyEcdsaSignerBinding({
      walletId: exactRequest.key.walletId,
      chainTarget: exactRequest.lanePolicy.chainTarget,
      keyHandle: toEvmFamilyEcdsaKeyHandle(exactRequest.keyHandle),
      key: exactRequest.key,
    }),
    auth,
    signingGrantId,
    thresholdSessionId,
  });
}

export async function provisionThresholdEcdsaSessionFromBootstrapArgs(
  deps: ProvisionThresholdEcdsaSessionDeps,
  request: EcdsaBootstrapRequest,
): Promise<ThresholdEcdsaSessionBootstrapResult> {
  const walletId = toWalletId(ecdsaBootstrapWalletId(request));
  return await withThresholdEcdsaBootstrapQueue(deps.queueByWallet, walletId, async () => {
    const bootstrap = await bootstrapEcdsaSessionValue(deps.activationDeps, request);
    const thresholdSessionId = String(
      bootstrap.thresholdEcdsaKeyRef.thresholdSessionId || '',
    ).trim();
    if (thresholdSessionId && shouldEnsurePasskeyEcdsaSealAfterProvision(request)) {
      const sealLane = exactEcdsaSealLaneFromBootstrap({
        deps,
        request,
        bootstrap,
      });
      const sealRequired = request.kind === 'wallet_session_reconnect_ecdsa_bootstrap';
      if (!sealLane) {
        if (sealRequired) {
          throw new Error(
            '[WarmSessionStore] threshold ECDSA required seal persistence needs exact lane identity',
          );
        }
        return bootstrap;
      }
      await ensureEcdsaPrfSealPersisted({
        touchConfirm: deps.touchConfirm,
        lane: sealLane,
        required: sealRequired,
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
