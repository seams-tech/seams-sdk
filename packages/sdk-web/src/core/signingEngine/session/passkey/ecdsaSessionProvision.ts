import type { ThresholdSessionSealTransportAuthMaterial } from '../persistence/records';
import type { PersistedEcdsaRoleLocalMaterial } from '../material/ecdsaRoleLocalMaterialResolver';
import type {
  DurableRecordStore,
  EmailOtpEcdsaExportWorkerIssuedSessionHandle,
  EmailOtpWorkerIssuedSessionHandle,
} from '@/core/platform';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  bootstrapEmailOtpExplicitExportEcdsaSessionValue,
  bootstrapEcdsaSessionValue,
  bootstrapExplicitKeyExportEcdsaSessionValue,
  type EmailOtpEcdsaExplicitExportBootstrapResult,
  type EmailOtpEcdsaExplicitExportBootstrapRequest,
  ecdsaBootstrapWalletId,
  type EcdsaBootstrapRequest,
  type PasskeyEcdsaExportBootstrapRequest,
  type WalletSessionActivationDeps,
} from './ecdsaBootstrap';
import { withThresholdEcdsaBootstrapQueue } from '../warmCapabilities/ecdsaBootstrapQueue';
import { ensureEcdsaPrfSealPersisted, type WarmSessionSealPersistPorts } from './runtime';
import type {
  EcdsaExplicitExportOperationAuthorization,
  ThresholdEcdsaExplicitKeyExportActivationResult,
  ThresholdEcdsaSessionBootstrapResult,
} from '../../threshold/ecdsa/activation';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type {
  ThresholdEcdsaEmailOtpAuthContext,
  ThresholdEcdsaEmailOtpPendingSingleUseAuthContext,
  ThresholdEcdsaEmailOtpSessionAuthContext,
  ThresholdEcdsaSessionStoreSource,
} from '../identity/laneIdentity';
import {
  emailOtpAuthContextProviderUserId,
  emailOtpAuthContextRetention,
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
import { ecdsaRoleLocalReadyRecordStorageKeyFacts } from '../persistence/ecdsaRoleLocalRecords';
import type { SigningOperationIntent } from '../operationState/types';
import type { SigningLaneAuthBinding } from '../identity/signingLaneAuthBinding';
import type {
  EcdsaSessionIdentity,
} from '../warmCapabilities/ecdsaProvisionPlan';
import type {
  ThresholdRuntimePolicyScope,
  ThresholdSessionKind,
} from '../../threshold/sessionPolicy';
import type { ThresholdEcdsaBackendBinding } from '../../interfaces/signing';
import type {
  RouterAbEcdsaDerivationPublicCapabilityV1,
  RouterAbEcdsaPostRegistrationSessionActivationResponseV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import type { AppOrWalletSessionAuth } from '@shared/utils/sessionTokens';
import { walletSessionAuthorizations } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import type { ActiveEvmFamilyWalletSessionAuthorization } from '../../flows/signEvmFamily/ecdsaSigningCapability';

export type ProvisionThresholdEcdsaSessionDeps = {
  queueByWallet: Map<string, Promise<void>>;
  activationDeps: WalletSessionActivationDeps;
  touchConfirm: WarmSessionSealPersistPorts;
  persistEcdsaRoleLocalReadyRecord: DurableRecordStore['persistEcdsaRoleLocalReadyRecord'];
  resolveSealTransport: (args: {
    lane: ExactEcdsaSigningLaneIdentity;
    authorization: ActiveEvmFamilyWalletSessionAuthorization;
  }) => Promise<ThresholdSessionSealTransportAuthMaterial | null>;
};

type ExactEcdsaSealLane = {
  lane: ExactEcdsaSigningLaneIdentity;
  authorization: ActiveEvmFamilyWalletSessionAuthorization;
};

export type ThresholdEcdsaActivationPolicy =
  | { kind: 'default_policy' }
  | { kind: 'scoped_policy'; scope: ThresholdRuntimePolicyScope };

export type ThresholdEcdsaActivationRuntimeScopeBootstrap = {
  projectEnvironmentId: string;
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
  publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
  existingRoleLocalMaterial: PersistedEcdsaRoleLocalMaterial;
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
  purpose: 'transaction_signing';
  sessionIdentity: EcdsaSessionIdentity;
  sessionKind: 'jwt';
  requestId: string;
  passkeyPrfFirstB64u: string;
  webauthnAuthentication: WebAuthnAuthenticationCredential;
  walletSessionRouteAuth: AppOrWalletSessionAuth;
  emailOtpAuthContext?: never;
};

type ThresholdEcdsaExplicitExportActivationRequestBase = {
  readonly purpose: 'explicit_key_export';
  readonly relayerUrl: string;
  readonly existingRoleLocalMaterial: PersistedEcdsaRoleLocalMaterial;
  readonly authorization: EcdsaExplicitExportOperationAuthorization;
};

export type ThresholdEcdsaPasskeyExportActivationRequest =
  ThresholdEcdsaExplicitExportActivationRequestBase & {
    readonly kind: 'passkey_ecdsa_export_activation';
  };

type ThresholdEcdsaEmailOtpActivationRequestBase = ThresholdEcdsaActivationRequestCommon & {
  kind: 'email_otp_ecdsa_activation';
  purpose: 'transaction_signing';
  sessionIdentity: EcdsaSessionIdentity;
  sessionKind: 'jwt';
  emailOtpWorkerSessionHandle: EmailOtpEcdsaBootstrapWorkerHandle;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  passkeyPrfFirstB64u?: never;
  webauthnAuthentication?: never;
};

export type ThresholdEcdsaEmailOtpActivationRequest =
  ThresholdEcdsaEmailOtpActivationRequestBase &
    (
      | {
          walletSessionRouteAuth: AppOrWalletSessionAuth;
          preauthorizedSessionActivation?: never;
        }
      | {
          preauthorizedSessionActivation: RouterAbEcdsaPostRegistrationSessionActivationResponseV1;
          walletSessionRouteAuth?: never;
        }
    );

export type ThresholdEcdsaEmailOtpExportActivationRequest =
  ThresholdEcdsaExplicitExportActivationRequestBase & {
    readonly kind: 'email_otp_ecdsa_export_activation';
  };

export type ThresholdEcdsaActivationRequest =
  | ThresholdEcdsaPasskeyActivationRequest
  | ThresholdEcdsaEmailOtpActivationRequest;

export type ThresholdEcdsaExplicitKeyExportBootstrapResult =
  ThresholdEcdsaExplicitKeyExportActivationResult;

type BuildThresholdEcdsaActivationRequestCommon = ThresholdEcdsaActivationRequestCommon;

type BuildPasskeyEcdsaActivationArgs = BuildThresholdEcdsaActivationRequestCommon & {
  sessionIdentity: EcdsaSessionIdentity;
  sessionKind: 'jwt';
  requestId: string;
  passkeyPrfFirstB64u: string;
  webauthnAuthentication: WebAuthnAuthenticationCredential;
  walletSessionRouteAuth: AppOrWalletSessionAuth;
  emailOtpAuthContext?: never;
};

type BuildPasskeyEcdsaExportActivationArgs = Omit<
  ThresholdEcdsaPasskeyExportActivationRequest,
  'kind' | 'purpose'
>;

type BuildEmailOtpSessionBootstrapEcdsaActivationArgs =
  BuildThresholdEcdsaActivationRequestCommon & {
    sessionIdentity: EcdsaSessionIdentity;
    sessionKind: 'jwt';
    emailOtpWorkerSessionHandle: EmailOtpEcdsaBootstrapWorkerHandle;
    emailOtpAuthContext: ThresholdEcdsaEmailOtpSessionAuthContext;
  walletSessionRouteAuth: AppOrWalletSessionAuth;
    passkeyPrfFirstB64u?: never;
    webauthnAuthentication?: never;
  };

type BuildEmailOtpPreauthorizedSessionBootstrapEcdsaActivationArgs = Omit<
  BuildEmailOtpSessionBootstrapEcdsaActivationArgs,
  'walletSessionRouteAuth'
> & {
  preauthorizedSessionActivation: RouterAbEcdsaPostRegistrationSessionActivationResponseV1;
  walletSessionRouteAuth?: never;
};

type BuildEmailOtpPerOperationReauthEcdsaActivationArgs =
  BuildThresholdEcdsaActivationRequestCommon & {
    sessionIdentity: EcdsaSessionIdentity;
    sessionKind: 'jwt';
    emailOtpWorkerSessionHandle: EmailOtpEcdsaBootstrapWorkerHandle;
    emailOtpAuthContext: ThresholdEcdsaEmailOtpPendingSingleUseAuthContext;
    walletSessionRouteAuth: AppOrWalletSessionAuth;
    passkeyPrfFirstB64u?: never;
    webauthnAuthentication?: never;
  };

type BuildEmailOtpExplicitExportEcdsaActivationArgs = Omit<
  ThresholdEcdsaEmailOtpExportActivationRequest,
  'kind' | 'purpose'
>;

type AnyThresholdEcdsaActivationRequest = ThresholdEcdsaActivationRequest;

function applyOptionalActivationFields<T extends AnyThresholdEcdsaActivationRequest>(
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
    purpose: 'transaction_signing',
    walletKey: args.walletKey,
    lanePolicy: args.lanePolicy,
    publicCapability: args.publicCapability,
    existingRoleLocalMaterial: args.existingRoleLocalMaterial,
    source: args.source,
    relayerUrl: args.relayerUrl,
    sessionIdentity: args.sessionIdentity,
    sessionKind: args.sessionKind,
    sessionBudgetUses: args.sessionBudgetUses,
    requestId: args.requestId,
    runtimePolicy: args.runtimePolicy,
    passkeyPrfFirstB64u: args.passkeyPrfFirstB64u,
    webauthnAuthentication: args.webauthnAuthentication,
    walletSessionRouteAuth: args.walletSessionRouteAuth,
  };
  return applyOptionalActivationFields(request, args);
}

export function buildPasskeyRegistrationEcdsaActivation(
  args: BuildPasskeyEcdsaActivationArgs,
): ThresholdEcdsaPasskeyActivationRequest {
  return buildPasskeyEcdsaActivationRequest(args);
}

function buildEmailOtpEcdsaActivationRequest(
  args:
    | BuildEmailOtpSessionBootstrapEcdsaActivationArgs
    | BuildEmailOtpPreauthorizedSessionBootstrapEcdsaActivationArgs
    | BuildEmailOtpPerOperationReauthEcdsaActivationArgs,
): ThresholdEcdsaEmailOtpActivationRequest {
  const request: ThresholdEcdsaEmailOtpActivationRequest = {
    kind: 'email_otp_ecdsa_activation',
    purpose: 'transaction_signing',
    walletKey: args.walletKey,
    lanePolicy: args.lanePolicy,
    publicCapability: args.publicCapability,
    existingRoleLocalMaterial: args.existingRoleLocalMaterial,
    source: args.source,
    relayerUrl: args.relayerUrl,
    sessionIdentity: args.sessionIdentity,
    sessionKind: args.sessionKind,
    sessionBudgetUses: args.sessionBudgetUses,
    runtimePolicy: args.runtimePolicy,
    emailOtpWorkerSessionHandle: args.emailOtpWorkerSessionHandle,
    emailOtpAuthContext: args.emailOtpAuthContext,
    ...('preauthorizedSessionActivation' in args
      ? { preauthorizedSessionActivation: args.preauthorizedSessionActivation }
      : { walletSessionRouteAuth: args.walletSessionRouteAuth }),
  };
  return applyOptionalActivationFields(request, args);
}

function assertEmailOtpActivationRetention(args: {
  context: ThresholdEcdsaEmailOtpAuthContext;
  expected: 'session' | 'single_use';
  label: string;
}): void {
  const actual = emailOtpAuthContextRetention(args.context);
  if (actual !== args.expected) {
    throw new Error(`Email OTP ${args.label} activation requires ${args.expected} retention`);
  }
}

export function buildEmailOtpSessionBootstrapEcdsaActivation(
  args: BuildEmailOtpSessionBootstrapEcdsaActivationArgs,
): ThresholdEcdsaEmailOtpActivationRequest {
  assertEmailOtpActivationRetention({
    context: args.emailOtpAuthContext,
    expected: 'session',
    label: 'session bootstrap',
  });
  return buildEmailOtpEcdsaActivationRequest(args);
}

export function buildEmailOtpPreauthorizedSessionBootstrapEcdsaActivation(
  args: BuildEmailOtpPreauthorizedSessionBootstrapEcdsaActivationArgs,
): ThresholdEcdsaEmailOtpActivationRequest {
  assertEmailOtpActivationRetention({
    context: args.emailOtpAuthContext,
    expected: 'session',
    label: 'preauthorized session bootstrap',
  });
  return buildEmailOtpEcdsaActivationRequest(args);
}

export function buildEmailOtpPerOperationReauthEcdsaActivation(
  args: BuildEmailOtpPerOperationReauthEcdsaActivationArgs,
): ThresholdEcdsaEmailOtpActivationRequest {
  assertEmailOtpActivationRetention({
    context: args.emailOtpAuthContext,
    expected: 'single_use',
    label: 'per-operation reauth',
  });
  return buildEmailOtpEcdsaActivationRequest(args);
}

export function buildEmailOtpExplicitExportEcdsaActivation(
  args: BuildEmailOtpExplicitExportEcdsaActivationArgs,
): ThresholdEcdsaEmailOtpExportActivationRequest {
  return {
    kind: 'email_otp_ecdsa_export_activation',
    purpose: 'explicit_key_export',
    existingRoleLocalMaterial: args.existingRoleLocalMaterial,
    relayerUrl: args.relayerUrl,
    authorization: args.authorization,
  };
}

export function shouldEnsurePasskeyEcdsaSealAfterProvision(
  request: EcdsaBootstrapRequest,
): boolean {
  return request.kind !== 'email_otp_ecdsa_bootstrap';
}

export function buildEcdsaExportActivation(
  args: BuildPasskeyEcdsaExportActivationArgs,
): ThresholdEcdsaPasskeyExportActivationRequest {
  return {
    kind: 'passkey_ecdsa_export_activation',
    purpose: 'explicit_key_export',
    existingRoleLocalMaterial: args.existingRoleLocalMaterial,
    relayerUrl: args.relayerUrl,
    authorization: args.authorization,
  };
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

type AnyEcdsaBootstrapRequest = EcdsaBootstrapRequest;

function applyCommonActivationRequestFields<T extends AnyEcdsaBootstrapRequest>(
  args: T,
  request: AnyThresholdEcdsaActivationRequest,
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
    };

function toEcdsaBootstrapLifecycleCommand(
  request: ThresholdEcdsaActivationRequest,
): EcdsaBootstrapLifecycleCommand {
  switch (request.kind) {
    case 'passkey_ecdsa_activation':
      return { kind: 'passkey_existing_session_activation', request };
    case 'email_otp_ecdsa_activation':
      return { kind: 'email_otp_existing_session_activation', request };
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
          publicCapability: command.request.publicCapability,
          existingRoleLocalMaterial: command.request.existingRoleLocalMaterial,
          source: command.request.source,
          relayerUrl: command.request.relayerUrl,
          requestId: command.request.requestId,
          passkeyPrfFirstB64u: command.request.passkeyPrfFirstB64u,
          webauthnAuthentication: command.request.webauthnAuthentication,
          routeAuth: command.request.walletSessionRouteAuth,
        },
        command.request,
      );
    case 'email_otp_existing_session_activation': {
      const common = {
          kind: 'email_otp_ecdsa_bootstrap',
          keyHandle: command.request.walletKey.keyHandle,
          key: evmFamilyEcdsaWalletKeyToIdentity(command.request.walletKey),
          lanePolicy: command.request.lanePolicy,
          publicCapability: command.request.publicCapability,
          existingRoleLocalMaterial: command.request.existingRoleLocalMaterial,
          source: 'email_otp',
          relayerUrl: command.request.relayerUrl,
          emailOtpWorkerSessionHandle: command.request.emailOtpWorkerSessionHandle,
          emailOtpAuthContext: command.request.emailOtpAuthContext,
        } as const;
      return command.request.preauthorizedSessionActivation
        ? applyCommonActivationRequestFields(
            { ...common, sessionActivation: command.request.preauthorizedSessionActivation },
            command.request,
          )
        : applyCommonActivationRequestFields(
            { ...common, routeAuth: command.request.walletSessionRouteAuth },
            command.request,
          );
    }
  }
  command satisfies never;
  throw new Error('[SigningEngine][ecdsa] unsupported activation request');
}

function toExplicitKeyExportEcdsaBootstrapRequest(
  request: ThresholdEcdsaPasskeyExportActivationRequest,
): PasskeyEcdsaExportBootstrapRequest {
  return {
    kind: 'passkey_ecdsa_export_bootstrap',
    purpose: 'explicit_key_export',
    existingRoleLocalMaterial: request.existingRoleLocalMaterial,
    relayerUrl: request.relayerUrl,
    authorization: request.authorization,
  };
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
    const providerSubjectId = String(
      emailOtpAuthContextProviderUserId(args.request.emailOtpAuthContext),
    ).trim();
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

async function exactEcdsaSealLaneFromBootstrap(args: {
  deps: ProvisionThresholdEcdsaSessionDeps;
  request: EcdsaBootstrapRequest;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
}): Promise<ExactEcdsaSealLane | null> {
  const exactRequest = exactEcdsaBootstrapRequest(args.request);
  if (!exactRequest) return null;
  const auth = exactEcdsaBootstrapAuthBinding({
    deps: args.deps,
    request: args.request,
  });
  if (!auth) return null;
  const authorizationRead = await walletSessionAuthorizations.readActiveForWallet(
    exactRequest.key.walletId,
  );
  if (authorizationRead.kind !== 'found') return null;
  const projection = authorizationRead.projection;
  if (
    projection.walletSessionId !== args.bootstrap.session.walletSessionId ||
    projection.quotaId !== args.bootstrap.session.quotaId ||
    projection.authorizationSessionId !== args.bootstrap.session.authorizationSessionId ||
    args.bootstrap.session.remainingUses <= 0
  ) {
    return null;
  }
  const authorization: ActiveEvmFamilyWalletSessionAuthorization = {
    kind: 'active_reusable_wallet_session_authorization',
    projection,
    status: {
      status: 'active',
      walletSessionId: projection.walletSessionId,
      quotaId: projection.quotaId,
      remainingUses: args.bootstrap.session.remainingUses,
      expiresAtMs: projection.expiresAtMs,
    },
  };
  const lane = exactEcdsaSigningLaneIdentity({
    signer: buildEvmFamilyEcdsaSignerBinding({
      walletId: exactRequest.key.walletId,
      chainTarget: exactRequest.lanePolicy.chainTarget,
      keyHandle: toEvmFamilyEcdsaKeyHandle(exactRequest.keyHandle),
      key: exactRequest.key,
      materialActivation: exactRequest.existingRoleLocalMaterial.materialActivation,
    }),
    auth,
  });
  return { lane, authorization };
}

async function persistEcdsaRoleLocalReadyRecordForBootstrap(args: {
  deps: ProvisionThresholdEcdsaSessionDeps;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
}): Promise<void> {
  const binding = args.bootstrap.thresholdEcdsaKeyRef.backendBinding;
  if (!binding) {
    throw new Error('[WarmSessionStore] threshold ECDSA bootstrap is missing its backend binding');
  }
  const record = roleLocalReadyRecordForPersistence(binding);
  if (!record) return;
  const persisted = await args.deps.persistEcdsaRoleLocalReadyRecord({
    record,
    storageKeyFacts: ecdsaRoleLocalReadyRecordStorageKeyFacts(record),
  });
  if (!persisted.ok) {
    throw new Error(
      `[WarmSessionStore] threshold ECDSA role-local ready record persistence failed (${persisted.code}): ${persisted.message}`,
    );
  }
}

function roleLocalReadyRecordForPersistence(
  binding: ThresholdEcdsaBackendBinding,
): ThresholdEcdsaBackendBinding['ecdsaRoleLocalReadyRecord'] | null {
  switch (binding.materialKind) {
    case 'email_otp_worker_handle':
    case 'role_local_ready_state_blob':
      return binding.ecdsaRoleLocalReadyRecord;
    case 'role_local_worker_handle':
    case 'role_local_durable_public_anchor':
    case 'role_local_durable_sealed_ref':
    case 'metadata_only':
      return null;
    default: {
      const exhaustive: never = binding;
      throw new Error(
        `[WarmSessionStore] unsupported threshold ECDSA backend binding: ${JSON.stringify(exhaustive)}`,
      );
    }
  }
}

export async function provisionThresholdEcdsaSessionFromBootstrapArgs(
  deps: ProvisionThresholdEcdsaSessionDeps,
  request: EcdsaBootstrapRequest,
): Promise<ThresholdEcdsaSessionBootstrapResult> {
  const walletId = toWalletId(ecdsaBootstrapWalletId(request));
  return await withThresholdEcdsaBootstrapQueue(deps.queueByWallet, walletId, async () => {
    const bootstrap = await bootstrapEcdsaSessionValue(deps.activationDeps, request);
    await persistEcdsaRoleLocalReadyRecordForBootstrap({ deps, bootstrap });
    const thresholdSessionId = String(
      bootstrap.thresholdEcdsaKeyRef.thresholdSessionId || '',
    ).trim();
    if (thresholdSessionId && shouldEnsurePasskeyEcdsaSealAfterProvision(request)) {
      const sealLane = await exactEcdsaSealLaneFromBootstrap({
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
        lane: sealLane.lane,
        authorization: sealLane.authorization,
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

export async function provisionPasskeyEcdsaExplicitExportSession(
  deps: ProvisionThresholdEcdsaSessionDeps,
  request: ThresholdEcdsaPasskeyExportActivationRequest,
): Promise<ThresholdEcdsaExplicitKeyExportBootstrapResult> {
  return await bootstrapExplicitKeyExportEcdsaSessionValue(
    deps.activationDeps,
    toExplicitKeyExportEcdsaBootstrapRequest(request),
  );
}

export async function provisionEmailOtpEcdsaExplicitExportSession(
  deps: ProvisionThresholdEcdsaSessionDeps,
  request: ThresholdEcdsaEmailOtpExportActivationRequest,
): Promise<EmailOtpEcdsaExplicitExportBootstrapResult> {
  const bootstrapRequest: EmailOtpEcdsaExplicitExportBootstrapRequest = {
    kind: 'email_otp_ecdsa_export_bootstrap',
    purpose: 'explicit_key_export',
    existingRoleLocalMaterial: request.existingRoleLocalMaterial,
    relayerUrl: request.relayerUrl,
    authorization: request.authorization,
  };
  return await bootstrapEmailOtpExplicitExportEcdsaSessionValue(
    deps.activationDeps,
    bootstrapRequest,
  );
}
