import { thresholdEcdsaRecordHasRoleLocalSigningMaterial } from '../session/persistence/ecdsaRoleLocalRecords';
import {
  requirePersistedEcdsaRoleLocalMaterial,
  type PersistedEcdsaRoleLocalMaterial,
  type ThresholdEcdsaSessionRecord,
} from '../session/persistence/records';
import { mpcMaterialActivationRefsEqual } from '@shared/utils/domainIds';
import {
  isEmailOtpPendingSingleUseAuthContext,
  isEmailOtpSessionAuthContext,
  type ThresholdEcdsaEmailOtpAuthContext,
  type ThresholdEcdsaSessionStoreSource,
} from '../session/identity/laneIdentity';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../interfaces/signing';
import type { ThresholdEcdsaSessionBootstrapResult } from '../threshold/ecdsa/activation';
import {
  DEFAULT_THRESHOLD_SESSION_POLICY,
  type ThresholdRuntimePolicyScope,
} from '../threshold/sessionPolicy';
import type { SigningOperationIntent } from '../session/operationState/types';
import {
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  emitWarmSessionTransition,
  summarizeWarmSessionTransition,
  type WarmSessionTransitionEvent,
} from '../session/warmCapabilities/transitions';
import {
  buildEmailOtpEcdsaProvisionSecretSource,
  type EcdsaSessionIdentity,
  getEcdsaProvisionPlanLaneIdentity,
  type EcdsaSessionProvisionPlan,
} from '../session/warmCapabilities/ecdsaProvisionPlan';
import { hasSufficientWarmClaim } from '../session/warmCapabilities/readModel';
import type {
  WarmSessionEcdsaCapabilityState,
  WarmSessionEnvelope,
} from '../session/warmCapabilities/types';
import type {
  EnsureWarmEcdsaProvisionPlanReadyArgs,
  EnsureWarmEcdsaCapabilityReadyResult,
} from '../session/warmCapabilities/types';
import type {
  ThresholdEcdsaActivationPolicy,
  ThresholdEcdsaActivationRequest,
  ThresholdEcdsaActivationRuntimeScopeBootstrap,
} from '../session/passkey/ecdsaSessionProvision';
import {
  buildEmailOtpPerOperationReauthEcdsaActivation,
  buildEmailOtpSessionBootstrapEcdsaActivation,
  buildPasskeyReconnectEcdsaActivation,
  buildWalletSessionReconnectEcdsaActivation,
} from '../session/passkey/ecdsaSessionProvision';
import { claimPasskeyEcdsaPrfFirst } from '../session/passkey/ecdsaRecovery';
import type { PasskeyWarmSessionRecoveryPorts } from '../session/passkey/prfClaim';
import {
  buildBaseEvmFamilyEcdsaKeyIdentity,
  buildEvmFamilyEcdsaWalletKey,
  buildEvmFamilyEcdsaSessionLanePolicy,
  resolveThresholdEcdsaKeyIdFromRecord,
  resolveThresholdSigningRootBindingFromRecord,
  type EvmFamilyEcdsaWalletKey,
  type EvmFamilyEcdsaSessionLanePolicy,
} from '../session/identity/evmFamilyEcdsaIdentity';
import type { RouterAbEcdsaDerivationPublicCapabilityV1 } from '@shared/utils/routerAbEcdsaDerivation';

export type WarmSessionEcdsaProvisionerDeps = {
  getWarmSession: (walletId: WalletId) => Promise<WarmSessionEnvelope>;
};

export type WarmSessionEcdsaReconnectDeps = {
  getWarmSession: (walletId: WalletId) => Promise<WarmSessionEnvelope>;
  canProvisionEcdsaCapability: boolean;
  provisionThresholdEcdsaSession: (
    args: ThresholdEcdsaActivationRequest,
  ) => Promise<ThresholdEcdsaSessionBootstrapResult>;
  touchConfirm: PasskeyWarmSessionRecoveryPorts;
  reconnectInFlightByCapability: Map<string, Promise<EnsureWarmEcdsaCapabilityReadyResult>>;
  onTransition?: (event: WarmSessionTransitionEvent) => void | Promise<void>;
};

type EcdsaProvisionActivationCommon = {
  walletId: WalletId;
  relayerUrl: string;
  source: ThresholdEcdsaSessionStoreSource;
  walletKey: EvmFamilyEcdsaWalletKey;
  lanePolicy: EvmFamilyEcdsaSessionLanePolicy;
  publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
  existingRoleLocalMaterial: PersistedEcdsaRoleLocalMaterial;
  sessionIdentity: EcdsaSessionIdentity;
  sessionKind: 'jwt';
  sessionBudgetUses: number;
  runtimePolicy: ThresholdEcdsaActivationPolicy;
  runtimeScopeBootstrap?: ThresholdEcdsaActivationRuntimeScopeBootstrap;
  operationIntent?: SigningOperationIntent;
  beforeProvision?: () => void | Promise<void>;
  assertNotCancelled?: () => void;
};

type PasskeyEcdsaActivation = EcdsaProvisionActivationCommon & {
  kind: 'passkey_ecdsa_activation';
  passkeyPrfFirstB64u: string;
  webauthnAuthentication: Extract<
    EcdsaSessionProvisionPlan,
    { kind: 'passkey_ecdsa_session_provision' }
  >['provisionSecretSource']['webauthnAuthentication'];
  walletSessionRouteAuth: Extract<
    EcdsaSessionProvisionPlan,
    { kind: 'passkey_ecdsa_session_provision' }
  >['walletSessionRouteAuth'];
  plan: Extract<EcdsaSessionProvisionPlan, { kind: 'passkey_ecdsa_session_provision' }>;
};

type EmailOtpEcdsaActivation = EcdsaProvisionActivationCommon & {
  kind: 'email_otp_ecdsa_activation';
  emailOtpWorkerSessionHandle: Extract<
    EcdsaSessionProvisionPlan,
    { kind: 'email_otp_ecdsa_session_provision' }
  >['provisionSecretSource']['workerHandle'];
  emailOtpAuthContext: Extract<
    EcdsaSessionProvisionPlan,
    { kind: 'email_otp_ecdsa_session_provision' }
  >['provisionSecretSource']['emailOtpAuthContext'];
  walletSessionRouteAuth: Extract<
    EcdsaSessionProvisionPlan,
    { kind: 'email_otp_ecdsa_session_provision' }
  >['walletSessionRouteAuth'];
  plan: Extract<EcdsaSessionProvisionPlan, { kind: 'email_otp_ecdsa_session_provision' }>;
};

type WalletSessionEcdsaActivation = EcdsaProvisionActivationCommon & {
  kind: 'wallet_session_reconnect';
  sessionKind: 'jwt';
  walletSessionAuth: Extract<
    EcdsaSessionProvisionPlan,
    { kind: 'wallet_session_ecdsa_reconnect' }
  >['walletSessionAuth'];
  passkeyCredentialIdB64u: string;
  plan: Extract<EcdsaSessionProvisionPlan, { kind: 'wallet_session_ecdsa_reconnect' }>;
};

type EcdsaProvisionActivation =
  | PasskeyEcdsaActivation
  | EmailOtpEcdsaActivation
  | WalletSessionEcdsaActivation;

type EcdsaActivationPolicy = ThresholdEcdsaActivationPolicy;

type EcdsaActivationOptions = Pick<
  EcdsaProvisionActivationCommon,
  'runtimeScopeBootstrap' | 'operationIntent' | 'beforeProvision' | 'assertNotCancelled'
>;

type EcdsaActivationIdentityPair = {
  walletKey: EvmFamilyEcdsaWalletKey;
  lanePolicy: EvmFamilyEcdsaSessionLanePolicy;
  publicCapability: ThresholdEcdsaSessionRecord['ecdsaRoleLocalPublicFacts']['publicCapability'];
  existingRoleLocalMaterial: PersistedEcdsaRoleLocalMaterial;
};

type EcdsaRecordCandidate = {
  source: ThresholdEcdsaSessionStoreSource;
  record: ThresholdEcdsaSessionRecord;
};

type EcdsaReconnectProvisionPlan = Extract<
  EcdsaSessionProvisionPlan,
  { kind: 'wallet_session_ecdsa_reconnect' }
>;

function hasEcdsaRecordSigningMaterial(record: ThresholdEcdsaSessionRecord): boolean {
  return thresholdEcdsaRecordHasRoleLocalSigningMaterial(record);
}

function ecdsaReconnectProvisionPlan(
  plan: EcdsaSessionProvisionPlan,
): EcdsaReconnectProvisionPlan | null {
  switch (plan.kind) {
    case 'wallet_session_ecdsa_reconnect':
      return plan;
    case 'passkey_ecdsa_session_provision':
    case 'email_otp_ecdsa_session_provision':
      return null;
  }
  plan satisfies never;
  return null;
}

function buildDefaultEcdsaActivationPolicy(): EcdsaActivationPolicy {
  return { kind: 'default_policy' };
}

function buildScopedEcdsaActivationPolicy(
  scope: ThresholdRuntimePolicyScope,
): EcdsaActivationPolicy {
  return { kind: 'scoped_policy', scope };
}

function buildEcdsaActivationPolicy(
  scope: ThresholdRuntimePolicyScope | undefined,
): EcdsaActivationPolicy {
  return scope ? buildScopedEcdsaActivationPolicy(scope) : buildDefaultEcdsaActivationPolicy();
}

function buildActivationOptions(
  args: EnsureWarmEcdsaProvisionPlanReadyArgs,
): EcdsaActivationOptions {
  const options: EcdsaActivationOptions = {};
  if (args.runtimeScopeBootstrap) {
    options.runtimeScopeBootstrap = args.runtimeScopeBootstrap;
  }
  if (args.operationIntent) {
    options.operationIntent = args.operationIntent;
  }
  if (args.beforeReconnect) {
    options.beforeProvision = args.beforeReconnect;
  }
  if (args.assertNotCancelled) {
    options.assertNotCancelled = args.assertNotCancelled;
  }
  return options;
}

function runtimePolicyScopeFromActivationPolicy(
  policy: EcdsaActivationPolicy,
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

function participantIdsKey(value: unknown): string {
  return normalizeParticipantIds(value)?.join(',') || '';
}

function normalizeSigningRootVersion(value: unknown): string {
  return String(value ?? '').trim() || 'default';
}

function hasRecordSigningRootBinding(record: ThresholdEcdsaSessionRecord): boolean {
  return Boolean(record.runtimePolicyScope);
}

function signingRootBindingFromProvisionPlan(args: {
  plan: EcdsaSessionProvisionPlan;
  record: ThresholdEcdsaSessionRecord;
}): { signingRootId: string; signingRootVersion: string } {
  if ('key' in args.plan) {
    return {
      signingRootId: String(args.plan.key.signingRootId),
      signingRootVersion: String(args.plan.key.signingRootVersion),
    };
  }
  const recordSigningRoot = resolveThresholdSigningRootBindingFromRecord({
    record: args.record,
  });
  return {
    signingRootId: String(recordSigningRoot.signingRootId),
    signingRootVersion: String(recordSigningRoot.signingRootVersion),
  };
}

function buildActivationKeyAndLanePolicy(args: {
  record: ThresholdEcdsaSessionRecord | null;
  plan: EcdsaSessionProvisionPlan;
  runtimePolicy: EcdsaActivationPolicy;
}): EcdsaActivationIdentityPair {
  if (!args.record) {
    const sessionIdentity = getEcdsaProvisionPlanLaneIdentity(args.plan);
    console.warn('[WarmSessionStore] missing ECDSA activation record', {
      planKind: args.plan.kind,
      chainTarget: args.plan.chainTarget,
      thresholdSessionId: sessionIdentity.thresholdSessionId,
      signingGrantId: sessionIdentity.signingGrantId,
      ecdsaThresholdKeyId: args.plan.signingKeyContext.ecdsaThresholdKeyId,
    });
    throw new Error('[WarmSessionStore] ECDSA activation requires an exact session record');
  }
  const planKeyId = String(args.plan.signingKeyContext.ecdsaThresholdKeyId || '').trim();
  const planSigningRoot = signingRootBindingFromProvisionPlan({
    plan: args.plan,
    record: args.record,
  });
  const planSigningRootId = String(planSigningRoot.signingRootId || '').trim();
  const planSigningRootVersion = normalizeSigningRootVersion(planSigningRoot.signingRootVersion);
  const planParticipantIds = normalizeParticipantIds(args.plan.signingKeyContext.participantIds);
  if (!planKeyId || !planSigningRootId || !planParticipantIds?.length) {
    throw new Error('[WarmSessionStore] ECDSA activation signing key context is invalid');
  }
  if (participantIdsKey(args.record.participantIds) !== participantIdsKey(planParticipantIds)) {
    throw new Error(
      '[WarmSessionStore] ECDSA activation participant ids do not match session record',
    );
  }
  const recordKeyId = String(args.record.ecdsaThresholdKeyId || '').trim();
  if (recordKeyId && recordKeyId !== planKeyId) {
    throw new Error('[WarmSessionStore] ECDSA activation key id does not match session record');
  }
  if (hasRecordSigningRootBinding(args.record)) {
    const recordSigningRoot = resolveThresholdSigningRootBindingFromRecord({
      record: args.record,
    });
    if (
      String(recordSigningRoot.signingRootId) !== planSigningRootId ||
      normalizeSigningRootVersion(recordSigningRoot.signingRootVersion) !== planSigningRootVersion
    ) {
      throw new Error(
        '[WarmSessionStore] ECDSA activation signing root does not match session record',
      );
    }
  }
  const key = buildBaseEvmFamilyEcdsaKeyIdentity({
    walletId: args.record.walletId,
    ecdsaThresholdKeyId: planKeyId,
    signingRootId: planSigningRootId,
    signingRootVersion: planSigningRootVersion,
    participantIds: planParticipantIds,
    thresholdOwnerAddress: args.record.ethereumAddress,
  });
  const sessionIdentity = getEcdsaProvisionPlanLaneIdentity(args.plan);
  const publicCapability = args.record.ecdsaRoleLocalPublicFacts.publicCapability;
  const runtimePolicyScope = runtimePolicyScopeFromActivationPolicy(args.runtimePolicy);
  return {
    publicCapability,
    existingRoleLocalMaterial: requirePersistedEcdsaRoleLocalMaterial(args.record),
    walletKey: buildEvmFamilyEcdsaWalletKey({
      walletId: key.walletId,
      evmFamilySigningKeySlotId: args.record.evmFamilySigningKeySlotId,
      keyHandle: args.record.keyHandle,
      chainTarget: args.plan.chainTarget,
      ecdsaThresholdKeyId: key.ecdsaThresholdKeyId,
      signingRootId: key.signingRootId,
      signingRootVersion: key.signingRootVersion,
      participantIds: key.participantIds,
      thresholdOwnerAddress: key.thresholdOwnerAddress,
      thresholdEcdsaPublicKeyB64u: args.record.thresholdEcdsaPublicKeyB64u,
    }),
    lanePolicy: buildEvmFamilyEcdsaSessionLanePolicy({
      chainTarget: args.plan.chainTarget,
      thresholdSessionId: sessionIdentity.thresholdSessionId,
      signingGrantId: sessionIdentity.signingGrantId,
      thresholdSessionKind: args.plan.sessionKind,
      ttlMs: DEFAULT_THRESHOLD_SESSION_POLICY.ttlMs,
      remainingUses: args.plan.sessionBudgetUses,
      ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    }),
  };
}

function buildPasskeyEcdsaActivation(args: {
  walletId: WalletId;
  relayerUrl: string;
  source: ThresholdEcdsaSessionStoreSource;
  runtimePolicy: EcdsaActivationPolicy;
  options: EcdsaActivationOptions;
  plan: Extract<EcdsaSessionProvisionPlan, { kind: 'passkey_ecdsa_session_provision' }>;
  identityPair: EcdsaActivationIdentityPair;
}): PasskeyEcdsaActivation {
  const activation: PasskeyEcdsaActivation = {
    kind: 'passkey_ecdsa_activation',
    walletId: args.walletId,
    relayerUrl: args.relayerUrl,
    source: args.source,
    walletKey: args.identityPair.walletKey,
    lanePolicy: args.identityPair.lanePolicy,
    publicCapability: args.identityPair.publicCapability,
    existingRoleLocalMaterial: args.identityPair.existingRoleLocalMaterial,
    sessionIdentity: args.plan.newSessionIdentity,
    sessionKind: args.plan.sessionKind,
    sessionBudgetUses: args.plan.sessionBudgetUses,
    runtimePolicy: args.runtimePolicy,
    passkeyPrfFirstB64u: args.plan.provisionSecretSource.passkeyPrfFirstB64u,
    webauthnAuthentication: args.plan.provisionSecretSource.webauthnAuthentication,
    walletSessionRouteAuth: args.plan.walletSessionRouteAuth,
    plan: args.plan,
  };
  if (args.options.runtimeScopeBootstrap) {
    activation.runtimeScopeBootstrap = args.options.runtimeScopeBootstrap;
  }
  if (args.options.operationIntent) {
    activation.operationIntent = args.options.operationIntent;
  }
  if (args.options.beforeProvision) {
    activation.beforeProvision = args.options.beforeProvision;
  }
  if (args.options.assertNotCancelled) {
    activation.assertNotCancelled = args.options.assertNotCancelled;
  }
  return activation;
}

function buildEmailOtpEcdsaActivation(args: {
  walletId: WalletId;
  relayerUrl: string;
  source: ThresholdEcdsaSessionStoreSource;
  runtimePolicy: EcdsaActivationPolicy;
  options: EcdsaActivationOptions;
  plan: Extract<EcdsaSessionProvisionPlan, { kind: 'email_otp_ecdsa_session_provision' }>;
  identityPair: EcdsaActivationIdentityPair;
}): EmailOtpEcdsaActivation {
  const activation: EmailOtpEcdsaActivation = {
    kind: 'email_otp_ecdsa_activation',
    walletId: args.walletId,
    relayerUrl: args.relayerUrl,
    source: args.source,
    walletKey: args.identityPair.walletKey,
    lanePolicy: args.identityPair.lanePolicy,
    publicCapability: args.identityPair.publicCapability,
    existingRoleLocalMaterial: args.identityPair.existingRoleLocalMaterial,
    sessionIdentity: args.plan.newSessionIdentity,
    sessionKind: args.plan.sessionKind,
    sessionBudgetUses: args.plan.sessionBudgetUses,
    runtimePolicy: args.runtimePolicy,
    emailOtpWorkerSessionHandle: args.plan.provisionSecretSource.workerHandle,
    emailOtpAuthContext: args.plan.provisionSecretSource.emailOtpAuthContext,
    walletSessionRouteAuth: args.plan.walletSessionRouteAuth,
    plan: args.plan,
  };
  if (args.options.runtimeScopeBootstrap) {
    activation.runtimeScopeBootstrap = args.options.runtimeScopeBootstrap;
  }
  if (args.options.operationIntent) {
    activation.operationIntent = args.options.operationIntent;
  }
  if (args.options.beforeProvision) {
    activation.beforeProvision = args.options.beforeProvision;
  }
  if (args.options.assertNotCancelled) {
    activation.assertNotCancelled = args.options.assertNotCancelled;
  }
  return activation;
}

function buildWalletSessionEcdsaActivation(args: {
  walletId: WalletId;
  relayerUrl: string;
  source: ThresholdEcdsaSessionStoreSource;
  runtimePolicy: EcdsaActivationPolicy;
  options: EcdsaActivationOptions;
  plan: Extract<EcdsaSessionProvisionPlan, { kind: 'wallet_session_ecdsa_reconnect' }>;
  identityPair: EcdsaActivationIdentityPair;
}): WalletSessionEcdsaActivation {
  const activation: WalletSessionEcdsaActivation = {
    kind: 'wallet_session_reconnect',
    walletId: args.walletId,
    relayerUrl: args.relayerUrl,
    source: args.source,
    walletKey: args.identityPair.walletKey,
    lanePolicy: args.identityPair.lanePolicy,
    publicCapability: args.identityPair.publicCapability,
    existingRoleLocalMaterial: args.identityPair.existingRoleLocalMaterial,
    sessionIdentity: args.plan.existingSessionIdentity,
    sessionKind: 'jwt',
    sessionBudgetUses: args.plan.sessionBudgetUses,
    runtimePolicy: args.runtimePolicy,
    walletSessionAuth: args.plan.walletSessionAuth,
    passkeyCredentialIdB64u: args.plan.passkeyCredentialIdB64u,
    plan: args.plan,
  };
  if (args.options.runtimeScopeBootstrap) {
    activation.runtimeScopeBootstrap = args.options.runtimeScopeBootstrap;
  }
  if (args.options.operationIntent) {
    activation.operationIntent = args.options.operationIntent;
  }
  if (args.options.beforeProvision) {
    activation.beforeProvision = args.options.beforeProvision;
  }
  if (args.options.assertNotCancelled) {
    activation.assertNotCancelled = args.options.assertNotCancelled;
  }
  return activation;
}

async function provisionEcdsaActivation(
  deps: Pick<WarmSessionEcdsaReconnectDeps, 'provisionThresholdEcdsaSession' | 'touchConfirm'>,
  activation: EcdsaProvisionActivation,
): Promise<ThresholdEcdsaSessionBootstrapResult> {
  await activation.beforeProvision?.();
  activation.assertNotCancelled?.();
  switch (activation.kind) {
    case 'passkey_ecdsa_activation':
      return await provisionPasskeyEcdsaSession(deps, activation);
    case 'wallet_session_reconnect':
      return await reconnectWalletSessionEcdsaSession(deps, activation);
    case 'email_otp_ecdsa_activation':
      return await provisionEmailOtpEcdsaSession(deps, activation);
  }
  activation satisfies never;
  throw new Error('[SigningEngine][ecdsa] unsupported ECDSA provision plan');
}

async function provisionPasskeyEcdsaSession(
  deps: Pick<WarmSessionEcdsaReconnectDeps, 'provisionThresholdEcdsaSession'>,
  activation: PasskeyEcdsaActivation,
): Promise<ThresholdEcdsaSessionBootstrapResult> {
  const plan = activation.plan;
  const baseArgs = {
    source: activation.source,
    relayerUrl: activation.relayerUrl,
    sessionIdentity: plan.newSessionIdentity,
    sessionKind: plan.sessionKind,
    sessionBudgetUses: plan.sessionBudgetUses,
    requestId: plan.requestId,
    runtimePolicy: activation.runtimePolicy,
    ...(activation.runtimeScopeBootstrap
      ? { runtimeScopeBootstrap: activation.runtimeScopeBootstrap }
      : {}),
    ...(activation.operationIntent ? { operationIntent: activation.operationIntent } : {}),
    passkeyPrfFirstB64u: plan.provisionSecretSource.passkeyPrfFirstB64u,
    webauthnAuthentication: plan.provisionSecretSource.webauthnAuthentication,
    walletSessionRouteAuth: plan.walletSessionRouteAuth,
  };
  return await deps.provisionThresholdEcdsaSession(
    buildPasskeyReconnectEcdsaActivation({
      source: baseArgs.source,
      relayerUrl: baseArgs.relayerUrl,
      sessionIdentity: baseArgs.sessionIdentity,
      sessionKind: baseArgs.sessionKind,
      sessionBudgetUses: baseArgs.sessionBudgetUses,
      requestId: baseArgs.requestId,
      runtimePolicy: baseArgs.runtimePolicy,
      ...(baseArgs.runtimeScopeBootstrap
        ? { runtimeScopeBootstrap: baseArgs.runtimeScopeBootstrap }
        : {}),
      ...(baseArgs.operationIntent ? { operationIntent: baseArgs.operationIntent } : {}),
      passkeyPrfFirstB64u: baseArgs.passkeyPrfFirstB64u,
      webauthnAuthentication: baseArgs.webauthnAuthentication,
      walletSessionRouteAuth: baseArgs.walletSessionRouteAuth,
      walletKey: activation.walletKey,
      lanePolicy: activation.lanePolicy,
      publicCapability: activation.publicCapability,
      existingRoleLocalMaterial: activation.existingRoleLocalMaterial,
    }),
  );
}

async function reconnectWalletSessionEcdsaSession(
  deps: Pick<WarmSessionEcdsaReconnectDeps, 'provisionThresholdEcdsaSession' | 'touchConfirm'>,
  activation: WalletSessionEcdsaActivation,
): Promise<ThresholdEcdsaSessionBootstrapResult> {
  const plan = activation.plan;
  const passkeyPrfFirstB64u = await claimPasskeyEcdsaPrfFirst({
    touchConfirm: deps.touchConfirm,
    walletId: activation.walletId,
    signingGrantId: plan.existingSessionIdentity.signingGrantId,
    thresholdSessionId: plan.existingSessionIdentity.thresholdSessionId,
    chainTarget: plan.chainTarget,
    errorContext: 'threshold-ecdsa authorization bootstrap',
    uses: 1,
  });
  const baseArgs = {
    source: activation.source,
    relayerUrl: activation.relayerUrl,
    sessionIdentity: plan.existingSessionIdentity,
    sessionKind: 'jwt' as const,
    sessionBudgetUses: plan.sessionBudgetUses,
    runtimePolicy: activation.runtimePolicy,
    ...(activation.runtimeScopeBootstrap
      ? { runtimeScopeBootstrap: activation.runtimeScopeBootstrap }
      : {}),
    ...(activation.operationIntent ? { operationIntent: activation.operationIntent } : {}),
    passkeyPrfFirstB64u,
    passkeyCredentialIdB64u: plan.passkeyCredentialIdB64u,
    walletSessionAuth: plan.walletSessionAuth,
  };
  return await deps.provisionThresholdEcdsaSession(
    buildWalletSessionReconnectEcdsaActivation({
      source: baseArgs.source,
      relayerUrl: baseArgs.relayerUrl,
      sessionIdentity: baseArgs.sessionIdentity,
      sessionKind: baseArgs.sessionKind,
      sessionBudgetUses: baseArgs.sessionBudgetUses,
      runtimePolicy: baseArgs.runtimePolicy,
      ...(baseArgs.runtimeScopeBootstrap
        ? { runtimeScopeBootstrap: baseArgs.runtimeScopeBootstrap }
        : {}),
      ...(baseArgs.operationIntent ? { operationIntent: baseArgs.operationIntent } : {}),
      passkeyPrfFirstB64u: baseArgs.passkeyPrfFirstB64u,
      passkeyCredentialIdB64u: baseArgs.passkeyCredentialIdB64u,
      walletSessionAuth: baseArgs.walletSessionAuth,
      walletKey: activation.walletKey,
      lanePolicy: activation.lanePolicy,
      publicCapability: activation.publicCapability,
      existingRoleLocalMaterial: activation.existingRoleLocalMaterial,
    }),
  );
}

async function provisionEmailOtpEcdsaSession(
  deps: Pick<WarmSessionEcdsaReconnectDeps, 'provisionThresholdEcdsaSession'>,
  activation: EmailOtpEcdsaActivation,
): Promise<ThresholdEcdsaSessionBootstrapResult> {
  const plan = activation.plan;
  const baseArgs = {
    source: activation.source,
    relayerUrl: activation.relayerUrl,
    sessionIdentity: plan.newSessionIdentity,
    sessionKind: plan.sessionKind,
    sessionBudgetUses: plan.sessionBudgetUses,
    runtimePolicy: activation.runtimePolicy,
    ...(activation.runtimeScopeBootstrap
      ? { runtimeScopeBootstrap: activation.runtimeScopeBootstrap }
      : {}),
    ...(activation.operationIntent ? { operationIntent: activation.operationIntent } : {}),
    emailOtpWorkerSessionHandle: plan.provisionSecretSource.workerHandle,
  };
  const emailOtpAuthContext = plan.provisionSecretSource.emailOtpAuthContext;
  if (isEmailOtpPendingSingleUseAuthContext(emailOtpAuthContext)) {
    return await deps.provisionThresholdEcdsaSession(
      buildEmailOtpPerOperationReauthEcdsaActivation({
        source: baseArgs.source,
        relayerUrl: baseArgs.relayerUrl,
        sessionIdentity: baseArgs.sessionIdentity,
        sessionKind: baseArgs.sessionKind,
        sessionBudgetUses: baseArgs.sessionBudgetUses,
        runtimePolicy: baseArgs.runtimePolicy,
        ...(baseArgs.runtimeScopeBootstrap
          ? { runtimeScopeBootstrap: baseArgs.runtimeScopeBootstrap }
          : {}),
        ...(baseArgs.operationIntent ? { operationIntent: baseArgs.operationIntent } : {}),
        emailOtpWorkerSessionHandle: baseArgs.emailOtpWorkerSessionHandle,
        walletKey: activation.walletKey,
        lanePolicy: activation.lanePolicy,
        publicCapability: activation.publicCapability,
        existingRoleLocalMaterial: activation.existingRoleLocalMaterial,
        emailOtpAuthContext,
        walletSessionRouteAuth: activation.walletSessionRouteAuth,
      }),
    );
  }
  if (isEmailOtpSessionAuthContext(emailOtpAuthContext)) {
    return await deps.provisionThresholdEcdsaSession(
      buildEmailOtpSessionBootstrapEcdsaActivation({
        source: baseArgs.source,
        relayerUrl: baseArgs.relayerUrl,
        sessionIdentity: baseArgs.sessionIdentity,
        sessionKind: baseArgs.sessionKind,
        sessionBudgetUses: baseArgs.sessionBudgetUses,
        runtimePolicy: baseArgs.runtimePolicy,
        ...(baseArgs.runtimeScopeBootstrap
          ? { runtimeScopeBootstrap: baseArgs.runtimeScopeBootstrap }
          : {}),
        ...(baseArgs.operationIntent ? { operationIntent: baseArgs.operationIntent } : {}),
        emailOtpWorkerSessionHandle: baseArgs.emailOtpWorkerSessionHandle,
        walletKey: activation.walletKey,
        lanePolicy: activation.lanePolicy,
        publicCapability: activation.publicCapability,
        existingRoleLocalMaterial: activation.existingRoleLocalMaterial,
        emailOtpAuthContext,
        walletSessionRouteAuth: activation.walletSessionRouteAuth,
      }),
    );
  }
  throw new Error('Email OTP ECDSA activation cannot use a consumed single-use context');
}

function requireActivationRelayerUrl(args: {
  plan: EcdsaSessionProvisionPlan;
  reconnectRecord: ThresholdEcdsaSessionRecord | null;
  secondaryRecord: ThresholdEcdsaSessionRecord | null;
}): string {
  const relayerUrl = String(
    args.reconnectRecord?.relayerUrl || args.secondaryRecord?.relayerUrl,
  ).trim();
  if (!relayerUrl) {
    throw new Error('[WarmSessionStore] ECDSA activation requires relayerUrl');
  }
  return relayerUrl;
}

// Reconnects serialize per exact material owner: the key is the material
// activation (plus flow kind and requested budget), never a session or grant
// id. The reusable authorization is the OUTPUT of a reconnect, so concurrent
// requests for the same material coalesce regardless of which authorization
// they would mint.
function buildEcdsaCapabilityInflightKey(args: {
  walletId: WalletId;
  chainTarget: ThresholdEcdsaChainTarget;
  planKind: EcdsaSessionProvisionPlan['kind'];
  usesNeeded?: number;
  sessionBudgetUses: number;
  record: ThresholdEcdsaSessionRecord | null;
}): string {
  const activationId = args.record
    ? String(args.record.materialActivation.activationId)
    : 'auto';
  const usesNeeded = Math.floor(Number(args.usesNeeded) || 0);
  const sessionBudgetUses = Math.floor(Number(args.sessionBudgetUses) || 0);
  return [
    String(args.walletId),
    thresholdEcdsaChainTargetKey(args.chainTarget),
    args.planKind,
    activationId,
    String(usesNeeded > 0 ? usesNeeded : 1),
    String(sessionBudgetUses > 0 ? sessionBudgetUses : 1),
  ].join('::');
}

export async function ensureWarmEcdsaCapabilityReady(
  deps: WarmSessionEcdsaReconnectDeps,
  args: EnsureWarmEcdsaProvisionPlanReadyArgs,
): Promise<EnsureWarmEcdsaCapabilityReadyResult> {
  const exactWalletId = args.walletId;
  const walletId = exactWalletId;
  const chainTarget = args.chainTarget;
  const chain = chainTarget.kind;
  const chainId = chainTarget.chainId;
  const warmSession = await deps.getWarmSession(exactWalletId);
  const plannedRecord = args.record;
  const reconnectPlan = ecdsaReconnectProvisionPlan(args.plan);
  if (reconnectPlan && !plannedRecord) {
    throw new Error('[WarmSessionStore] ECDSA reconnect readiness requires a session record');
  }
  if (
    reconnectPlan &&
    plannedRecord &&
    !thresholdEcdsaChainTargetsEqual(plannedRecord.chainTarget, chainTarget)
  ) {
    throw new Error(
      '[WarmSessionStore] ECDSA readiness record chain target does not match request',
    );
  }
  const recordCandidates: EcdsaRecordCandidate[] = [];
  const seenRecordCandidates = new Set<string>();
  for (const candidate of plannedRecord ? [{ source: args.source, record: plannedRecord }] : []) {
    const candidateKey = [
      candidate.source,
      String(candidate.record.materialActivation.activationId),
      String(resolveThresholdEcdsaKeyIdFromRecord({ record: candidate.record }) || '').trim(),
    ].join(':');
    if (seenRecordCandidates.has(candidateKey)) continue;
    seenRecordCandidates.add(candidateKey);
    recordCandidates.push(candidate);
  }
  const confirmedReconnectRequested =
    args.plan.kind === 'passkey_ecdsa_session_provision' ||
    args.plan.kind === 'email_otp_ecdsa_session_provision';
  let reconnectCandidateRecord: ThresholdEcdsaSessionRecord | null = null;
  let reconnectCandidateSource: ThresholdEcdsaSessionStoreSource | undefined;
  for (const candidate of recordCandidates) {
    const capability = getMatchingReadyEcdsaCapability({
      warmSession,
      chainTarget,
      record: candidate.record,
      usesNeeded: args.usesNeeded,
    });
    if (!capability || !hasEcdsaRecordSigningMaterial(candidate.record)) {
      if (!reconnectCandidateRecord) {
        reconnectCandidateRecord = candidate.record;
        reconnectCandidateSource = candidate.source;
      }
      continue;
    }
    if (
      reconnectPlan &&
      plannedRecord &&
      !mpcMaterialActivationRefsEqual(
        candidate.record.materialActivation,
        plannedRecord.materialActivation,
      )
    ) {
      reconnectCandidateRecord = candidate.record;
      reconnectCandidateSource = candidate.source;
      continue;
    }
    // A confirmed step-up must mint/refresh server budget even if local worker
    // material still looks ready; otherwise stale exhausted wallet budget wins.
    if (confirmedReconnectRequested) {
      reconnectCandidateRecord = candidate.record;
      reconnectCandidateSource = candidate.source;
      continue;
    }
    const readyRecord = capability.record;
    if (!readyRecord) continue;
    return {
      record: readyRecord,
      warmSession,
      capability,
      reconnected: false,
    };
  }
  if (!deps.canProvisionEcdsaCapability) {
    throw new Error(
      '[WarmSessionStore] provisionThresholdEcdsaSession is required to reconnect ECDSA capability',
    );
  }
  // The caller supplies the exact record whose material this reconnect
  // rehydrates; there is no re-read or source fallback.
  const reconnectRecord = plannedRecord;
  const secondaryRecord = args.source
    ? null
    : getPrimaryAndSecondaryEcdsaCapabilities({
        warmSession,
        chainTarget,
      }).secondary.record;
  const secondaryEmailOtpRecord = secondaryRecord?.source === 'email_otp' ? secondaryRecord : null;
  const inheritedEmailOtpRecord =
    reconnectRecord?.source === 'email_otp' ? reconnectRecord : secondaryEmailOtpRecord;

  const inflightKey = buildEcdsaCapabilityInflightKey({
    walletId,
    chainTarget,
    planKind: args.plan.kind,
    usesNeeded: args.usesNeeded,
    sessionBudgetUses: args.sessionBudgetUses,
    record: reconnectCandidateRecord || plannedRecord,
  });
  let reconnectPromise = deps.reconnectInFlightByCapability.get(inflightKey);
  if (!reconnectPromise) {
    reconnectPromise = (async (): Promise<EnsureWarmEcdsaCapabilityReadyResult> => {
      const effectivePlan =
        args.plan.kind === 'email_otp_ecdsa_session_provision' &&
        inheritedEmailOtpRecord?.emailOtpAuthContext
          ? {
              kind: 'email_otp_ecdsa_session_provision' as const,
              key: args.plan.key,
              chainTarget: args.plan.chainTarget,
              newSessionIdentity: args.plan.newSessionIdentity,
              signingKeyContext: args.plan.signingKeyContext,
              sessionKind: args.plan.sessionKind,
              sessionBudgetUses: args.plan.sessionBudgetUses,
              provisionSecretSource: buildEmailOtpEcdsaProvisionSecretSource({
                workerHandle: args.plan.provisionSecretSource.workerHandle,
                emailOtpAuthContext: inheritedEmailOtpRecord.emailOtpAuthContext,
              }),
              walletSessionRouteAuth: args.plan.walletSessionRouteAuth,
              ...(args.plan.runtimePolicyScope
                ? { runtimePolicyScope: args.plan.runtimePolicyScope }
                : {}),
            }
          : args.plan;
      const activationSource = inheritedEmailOtpRecord
        ? 'email_otp'
        : reconnectCandidateSource || args.source || 'login';
      const activationPolicy = buildEcdsaActivationPolicy(
        'runtimePolicyScope' in effectivePlan ? effectivePlan.runtimePolicyScope : undefined,
      );
      const activationOptions = buildActivationOptions(args);
      const relayerUrl = requireActivationRelayerUrl({
        plan: effectivePlan,
        reconnectRecord,
        secondaryRecord: secondaryRecord || reconnectCandidateRecord || plannedRecord,
      });
      const activationIdentityPair = buildActivationKeyAndLanePolicy({
        record:
          reconnectRecord ||
          inheritedEmailOtpRecord ||
          secondaryRecord ||
          reconnectCandidateRecord ||
          plannedRecord,
        plan: effectivePlan,
        runtimePolicy: activationPolicy,
      });
      const activation =
        effectivePlan.kind === 'passkey_ecdsa_session_provision'
          ? buildPasskeyEcdsaActivation({
              walletId,
              relayerUrl,
              source: activationSource,
              runtimePolicy: activationPolicy,
              options: activationOptions,
              plan: effectivePlan,
              identityPair: activationIdentityPair,
            })
          : effectivePlan.kind === 'email_otp_ecdsa_session_provision'
            ? buildEmailOtpEcdsaActivation({
                walletId,
                relayerUrl,
                source: activationSource,
                runtimePolicy: activationPolicy,
                options: activationOptions,
                plan: effectivePlan,
                identityPair: activationIdentityPair,
              })
            : effectivePlan.kind === 'wallet_session_ecdsa_reconnect'
              ? buildWalletSessionEcdsaActivation({
                  walletId,
                  relayerUrl,
                  source: activationSource,
                  runtimePolicy: activationPolicy,
                  options: activationOptions,
                  plan: effectivePlan,
                  identityPair: activationIdentityPair,
                })
              : (() => {
                  effectivePlan satisfies never;
                  throw new Error('[SigningEngine][ecdsa] unsupported ECDSA provision plan');
                })();
      const provisioned = await provisionEcdsaActivation(deps, activation);
      args.assertNotCancelled?.();

      const refreshedKeyRef = provisioned.thresholdEcdsaKeyRef;
      const refreshedWarmSession = await deps.getWarmSession(exactWalletId);
      const refreshedPrimary = getPrimaryAndSecondaryEcdsaCapabilities({
        warmSession: refreshedWarmSession,
        chainTarget,
      }).primary;
      const readyRefreshedRecord =
        refreshedPrimary.state === 'ready' &&
        refreshedPrimary.record &&
        thresholdEcdsaChainTargetsEqual(refreshedPrimary.record.chainTarget, chainTarget) &&
        hasSufficientWarmClaim(refreshedPrimary.prfClaim, args.usesNeeded)
          ? refreshedPrimary.record
          : null;
      if (!refreshedKeyRef || !readyRefreshedRecord) {
        throw new Error(
          '[WarmSessionStore] threshold ECDSA warm capability is not ready after reconnect',
        );
      }
      // This path only ever rehydrates existing role-local material and mints
      // a fresh authorization for it. Rehydration preserves the exact material
      // activation; a changed activation would be a re-activation, which only
      // registration or explicit re-activation may perform.
      const activationRecord =
        reconnectRecord ||
        inheritedEmailOtpRecord ||
        secondaryRecord ||
        reconnectCandidateRecord ||
        plannedRecord;
      if (
        activationRecord &&
        !mpcMaterialActivationRefsEqual(
          readyRefreshedRecord.materialActivation,
          activationRecord.materialActivation,
        )
      ) {
        throw new Error(
          '[WarmSessionStore] ECDSA reconnect changed the material activation; rehydration must preserve it',
        );
      }
      const refreshedCapability = refreshedPrimary;

      emitWarmSessionTransition({
        onTransition: deps.onTransition,
        event: {
          type: 'ecdsa_capability_reconnected',
          walletId,
          chainTarget,
          thresholdSessionId: readyRefreshedRecord.thresholdSessionId,
          before: summarizeWarmSessionTransition(warmSession),
          after: summarizeWarmSessionTransition(refreshedWarmSession),
        },
      });

      return {
        record: readyRefreshedRecord,
        warmSession: refreshedWarmSession,
        capability: refreshedCapability,
        reconnected: true,
      };
    })();
    deps.reconnectInFlightByCapability.set(inflightKey, reconnectPromise);
    void reconnectPromise.then(
      () => {
        if (deps.reconnectInFlightByCapability.get(inflightKey) === reconnectPromise) {
          deps.reconnectInFlightByCapability.delete(inflightKey);
        }
      },
      () => {
        if (deps.reconnectInFlightByCapability.get(inflightKey) === reconnectPromise) {
          deps.reconnectInFlightByCapability.delete(inflightKey);
        }
      },
    );
  }

  const reconnectedCapability = await reconnectPromise;
  args.assertNotCancelled?.();
  return reconnectedCapability;
}
export function getMatchingReadyEcdsaCapability(args: {
  warmSession: WarmSessionEnvelope;
  chainTarget: ThresholdEcdsaChainTarget;
  record: ThresholdEcdsaSessionRecord | null;
  usesNeeded?: number;
}): WarmSessionEcdsaCapabilityState | null {
  const chain = args.chainTarget.kind;
  const capability = args.warmSession.capabilities.ecdsa[chain];
  if (!args.record || capability.state !== 'ready' || !capability.record) return null;

  // Exact material identity: the activation reference alone names the
  // material instance; session and grant identifiers do not participate.
  if (
    !mpcMaterialActivationRefsEqual(
      capability.record.materialActivation,
      args.record.materialActivation,
    )
  ) {
    return null;
  }

  if (!hasSufficientWarmClaim(capability.prfClaim, args.usesNeeded)) {
    return null;
  }

  return capability;
}

export function normalizeParticipantIds(participantIds: unknown): number[] | undefined {
  if (!Array.isArray(participantIds)) return undefined;
  const normalized = participantIds
    .map((value) => Number(value))
    .filter((value) => Number.isFinite(value));
  return normalized.length ? normalized : undefined;
}

export function toOptionalNonEmptyString(value: unknown): string | undefined {
  const normalized = String(value || '').trim();
  return normalized || undefined;
}

export function getPrimaryAndSecondaryEcdsaCapabilities(args: {
  warmSession: WarmSessionEnvelope;
  chainTarget: ThresholdEcdsaChainTarget;
}): {
  primary: WarmSessionEcdsaCapabilityState;
  secondary: WarmSessionEcdsaCapabilityState;
} {
  const chain = args.chainTarget.kind;
  return {
    primary: args.warmSession.capabilities.ecdsa[chain],
    secondary:
      chain === 'tempo'
        ? args.warmSession.capabilities.ecdsa.evm
        : args.warmSession.capabilities.ecdsa.tempo,
  };
}
