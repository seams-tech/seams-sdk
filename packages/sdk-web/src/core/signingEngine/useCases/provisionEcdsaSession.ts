import { toAccountId, type AccountId } from '@/core/types/accountIds';
import { thresholdEcdsaRecordHasRoleLocalSigningMaterial } from '../session/persistence/ecdsaRoleLocalRecords';
import {
  thresholdEcdsaRecordRpId,
  type ThresholdEcdsaSessionRecord,
} from '../session/persistence/records';
import type {
  ThresholdEcdsaEmailOtpAuthContext,
  ThresholdEcdsaSessionStoreSource,
} from '../session/identity/laneIdentity';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../interfaces/signing';
import type { ThresholdEcdsaSessionBootstrapResult } from '../threshold/ecdsa/activation';
import {
  DEFAULT_THRESHOLD_SESSION_POLICY,
  type ThresholdRuntimePolicyScope,
} from '../threshold/sessionPolicy';
import type { SigningOperationIntent } from '../session/operationState/types';
import {
  ecdsaPostSignPolicySessionFromRecord,
  formatEmailOtpSensitiveOperationError,
} from '../session/operationState/postSignPolicy';
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
  buildEcdsaSessionIdentity,
  ecdsaSessionIdentitiesEqual,
  ecdsaSessionIdentityMatches,
  type EcdsaSessionIdentity,
  getEcdsaSessionProvisionIdentity,
  tryBuildEcdsaSessionIdentity,
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
import { buildThresholdEcdsaSecp256k1KeyRefFromRecord } from '../session/identity/thresholdEcdsaSignerAdapter';

export type WarmSessionEcdsaProvisionerDeps = {
  getWarmSession: (walletId: WalletId) => Promise<WarmSessionEnvelope>;
  listThresholdEcdsaRecordsForWalletTarget: (args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    source?: ThresholdEcdsaSessionStoreSource;
  }) => EcdsaRecordCandidate[];
};

export type WarmSessionEcdsaReconnectDeps = {
  getWarmSession: (walletId: WalletId) => Promise<WarmSessionEnvelope>;
  listThresholdEcdsaRecordsForWalletTarget: (args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    source?: ThresholdEcdsaSessionStoreSource;
  }) => EcdsaRecordCandidate[];
  canProvisionEcdsaCapability: boolean;
  provisionThresholdEcdsaSession: (
    args: ThresholdEcdsaActivationRequest,
  ) => Promise<ThresholdEcdsaSessionBootstrapResult>;
  touchConfirm: PasskeyWarmSessionRecoveryPorts;
  resolveExactEcdsaRecord: (args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    thresholdSessionId: string;
    source?: ThresholdEcdsaSessionStoreSource;
  }) => ThresholdEcdsaSessionRecord | null;
  readEcdsaCapabilityByThresholdSessionId: (
    thresholdSessionId: string,
  ) => Promise<WarmSessionEcdsaCapabilityState | null>;
  reconnectInFlightByCapability: Map<string, Promise<EnsureWarmEcdsaCapabilityReadyResult>>;
  onTransition?: (event: WarmSessionTransitionEvent) => void | Promise<void>;
};

type EcdsaProvisionActivationCommon = {
  walletId: AccountId;
  relayerUrl: string;
  source: ThresholdEcdsaSessionStoreSource;
  walletKey: EvmFamilyEcdsaWalletKey;
  lanePolicy: EvmFamilyEcdsaSessionLanePolicy;
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
};

function assertPersistedEcdsaWarmSessionRecord(args: {
  walletId: AccountId;
  expectedSessionId: string;
  persistedSessionIdRaw: unknown;
  fallbackPersistedSessionIdRaw?: unknown;
}): void {
  const persistedSessionId = String(args.persistedSessionIdRaw || '').trim();
  if (persistedSessionId === args.expectedSessionId) {
    return;
  }
  const fallbackPersistedSessionId = String(args.fallbackPersistedSessionIdRaw || '').trim();
  throw new Error(
    `[WarmSessionStore] provisioned ECDSA capability was not persisted for ${args.walletId} (expected sessionId=${args.expectedSessionId}, found=${persistedSessionId || fallbackPersistedSessionId || 'missing'})`,
  );
}

type EcdsaRecordCandidate = {
  source: ThresholdEcdsaSessionStoreSource;
  record: ThresholdEcdsaSessionRecord;
};

function hasEcdsaRecordSigningMaterial(record: ThresholdEcdsaSessionRecord): boolean {
  return thresholdEcdsaRecordHasRoleLocalSigningMaterial(record);
}

function readEcdsaRecordCandidates(
  deps: Pick<WarmSessionEcdsaProvisionerDeps, 'listThresholdEcdsaRecordsForWalletTarget'>,
  args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    source?: ThresholdEcdsaSessionStoreSource;
  },
): EcdsaRecordCandidate[] {
  const candidates: EcdsaRecordCandidate[] = [];
  const seen = new Set<string>();
  let listed: EcdsaRecordCandidate[] = [];
  try {
    listed = deps.listThresholdEcdsaRecordsForWalletTarget({
      walletId: args.walletId,
      chainTarget: args.chainTarget,
      ...(args.source ? { source: args.source } : {}),
    });
  } catch {
    return [];
  }
  for (const candidate of listed) {
    const source = candidate.source;
    const record = candidate.record;
    if (args.source && source !== args.source) continue;
    try {
      const identity = buildEcdsaSessionIdentity(record);
      const key = [
        source,
        identity.thresholdSessionId,
        resolveThresholdEcdsaKeyIdFromRecord({ record }),
      ].join(':');
      if (seen.has(key)) continue;
      seen.add(key);
      candidates.push({ source, record });
    } catch {}
  }
  return candidates;
}

function recordMatchesPlannedIdentity(args: {
  record: ThresholdEcdsaSessionRecord;
  plan: EcdsaSessionProvisionPlan;
}): boolean {
  const identity = getEcdsaSessionProvisionIdentity(args.plan);
  return ecdsaSessionIdentityMatches(identity, args.record);
}

function provisionPlanRequiresExistingRecordIdentity(plan: EcdsaSessionProvisionPlan): boolean {
  switch (plan.kind) {
    case 'wallet_session_ecdsa_reconnect':
    case 'passkey_ecdsa_session_provision':
      return true;
    case 'email_otp_ecdsa_session_provision':
      return false;
  }
  plan satisfies never;
  return false;
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
    const sessionIdentity = getEcdsaSessionProvisionIdentity(args.plan);
    console.warn('[WarmSessionStore] missing ECDSA activation record', {
      planKind: args.plan.kind,
      chainTarget: args.plan.chainTarget,
      thresholdSessionId: sessionIdentity.thresholdSessionId,
      walletSigningSessionId: sessionIdentity.walletSigningSessionId,
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
    rpId: thresholdEcdsaRecordRpId(args.record),
    ecdsaThresholdKeyId: planKeyId,
    signingRootId: planSigningRootId,
    signingRootVersion: planSigningRootVersion,
    participantIds: planParticipantIds,
    thresholdOwnerAddress: args.record.ethereumAddress,
  });
  const sessionIdentity = getEcdsaSessionProvisionIdentity(args.plan);
  const runtimePolicyScope = runtimePolicyScopeFromActivationPolicy(args.runtimePolicy);
  return {
    walletKey: buildEvmFamilyEcdsaWalletKey({
      walletId: key.walletId,
      rpId: key.rpId,
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
      walletSigningSessionId: sessionIdentity.walletSigningSessionId,
      thresholdSessionKind: args.plan.sessionKind,
      ttlMs: DEFAULT_THRESHOLD_SESSION_POLICY.ttlMs,
      remainingUses: args.plan.sessionBudgetUses,
      ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    }),
  };
}

function buildPasskeyEcdsaActivation(args: {
  walletId: AccountId;
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
    sessionIdentity: args.plan.newSessionIdentity,
    sessionKind: args.plan.sessionKind,
    sessionBudgetUses: args.plan.sessionBudgetUses,
    runtimePolicy: args.runtimePolicy,
    passkeyPrfFirstB64u: args.plan.provisionSecretSource.passkeyPrfFirstB64u,
    webauthnAuthentication: args.plan.provisionSecretSource.webauthnAuthentication,
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
  walletId: AccountId;
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
    sessionIdentity: args.plan.newSessionIdentity,
    sessionKind: args.plan.sessionKind,
    sessionBudgetUses: args.plan.sessionBudgetUses,
    runtimePolicy: args.runtimePolicy,
    emailOtpWorkerSessionHandle: args.plan.provisionSecretSource.workerHandle,
    emailOtpAuthContext: args.plan.provisionSecretSource.emailOtpAuthContext,
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
  walletId: AccountId;
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
      walletKey: activation.walletKey,
      lanePolicy: activation.lanePolicy,
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
    walletSigningSessionId: plan.existingSessionIdentity.walletSigningSessionId,
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
  if (plan.provisionSecretSource.emailOtpAuthContext.retention === 'single_use') {
    const emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext & {
      retention: 'single_use';
    } = {
      policy: plan.provisionSecretSource.emailOtpAuthContext.policy,
      retention: 'single_use',
      reason: plan.provisionSecretSource.emailOtpAuthContext.reason,
      authMethod: 'email_otp',
      ...(plan.provisionSecretSource.emailOtpAuthContext.authSubjectId
        ? { authSubjectId: plan.provisionSecretSource.emailOtpAuthContext.authSubjectId }
        : {}),
      ...(typeof plan.provisionSecretSource.emailOtpAuthContext.consumedAtMs === 'number'
        ? { consumedAtMs: plan.provisionSecretSource.emailOtpAuthContext.consumedAtMs }
        : {}),
    };
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
        emailOtpAuthContext,
      }),
    );
  }
  const emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext & {
    retention: 'session';
  } = {
    policy: plan.provisionSecretSource.emailOtpAuthContext.policy,
    retention: 'session',
    reason: plan.provisionSecretSource.emailOtpAuthContext.reason,
    authMethod: 'email_otp',
    ...(plan.provisionSecretSource.emailOtpAuthContext.authSubjectId
      ? { authSubjectId: plan.provisionSecretSource.emailOtpAuthContext.authSubjectId }
      : {}),
    ...(typeof plan.provisionSecretSource.emailOtpAuthContext.consumedAtMs === 'number'
      ? { consumedAtMs: plan.provisionSecretSource.emailOtpAuthContext.consumedAtMs }
      : {}),
  };
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
      emailOtpAuthContext,
    }),
  );
}

export async function tryReuseReadyWarmEcdsaBootstrap(
  deps: WarmSessionEcdsaProvisionerDeps,
  args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    source?: ThresholdEcdsaSessionStoreSource;
  },
): Promise<ThresholdEcdsaSessionBootstrapResult | null> {
  const exactWalletId = args.walletId;
  const walletId = toAccountId(exactWalletId);
  const recordCandidates = readEcdsaRecordCandidates(deps, {
    walletId: exactWalletId,
    chainTarget: args.chainTarget,
    ...(args.source ? { source: args.source } : {}),
  });
  if (!recordCandidates.length) return null;
  const warmSession = await deps.getWarmSession(exactWalletId);
  for (const candidate of recordCandidates) {
    if (!hasEcdsaRecordSigningMaterial(candidate.record)) {
      continue;
    }
    const capability = getMatchingReadyEcdsaCapability({
      warmSession,
      chainTarget: args.chainTarget,
      record: candidate.record,
      usesNeeded: 1,
    });
    if (!capability) continue;
    const reusableBootstrap = buildReusableEcdsaBootstrapResult({
      record: candidate.record,
      capability,
      source: candidate.source,
    });
    if (reusableBootstrap) return reusableBootstrap;
  }
  return null;
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

function buildEcdsaCapabilityInflightKey(args: {
  walletId: AccountId;
  chainTarget: ThresholdEcdsaChainTarget;
  usesNeeded?: number;
  sessionBudgetUses: number;
  record: ThresholdEcdsaSessionRecord | null;
}): string {
  const keyId = args.record
    ? String(resolveThresholdEcdsaKeyIdFromRecord({ record: args.record }) || '').trim() || 'auto'
    : 'auto';
  const sessionIdentity = args.record ? tryBuildEcdsaSessionIdentity(args.record) : null;
  const usesNeeded = Math.floor(Number(args.usesNeeded) || 0);
  const sessionBudgetUses = Math.floor(Number(args.sessionBudgetUses) || 0);
  return [
    String(args.walletId),
    thresholdEcdsaChainTargetKey(args.chainTarget),
    String(usesNeeded > 0 ? usesNeeded : 1),
    String(sessionBudgetUses > 0 ? sessionBudgetUses : 1),
    keyId,
    sessionIdentity?.thresholdSessionId || 'auto',
  ].join('::');
}

function resolveExactEcdsaRecordWithSourceFallback(
  deps: Pick<WarmSessionEcdsaReconnectDeps, 'resolveExactEcdsaRecord'>,
  args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    thresholdSessionId: string;
    source?: ThresholdEcdsaSessionStoreSource;
  },
): ThresholdEcdsaSessionRecord | null {
  if (args.source) {
    const sourcedRecord = deps.resolveExactEcdsaRecord({
      walletId: args.walletId,
      chainTarget: args.chainTarget,
      thresholdSessionId: args.thresholdSessionId,
      source: args.source,
    });
    if (sourcedRecord) return sourcedRecord;
  }
  return deps.resolveExactEcdsaRecord({
    walletId: args.walletId,
    chainTarget: args.chainTarget,
    thresholdSessionId: args.thresholdSessionId,
  });
}

export async function ensureWarmEcdsaCapabilityReady(
  deps: WarmSessionEcdsaReconnectDeps,
  args: EnsureWarmEcdsaProvisionPlanReadyArgs,
): Promise<EnsureWarmEcdsaCapabilityReadyResult> {
  const exactWalletId = args.walletId;
  const walletId = toAccountId(exactWalletId);
  const chainTarget = args.chainTarget;
  const chain = chainTarget.kind;
  const chainId = chainTarget.chainId;
  const warmSession = await deps.getWarmSession(exactWalletId);
  const plannedRecord = args.record;
  const planRequiresExistingRecord = provisionPlanRequiresExistingRecordIdentity(args.plan);
  if (planRequiresExistingRecord && !plannedRecord) {
    throw new Error('[WarmSessionStore] ECDSA reconnect readiness requires a session record');
  }
  if (
    planRequiresExistingRecord &&
    plannedRecord &&
    !thresholdEcdsaChainTargetsEqual(plannedRecord.chainTarget, chainTarget)
  ) {
    throw new Error(
      '[WarmSessionStore] ECDSA readiness record chain target does not match request',
    );
  }
  const plannedIdentity = getEcdsaSessionProvisionIdentity(args.plan);
  const plannedRecordIdentity = plannedRecord
    ? buildEcdsaSessionIdentity({
        thresholdSessionId: plannedRecord.thresholdSessionId,
        walletSigningSessionId: plannedRecord.walletSigningSessionId,
      })
    : null;
  if (
    planRequiresExistingRecord &&
    (!plannedRecordIdentity || !ecdsaSessionIdentitiesEqual(plannedRecordIdentity, plannedIdentity))
  ) {
    throw new Error('[WarmSessionStore] ECDSA readiness record identity does not match plan');
  }
  const recordCandidates: EcdsaRecordCandidate[] = [];
  const seenRecordCandidates = new Set<string>();
  for (const candidate of [
    ...(plannedRecord ? [{ source: args.source, record: plannedRecord }] : []),
    ...readEcdsaRecordCandidates(deps, {
      walletId: exactWalletId,
      chainTarget,
      source: args.source,
    }),
  ]) {
    const candidateIdentity = tryBuildEcdsaSessionIdentity(candidate.record);
    const candidateKey = [
      candidate.source,
      candidateIdentity?.walletSigningSessionId || '',
      candidateIdentity?.thresholdSessionId || '',
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
    if (!recordMatchesPlannedIdentity({ record: candidate.record, plan: args.plan })) {
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
  if (!reconnectCandidateRecord && recordCandidates[0]) {
    reconnectCandidateRecord = recordCandidates[0].record;
    reconnectCandidateSource = recordCandidates[0].source;
  }

  for (const candidate of recordCandidates) {
    const candidateIdentity = tryBuildEcdsaSessionIdentity(candidate.record);
    if (!candidateIdentity) continue;
    const directCapability = await deps.readEcdsaCapabilityByThresholdSessionId(
      candidateIdentity.thresholdSessionId,
    );
    if (
      directCapability?.record?.chainTarget &&
      thresholdEcdsaChainTargetsEqual(directCapability.record.chainTarget, chainTarget) &&
      directCapability.state === 'ready' &&
      hasSufficientWarmClaim(directCapability.prfClaim, args.usesNeeded)
    ) {
      if (hasEcdsaRecordSigningMaterial(candidate.record)) {
        if (!recordMatchesPlannedIdentity({ record: candidate.record, plan: args.plan })) {
          reconnectCandidateRecord = candidate.record;
          reconnectCandidateSource = candidate.source;
          continue;
        }
        if (confirmedReconnectRequested) {
          reconnectCandidateRecord = candidate.record;
          reconnectCandidateSource = candidate.source;
          continue;
        }
        const readyRecord = directCapability.record;
        if (!readyRecord) continue;
        return {
          record: readyRecord,
          warmSession,
          capability: directCapability,
          reconnected: false,
        };
      }
      if (!reconnectCandidateRecord) {
        reconnectCandidateRecord = candidate.record;
        reconnectCandidateSource = candidate.source;
      }
    }
  }

  if (!deps.canProvisionEcdsaCapability) {
    throw new Error(
      '[WarmSessionStore] provisionThresholdEcdsaSession is required to reconnect ECDSA capability',
    );
  }
  const reconnectRecord =
    resolveExactEcdsaRecordWithSourceFallback(deps, {
      walletId: exactWalletId,
      chainTarget,
      thresholdSessionId: plannedIdentity.thresholdSessionId,
      ...(args.source ? { source: args.source } : {}),
    }) || plannedRecord;
  const secondaryRecord = args.source
    ? null
    : getPrimaryAndSecondaryEcdsaCapabilities({
        warmSession,
        chainTarget,
      }).secondary.record;
  const secondaryEmailOtpRecord = secondaryRecord?.source === 'email_otp' ? secondaryRecord : null;
  const reconnectPolicySession = reconnectRecord
    ? ecdsaPostSignPolicySessionFromRecord(reconnectRecord)
    : null;
  const secondaryEmailOtpPolicySession = secondaryEmailOtpRecord
    ? ecdsaPostSignPolicySessionFromRecord(secondaryEmailOtpRecord)
    : null;
  if (
    reconnectPolicySession?.source === 'email_otp' &&
    reconnectPolicySession.emailOtpRetention === 'single_use'
  ) {
    throw formatEmailOtpSensitiveOperationError({
      operationLabel: `${chain} signing`,
      mode: 'per_operation',
    });
  }
  if (
    !reconnectRecord &&
    secondaryEmailOtpPolicySession?.emailOtpRetention === 'single_use' &&
    Number(secondaryEmailOtpPolicySession.emailOtpConsumedAtMs) > 0
  ) {
    throw formatEmailOtpSensitiveOperationError({
      operationLabel: `${chain} signing`,
      mode: 'per_operation',
    });
  }
  const inheritedEmailOtpRecord =
    reconnectRecord?.source === 'email_otp' ? reconnectRecord : secondaryEmailOtpRecord;

  const inflightKey = buildEcdsaCapabilityInflightKey({
    walletId,
    chainTarget,
    usesNeeded: args.usesNeeded,
    sessionBudgetUses: args.sessionBudgetUses,
    record: reconnectCandidateRecord,
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
      const refreshedIdentity = refreshedKeyRef
        ? tryBuildEcdsaSessionIdentity(refreshedKeyRef)
        : null;
      const refreshedRecord = refreshedIdentity
        ? resolveExactEcdsaRecordWithSourceFallback(deps, {
            walletId: exactWalletId,
            chainTarget,
            thresholdSessionId: refreshedIdentity.thresholdSessionId,
            ...(activationSource ? { source: activationSource } : {}),
          })
        : null;
      let refreshedCapability = getMatchingReadyEcdsaCapability({
        warmSession: refreshedWarmSession,
        chainTarget,
        record: refreshedRecord,
        usesNeeded: args.usesNeeded,
      });
      if (!refreshedCapability && refreshedIdentity) {
        const directCapability = await deps.readEcdsaCapabilityByThresholdSessionId(
          refreshedIdentity.thresholdSessionId,
        );
        if (
          directCapability?.record?.chainTarget &&
          thresholdEcdsaChainTargetsEqual(directCapability.record.chainTarget, chainTarget) &&
          directCapability.state === 'ready' &&
          hasSufficientWarmClaim(directCapability.prfClaim, args.usesNeeded)
        ) {
          refreshedCapability = directCapability;
        }
      }
      if (!refreshedKeyRef || !refreshedIdentity || !refreshedCapability) {
        throw new Error(
          '[WarmSessionStore] threshold ECDSA warm capability is not ready after reconnect',
        );
      }
      const readyRefreshedRecord = refreshedCapability.record;
      if (!readyRefreshedRecord) {
        throw new Error(
          '[WarmSessionStore] threshold ECDSA warm capability record is missing after reconnect',
        );
      }

      emitWarmSessionTransition({
        onTransition: deps.onTransition,
        event: {
          type: 'ecdsa_capability_reconnected',
          walletId,
          chainTarget,
          thresholdSessionId: refreshedIdentity.thresholdSessionId,
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
  if (!args.record || capability.state !== 'ready') return null;

  const recordIdentity = capability.record ? tryBuildEcdsaSessionIdentity(capability.record) : null;
  const candidateIdentity = tryBuildEcdsaSessionIdentity(args.record);
  if (
    !recordIdentity ||
    !candidateIdentity ||
    !ecdsaSessionIdentitiesEqual(recordIdentity, candidateIdentity)
  ) {
    return null;
  }

  const recordThresholdKeyId = String(
    capability.record
      ? resolveThresholdEcdsaKeyIdFromRecord({
          record: capability.record,
        })
      : '',
  ).trim();
  const candidateThresholdKeyId = String(
    resolveThresholdEcdsaKeyIdFromRecord({ record: args.record }),
  ).trim();
  if (
    !recordThresholdKeyId ||
    (candidateThresholdKeyId && recordThresholdKeyId !== candidateThresholdKeyId)
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

export function getEcdsaCapabilityCandidates(args: {
  warmSession: WarmSessionEnvelope;
  chainTarget: ThresholdEcdsaChainTarget;
}): WarmSessionEcdsaCapabilityState[] {
  const chain = args.chainTarget.kind;
  const primary = args.warmSession.capabilities.ecdsa[chain];
  const secondary =
    chain === 'tempo'
      ? args.warmSession.capabilities.ecdsa.evm
      : args.warmSession.capabilities.ecdsa.tempo;
  return primary === secondary ? [primary] : [primary, secondary];
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

export function buildReusableEcdsaBootstrapResult(args: {
  record: ThresholdEcdsaSessionRecord;
  capability: WarmSessionEcdsaCapabilityState;
  source: 'login' | 'registration' | 'manual-bootstrap' | 'email_otp';
}): ThresholdEcdsaSessionBootstrapResult | null {
  const record = args.capability.record;
  const auth = args.capability.auth;
  const prfClaim = args.capability.prfClaim;
  if (!record || !auth || !prfClaim || prfClaim.state !== 'warm') return null;

  const clientVerifyingShareB64u = String(record.clientVerifyingShareB64u || '').trim();
  const relayerKeyId = String(record.relayerKeyId || '').trim();
  const identity = tryBuildEcdsaSessionIdentity(record);
  // A warm ECDSA capability is only directly reusable when the persisted
  // session record already carries local signing material. Restored passkey
  // lanes often have only the PRF/JWT until reconnect recreates the additive
  // share.
  if (!clientVerifyingShareB64u || !relayerKeyId || !identity) {
    return null;
  }
  if (!thresholdEcdsaRecordHasRoleLocalSigningMaterial(record)) {
    return null;
  }
  const ecdsaThresholdKeyId = String(resolveThresholdEcdsaKeyIdFromRecord({ record }) || '').trim();
  if (!ecdsaThresholdKeyId) {
    return null;
  }
  const keyRef = buildThresholdEcdsaSecp256k1KeyRefFromRecord({ record });

  return {
    thresholdEcdsaKeyRef: {
      ...keyRef,
      relayerUrl: String(record.relayerUrl || keyRef.relayerUrl || '').trim(),
      ecdsaThresholdKeyId,
      participantIds: record.participantIds,
      thresholdSessionKind: record.thresholdSessionKind,
      thresholdSessionId: identity.thresholdSessionId,
      walletSigningSessionId: identity.walletSigningSessionId,
      walletSessionJwt: String(auth.walletSessionJwt || keyRef.walletSessionJwt || '').trim(),
    },
    keygen: {
      ok: true,
      ecdsaThresholdKeyId,
      relayerKeyId,
      clientVerifyingShareB64u,
      participantIds: record.participantIds,
      thresholdEcdsaPublicKeyB64u: record.thresholdEcdsaPublicKeyB64u,
      ethereumAddress: record.ethereumAddress,
      relayerVerifyingShareB64u: record.relayerVerifyingShareB64u,
      chainId: record.chainTarget.chainId,
    },
    session: {
      ok: true,
      sessionId: identity.thresholdSessionId,
      walletSigningSessionId: identity.walletSigningSessionId,
      ...(String(auth.walletSessionJwt || '').trim()
        ? { jwt: String(auth.walletSessionJwt || '').trim() }
        : {}),
      expiresAtMs: Math.max(0, Math.floor(Number(prfClaim.expiresAtMs) || 0)),
      remainingUses: Math.max(0, Math.floor(Number(prfClaim.remainingUses) || 0)),
      clientVerifyingShareB64u,
    },
  };
}
