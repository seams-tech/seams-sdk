import { toAccountId, type AccountId } from '@/core/types/accountIds';
import {
  thresholdEcdsaRecordRpId,
  type ThresholdEcdsaSessionRecord,
} from '../persistence/records';
import type {
  ThresholdEcdsaEmailOtpAuthContext,
  ThresholdEcdsaSessionStoreSource,
} from '../identity/laneIdentity';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import {
  DEFAULT_THRESHOLD_SESSION_POLICY,
  type ThresholdRuntimePolicyScope,
} from '../../threshold/sessionPolicy';
import type { SigningOperationIntent } from '../operationState/types';
import {
  ecdsaPostSignPolicySessionFromRecord,
  formatEmailOtpSensitiveOperationError,
} from '../operationState/postSignPolicy';
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
} from '../warmCapabilities/transitions';
import {
  buildEcdsaSessionIdentity,
  ecdsaSessionIdentitiesEqual,
  ecdsaSessionIdentityMatches,
  type EcdsaSessionIdentity,
  getEcdsaSessionProvisionIdentity,
  tryBuildEcdsaSessionIdentity,
  type EcdsaSessionProvisionPlan,
} from '../warmCapabilities/ecdsaProvisionPlan';
import { hasSufficientWarmClaim } from '../warmCapabilities/readModel';
import type {
  WarmSessionEcdsaCapabilityState,
  WarmSessionEnvelope,
} from '../warmCapabilities/types';
import type {
  EnsureWarmEcdsaProvisionPlanReadyArgs,
  EnsureWarmEcdsaCapabilityReadyResult,
} from '../warmCapabilities/types';
import type {
  ThresholdEcdsaActivationPolicy,
  ThresholdEcdsaActivationRequest,
  ThresholdEcdsaActivationRuntimeScopeBootstrap,
} from './ecdsaSessionProvision';
import {
  buildCookieReconnectEcdsaActivation,
  buildEmailOtpPerOperationReauthEcdsaActivation,
  buildEmailOtpSessionBootstrapEcdsaActivation,
  buildPasskeyReconnectEcdsaActivation,
  buildThresholdSessionReconnectEcdsaActivation,
} from './ecdsaSessionProvision';
import { claimPasskeyEcdsaPrfFirst } from './ecdsaRecovery';
import type { PasskeyWarmSessionRecoveryPorts } from './prfClaim';
import {
  buildBaseEvmFamilyEcdsaKeyIdentity,
  buildEvmFamilyEcdsaSessionLanePolicy,
  resolveThresholdEcdsaKeyIdFromKeyRef,
  resolveThresholdEcdsaKeyIdFromRecord,
  resolveThresholdSigningRootBindingFromRecord,
  toEvmFamilyEcdsaKeyHandle,
  type EvmFamilyEcdsaKeyHandle,
  type EvmFamilyEcdsaKeyIdentity,
  type EvmFamilyEcdsaSessionLanePolicy,
} from '../identity/evmFamilyEcdsaIdentity';

export type WarmSessionEcdsaProvisionerDeps = {
  getWarmSession: (walletId: WalletId) => Promise<WarmSessionEnvelope>;
  listThresholdEcdsaKeyRefsForWalletTarget?: (args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    source?: ThresholdEcdsaSessionStoreSource;
  }) => EcdsaKeyRefCandidate[];
};

export type WarmSessionEcdsaReconnectDeps = {
  getWarmSession: (walletId: WalletId) => Promise<WarmSessionEnvelope>;
  listThresholdEcdsaKeyRefsForWalletTarget?: (args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    source?: ThresholdEcdsaSessionStoreSource;
  }) => EcdsaKeyRefCandidate[];
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
  keyHandle: EvmFamilyEcdsaKeyHandle;
  key: EvmFamilyEcdsaKeyIdentity;
  lanePolicy: EvmFamilyEcdsaSessionLanePolicy;
  sessionIdentity: EcdsaSessionIdentity;
  sessionKind: 'cookie' | 'jwt';
  sessionBudgetUses: number;
  runtimePolicy: ThresholdEcdsaActivationPolicy;
  runtimeScopeBootstrap?: ThresholdEcdsaActivationRuntimeScopeBootstrap;
  operationIntent?: SigningOperationIntent;
  beforeProvision?: () => void | Promise<void>;
  assertNotCancelled?: () => void;
};

type PasskeyEcdsaActivation = EcdsaProvisionActivationCommon & {
  kind: 'passkey_ecdsa_activation';
  clientRootShare32B64u: string;
  webauthnAuthentication: Extract<
    EcdsaSessionProvisionPlan,
    { kind: 'passkey_ecdsa_session_provision' }
  >['webauthnAuthentication'];
  plan: Extract<EcdsaSessionProvisionPlan, { kind: 'passkey_ecdsa_session_provision' }>;
};

type EmailOtpEcdsaActivation = EcdsaProvisionActivationCommon & {
  kind: 'email_otp_ecdsa_activation';
  clientRootShare32B64u: string;
  emailOtpAuthContext: Extract<
    EcdsaSessionProvisionPlan,
    { kind: 'email_otp_ecdsa_session_provision' }
  >['emailOtpAuthContext'];
  plan: Extract<EcdsaSessionProvisionPlan, { kind: 'email_otp_ecdsa_session_provision' }>;
};

type CookieEcdsaActivation = EcdsaProvisionActivationCommon & {
  kind: 'cookie_reconnect';
  sessionKind: 'cookie';
  plan: Extract<EcdsaSessionProvisionPlan, { kind: 'cookie_ecdsa_reconnect' }>;
};

type ThresholdSessionAuthEcdsaActivation = EcdsaProvisionActivationCommon & {
  kind: 'threshold_session_auth_reconnect';
  sessionKind: 'jwt';
  thresholdSessionAuth: Extract<
    EcdsaSessionProvisionPlan,
    { kind: 'threshold_session_auth_ecdsa_reconnect' }
  >['thresholdSessionAuth'];
  plan: Extract<EcdsaSessionProvisionPlan, { kind: 'threshold_session_auth_ecdsa_reconnect' }>;
};

type EcdsaProvisionActivation =
  | PasskeyEcdsaActivation
  | EmailOtpEcdsaActivation
  | CookieEcdsaActivation
  | ThresholdSessionAuthEcdsaActivation;

type EcdsaActivationPolicy = ThresholdEcdsaActivationPolicy;

type EcdsaActivationOptions = Pick<
  EcdsaProvisionActivationCommon,
  'runtimeScopeBootstrap' | 'operationIntent' | 'beforeProvision' | 'assertNotCancelled'
>;

type EcdsaActivationIdentityPair = {
  keyHandle: EvmFamilyEcdsaKeyHandle;
  key: EvmFamilyEcdsaKeyIdentity;
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

type EcdsaKeyRefCandidate = {
  source: ThresholdEcdsaSessionStoreSource;
  keyRef: ThresholdEcdsaSecp256k1KeyRef;
};

function hasEcdsaKeyRefSigningMaterial(keyRef: ThresholdEcdsaSecp256k1KeyRef): boolean {
  const binding = keyRef.backendBinding;
  if (!binding) return false;
  if (String(binding.clientAdditiveShare32B64u || '').trim()) return true;
  return binding.clientAdditiveShareHandle?.kind === 'email_otp_worker_session';
}

function readEcdsaKeyRefCandidates(
  deps: Pick<WarmSessionEcdsaProvisionerDeps, 'listThresholdEcdsaKeyRefsForWalletTarget'>,
  args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    source?: ThresholdEcdsaSessionStoreSource;
  },
): EcdsaKeyRefCandidate[] {
  if (typeof deps.listThresholdEcdsaKeyRefsForWalletTarget !== 'function') return [];
  const candidates: EcdsaKeyRefCandidate[] = [];
  const seen = new Set<string>();
  let listed: EcdsaKeyRefCandidate[] = [];
  try {
    listed = deps.listThresholdEcdsaKeyRefsForWalletTarget({
      walletId: args.walletId,
      chainTarget: args.chainTarget,
      ...(args.source ? { source: args.source } : {}),
    });
  } catch {
    return [];
  }
  for (const candidate of listed) {
    const source = candidate.source;
    const keyRef = candidate.keyRef;
    if (args.source && source !== args.source) continue;
    try {
      const identity = buildEcdsaSessionIdentity(keyRef);
      const key = [
        source,
        identity.thresholdSessionId,
        String(keyRef.ecdsaThresholdKeyId || '').trim(),
      ].join(':');
      if (seen.has(key)) continue;
      seen.add(key);
      candidates.push({ source, keyRef });
    } catch {}
  }
  return candidates;
}

function keyRefMatchesPlannedIdentity(args: {
  keyRef: ThresholdEcdsaSecp256k1KeyRef;
  plan: EcdsaSessionProvisionPlan;
}): boolean {
  const identity = getEcdsaSessionProvisionIdentity(args.plan);
  return ecdsaSessionIdentityMatches(identity, args.keyRef);
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
  const planSigningRootId = String(args.plan.signingKeyContext.signingRootId || '').trim();
  const planSigningRootVersion = normalizeSigningRootVersion(
    args.plan.signingKeyContext.signingRootVersion,
  );
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
      normalizeSigningRootVersion(recordSigningRoot.signingRootVersion) !==
        planSigningRootVersion
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
    keyHandle: toEvmFamilyEcdsaKeyHandle(args.record.keyHandle),
    key,
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
    keyHandle: args.identityPair.keyHandle,
    key: args.identityPair.key,
    lanePolicy: args.identityPair.lanePolicy,
    sessionIdentity: args.plan.newSessionIdentity,
    sessionKind: args.plan.sessionKind,
    sessionBudgetUses: args.plan.sessionBudgetUses,
    runtimePolicy: args.runtimePolicy,
    clientRootShare32B64u: args.plan.clientRootShare32B64u,
    webauthnAuthentication: args.plan.webauthnAuthentication,
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
    keyHandle: args.identityPair.keyHandle,
    key: args.identityPair.key,
    lanePolicy: args.identityPair.lanePolicy,
    sessionIdentity: args.plan.newSessionIdentity,
    sessionKind: args.plan.sessionKind,
    sessionBudgetUses: args.plan.sessionBudgetUses,
    runtimePolicy: args.runtimePolicy,
    clientRootShare32B64u: args.plan.clientRootShare32B64u,
    emailOtpAuthContext: args.plan.emailOtpAuthContext,
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

function buildThresholdSessionAuthEcdsaActivation(args: {
  walletId: AccountId;
  relayerUrl: string;
  source: ThresholdEcdsaSessionStoreSource;
  runtimePolicy: EcdsaActivationPolicy;
  options: EcdsaActivationOptions;
  plan: Extract<EcdsaSessionProvisionPlan, { kind: 'threshold_session_auth_ecdsa_reconnect' }>;
  identityPair: EcdsaActivationIdentityPair;
}): ThresholdSessionAuthEcdsaActivation {
  const activation: ThresholdSessionAuthEcdsaActivation = {
    kind: 'threshold_session_auth_reconnect',
    walletId: args.walletId,
    relayerUrl: args.relayerUrl,
    source: args.source,
    keyHandle: args.identityPair.keyHandle,
    key: args.identityPair.key,
    lanePolicy: args.identityPair.lanePolicy,
    sessionIdentity: args.plan.existingSessionIdentity,
    sessionKind: 'jwt',
    sessionBudgetUses: args.plan.sessionBudgetUses,
    runtimePolicy: args.runtimePolicy,
    thresholdSessionAuth: args.plan.thresholdSessionAuth,
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

function buildCookieEcdsaActivation(args: {
  walletId: AccountId;
  relayerUrl: string;
  source: ThresholdEcdsaSessionStoreSource;
  runtimePolicy: EcdsaActivationPolicy;
  options: EcdsaActivationOptions;
  plan: Extract<EcdsaSessionProvisionPlan, { kind: 'cookie_ecdsa_reconnect' }>;
  identityPair: EcdsaActivationIdentityPair;
}): CookieEcdsaActivation {
  const activation: CookieEcdsaActivation = {
    kind: 'cookie_reconnect',
    walletId: args.walletId,
    relayerUrl: args.relayerUrl,
    source: args.source,
    keyHandle: args.identityPair.keyHandle,
    key: args.identityPair.key,
    lanePolicy: args.identityPair.lanePolicy,
    sessionIdentity: args.plan.existingSessionIdentity,
    sessionKind: 'cookie',
    sessionBudgetUses: args.plan.sessionBudgetUses,
    runtimePolicy: args.runtimePolicy,
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
    case 'threshold_session_auth_reconnect':
      return await reconnectThresholdSessionAuthEcdsaSession(deps, activation);
    case 'cookie_reconnect':
      return await reconnectCookieEcdsaSession(deps, activation);
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
    runtimePolicy: activation.runtimePolicy,
    ...(activation.runtimeScopeBootstrap
      ? { runtimeScopeBootstrap: activation.runtimeScopeBootstrap }
      : {}),
    ...(activation.operationIntent ? { operationIntent: activation.operationIntent } : {}),
    clientRootShare32B64u: plan.clientRootShare32B64u,
    webauthnAuthentication: plan.webauthnAuthentication,
  };
  return await deps.provisionThresholdEcdsaSession(
    buildPasskeyReconnectEcdsaActivation({
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
      clientRootShare32B64u: baseArgs.clientRootShare32B64u,
      webauthnAuthentication: baseArgs.webauthnAuthentication,
      keyHandle: activation.keyHandle,
      key: activation.key,
      lanePolicy: activation.lanePolicy,
    }),
  );
}

async function reconnectThresholdSessionAuthEcdsaSession(
  deps: Pick<WarmSessionEcdsaReconnectDeps, 'provisionThresholdEcdsaSession' | 'touchConfirm'>,
  activation: ThresholdSessionAuthEcdsaActivation,
): Promise<ThresholdEcdsaSessionBootstrapResult> {
  const plan = activation.plan;
  const clientRootShare32B64u = await claimPasskeyEcdsaPrfFirst({
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
    clientRootShare32B64u,
    thresholdSessionAuth: plan.thresholdSessionAuth,
  };
  return await deps.provisionThresholdEcdsaSession(
    buildThresholdSessionReconnectEcdsaActivation({
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
      clientRootShare32B64u: baseArgs.clientRootShare32B64u,
      thresholdSessionAuth: baseArgs.thresholdSessionAuth,
      keyHandle: activation.keyHandle,
      key: activation.key,
      lanePolicy: activation.lanePolicy,
    }),
  );
}

async function reconnectCookieEcdsaSession(
  deps: Pick<WarmSessionEcdsaReconnectDeps, 'provisionThresholdEcdsaSession'>,
  activation: CookieEcdsaActivation,
): Promise<ThresholdEcdsaSessionBootstrapResult> {
  const plan = activation.plan;
  const baseArgs = {
    source: activation.source,
    relayerUrl: activation.relayerUrl,
    sessionIdentity: plan.existingSessionIdentity,
    sessionKind: 'cookie' as const,
    sessionBudgetUses: plan.sessionBudgetUses,
    runtimePolicy: activation.runtimePolicy,
    ...(activation.runtimeScopeBootstrap
      ? { runtimeScopeBootstrap: activation.runtimeScopeBootstrap }
      : {}),
    ...(activation.operationIntent ? { operationIntent: activation.operationIntent } : {}),
  };
  return await deps.provisionThresholdEcdsaSession(
    buildCookieReconnectEcdsaActivation({
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
      keyHandle: activation.keyHandle,
      key: activation.key,
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
    clientRootShare32B64u: plan.clientRootShare32B64u,
  };
  if (plan.emailOtpAuthContext.retention === 'single_use') {
    const emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext & {
      retention: 'single_use';
    } = {
      policy: plan.emailOtpAuthContext.policy,
      retention: 'single_use',
      reason: plan.emailOtpAuthContext.reason,
      authMethod: 'email_otp',
      ...(plan.emailOtpAuthContext.authSubjectId
        ? { authSubjectId: plan.emailOtpAuthContext.authSubjectId }
        : {}),
      ...(typeof plan.emailOtpAuthContext.consumedAtMs === 'number'
        ? { consumedAtMs: plan.emailOtpAuthContext.consumedAtMs }
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
        clientRootShare32B64u: baseArgs.clientRootShare32B64u,
        keyHandle: activation.keyHandle,
        key: activation.key,
        lanePolicy: activation.lanePolicy,
        emailOtpAuthContext,
      }),
    );
  }
  const emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext & {
    retention: 'session';
  } = {
    policy: plan.emailOtpAuthContext.policy,
    retention: 'session',
    reason: plan.emailOtpAuthContext.reason,
    authMethod: 'email_otp',
    ...(plan.emailOtpAuthContext.authSubjectId
      ? { authSubjectId: plan.emailOtpAuthContext.authSubjectId }
      : {}),
    ...(typeof plan.emailOtpAuthContext.consumedAtMs === 'number'
      ? { consumedAtMs: plan.emailOtpAuthContext.consumedAtMs }
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
      clientRootShare32B64u: baseArgs.clientRootShare32B64u,
      keyHandle: activation.keyHandle,
      key: activation.key,
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
  const keyRefCandidates = readEcdsaKeyRefCandidates(deps, {
    walletId: exactWalletId,
    chainTarget: args.chainTarget,
    ...(args.source ? { source: args.source } : {}),
  });
  if (!keyRefCandidates.length) return null;
  const warmSession = await deps.getWarmSession(exactWalletId);
  for (const candidate of keyRefCandidates) {
    if (!hasEcdsaKeyRefSigningMaterial(candidate.keyRef)) {
      continue;
    }
    const capability = getMatchingReadyEcdsaCapability({
      warmSession,
      chainTarget: args.chainTarget,
      keyRef: candidate.keyRef,
      usesNeeded: 1,
    });
    if (!capability) continue;
    const reusableBootstrap = buildReusableEcdsaBootstrapResult({
      keyRef: candidate.keyRef,
      capability,
      source: candidate.source,
    });
    if (reusableBootstrap) return reusableBootstrap;
  }
  return null;
}

function requireActivationRelayerUrl(args: {
  keyRef: ThresholdEcdsaSecp256k1KeyRef | null;
  reconnectRecord: ThresholdEcdsaSessionRecord | null;
  secondaryRecord: ThresholdEcdsaSessionRecord | null;
}): string {
  const relayerUrl = String(
    args.reconnectRecord?.relayerUrl ||
      (args.keyRef ? args.keyRef.relayerUrl : '') ||
      args.secondaryRecord?.relayerUrl ||
      '',
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
  keyRef: ThresholdEcdsaSecp256k1KeyRef | null;
}): string {
  const keyId = args.keyRef
    ? String(args.keyRef.ecdsaThresholdKeyId || '').trim() || 'auto'
    : 'auto';
  const sessionIdentity = args.keyRef ? tryBuildEcdsaSessionIdentity(args.keyRef) : null;
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
  const keyRefCandidates: EcdsaKeyRefCandidate[] = args.keyRef
    ? [{ source: args.source || 'manual-bootstrap', keyRef: args.keyRef }]
    : readEcdsaKeyRefCandidates(deps, {
        walletId: exactWalletId,
        chainTarget,
        ...(args.source ? { source: args.source } : {}),
      });
  const confirmedReconnectRequested =
    args.plan.kind === 'passkey_ecdsa_session_provision' ||
    args.plan.kind === 'email_otp_ecdsa_session_provision';
  let keyRef: ThresholdEcdsaSecp256k1KeyRef | null = null;
  let keyRefSource: ThresholdEcdsaSessionStoreSource | undefined;
  for (const candidate of keyRefCandidates) {
    const capability = getMatchingReadyEcdsaCapability({
      warmSession,
      chainTarget,
      keyRef: candidate.keyRef,
      usesNeeded: args.usesNeeded,
    });
    if (!capability || !hasEcdsaKeyRefSigningMaterial(candidate.keyRef)) {
      if (!keyRef) {
        keyRef = candidate.keyRef;
        keyRefSource = candidate.source;
      }
      continue;
    }
    if (!keyRefMatchesPlannedIdentity({ keyRef: candidate.keyRef, plan: args.plan })) {
      keyRef = candidate.keyRef;
      keyRefSource = candidate.source;
      continue;
    }
    // A confirmed step-up must mint/refresh server budget even if local worker
    // material still looks ready; otherwise stale exhausted wallet budget wins.
    if (confirmedReconnectRequested) {
      keyRef = candidate.keyRef;
      keyRefSource = candidate.source;
      continue;
    }
    return {
      keyRef: candidate.keyRef,
      warmSession,
      capability,
      reconnected: false,
    };
  }
  if (!keyRef && keyRefCandidates[0]) {
    keyRef = keyRefCandidates[0].keyRef;
    keyRefSource = keyRefCandidates[0].source;
  }

  for (const candidate of keyRefCandidates) {
    const keyRefIdentity = tryBuildEcdsaSessionIdentity(candidate.keyRef);
    if (!keyRefIdentity) continue;
    const directCapability = await deps.readEcdsaCapabilityByThresholdSessionId(
      keyRefIdentity.thresholdSessionId,
    );
    if (
      directCapability?.record?.chainTarget &&
      thresholdEcdsaChainTargetsEqual(directCapability.record.chainTarget, chainTarget) &&
      directCapability.state === 'ready' &&
      hasSufficientWarmClaim(directCapability.prfClaim, args.usesNeeded)
    ) {
      if (hasEcdsaKeyRefSigningMaterial(candidate.keyRef)) {
        if (!keyRefMatchesPlannedIdentity({ keyRef: candidate.keyRef, plan: args.plan })) {
          keyRef = candidate.keyRef;
          keyRefSource = candidate.source;
          continue;
        }
        if (confirmedReconnectRequested) {
          keyRef = candidate.keyRef;
          keyRefSource = candidate.source;
          continue;
        }
        return {
          keyRef: candidate.keyRef,
          warmSession,
          capability: directCapability,
          reconnected: false,
        };
      }
      if (!keyRef) {
        keyRef = candidate.keyRef;
        keyRefSource = candidate.source;
      }
    }
  }

  if (!deps.canProvisionEcdsaCapability) {
    throw new Error(
      '[WarmSessionStore] provisionThresholdEcdsaSession is required to reconnect ECDSA capability',
    );
  }
  if (typeof deps.listThresholdEcdsaKeyRefsForWalletTarget !== 'function') {
    throw new Error(
      '[WarmSessionStore] listThresholdEcdsaKeyRefsForWalletTarget is required to resolve ECDSA capability',
    );
  }

  const plannedIdentity = getEcdsaSessionProvisionIdentity(args.plan);
  const reconnectRecord =
    deps.resolveExactEcdsaRecord({
      walletId: exactWalletId,
      chainTarget,
      thresholdSessionId: plannedIdentity.thresholdSessionId,
      ...(args.source ? { source: args.source } : {}),
    }) ||
    (args.source
      ? deps.resolveExactEcdsaRecord({
          walletId: exactWalletId,
          chainTarget,
          thresholdSessionId: plannedIdentity.thresholdSessionId,
        })
      : null);
  const secondaryRecord = args.source
    ? null
    : getPrimaryAndSecondaryEcdsaCapabilities({
        warmSession,
        chainTarget,
      }).secondary.record;
  const keyRefIdentity = keyRef ? tryBuildEcdsaSessionIdentity(keyRef) : null;
  const keyRefRecord = keyRefIdentity
    ? deps.resolveExactEcdsaRecord({
        walletId: exactWalletId,
        chainTarget,
        thresholdSessionId: keyRefIdentity.thresholdSessionId,
        ...(args.source ? { source: args.source } : {}),
      }) ||
      (args.source
        ? deps.resolveExactEcdsaRecord({
            walletId: exactWalletId,
            chainTarget,
            thresholdSessionId: keyRefIdentity.thresholdSessionId,
          })
        : null)
    : null;
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
    keyRef,
  });
  let reconnectPromise = deps.reconnectInFlightByCapability.get(inflightKey);
  if (!reconnectPromise) {
    reconnectPromise = (async (): Promise<EnsureWarmEcdsaCapabilityReadyResult> => {
      const effectivePlan =
        args.plan.kind === 'email_otp_ecdsa_session_provision' && inheritedEmailOtpRecord?.emailOtpAuthContext
          ? {
              kind: 'email_otp_ecdsa_session_provision' as const,
              key: args.plan.key,
              chainTarget: args.plan.chainTarget,
              newSessionIdentity: args.plan.newSessionIdentity,
              signingKeyContext: args.plan.signingKeyContext,
              sessionKind: args.plan.sessionKind,
              sessionBudgetUses: args.plan.sessionBudgetUses,
              emailOtpAuthContext: inheritedEmailOtpRecord.emailOtpAuthContext,
              clientRootShare32B64u: args.plan.clientRootShare32B64u,
              ...(args.plan.runtimePolicyScope
                ? { runtimePolicyScope: args.plan.runtimePolicyScope }
                : {}),
            }
          : args.plan;
      const activationSource = inheritedEmailOtpRecord ? 'email_otp' : keyRefSource || args.source || 'login';
      const activationPolicy = buildEcdsaActivationPolicy(
        'runtimePolicyScope' in effectivePlan ? effectivePlan.runtimePolicyScope : undefined,
      );
      const activationOptions = buildActivationOptions(args);
      const relayerUrl = requireActivationRelayerUrl({
        keyRef,
        reconnectRecord,
        secondaryRecord: secondaryRecord || keyRefRecord,
      });
      const activationIdentityPair = buildActivationKeyAndLanePolicy({
        record: reconnectRecord || inheritedEmailOtpRecord || secondaryRecord || keyRefRecord,
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
            : effectivePlan.kind === 'threshold_session_auth_ecdsa_reconnect'
              ? buildThresholdSessionAuthEcdsaActivation({
                  walletId,
                  relayerUrl,
                  source: activationSource,
                  runtimePolicy: activationPolicy,
                  options: activationOptions,
                  plan: effectivePlan,
                  identityPair: activationIdentityPair,
                })
              : buildCookieEcdsaActivation({
                  walletId,
                  relayerUrl,
                  source: activationSource,
                  runtimePolicy: activationPolicy,
                  options: activationOptions,
                  plan: effectivePlan,
                  identityPair: activationIdentityPair,
                });
      const provisioned = await provisionEcdsaActivation(deps, activation);
      args.assertNotCancelled?.();

      const refreshedKeyRef = provisioned.thresholdEcdsaKeyRef;
      const refreshedWarmSession = await deps.getWarmSession(exactWalletId);
      let refreshedCapability = getMatchingReadyEcdsaCapability({
        warmSession: refreshedWarmSession,
        chainTarget,
        keyRef: refreshedKeyRef,
        usesNeeded: args.usesNeeded,
      });
      const refreshedIdentity = refreshedKeyRef
        ? tryBuildEcdsaSessionIdentity(refreshedKeyRef)
        : null;
      if (!refreshedCapability && refreshedIdentity) {
        const directCapability =
          await deps.readEcdsaCapabilityByThresholdSessionId(
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
        keyRef: refreshedKeyRef,
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
  keyRef: ThresholdEcdsaSecp256k1KeyRef | null;
  usesNeeded?: number;
}): WarmSessionEcdsaCapabilityState | null {
  const chain = args.chainTarget.kind;
  const capability = args.warmSession.capabilities.ecdsa[chain];
  if (!args.keyRef || capability.state !== 'ready') return null;

  const recordIdentity = capability.record
    ? tryBuildEcdsaSessionIdentity(capability.record)
    : null;
  const keyRefIdentity = tryBuildEcdsaSessionIdentity(args.keyRef);
  if (
    !recordIdentity ||
    !keyRefIdentity ||
    !ecdsaSessionIdentitiesEqual(recordIdentity, keyRefIdentity)
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
  const keyRefThresholdKeyId = String(
    resolveThresholdEcdsaKeyIdFromKeyRef({
      keyRef: args.keyRef,
    }),
  ).trim();
  if (
    !recordThresholdKeyId ||
    (keyRefThresholdKeyId && recordThresholdKeyId !== keyRefThresholdKeyId)
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
  keyRef: ThresholdEcdsaSecp256k1KeyRef;
  capability: WarmSessionEcdsaCapabilityState;
  source: 'login' | 'registration' | 'manual-bootstrap' | 'email_otp';
}): ThresholdEcdsaSessionBootstrapResult | null {
  const record = args.capability.record;
  const auth = args.capability.auth;
  const prfClaim = args.capability.prfClaim;
  if (!record || !auth || !prfClaim || prfClaim.state !== 'warm') return null;

  const clientVerifyingShareB64u = String(record.clientVerifyingShareB64u || '').trim();
  const clientAdditiveShare32B64u = String(record.clientAdditiveShare32B64u || '').trim();
  const relayerKeyId = String(record.relayerKeyId || '').trim();
  const identity = tryBuildEcdsaSessionIdentity(record);
  // A warm ECDSA capability is only directly reusable when the canonical
  // keyRef already carries local signing material. Restored passkey lanes
  // often have only the PRF/JWT until reconnect recreates the additive share.
  if (!clientVerifyingShareB64u || !clientAdditiveShare32B64u || !relayerKeyId || !identity) {
    return null;
  }
  const ecdsaThresholdKeyId = String(
    resolveThresholdEcdsaKeyIdFromKeyRef({ keyRef: args.keyRef }) ||
      resolveThresholdEcdsaKeyIdFromRecord({ record }) ||
      '',
  ).trim();
  if (!ecdsaThresholdKeyId) {
    return null;
  }

  return {
    thresholdEcdsaKeyRef: {
      ...args.keyRef,
      relayerUrl: String(record.relayerUrl || args.keyRef.relayerUrl || '').trim(),
      ecdsaThresholdKeyId,
      participantIds: record.participantIds,
      thresholdSessionKind: record.thresholdSessionKind,
      thresholdSessionId: identity.thresholdSessionId,
      walletSigningSessionId: identity.walletSigningSessionId,
      thresholdSessionAuthToken: String(
        auth.thresholdSessionAuthToken || args.keyRef.thresholdSessionAuthToken || '',
      ).trim(),
    },
    keygen: {
      ok: true,
      ecdsaThresholdKeyId,
      relayerKeyId,
      clientVerifyingShareB64u,
      clientAdditiveShare32B64u,
      participantIds: record.participantIds,
      thresholdEcdsaPublicKeyB64u: record.thresholdEcdsaPublicKeyB64u,
      ethereumAddress: record.ethereumAddress,
      relayerVerifyingShareB64u: record.relayerVerifyingShareB64u,
    },
    session: {
      ok: true,
      sessionId: identity.thresholdSessionId,
      walletSigningSessionId: identity.walletSigningSessionId,
      ...(String(auth.thresholdSessionAuthToken || '').trim()
        ? { jwt: String(auth.thresholdSessionAuthToken || '').trim() }
        : {}),
      expiresAtMs: Math.max(0, Math.floor(Number(prfClaim.expiresAtMs) || 0)),
      remainingUses: Math.max(0, Math.floor(Number(prfClaim.remainingUses) || 0)),
      clientVerifyingShareB64u,
    },
  };
}
