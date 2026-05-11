import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { ThresholdEcdsaSessionRecord } from '../persistence/records';
import type { ThresholdEcdsaSessionStoreSource } from '../identity/laneIdentity';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import type { ThresholdRuntimePolicyScope } from '../../threshold/sessionPolicy';
import type { SigningOperationIntent } from '../operationState/types';
import {
  ecdsaPostSignPolicySessionFromRecord,
  formatEmailOtpSensitiveOperationError,
} from '../operationState/postSignPolicy';
import {
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
  type WalletSubjectId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  emitWarmSessionTransition,
  summarizeWarmSessionTransition,
  type WarmSessionTransitionEvent,
} from '../warmCapabilities/transitions';
import {
  getEcdsaSessionProvisionIdentity,
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
  ThresholdEcdsaCookieReconnectRequest,
  ThresholdEcdsaEmailOtpActivationRequest,
  ThresholdEcdsaPasskeyActivationRequest,
  ThresholdEcdsaThresholdSessionAuthReconnectRequest,
} from './ecdsaSessionProvision';

export type WarmSessionEcdsaProvisionerDeps = {
  getWarmSession: (nearAccountId: AccountId | string) => Promise<WarmSessionEnvelope>;
  listThresholdEcdsaKeyRefsForAccountTarget?: (args: {
    nearAccountId: AccountId | string;
    subjectId: WalletSubjectId;
    chainTarget: ThresholdEcdsaChainTarget;
    source?: ThresholdEcdsaSessionStoreSource;
  }) => EcdsaKeyRefCandidate[];
};

export type WarmSessionEcdsaReconnectDeps = {
  getWarmSession: (nearAccountId: AccountId | string) => Promise<WarmSessionEnvelope>;
  listThresholdEcdsaKeyRefsForAccountTarget?: (args: {
    nearAccountId: AccountId | string;
    subjectId: WalletSubjectId;
    chainTarget: ThresholdEcdsaChainTarget;
    source?: ThresholdEcdsaSessionStoreSource;
  }) => EcdsaKeyRefCandidate[];
  canProvisionEcdsaCapability: boolean;
  provisionThresholdEcdsaSession: (
    args: ThresholdEcdsaActivationRequest,
  ) => Promise<ThresholdEcdsaSessionBootstrapResult>;
  resolveCurrentEcdsaRecord: (args: {
    nearAccountId: AccountId;
    chainTarget: ThresholdEcdsaChainTarget;
    source?: ThresholdEcdsaSessionStoreSource;
  }) => ThresholdEcdsaSessionRecord | null;
  readEcdsaCapabilityByThresholdSessionId: (
    thresholdSessionId: string,
  ) => Promise<WarmSessionEcdsaCapabilityState | null>;
  reconnectInFlightByCapability: Map<string, Promise<EnsureWarmEcdsaCapabilityReadyResult>>;
  onTransition?: (event: WarmSessionTransitionEvent) => void | Promise<void>;
};

type EcdsaProvisionActivationCommon = {
  nearAccountId: AccountId;
  relayerUrl: string;
  source: ThresholdEcdsaSessionStoreSource;
  runtimePolicy: ThresholdEcdsaActivationPolicy;
  runtimeScopeBootstrap?: ThresholdEcdsaActivationRuntimeScopeBootstrap;
  operationIntent?: SigningOperationIntent;
  beforeProvision?: () => void | Promise<void>;
  assertNotCancelled?: () => void;
};

type PasskeyEcdsaActivation = ThresholdEcdsaPasskeyActivationRequest &
  Pick<EcdsaProvisionActivationCommon, 'beforeProvision' | 'assertNotCancelled'> & {
    plan: Extract<EcdsaSessionProvisionPlan, { kind: 'passkey_ecdsa_session_provision' }>;
  };

type EmailOtpEcdsaActivation = ThresholdEcdsaEmailOtpActivationRequest &
  Pick<EcdsaProvisionActivationCommon, 'beforeProvision' | 'assertNotCancelled'> & {
    plan: Extract<EcdsaSessionProvisionPlan, { kind: 'email_otp_ecdsa_session_provision' }>;
  };

type CookieEcdsaActivation = ThresholdEcdsaCookieReconnectRequest &
  Pick<EcdsaProvisionActivationCommon, 'beforeProvision' | 'assertNotCancelled'> & {
    plan: Extract<EcdsaSessionProvisionPlan, { kind: 'cookie_ecdsa_reconnect' }>;
  };

type ThresholdSessionAuthEcdsaActivation = ThresholdEcdsaThresholdSessionAuthReconnectRequest &
  Pick<EcdsaProvisionActivationCommon, 'beforeProvision' | 'assertNotCancelled'> & {
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

function assertPersistedEcdsaWarmSessionRecord(args: {
  nearAccountId: AccountId;
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
    `[WarmSessionStore] provisioned ECDSA capability was not persisted for ${args.nearAccountId} (expected sessionId=${args.expectedSessionId}, found=${persistedSessionId || fallbackPersistedSessionId || 'missing'})`,
  );
}

type EcdsaKeyRefCandidate = {
  source: ThresholdEcdsaSessionStoreSource;
  keyRef: ThresholdEcdsaSecp256k1KeyRef;
};

function summarizeReconnectKeyRef(
  keyRef: ThresholdEcdsaSecp256k1KeyRef | null | undefined,
): Record<string, unknown> {
  if (!keyRef) return { present: false };
  return {
    present: true,
    thresholdSessionId: keyRef.thresholdSessionId,
    walletSigningSessionId: keyRef.walletSigningSessionId,
    ecdsaThresholdKeyId: keyRef.ecdsaThresholdKeyId,
    signingRootId: keyRef.signingRootId,
    signingRootVersion: keyRef.signingRootVersion,
    thresholdSessionKind: keyRef.thresholdSessionKind,
    hasThresholdSessionAuthToken: Boolean(String(keyRef.thresholdSessionAuthToken || '').trim()),
    hasBackendBinding: Boolean(keyRef.backendBinding),
    hasRelayerKeyId: Boolean(keyRef.backendBinding?.relayerKeyId),
  };
}

function summarizeReconnectRecord(
  record: ThresholdEcdsaSessionRecord | null | undefined,
): Record<string, unknown> {
  if (!record) return { present: false };
  return {
    present: true,
    source: record.source,
    chain: record.chainTarget.kind,
    thresholdSessionId: record.thresholdSessionId,
    walletSigningSessionId: record.walletSigningSessionId,
    ecdsaThresholdKeyId: record.ecdsaThresholdKeyId,
    signingRootId: record.signingRootId,
    signingRootVersion: record.signingRootVersion,
    thresholdSessionKind: record.thresholdSessionKind,
    remainingUses: record.remainingUses,
    expiresAtMs: record.expiresAtMs,
    updatedAtMs: record.updatedAtMs,
    emailOtpRetention: record.emailOtpAuthContext?.retention,
    emailOtpReason: record.emailOtpAuthContext?.reason,
    hasThresholdSessionAuthToken: Boolean(String(record.thresholdSessionAuthToken || '').trim()),
  };
}

function hasEcdsaKeyRefSigningMaterial(keyRef: ThresholdEcdsaSecp256k1KeyRef | null): boolean {
  const binding = keyRef?.backendBinding;
  if (!binding) return false;
  if (String(binding.clientAdditiveShare32B64u || '').trim()) return true;
  return binding.clientAdditiveShareHandle?.kind === 'email_otp_worker_session';
}

function readEcdsaKeyRefCandidates(
  deps: Pick<WarmSessionEcdsaProvisionerDeps, 'listThresholdEcdsaKeyRefsForAccountTarget'>,
  args: {
    nearAccountId: AccountId;
    subjectId: WalletSubjectId;
    chainTarget: ThresholdEcdsaChainTarget;
    source?: ThresholdEcdsaSessionStoreSource;
  },
): EcdsaKeyRefCandidate[] {
  if (typeof deps.listThresholdEcdsaKeyRefsForAccountTarget !== 'function') return [];
  const candidates: EcdsaKeyRefCandidate[] = [];
  const seen = new Set<string>();
  let listed: EcdsaKeyRefCandidate[] = [];
  try {
    listed = deps.listThresholdEcdsaKeyRefsForAccountTarget({
      nearAccountId: args.nearAccountId,
      subjectId: args.subjectId,
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
      const key = [
        source,
        String(keyRef.thresholdSessionId || '').trim(),
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
  return (
    identity.thresholdSessionId === String(args.keyRef.thresholdSessionId || '').trim() &&
    identity.walletSigningSessionId === String(args.keyRef.walletSigningSessionId || '').trim()
  );
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

function buildPasskeyEcdsaActivation(args: {
  nearAccountId: AccountId;
  relayerUrl: string;
  source: ThresholdEcdsaSessionStoreSource;
  runtimePolicy: EcdsaActivationPolicy;
  options: EcdsaActivationOptions;
  plan: Extract<EcdsaSessionProvisionPlan, { kind: 'passkey_ecdsa_session_provision' }>;
}): PasskeyEcdsaActivation {
  const activation: PasskeyEcdsaActivation = {
    kind: 'passkey_ecdsa_activation',
    nearAccountId: args.nearAccountId,
    subjectId: args.plan.subjectId,
    chainTarget: args.plan.chainTarget,
    relayerUrl: args.relayerUrl,
    source: args.source,
    ecdsaThresholdKeyId: args.plan.signingKeyContext.ecdsaThresholdKeyId,
    participantIds: [...args.plan.signingKeyContext.participantIds],
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
  nearAccountId: AccountId;
  relayerUrl: string;
  source: ThresholdEcdsaSessionStoreSource;
  runtimePolicy: EcdsaActivationPolicy;
  options: EcdsaActivationOptions;
  plan: Extract<EcdsaSessionProvisionPlan, { kind: 'email_otp_ecdsa_session_provision' }>;
}): EmailOtpEcdsaActivation {
  const activation: EmailOtpEcdsaActivation = {
    kind: 'email_otp_ecdsa_activation',
    nearAccountId: args.nearAccountId,
    subjectId: args.plan.subjectId,
    chainTarget: args.plan.chainTarget,
    relayerUrl: args.relayerUrl,
    source: args.source,
    ecdsaThresholdKeyId: args.plan.signingKeyContext.ecdsaThresholdKeyId,
    participantIds: [...args.plan.signingKeyContext.participantIds],
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
  nearAccountId: AccountId;
  relayerUrl: string;
  source: ThresholdEcdsaSessionStoreSource;
  runtimePolicy: EcdsaActivationPolicy;
  options: EcdsaActivationOptions;
  plan: Extract<EcdsaSessionProvisionPlan, { kind: 'threshold_session_auth_ecdsa_reconnect' }>;
}): ThresholdSessionAuthEcdsaActivation {
  const activation: ThresholdSessionAuthEcdsaActivation = {
    kind: 'threshold_session_auth_reconnect',
    nearAccountId: args.nearAccountId,
    subjectId: args.plan.subjectId,
    chainTarget: args.plan.chainTarget,
    relayerUrl: args.relayerUrl,
    source: args.source,
    ecdsaThresholdKeyId: args.plan.signingKeyContext.ecdsaThresholdKeyId,
    participantIds: [...args.plan.signingKeyContext.participantIds],
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
  nearAccountId: AccountId;
  relayerUrl: string;
  source: ThresholdEcdsaSessionStoreSource;
  runtimePolicy: EcdsaActivationPolicy;
  options: EcdsaActivationOptions;
  plan: Extract<EcdsaSessionProvisionPlan, { kind: 'cookie_ecdsa_reconnect' }>;
}): CookieEcdsaActivation {
  const activation: CookieEcdsaActivation = {
    kind: 'cookie_reconnect',
    nearAccountId: args.nearAccountId,
    subjectId: args.plan.subjectId,
    chainTarget: args.plan.chainTarget,
    relayerUrl: args.relayerUrl,
    source: args.source,
    ecdsaThresholdKeyId: args.plan.signingKeyContext.ecdsaThresholdKeyId,
    participantIds: [...args.plan.signingKeyContext.participantIds],
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
  deps: Pick<WarmSessionEcdsaReconnectDeps, 'provisionThresholdEcdsaSession'>,
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
  const request: ThresholdEcdsaPasskeyActivationRequest = {
    kind: 'passkey_ecdsa_activation',
    nearAccountId: activation.nearAccountId,
    subjectId: plan.subjectId,
    chainTarget: plan.chainTarget,
    source: activation.source,
    relayerUrl: activation.relayerUrl,
    ecdsaThresholdKeyId: plan.signingKeyContext.ecdsaThresholdKeyId,
    participantIds: [...plan.signingKeyContext.participantIds],
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
  return await deps.provisionThresholdEcdsaSession(request);
}

async function reconnectThresholdSessionAuthEcdsaSession(
  deps: Pick<WarmSessionEcdsaReconnectDeps, 'provisionThresholdEcdsaSession'>,
  activation: ThresholdSessionAuthEcdsaActivation,
): Promise<ThresholdEcdsaSessionBootstrapResult> {
  const plan = activation.plan;
  const request: ThresholdEcdsaThresholdSessionAuthReconnectRequest = {
    kind: 'threshold_session_auth_reconnect',
    nearAccountId: activation.nearAccountId,
    subjectId: plan.subjectId,
    chainTarget: plan.chainTarget,
    source: activation.source,
    relayerUrl: activation.relayerUrl,
    ecdsaThresholdKeyId: plan.signingKeyContext.ecdsaThresholdKeyId,
    participantIds: [...plan.signingKeyContext.participantIds],
    sessionIdentity: plan.existingSessionIdentity,
    sessionKind: 'jwt',
    sessionBudgetUses: plan.sessionBudgetUses,
    runtimePolicy: activation.runtimePolicy,
    ...(activation.runtimeScopeBootstrap
      ? { runtimeScopeBootstrap: activation.runtimeScopeBootstrap }
      : {}),
    ...(activation.operationIntent ? { operationIntent: activation.operationIntent } : {}),
    thresholdSessionAuth: plan.thresholdSessionAuth,
  };
  return await deps.provisionThresholdEcdsaSession(request);
}

async function reconnectCookieEcdsaSession(
  deps: Pick<WarmSessionEcdsaReconnectDeps, 'provisionThresholdEcdsaSession'>,
  activation: CookieEcdsaActivation,
): Promise<ThresholdEcdsaSessionBootstrapResult> {
  const plan = activation.plan;
  const request: ThresholdEcdsaCookieReconnectRequest = {
    kind: 'cookie_reconnect',
    nearAccountId: activation.nearAccountId,
    subjectId: plan.subjectId,
    chainTarget: plan.chainTarget,
    source: activation.source,
    relayerUrl: activation.relayerUrl,
    ecdsaThresholdKeyId: plan.signingKeyContext.ecdsaThresholdKeyId,
    participantIds: [...plan.signingKeyContext.participantIds],
    sessionIdentity: plan.existingSessionIdentity,
    sessionKind: 'cookie',
    sessionBudgetUses: plan.sessionBudgetUses,
    runtimePolicy: activation.runtimePolicy,
    ...(activation.runtimeScopeBootstrap
      ? { runtimeScopeBootstrap: activation.runtimeScopeBootstrap }
      : {}),
    ...(activation.operationIntent ? { operationIntent: activation.operationIntent } : {}),
  };
  return await deps.provisionThresholdEcdsaSession(request);
}

async function provisionEmailOtpEcdsaSession(
  deps: Pick<WarmSessionEcdsaReconnectDeps, 'provisionThresholdEcdsaSession'>,
  activation: EmailOtpEcdsaActivation,
): Promise<ThresholdEcdsaSessionBootstrapResult> {
  const plan = activation.plan;
  const request: ThresholdEcdsaEmailOtpActivationRequest = {
    kind: 'email_otp_ecdsa_activation',
    nearAccountId: activation.nearAccountId,
    subjectId: plan.subjectId,
    chainTarget: plan.chainTarget,
    source: activation.source,
    relayerUrl: activation.relayerUrl,
    ecdsaThresholdKeyId: plan.signingKeyContext.ecdsaThresholdKeyId,
    participantIds: [...plan.signingKeyContext.participantIds],
    sessionIdentity: plan.newSessionIdentity,
    sessionKind: plan.sessionKind,
    sessionBudgetUses: plan.sessionBudgetUses,
    runtimePolicy: activation.runtimePolicy,
    ...(activation.runtimeScopeBootstrap
      ? { runtimeScopeBootstrap: activation.runtimeScopeBootstrap }
      : {}),
    ...(activation.operationIntent ? { operationIntent: activation.operationIntent } : {}),
    clientRootShare32B64u: plan.clientRootShare32B64u,
    emailOtpAuthContext: plan.emailOtpAuthContext,
  };
  return await deps.provisionThresholdEcdsaSession(request);
}

export async function tryReuseReadyWarmEcdsaBootstrap(
  deps: WarmSessionEcdsaProvisionerDeps,
  args: {
    nearAccountId: AccountId | string;
    subjectId: WalletSubjectId;
    chainTarget: ThresholdEcdsaChainTarget;
    source?: ThresholdEcdsaSessionStoreSource;
  },
): Promise<ThresholdEcdsaSessionBootstrapResult | null> {
  const nearAccountId = toAccountId(args.nearAccountId);
  const keyRefCandidates = readEcdsaKeyRefCandidates(deps, {
    nearAccountId,
    subjectId: args.subjectId,
    chainTarget: args.chainTarget,
    ...(args.source ? { source: args.source } : {}),
  });
  if (!keyRefCandidates.length) return null;
  const warmSession = await deps.getWarmSession(nearAccountId);
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
      args.keyRef?.relayerUrl ||
      args.secondaryRecord?.relayerUrl ||
      '',
  ).trim();
  if (!relayerUrl) {
    throw new Error('[WarmSessionStore] ECDSA activation requires relayerUrl');
  }
  return relayerUrl;
}

function buildEcdsaCapabilityInflightKey(args: {
  nearAccountId: AccountId;
  chainTarget: ThresholdEcdsaChainTarget;
  usesNeeded?: number;
  sessionBudgetUses: number;
  keyRef: ThresholdEcdsaSecp256k1KeyRef | null;
}): string {
  const keyId = String(args.keyRef?.ecdsaThresholdKeyId || '').trim() || 'auto';
  const sessionId = String(args.keyRef?.thresholdSessionId || '').trim() || 'auto';
  const usesNeeded = Math.floor(Number(args.usesNeeded) || 0);
  const sessionBudgetUses = Math.floor(Number(args.sessionBudgetUses) || 0);
  return [
    String(args.nearAccountId),
    thresholdEcdsaChainTargetKey(args.chainTarget),
    String(usesNeeded > 0 ? usesNeeded : 1),
    String(sessionBudgetUses > 0 ? sessionBudgetUses : 1),
    keyId,
    sessionId,
  ].join('::');
}

export async function ensureWarmEcdsaCapabilityReady(
  deps: WarmSessionEcdsaReconnectDeps,
  args: EnsureWarmEcdsaProvisionPlanReadyArgs,
): Promise<EnsureWarmEcdsaCapabilityReadyResult> {
  const nearAccountId = toAccountId(args.nearAccountId);
  const chainTarget = args.chainTarget;
  const chain = chainTarget.kind;
  const chainId = chainTarget.chainId;
  const warmSession = await deps.getWarmSession(nearAccountId);
  const keyRefCandidates: EcdsaKeyRefCandidate[] = args.keyRef
    ? [{ source: args.source || 'manual-bootstrap', keyRef: args.keyRef }]
    : readEcdsaKeyRefCandidates(deps, {
        nearAccountId,
        subjectId: args.subjectId,
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
    const keyRefSessionId = String(candidate.keyRef.thresholdSessionId || '').trim();
    if (!keyRefSessionId) continue;
    const directCapability = await deps.readEcdsaCapabilityByThresholdSessionId(keyRefSessionId);
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
  if (typeof deps.listThresholdEcdsaKeyRefsForAccountTarget !== 'function') {
    throw new Error(
      '[WarmSessionStore] listThresholdEcdsaKeyRefsForAccountTarget is required to resolve ECDSA capability',
    );
  }

  const reconnectRecord = deps.resolveCurrentEcdsaRecord({
    nearAccountId,
    chainTarget,
    ...(args.source ? { source: args.source } : {}),
  });
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
    nearAccountId,
    chainTarget,
    usesNeeded: args.usesNeeded,
    sessionBudgetUses: args.sessionBudgetUses,
    keyRef,
  });
  let reconnectPromise = deps.reconnectInFlightByCapability.get(inflightKey);
  if (!reconnectPromise) {
    reconnectPromise = (async (): Promise<EnsureWarmEcdsaCapabilityReadyResult> => {
      const plannedIdentity = getEcdsaSessionProvisionIdentity(args.plan);
      try {
        console.info('[threshold-ecdsa][reconnect-provision][diagnostic]', {
          nearAccountId: String(nearAccountId),
          chain,
          chainId,
          requestedLaneIdentity: plannedIdentity,
          provisionMode: args.plan.kind,
          plannedProvisionIdentity: {
            thresholdSessionId: plannedIdentity.thresholdSessionId,
            walletSigningSessionId: plannedIdentity.walletSigningSessionId,
          },
          keyRefSource,
          provisionSource: inheritedEmailOtpRecord
            ? 'email_otp'
            : keyRefSource || args.source || 'login',
          usesNeeded: args.usesNeeded,
          sessionBudgetUses: args.sessionBudgetUses,
          selectedKeyRef: summarizeReconnectKeyRef(keyRef),
          reconnectRecord: summarizeReconnectRecord(reconnectRecord),
          secondaryRecord: summarizeReconnectRecord(secondaryRecord),
          inheritedEmailOtpRecord: summarizeReconnectRecord(inheritedEmailOtpRecord),
          allKeyRefCandidates: keyRefCandidates.map((candidate) => ({
            source: candidate.source,
            keyRef: summarizeReconnectKeyRef(candidate.keyRef),
          })),
          routeAuthClaims:
            args.plan.kind === 'threshold_session_auth_ecdsa_reconnect'
              ? {
                  present: true,
                  sessionId: args.plan.thresholdSessionAuth.identity.thresholdSessionId,
                  walletSigningSessionId:
                    args.plan.thresholdSessionAuth.identity.walletSigningSessionId,
                  exp: args.plan.thresholdSessionAuth.expiresAtMs,
                }
              : { present: false },
        });
      } catch {}
      const effectivePlan =
        args.plan.kind === 'email_otp_ecdsa_session_provision' && inheritedEmailOtpRecord?.emailOtpAuthContext
          ? {
              kind: 'email_otp_ecdsa_session_provision' as const,
              subjectId: args.plan.subjectId,
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
        secondaryRecord,
      });
      const activation =
        effectivePlan.kind === 'passkey_ecdsa_session_provision'
          ? buildPasskeyEcdsaActivation({
              nearAccountId,
              relayerUrl,
              source: activationSource,
              runtimePolicy: activationPolicy,
              options: activationOptions,
              plan: effectivePlan,
            })
          : effectivePlan.kind === 'email_otp_ecdsa_session_provision'
            ? buildEmailOtpEcdsaActivation({
                nearAccountId,
                relayerUrl,
                source: activationSource,
                runtimePolicy: activationPolicy,
                options: activationOptions,
                plan: effectivePlan,
              })
            : effectivePlan.kind === 'threshold_session_auth_ecdsa_reconnect'
              ? buildThresholdSessionAuthEcdsaActivation({
                  nearAccountId,
                  relayerUrl,
                  source: activationSource,
                  runtimePolicy: activationPolicy,
                  options: activationOptions,
                  plan: effectivePlan,
                })
              : buildCookieEcdsaActivation({
                  nearAccountId,
                  relayerUrl,
                  source: activationSource,
                  runtimePolicy: activationPolicy,
                  options: activationOptions,
                  plan: effectivePlan,
                });
      const provisioned = await provisionEcdsaActivation(deps, activation);
      args.assertNotCancelled?.();

      const refreshedKeyRef = provisioned.thresholdEcdsaKeyRef;
      const refreshedWarmSession = await deps.getWarmSession(nearAccountId);
      let refreshedCapability = getMatchingReadyEcdsaCapability({
        warmSession: refreshedWarmSession,
        chainTarget,
        keyRef: refreshedKeyRef,
        usesNeeded: args.usesNeeded,
      });
      const refreshedSessionId = String(refreshedKeyRef?.thresholdSessionId || '').trim();
      if (!refreshedCapability && refreshedSessionId) {
        const directCapability =
          await deps.readEcdsaCapabilityByThresholdSessionId(refreshedSessionId);
        if (
          directCapability?.record?.chainTarget &&
          thresholdEcdsaChainTargetsEqual(directCapability.record.chainTarget, chainTarget) &&
          directCapability.state === 'ready' &&
          hasSufficientWarmClaim(directCapability.prfClaim, args.usesNeeded)
        ) {
          refreshedCapability = directCapability;
        }
      }
      if (!refreshedKeyRef || !refreshedCapability) {
        throw new Error(
          '[WarmSessionStore] threshold ECDSA warm capability is not ready after reconnect',
        );
      }

      emitWarmSessionTransition({
        onTransition: deps.onTransition,
        event: {
          type: 'ecdsa_capability_reconnected',
          accountId: nearAccountId,
          chainTarget,
          thresholdSessionId: refreshedSessionId,
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

  const recordSessionId = String(capability.record?.thresholdSessionId || '').trim();
  const keyRefSessionId = String(args.keyRef.thresholdSessionId || '').trim();
  if (!recordSessionId || !keyRefSessionId || recordSessionId !== keyRefSessionId) {
    return null;
  }

  const recordThresholdKeyId = String(capability.record?.ecdsaThresholdKeyId || '').trim();
  const keyRefThresholdKeyId = String(args.keyRef.ecdsaThresholdKeyId || '').trim();
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
  const sessionId = String(record.thresholdSessionId || '').trim();
  // A warm ECDSA capability is only directly reusable when the canonical
  // keyRef already carries local signing material. Restored passkey lanes
  // often have only the PRF/JWT until reconnect recreates the additive share.
  if (!clientVerifyingShareB64u || !clientAdditiveShare32B64u || !relayerKeyId || !sessionId) {
    return null;
  }

  return {
    thresholdEcdsaKeyRef: {
      ...args.keyRef,
      relayerUrl: String(record.relayerUrl || args.keyRef.relayerUrl || '').trim(),
      ecdsaThresholdKeyId: String(
        record.ecdsaThresholdKeyId || args.keyRef.ecdsaThresholdKeyId || '',
      ).trim(),
      participantIds: record.participantIds,
      thresholdSessionKind: record.thresholdSessionKind,
      thresholdSessionId: sessionId,
      walletSigningSessionId: record.walletSigningSessionId,
      thresholdSessionAuthToken: String(
        auth.thresholdSessionAuthToken || args.keyRef.thresholdSessionAuthToken || '',
      ).trim(),
    },
    keygen: {
      ok: true,
      ecdsaThresholdKeyId: String(record.ecdsaThresholdKeyId || '').trim(),
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
      sessionId,
      walletSigningSessionId: record.walletSigningSessionId,
      ...(String(auth.thresholdSessionAuthToken || '').trim()
        ? { jwt: String(auth.thresholdSessionAuthToken || '').trim() }
        : {}),
      expiresAtMs: Math.max(0, Math.floor(Number(prfClaim.expiresAtMs) || 0)),
      remainingUses: Math.max(0, Math.floor(Number(prfClaim.remainingUses) || 0)),
      clientVerifyingShareB64u,
    },
  };
}
