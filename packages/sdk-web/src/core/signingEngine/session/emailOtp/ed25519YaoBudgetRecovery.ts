import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { NearEd25519YaoSigningCapability } from '@/core/signingEngine/interfaces/near';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type {
  EmailOtpEd25519YaoExactLocalSessionBootstrapV1,
  EmailOtpEd25519YaoRecoveryBootstrapV1,
} from '@/core/signingEngine/workerManager/workerTypes';
import {
  WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
  WALLET_EMAIL_OTP_UNLOCK_OPERATION,
} from '@shared/utils/emailOtpDomain';
import { walletAuthAuthoritiesMatch } from '@shared/utils/walletAuthAuthority';
import { base58Encode } from '@shared/utils/base58';
import { registrationNearEd25519BranchKey } from '@shared/utils/registrationIntent';
import type { ThresholdEd25519SessionRecord } from '../persistence/records';
import { resolveRouterAbEd25519WalletSessionStateFromRecord } from '../warmCapabilities/routerAbEd25519WalletSessionState';
import { persistWarmSessionEd25519Capability } from '../warmCapabilities/persistence';
import type { Ed25519YaoActiveClientIdentityV1 } from '../../threshold/ed25519/yaoActiveClientRegistry';
import { buildEmailOtpSigningSessionRoutePlan, buildFreshEmailOtpRoutePlan } from './routePlan';
import { resolveEmailOtpAuthLane } from '../../stepUpConfirmation/otpPrompt/authLane';
import type { Ed25519SigningLane } from './ed25519SigningLane';
import type { EmailOtpEd25519YaoPendingFactorHandle } from './ed25519YaoRootVault';
import {
  unlockEmailOtpEd25519YaoExactLocalSession,
  unlockEmailOtpEd25519YaoSession,
} from './walletUnlock';
import {
  buildEmailOtpEd25519YaoRecoveryContinuityMetadataV1,
  disposeEmailOtpEd25519YaoPendingFactorV1,
  recoverEmailOtpEd25519YaoWorkerClientV1,
  EmailOtpEd25519YaoWorkerActiveClientV1,
} from './ed25519YaoWorkerClient';
import type { RouterAbEd25519YaoActiveClientMetadataV1 } from '../../threshold/ed25519/yaoClient';
import type { EmailOtpAuthPolicy } from '@/core/types/seams';
import {
  buildEmailOtpAuthContextForWalletAuthMethod,
  emailOtpAuthContextEmailHashHex,
  emailOtpAuthContextProviderUserId,
} from '../identity/laneIdentity';
import { parseThresholdRuntimePolicyScopeFromJwt } from '../../threshold/sessionPolicy';

export type EmailOtpEd25519YaoBudgetRecoveryResult = {
  sessionId: string;
  record: ThresholdEd25519SessionRecord;
} & NearEd25519YaoSigningCapability;

export type PreparedEmailOtpEd25519YaoRecoveryV1 = {
  kind: 'prepared_active_email_otp_ed25519_yao_recovery_v1';
  identity: Ed25519YaoActiveClientIdentityV1;
  record: ThresholdEd25519SessionRecord;
  committedLane: Ed25519SigningLane;
  previous: NearEd25519YaoSigningCapability | null;
  expectedOperationalPublicKey: string;
  providerSubject: string;
  signerSlot: number;
};

export type PreparedColdEmailOtpEd25519YaoRecoveryV1 = {
  kind: 'prepared_cold_email_otp_ed25519_yao_recovery_v1';
  identity: Ed25519YaoActiveClientIdentityV1;
  signerSlot: number;
  expectedOperationalPublicKey: string;
  providerSubject: string;
  emailHashHex: string;
  rpId: string;
  relayerUrl: string;
  authPolicy: EmailOtpAuthPolicy;
  remainingUses: number;
  previous: NearEd25519YaoSigningCapability | null;
};

type EmailOtpEd25519YaoUnlockBootstrapV1 =
  | EmailOtpEd25519YaoRecoveryBootstrapV1
  | EmailOtpEd25519YaoExactLocalSessionBootstrapV1;

function requirePositiveInteger(value: unknown, label: string): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1) {
    throw new Error(`${label} must be a positive integer`);
  }
  return parsed;
}

function requireNonEmpty(value: unknown, label: string): string {
  const parsed = String(value ?? '').trim();
  if (!parsed) throw new Error(`${label} is required`);
  return parsed;
}

function buildEmailOtpEd25519LoginRoutePlan(appSessionJwt: string) {
  const authLane = resolveEmailOtpAuthLane({
    appSessionJwt: requireNonEmpty(appSessionJwt, 'appSessionJwt'),
  });
  if (!authLane) {
    throw new Error('Email OTP Ed25519 Yao login requires app session auth');
  }
  return buildFreshEmailOtpRoutePlan({
    freshRouteFamily: 'login',
    authLane,
    operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
  });
}

function sameBytes(
  left: readonly number[] | Uint8Array,
  right: readonly number[] | Uint8Array,
): boolean {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

function sameRuntimePolicyScope(
  left: NonNullable<ThresholdEd25519SessionRecord['runtimePolicyScope']>,
  right: NonNullable<ThresholdEd25519SessionRecord['runtimePolicyScope']>,
): boolean {
  return (
    left.orgId === right.orgId &&
    left.projectId === right.projectId &&
    left.envId === right.envId &&
    left.signingRootVersion === right.signingRootVersion
  );
}

function sameParticipants(left: readonly number[], right: readonly number[]): boolean {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

type WarmBootstrapContinuityField =
  | 'session.walletId'
  | 'session.nearAccountId'
  | 'session.nearEd25519SigningKeyId'
  | 'session.thresholdSessionId'
  | 'session.signingRootId'
  | 'session.signingRootVersion'
  | 'session.routerAbNormalSigning.signingWorkerId'
  | 'session.participantIds'
  | 'session.authorityScope.kind'
  | 'session.authorityScope.provider'
  | 'session.authorityScope.providerUserId'
  | 'session.runtimePolicyScope'
  | 'capability.applicationBinding.wallet_id'
  | 'capability.applicationBinding.near_ed25519_signing_key_id'
  | 'capability.applicationBinding.signing_root_id'
  | 'capability.applicationBinding.key_creation_signer_slot'
  | 'capability.nearAccountId'
  | 'capability.runtimePolicyScope'
  | 'capability.participantIds'
  | 'capability.lifecycle.accountId'
  | 'capability.lifecycle.walletSessionId'
  | 'capability.lifecycle.signerSetId'
  | 'capability.lifecycle.signingWorkerId'
  | 'capability.lifecycle.rootShareEpoch'
  | 'capability.registeredPublicKey'
  | 'capability.stateEpoch'
  | 'capability.activeCapabilityBinding';

function findWarmBootstrapContinuityMismatch(args: {
  bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
  record: ThresholdEd25519SessionRecord;
  lane: Ed25519SigningLane;
  previous: NearEd25519YaoSigningCapability | null;
  expectedOperationalPublicKey: string;
  recordRuntimePolicyScope: NonNullable<ThresholdEd25519SessionRecord['runtimePolicyScope']>;
}): WarmBootstrapContinuityField | null {
  const session = args.bootstrap.session;
  const capability = args.bootstrap.capability;
  const metadata = args.previous?.activeClient.metadata() ?? null;
  const record = args.record;
  if (String(session.walletId) !== String(record.walletId)) return 'session.walletId';
  if (session.nearAccountId !== String(record.nearAccountId)) return 'session.nearAccountId';
  if (session.nearEd25519SigningKeyId !== String(record.nearEd25519SigningKeyId)) {
    return 'session.nearEd25519SigningKeyId';
  }
  if (session.thresholdSessionId !== String(record.thresholdSessionId)) {
    return 'session.thresholdSessionId';
  }
  if (session.signingRootId !== String(record.signingRootId)) return 'session.signingRootId';
  if (session.signingRootVersion !== String(record.signingRootVersion)) {
    return 'session.signingRootVersion';
  }
  if (session.routerAbNormalSigning.signingWorkerId !== record.relayerKeyId) {
    return 'session.routerAbNormalSigning.signingWorkerId';
  }
  if (!sameParticipants(session.participantIds, record.participantIds)) {
    return 'session.participantIds';
  }
  if (session.authorityScope.kind !== 'email_otp') return 'session.authorityScope.kind';
  if (session.authorityScope.provider !== args.lane.authority.factor.provider) {
    return 'session.authorityScope.provider';
  }
  if (session.authorityScope.providerUserId !== args.lane.authority.factor.providerUserId) {
    return 'session.authorityScope.providerUserId';
  }
  if (!sameRuntimePolicyScope(session.runtimePolicyScope, args.recordRuntimePolicyScope)) {
    return 'session.runtimePolicyScope';
  }
  if (capability.applicationBinding.wallet_id !== String(record.walletId)) {
    return 'capability.applicationBinding.wallet_id';
  }
  if (
    capability.applicationBinding.near_ed25519_signing_key_id !==
    String(record.nearEd25519SigningKeyId)
  ) {
    return 'capability.applicationBinding.near_ed25519_signing_key_id';
  }
  if (capability.applicationBinding.signing_root_id !== String(record.signingRootId)) {
    return 'capability.applicationBinding.signing_root_id';
  }
  if (capability.applicationBinding.key_creation_signer_slot !== record.signerSlot) {
    return 'capability.applicationBinding.key_creation_signer_slot';
  }
  if (capability.nearAccountId !== String(record.nearAccountId)) {
    return 'capability.nearAccountId';
  }
  if (!sameRuntimePolicyScope(capability.runtimePolicyScope, args.recordRuntimePolicyScope)) {
    return 'capability.runtimePolicyScope';
  }
  if (!sameParticipants(capability.participantIds, record.participantIds)) {
    return 'capability.participantIds';
  }
  if (capability.lifecycle.accountId !== String(record.walletId)) {
    return 'capability.lifecycle.accountId';
  }
  if (capability.lifecycle.walletSessionId !== String(record.thresholdSessionId)) {
    return 'capability.lifecycle.walletSessionId';
  }
  if (
    capability.lifecycle.signerSetId !== String(registrationNearEd25519BranchKey(record.signerSlot))
  ) {
    return 'capability.lifecycle.signerSetId';
  }
  if (capability.lifecycle.signingWorkerId !== record.relayerKeyId) {
    return 'capability.lifecycle.signingWorkerId';
  }
  if (capability.lifecycle.rootShareEpoch !== String(record.signingRootVersion)) {
    return 'capability.lifecycle.rootShareEpoch';
  }
  if (
    `ed25519:${base58Encode(Uint8Array.from(capability.registeredPublicKey))}` !==
    args.expectedOperationalPublicKey
  ) {
    return 'capability.registeredPublicKey';
  }
  if (metadata === null) return null;
  if (BigInt(capability.stateEpoch) !== metadata.stateEpoch) return 'capability.stateEpoch';
  if (!sameBytes(capability.activeCapabilityBinding, metadata.activeCapabilityBinding)) {
    return 'capability.activeCapabilityBinding';
  }
  if (!sameBytes(capability.registeredPublicKey, metadata.registeredPublicKey)) {
    return 'capability.registeredPublicKey';
  }
  return null;
}

function assertBootstrapContinuity(args: {
  bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
  record: ThresholdEd25519SessionRecord;
  lane: Ed25519SigningLane;
  previous: NearEd25519YaoSigningCapability | null;
  expectedOperationalPublicKey: string;
}): void {
  const bootstrap = args.bootstrap;
  const recordRuntimePolicyScope = args.record.runtimePolicyScope;
  if (!recordRuntimePolicyScope) {
    throw new Error('Email OTP Ed25519 Yao recovery requires runtime policy scope');
  }
  const mismatch = findWarmBootstrapContinuityMismatch({
    ...args,
    recordRuntimePolicyScope,
  });
  if (mismatch !== null) {
    throw new Error(
      `Email OTP Ed25519 Yao recovery changed the active wallet identity: ${mismatch}`,
    );
  }
}

async function assertBootstrapContinuityOrDisposePending(args: {
  bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
  record: ThresholdEd25519SessionRecord;
  lane: Ed25519SigningLane;
  previous: NearEd25519YaoSigningCapability | null;
  expectedOperationalPublicKey: string;
  workerContext: WorkerOperationContext;
  pendingFactorHandle: EmailOtpEd25519YaoPendingFactorHandle;
}): Promise<void> {
  try {
    assertBootstrapContinuity(args);
  } catch (error) {
    try {
      const removed = await disposeEmailOtpEd25519YaoPendingFactorV1({
        workerContext: args.workerContext,
        pendingFactorHandle: args.pendingFactorHandle,
      });
      if (!removed) {
        throw new Error('Email OTP Ed25519 Yao pending factor was unavailable for disposal');
      }
    } catch (disposalError) {
      throw new AggregateError(
        [error, disposalError],
        'Email OTP Ed25519 Yao bootstrap continuity failed and pending-factor disposal failed',
      );
    }
    throw error;
  }
}

function persistRecoveredSession(args: {
  bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
  previousRecord: ThresholdEd25519SessionRecord;
}): ThresholdEd25519SessionRecord {
  const emailOtpAuthContext = args.previousRecord.emailOtpAuthContext;
  if (args.previousRecord.source !== 'email_otp' || !emailOtpAuthContext) {
    throw new Error('Email OTP Ed25519 Yao recovery requires Email OTP session authority');
  }
  const session = args.bootstrap.session;
  return persistWarmSessionEd25519Capability({
    kind: 'jwt_email_otp',
    walletId: String(session.walletId),
    nearAccountId: args.previousRecord.nearAccountId,
    nearEd25519SigningKeyId: session.nearEd25519SigningKeyId,
    rpId: requireNonEmpty(args.previousRecord.rpId, 'rpId'),
    relayerUrl: requireNonEmpty(args.previousRecord.relayerUrl, 'relayerUrl'),
    relayerKeyId: requireNonEmpty(args.previousRecord.relayerKeyId, 'relayerKeyId'),
    runtimePolicyScope: session.runtimePolicyScope,
    participantIds: session.participantIds,
    sessionId: session.thresholdSessionId,
    signingGrantId: session.signingGrantId,
    expiresAtMs: session.expiresAtMs,
    remainingUses: session.remainingUses,
    signerSlot: requirePositiveInteger(args.previousRecord.signerSlot, 'signerSlot'),
    routerAbNormalSigning: session.routerAbNormalSigning,
    jwt: session.walletSessionJwt,
    source: 'email_otp',
    emailOtpAuthContext,
  });
}

export async function prepareEmailOtpEd25519YaoRecoveryV1(args: {
  nearAccountId: AccountId;
  record: ThresholdEd25519SessionRecord;
  committedLane: Ed25519SigningLane;
  resolveActiveCapability: (
    identity: Ed25519YaoActiveClientIdentityV1,
  ) => NearEd25519YaoSigningCapability | null;
}): Promise<PreparedEmailOtpEd25519YaoRecoveryV1> {
  if (
    args.record.source !== 'email_otp' ||
    !args.record.emailOtpAuthContext ||
    !walletAuthAuthoritiesMatch(
      args.record.emailOtpAuthContext.authority,
      args.committedLane.authority,
    )
  ) {
    throw new Error('Email OTP Ed25519 Yao recovery authority changed');
  }
  const identity: Ed25519YaoActiveClientIdentityV1 = {
    walletId: args.record.walletId,
    nearAccountId: args.nearAccountId,
    thresholdSessionId: requireNonEmpty(args.record.thresholdSessionId, 'thresholdSessionId'),
  };
  const resolved = args.resolveActiveCapability(identity);
  const previous = resolved?.activeClient.status().kind === 'active' ? resolved : null;
  if (!previous) {
    throw new Error('Email OTP Ed25519 Yao recovery requires an active Client');
  }
  const expectedOperationalPublicKey = `ed25519:${base58Encode(
    previous.activeClient.metadata().registeredPublicKey,
  )}`;
  return {
    kind: 'prepared_active_email_otp_ed25519_yao_recovery_v1',
    identity,
    record: args.record,
    committedLane: args.committedLane,
    previous,
    expectedOperationalPublicKey,
    providerSubject: String(args.committedLane.authority.factor.providerUserId),
    signerSlot: requirePositiveInteger(args.record.signerSlot, 'signerSlot'),
  };
}

export function prepareColdEmailOtpEd25519YaoRecoveryV1(args: {
  identity: Ed25519YaoActiveClientIdentityV1;
  signerSlot: number;
  expectedOperationalPublicKey: string;
  providerSubject: string;
  emailHashHex: string;
  rpId: string;
  relayerUrl: string;
  authPolicy: EmailOtpAuthPolicy;
  remainingUses: number;
  resolveActiveCapability: (
    identity: Ed25519YaoActiveClientIdentityV1,
  ) => NearEd25519YaoSigningCapability | null;
}): PreparedColdEmailOtpEd25519YaoRecoveryV1 {
  const resolved = args.resolveActiveCapability(args.identity);
  const previous = resolved?.activeClient.status().kind === 'active' ? resolved : null;
  return {
    kind: 'prepared_cold_email_otp_ed25519_yao_recovery_v1',
    identity: args.identity,
    signerSlot: requirePositiveInteger(args.signerSlot, 'signerSlot'),
    expectedOperationalPublicKey: requireNonEmpty(
      args.expectedOperationalPublicKey,
      'operationalPublicKey',
    ),
    providerSubject: requireNonEmpty(args.providerSubject, 'providerSubject'),
    emailHashHex: requireNonEmpty(args.emailHashHex, 'emailHashHex'),
    rpId: requireNonEmpty(args.rpId, 'rpId'),
    relayerUrl: requireNonEmpty(args.relayerUrl, 'relayerUrl'),
    authPolicy: args.authPolicy,
    remainingUses: requirePositiveInteger(args.remainingUses, 'remainingUses'),
    previous,
  };
}

function assertColdBootstrapContinuity(args: {
  prepared: PreparedColdEmailOtpEd25519YaoRecoveryV1;
  bootstrap: EmailOtpEd25519YaoUnlockBootstrapV1;
}): void {
  const prepared = args.prepared;
  const session = args.bootstrap.session;
  const capability = args.bootstrap.capability;
  const metadata = prepared.previous?.activeClient.metadata() ?? null;
  if (
    session.authorityScope.kind !== 'email_otp' ||
    session.authorityScope.providerUserId !== prepared.providerSubject ||
    String(session.walletId) !== String(prepared.identity.walletId) ||
    session.nearAccountId !== String(prepared.identity.nearAccountId) ||
    session.thresholdSessionId !== prepared.identity.thresholdSessionId ||
    session.remainingUses > prepared.remainingUses ||
    capability.applicationBinding.wallet_id !== String(prepared.identity.walletId) ||
    capability.applicationBinding.key_creation_signer_slot !== prepared.signerSlot ||
    capability.nearAccountId !== String(prepared.identity.nearAccountId) ||
    capability.lifecycle.accountId !== String(prepared.identity.walletId) ||
    capability.lifecycle.walletSessionId !== prepared.identity.thresholdSessionId ||
    capability.lifecycle.signerSetId !==
      String(registrationNearEd25519BranchKey(prepared.signerSlot)) ||
    capability.lifecycle.signingWorkerId !== session.routerAbNormalSigning.signingWorkerId ||
    capability.lifecycle.rootShareEpoch !== session.signingRootVersion ||
    capability.applicationBinding.near_ed25519_signing_key_id !== session.nearEd25519SigningKeyId ||
    capability.applicationBinding.signing_root_id !== session.signingRootId ||
    !sameRuntimePolicyScope(capability.runtimePolicyScope, session.runtimePolicyScope) ||
    !sameParticipants(capability.participantIds, session.participantIds) ||
    `ed25519:${base58Encode(Uint8Array.from(capability.registeredPublicKey))}` !==
      prepared.expectedOperationalPublicKey ||
    (metadata !== null &&
      (BigInt(capability.stateEpoch) !== metadata.stateEpoch ||
        !sameBytes(capability.activeCapabilityBinding, metadata.activeCapabilityBinding) ||
        !sameBytes(capability.registeredPublicKey, metadata.registeredPublicKey)))
  ) {
    throw new Error('Email OTP Ed25519 Yao cold recovery changed the registered wallet identity');
  }
}

async function assertColdBootstrapContinuityOrDisposePending(args: {
  prepared: PreparedColdEmailOtpEd25519YaoRecoveryV1;
  bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
  workerContext: WorkerOperationContext;
  pendingFactorHandle: EmailOtpEd25519YaoPendingFactorHandle;
}): Promise<void> {
  try {
    assertColdBootstrapContinuity(args);
  } catch (error) {
    try {
      const removed = await disposeEmailOtpEd25519YaoPendingFactorV1(args);
      if (!removed) {
        throw new Error('Email OTP Ed25519 Yao pending factor was unavailable for disposal');
      }
    } catch (disposalError) {
      throw new AggregateError(
        [error, disposalError],
        'Email OTP Ed25519 Yao cold continuity failed and pending-factor disposal failed',
      );
    }
    throw error;
  }
}

function persistColdRecoveredSession(args: {
  prepared: PreparedColdEmailOtpEd25519YaoRecoveryV1;
  bootstrap: EmailOtpEd25519YaoUnlockBootstrapV1;
}): ThresholdEd25519SessionRecord {
  const session = args.bootstrap.session;
  const signerSlot = requirePositiveInteger(
    args.bootstrap.capability.applicationBinding.key_creation_signer_slot,
    'server capability signerSlot',
  );
  if (session.authorityScope.kind !== 'email_otp') {
    throw new Error('Email OTP Ed25519 Yao recovery returned another authority kind');
  }
  const emailOtpAuthContext = buildEmailOtpAuthContextForWalletAuthMethod({
    policy: args.prepared.authPolicy,
    walletId: session.walletId,
    emailHashHex: args.prepared.emailHashHex,
    retention: 'session',
    reason: 'login',
    provider: session.authorityScope.provider,
    providerUserId: session.authorityScope.providerUserId,
  });
  return persistWarmSessionEd25519Capability({
    kind: 'jwt_email_otp',
    walletId: String(session.walletId),
    nearAccountId: toAccountId(session.nearAccountId),
    nearEd25519SigningKeyId: session.nearEd25519SigningKeyId,
    rpId: args.prepared.rpId,
    relayerUrl: args.prepared.relayerUrl,
    relayerKeyId: session.routerAbNormalSigning.signingWorkerId,
    runtimePolicyScope: session.runtimePolicyScope,
    participantIds: session.participantIds,
    sessionId: session.thresholdSessionId,
    signingGrantId: session.signingGrantId,
    expiresAtMs: session.expiresAtMs,
    remainingUses: session.remainingUses,
    signerSlot,
    routerAbNormalSigning: session.routerAbNormalSigning,
    jwt: session.walletSessionJwt,
    source: 'email_otp',
    emailOtpAuthContext,
  });
}

export async function activateColdEmailOtpEd25519YaoLocalSessionV1(args: {
  prepared: PreparedColdEmailOtpEd25519YaoRecoveryV1;
  bootstrap: EmailOtpEd25519YaoExactLocalSessionBootstrapV1;
  activeClientHandle: string;
  metadata: RouterAbEd25519YaoActiveClientMetadataV1;
  workerContext: WorkerOperationContext;
  activateCapability: (
    capability: NearEd25519YaoSigningCapability,
  ) => Promise<Ed25519YaoActiveClientIdentityV1>;
}): Promise<EmailOtpEd25519YaoBudgetRecoveryResult> {
  assertColdBootstrapContinuity(args);
  let activeClient: NearEd25519YaoSigningCapability['activeClient'] | null =
    new EmailOtpEd25519YaoWorkerActiveClientV1(
      args.workerContext,
      args.activeClientHandle,
      args.metadata,
    );
  try {
    const record = persistColdRecoveredSession({
      prepared: args.prepared,
      bootstrap: args.bootstrap,
    });
    const walletSessionState = resolveRouterAbEd25519WalletSessionStateFromRecord(record);
    if (!walletSessionState) {
      throw new Error('Email OTP Ed25519 local custody returned unusable Wallet Session state');
    }
    const capability: NearEd25519YaoSigningCapability = { activeClient, walletSessionState };
    const identity = await args.activateCapability(capability);
    if (
      String(identity.walletId) !== String(args.prepared.identity.walletId) ||
      String(identity.nearAccountId) !== String(args.prepared.identity.nearAccountId) ||
      identity.thresholdSessionId !== args.prepared.identity.thresholdSessionId
    ) {
      throw new Error('Email OTP Ed25519 local custody activated a different identity');
    }
    activeClient = null;
    return { sessionId: walletSessionState.thresholdSessionId, record, ...capability };
  } finally {
    activeClient?.dispose();
  }
}

export async function activateColdEmailOtpEd25519YaoUnlockedRecoveryV1(args: {
  prepared: PreparedColdEmailOtpEd25519YaoRecoveryV1;
  bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
  pendingFactorHandle: EmailOtpEd25519YaoPendingFactorHandle;
  workerContext: WorkerOperationContext;
  activateCapability: (
    capability: NearEd25519YaoSigningCapability,
  ) => Promise<Ed25519YaoActiveClientIdentityV1>;
}): Promise<EmailOtpEd25519YaoBudgetRecoveryResult> {
  await assertColdBootstrapContinuityOrDisposePending(args);
  const expectedPriorMetadata = args.prepared.previous
    ? args.prepared.previous.activeClient.metadata()
    : buildEmailOtpEd25519YaoRecoveryContinuityMetadataV1(args.bootstrap);
  const authorityScope = args.bootstrap.session.authorityScope;
  if (authorityScope.kind !== 'email_otp') {
    throw new Error('Email OTP Ed25519 Yao recovery returned another authority kind');
  }
  const authority = buildEmailOtpAuthContextForWalletAuthMethod({
    policy: args.prepared.authPolicy,
    walletId: args.bootstrap.session.walletId,
    emailHashHex: args.prepared.emailHashHex,
    retention: 'session',
    reason: 'login',
    provider: authorityScope.provider,
    providerUserId: args.prepared.providerSubject,
  }).authority;
  const recovered = await recoverEmailOtpEd25519YaoWorkerClientV1({
    workerContext: args.workerContext,
    pendingFactorHandle: args.pendingFactorHandle,
    bootstrap: args.bootstrap,
    expectedPriorMetadata,
    providerSubject: args.prepared.providerSubject,
    registrationAuthorityId: String(authority.bindingId),
    routerOrigin: new URL(args.prepared.relayerUrl).origin,
  });
  let activeClient: NearEd25519YaoSigningCapability['activeClient'] | null = recovered.activeClient;
  try {
    const record = persistColdRecoveredSession({
      prepared: args.prepared,
      bootstrap: args.bootstrap,
    });
    const walletSessionState = resolveRouterAbEd25519WalletSessionStateFromRecord(record);
    if (!walletSessionState) {
      throw new Error('Email OTP Ed25519 Yao recovery returned unusable Wallet Session state');
    }
    const capability: NearEd25519YaoSigningCapability = { activeClient, walletSessionState };
    const activatedIdentity = await args.activateCapability(capability);
    if (
      String(activatedIdentity.walletId) !== String(args.prepared.identity.walletId) ||
      String(activatedIdentity.nearAccountId) !== String(args.prepared.identity.nearAccountId) ||
      activatedIdentity.thresholdSessionId !== args.prepared.identity.thresholdSessionId
    ) {
      throw new Error('Email OTP Ed25519 Yao recovery activated a different identity');
    }
    activeClient = null;
    return { sessionId: walletSessionState.thresholdSessionId, record, ...capability };
  } finally {
    activeClient?.dispose();
  }
}

export async function recoverColdEmailOtpEd25519CapabilityForLoginV1(args: {
  prepared: PreparedColdEmailOtpEd25519YaoRecoveryV1;
  challengeId: string;
  otpCode: string;
  appSessionJwt: string;
  shamirPrimeB64u: string | undefined;
  workerContext: WorkerOperationContext;
  activateCapability: (
    capability: NearEd25519YaoSigningCapability,
  ) => Promise<Ed25519YaoActiveClientIdentityV1>;
}): Promise<EmailOtpEd25519YaoBudgetRecoveryResult> {
  const appSessionJwt = requireNonEmpty(args.appSessionJwt, 'appSessionJwt');
  const runtimePolicyScope = parseThresholdRuntimePolicyScopeFromJwt(appSessionJwt);
  if (!runtimePolicyScope) {
    throw new Error('Email OTP Ed25519 Yao cold recovery requires runtime policy scope');
  }
  const unlocked = await unlockEmailOtpEd25519YaoSession({
    walletSession: {
      walletId: args.prepared.identity.walletId,
      walletSessionUserId: args.prepared.providerSubject,
    },
    relayUrl: args.prepared.relayerUrl,
    shamirPrimeB64u: requireNonEmpty(args.shamirPrimeB64u, 'shamirPrimeB64u'),
    otpCode: requireNonEmpty(args.otpCode, 'otpCode'),
    challengeId: requireNonEmpty(args.challengeId, 'challengeId'),
    routePlan: buildEmailOtpEd25519LoginRoutePlan(appSessionJwt),
    workerCtx: args.workerContext,
    providerSubject: args.prepared.providerSubject,
    signerSlot: args.prepared.signerSlot,
    remainingUses: args.prepared.remainingUses,
    orgId: runtimePolicyScope.orgId,
    nearAccountId: String(args.prepared.identity.nearAccountId),
    expectedOperationalPublicKey: args.prepared.expectedOperationalPublicKey,
    expectedThresholdSessionId: args.prepared.identity.thresholdSessionId,
  });
  if (unlocked.kind === 'ed25519_yao_local_session') {
    return await activateColdEmailOtpEd25519YaoLocalSessionV1({
      prepared: args.prepared,
      bootstrap: unlocked.ed25519YaoSession,
      activeClientHandle: unlocked.activeClientHandle,
      metadata: unlocked.metadata,
      workerContext: args.workerContext,
      activateCapability: args.activateCapability,
    });
  }
  return await activateColdEmailOtpEd25519YaoUnlockedRecoveryV1({
    prepared: args.prepared,
    bootstrap: unlocked.ed25519YaoRecovery,
    pendingFactorHandle: unlocked.pendingFactorHandle,
    workerContext: args.workerContext,
    activateCapability: args.activateCapability,
  });
}

export async function activateEmailOtpEd25519YaoUnlockedRecoveryV1(args: {
  prepared: PreparedEmailOtpEd25519YaoRecoveryV1;
  bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
  pendingFactorHandle: EmailOtpEd25519YaoPendingFactorHandle;
  workerContext: WorkerOperationContext;
  activateCapability: (
    capability: NearEd25519YaoSigningCapability,
  ) => Promise<Ed25519YaoActiveClientIdentityV1>;
}): Promise<EmailOtpEd25519YaoBudgetRecoveryResult> {
  const prepared = args.prepared;
  await assertBootstrapContinuityOrDisposePending({
    bootstrap: args.bootstrap,
    record: prepared.record,
    lane: prepared.committedLane,
    previous: prepared.previous,
    expectedOperationalPublicKey: prepared.expectedOperationalPublicKey,
    workerContext: args.workerContext,
    pendingFactorHandle: args.pendingFactorHandle,
  });
  const expectedPriorMetadata = prepared.previous
    ? prepared.previous.activeClient.metadata()
    : buildEmailOtpEd25519YaoRecoveryContinuityMetadataV1(args.bootstrap);
  const recovered = await recoverEmailOtpEd25519YaoWorkerClientV1({
    workerContext: args.workerContext,
    pendingFactorHandle: args.pendingFactorHandle,
    bootstrap: args.bootstrap,
    expectedPriorMetadata,
    providerSubject: prepared.providerSubject,
    registrationAuthorityId: String(prepared.committedLane.authority.bindingId),
    routerOrigin: new URL(prepared.record.relayerUrl).origin,
  });
  let activeClient: NearEd25519YaoSigningCapability['activeClient'] | null = recovered.activeClient;
  try {
    const record = persistRecoveredSession({
      bootstrap: args.bootstrap,
      previousRecord: prepared.record,
    });
    const walletSessionState = resolveRouterAbEd25519WalletSessionStateFromRecord(record);
    if (!walletSessionState) {
      throw new Error('Email OTP Ed25519 Yao recovery returned unusable Wallet Session state');
    }
    const capability: NearEd25519YaoSigningCapability = {
      activeClient,
      walletSessionState,
    };
    const activatedIdentity = await args.activateCapability(capability);
    if (
      String(activatedIdentity.walletId) !== String(prepared.identity.walletId) ||
      String(activatedIdentity.nearAccountId) !== String(prepared.identity.nearAccountId) ||
      activatedIdentity.thresholdSessionId !== prepared.identity.thresholdSessionId
    ) {
      throw new Error('Email OTP Ed25519 Yao recovery activated a different identity');
    }
    activeClient = null;
    return {
      sessionId: walletSessionState.thresholdSessionId,
      record,
      ...capability,
    };
  } finally {
    activeClient?.dispose();
  }
}

export async function rehydrateEmailOtpEd25519CapabilityForSigningV1(args: {
  nearAccountId: AccountId;
  record: ThresholdEd25519SessionRecord;
  committedLane: Ed25519SigningLane;
  challengeId: string;
  otpCode: string;
  remainingUses: number;
  expectedOperationalPublicKey: string;
  workerContext: WorkerOperationContext;
  shamirPrimeB64u: string | undefined;
  resolveActiveCapability: (
    identity: Ed25519YaoActiveClientIdentityV1,
  ) => NearEd25519YaoSigningCapability | null;
  activateCapability: (
    capability: NearEd25519YaoSigningCapability,
  ) => Promise<Ed25519YaoActiveClientIdentityV1>;
}): Promise<EmailOtpEd25519YaoBudgetRecoveryResult> {
  const thresholdSessionId = requireNonEmpty(args.record.thresholdSessionId, 'thresholdSessionId');
  const identity: Ed25519YaoActiveClientIdentityV1 = {
    walletId: args.record.walletId,
    nearAccountId: args.nearAccountId,
    thresholdSessionId,
  };
  const emailOtpAuthContext = args.record.emailOtpAuthContext;
  if (args.record.source !== 'email_otp' || !emailOtpAuthContext) {
    throw new Error('Email OTP Ed25519 Yao recovery requires Email OTP session authority');
  }
  const prepared = prepareColdEmailOtpEd25519YaoRecoveryV1({
    identity,
    signerSlot: args.record.signerSlot,
    expectedOperationalPublicKey: args.expectedOperationalPublicKey,
    providerSubject: emailOtpAuthContextProviderUserId(emailOtpAuthContext),
    emailHashHex: emailOtpAuthContextEmailHashHex(emailOtpAuthContext),
    rpId: args.record.rpId,
    relayerUrl: args.record.relayerUrl,
    authPolicy: emailOtpAuthContext.policy,
    remainingUses: args.remainingUses,
    resolveActiveCapability: args.resolveActiveCapability,
  });
  const unlocked = await unlockEmailOtpEd25519YaoExactLocalSession({
    walletSession: {
      walletId: args.record.walletId,
      walletSessionUserId: prepared.providerSubject,
    },
    relayUrl: requireNonEmpty(args.record.relayerUrl, 'relayerUrl'),
    shamirPrimeB64u: requireNonEmpty(args.shamirPrimeB64u, 'shamirPrimeB64u'),
    otpCode: requireNonEmpty(args.otpCode, 'otpCode'),
    challengeId: requireNonEmpty(args.challengeId, 'challengeId'),
    routePlan: buildEmailOtpSigningSessionRoutePlan({
      authLane: args.committedLane.authLane,
      operation: WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
    }),
    workerCtx: args.workerContext,
    providerSubject: prepared.providerSubject,
    signerSlot: prepared.signerSlot,
    remainingUses: requirePositiveInteger(args.remainingUses, 'remainingUses'),
    orgId: requireNonEmpty(args.record.runtimePolicyScope?.orgId, 'orgId'),
    nearAccountId: String(args.nearAccountId),
    expectedOperationalPublicKey: args.expectedOperationalPublicKey,
    expectedThresholdSessionId: prepared.identity.thresholdSessionId,
  });
  return await activateColdEmailOtpEd25519YaoLocalSessionV1({
    prepared,
    bootstrap: unlocked.ed25519YaoSession,
    activeClientHandle: unlocked.activeClientHandle,
    metadata: unlocked.metadata,
    workerContext: args.workerContext,
    activateCapability: args.activateCapability,
  });
}
