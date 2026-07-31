import { toAccountId } from '@/core/types/accountIds';
import type { NearEd25519YaoSigningCapability } from '@/core/signingEngine/interfaces/near';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type {
  EmailOtpEd25519YaoExactLocalSessionBootstrapV1,
  EmailOtpEd25519YaoRecoveryBootstrapV1,
} from '@/core/signingEngine/workerManager/workerTypes';
import { WALLET_EMAIL_OTP_UNLOCK_OPERATION } from '@shared/utils/emailOtpDomain';
import { base58Encode } from '@shared/utils/base58';
import {
  nearEd25519SigningKeyIdFromString,
  registrationNearEd25519BranchKey,
} from '@shared/utils/registrationIntent';
import type { ThresholdEd25519SessionId } from '../operationState/types';
import { buildEmailOtpRouterAbEd25519WalletSessionState } from '../warmCapabilities/routerAbEd25519WalletSessionState';
import type {
  Ed25519YaoActiveClientIdentityV1,
  Ed25519YaoActiveClientLookupScopeV1,
} from '../../threshold/ed25519/yaoActiveClientRegistry';
import { buildFreshEmailOtpRoutePlan } from './routePlan';
import { resolveEmailOtpAuthLane } from '../../stepUpConfirmation/otpPrompt/authLane';
import type { EmailOtpEd25519YaoPendingFactorHandle } from './ed25519YaoRootVault';
import { unlockEmailOtpEd25519YaoSession } from './walletUnlock';
import {
  buildEmailOtpEd25519YaoRecoveryContinuityMetadataV1,
  disposeEmailOtpEd25519YaoPendingFactorV1,
  recoverEmailOtpEd25519YaoWorkerClientV1,
  EmailOtpEd25519YaoWorkerActiveClientV1,
} from './ed25519YaoWorkerClient';
import type { RouterAbEd25519YaoActiveClientMetadataV1 } from '../../threshold/ed25519/yaoClient';
import type { EmailOtpAuthPolicy } from '@/core/types/seams';
import { buildEmailOtpAuthContextForWalletAuthMethod } from '../identity/laneIdentity';
import type { ThresholdRuntimePolicyScope } from '../../threshold/sessionPolicy';
import {
  mpcMaterialActivationRefsEqual,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';
import type { EmailOtpEd25519YaoPublicationContext } from './ed25519YaoPublication';
import { buildRouterAbEd25519SigningWalletSession } from '../routerAbSigningWalletSession';

export type EmailOtpEd25519YaoBudgetRecoveryResult = {
  sessionId: string;
  publicationContext: EmailOtpEd25519YaoPublicationContext;
} & NearEd25519YaoSigningCapability;

export type PreparedColdEmailOtpEd25519YaoRecoveryV1 = {
  kind: 'prepared_cold_email_otp_ed25519_yao_recovery_v1';
  identity: Ed25519YaoActiveClientIdentityV1;
  thresholdSessionId: ThresholdEd25519SessionId;
  signerSlot: number;
  expectedOperationalPublicKey: string;
  providerSubject: string;
  emailHashHex: string;
  rpId: string;
  relayerUrl: string;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
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

function isFreshActivationForSameSigner(
  previous: MpcMaterialActivationRef,
  next: MpcMaterialActivationRef,
): boolean {
  return (
    !mpcMaterialActivationRefsEqual(previous, next) &&
    previous.materialOwner === next.materialOwner &&
    previous.keyBinding === next.keyBinding &&
    previous.signingWorker === next.signingWorker
  );
}

function buildEmailOtpEd25519YaoPublicationContext(args: {
  prepared: PreparedColdEmailOtpEd25519YaoRecoveryV1;
  bootstrap: EmailOtpEd25519YaoUnlockBootstrapV1;
}): EmailOtpEd25519YaoPublicationContext {
  const authorityScope = args.bootstrap.session.authorityScope;
  if (authorityScope.kind !== 'email_otp') {
    throw new Error('Email OTP Ed25519 publication requires Email OTP authority');
  }
  const providerSubjectId = requireNonEmpty(
    args.prepared.providerSubject,
    'providerSubjectId',
  );
  if (authorityScope.providerUserId !== providerSubjectId) {
    throw new Error('Email OTP Ed25519 publication authority subject mismatch');
  }
  return {
    rpId: requireNonEmpty(args.prepared.rpId, 'rpId'),
    provider: authorityScope.provider,
    providerSubjectId,
    emailHashHex: requireNonEmpty(args.prepared.emailHashHex, 'emailHashHex'),
    materialActivation: args.prepared.identity.materialActivation,
  };
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
  left: ThresholdRuntimePolicyScope,
  right: ThresholdRuntimePolicyScope,
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

export function prepareColdEmailOtpEd25519YaoRecoveryV1(args: {
  identity: Ed25519YaoActiveClientIdentityV1;
  thresholdSessionId: ThresholdEd25519SessionId;
  signerSlot: number;
  expectedOperationalPublicKey: string;
  providerSubject: string;
  emailHashHex: string;
  rpId: string;
  relayerUrl: string;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  authPolicy: EmailOtpAuthPolicy;
  remainingUses: number;
  resolveActiveCapability: (
    scope: Ed25519YaoActiveClientLookupScopeV1,
  ) => NearEd25519YaoSigningCapability | null;
}): PreparedColdEmailOtpEd25519YaoRecoveryV1 {
  const resolved = args.resolveActiveCapability(args.identity);
  const previous = resolved?.activeClient.status().kind === 'active' ? resolved : null;
  return {
    kind: 'prepared_cold_email_otp_ed25519_yao_recovery_v1',
    identity: args.identity,
    thresholdSessionId: args.thresholdSessionId,
    signerSlot: requirePositiveInteger(args.signerSlot, 'signerSlot'),
    expectedOperationalPublicKey: requireNonEmpty(
      args.expectedOperationalPublicKey,
      'operationalPublicKey',
    ),
    providerSubject: requireNonEmpty(args.providerSubject, 'providerSubject'),
    emailHashHex: requireNonEmpty(args.emailHashHex, 'emailHashHex'),
    rpId: requireNonEmpty(args.rpId, 'rpId'),
    relayerUrl: requireNonEmpty(args.relayerUrl, 'relayerUrl'),
    runtimePolicyScope: args.runtimePolicyScope,
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
    session.thresholdSessionId !== prepared.thresholdSessionId ||
    session.remainingUses > prepared.remainingUses ||
    capability.applicationBinding.wallet_id !== String(prepared.identity.walletId) ||
    capability.applicationBinding.key_creation_signer_slot !== prepared.signerSlot ||
    capability.nearAccountId !== String(prepared.identity.nearAccountId) ||
    capability.lifecycle.accountId !== String(prepared.identity.walletId) ||
    capability.lifecycle.thresholdSessionId !== prepared.thresholdSessionId ||
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

function buildColdRecoveredWalletSessionState(args: {
  prepared: PreparedColdEmailOtpEd25519YaoRecoveryV1;
  bootstrap: EmailOtpEd25519YaoUnlockBootstrapV1;
}) {
  const session = args.bootstrap.session;
  if (session.authorityScope.kind !== 'email_otp') {
    throw new Error('Email OTP Ed25519 Yao recovery returned another authority kind');
  }
  const signingWalletSession = buildRouterAbEd25519SigningWalletSession({
    walletId: String(session.walletId),
    nearAccountId: session.nearAccountId,
    nearEd25519SigningKeyId: session.nearEd25519SigningKeyId,
    thresholdSessionId: session.thresholdSessionId,
    signingGrantId: session.signingGrantId,
    remainingUses: session.remainingUses,
    expiresAtMs: session.expiresAtMs,
    runtimePolicyScope: session.runtimePolicyScope,
    signingRootId: session.signingRootId,
    signingRootVersion: session.signingRootVersion,
    routerAbNormalSigning: session.routerAbNormalSigning,
    walletSessionJwt: session.walletSessionJwt,
    nowMs: Date.now(),
  });
  if (!signingWalletSession.ok) {
    throw new Error(
      `Email OTP Ed25519 Yao recovery returned unusable Wallet Session state (${signingWalletSession.reason})`,
    );
  }
  return buildEmailOtpRouterAbEd25519WalletSessionState({
    walletId: session.walletId,
    nearAccountId: toAccountId(session.nearAccountId),
    nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString(
      session.nearEd25519SigningKeyId,
    ),
    providerSubjectId: session.authorityScope.providerUserId,
    signerSlot: requirePositiveInteger(
      args.bootstrap.capability.applicationBinding.key_creation_signer_slot,
      'server capability signerSlot',
    ),
    relayerUrl: args.prepared.relayerUrl,
    signingWalletSession: signingWalletSession.value,
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
    const walletSessionState = buildColdRecoveredWalletSessionState(args);
    const capability: NearEd25519YaoSigningCapability = { activeClient, walletSessionState };
    const identity = await args.activateCapability(capability);
    if (
      String(identity.walletId) !== String(args.prepared.identity.walletId) ||
      String(identity.nearAccountId) !== String(args.prepared.identity.nearAccountId) ||
      !mpcMaterialActivationRefsEqual(
        identity.materialActivation,
        args.prepared.identity.materialActivation,
      )
    ) {
      throw new Error('Email OTP Ed25519 local custody activated a different identity');
    }
    activeClient = null;
    return {
      sessionId: walletSessionState.thresholdSessionId,
      publicationContext: buildEmailOtpEd25519YaoPublicationContext(args),
      ...capability,
    };
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
    const walletSessionState = buildColdRecoveredWalletSessionState(args);
    const capability: NearEd25519YaoSigningCapability = { activeClient, walletSessionState };
    const activatedIdentity = await args.activateCapability(capability);
    if (
      String(activatedIdentity.walletId) !== String(args.prepared.identity.walletId) ||
      String(activatedIdentity.nearAccountId) !== String(args.prepared.identity.nearAccountId) ||
      !isFreshActivationForSameSigner(
        args.prepared.identity.materialActivation,
        activatedIdentity.materialActivation,
      )
    ) {
      throw new Error('Email OTP Ed25519 Yao recovery activated a different identity');
    }
    activeClient = null;
    return {
      sessionId: walletSessionState.thresholdSessionId,
      publicationContext: buildEmailOtpEd25519YaoPublicationContext(args),
      ...capability,
    };
  } finally {
    activeClient?.dispose();
  }
}

export async function recoverColdEmailOtpEd25519CapabilityForLoginV1(args: {
  prepared: PreparedColdEmailOtpEd25519YaoRecoveryV1;
  challengeId: string;
  otpCode: string;
  appSessionJwt: string;
  groupId: string | undefined;
  workerContext: WorkerOperationContext;
  activateCapability: (
    capability: NearEd25519YaoSigningCapability,
  ) => Promise<Ed25519YaoActiveClientIdentityV1>;
}): Promise<EmailOtpEd25519YaoBudgetRecoveryResult> {
  const appSessionJwt = requireNonEmpty(args.appSessionJwt, 'appSessionJwt');
  const runtimePolicyScope = args.prepared.runtimePolicyScope;
  const unlocked = await unlockEmailOtpEd25519YaoSession({
    walletSession: {
      walletId: args.prepared.identity.walletId,
      walletSessionUserId: args.prepared.providerSubject,
    },
    relayUrl: args.prepared.relayerUrl,
    groupId: requireNonEmpty(args.groupId, 'groupId'),
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
    expectedThresholdSessionId: args.prepared.thresholdSessionId,
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
