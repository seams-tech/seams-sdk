import type { EmailOtpAuthPolicy, SeamsConfigsReadonly } from '@/core/types/seams';
import {
  buildEmailOtpAuthContextForWalletAuthMethod,
  emailOtpAuthContextEmailHashHex,
  emailOtpAuthContextProviderUserId,
  isEmailOtpPendingSingleUseAuthContext,
  isEmailOtpSessionAuthContext,
  type ThresholdEcdsaEmailOtpAuthContext,
  type ThresholdEcdsaEmailOtpPendingSingleUseAuthContext,
} from '@/core/signingEngine/session/identity/laneIdentity';
import type {
  ThresholdEcdsaChainTarget,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  thresholdEcdsaChainTargetsEqual,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import {
  generateSigningGrantId,
  parseThresholdRuntimePolicyScopeFromJwt,
} from '@/core/signingEngine/threshold/sessionPolicy';
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import type { WarmSessionEcdsaCapabilityState } from '@/core/signingEngine/session/warmCapabilities/types';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type {
  EmailOtpEd25519YaoRecoveryBootstrapV1,
  EmailOtpEcdsaSessionBootstrapHandlePayload,
  EmailOtpWorkerProgressEvent,
  EmailOtpWorkerSessionHandleOperation,
} from '@/core/signingEngine/workerManager/workerTypes';
import type {
  EmailOtpEcdsaCommittedLane,
  EmailOtpEcdsaPublicReauthLane,
} from '../../flows/signEvmFamily/ecdsaSelection';
import {
  WALLET_EMAIL_OTP_EXPORT_OPERATION,
  WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
  WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
  WALLET_EMAIL_OTP_UNLOCK_OPERATION,
  type WalletEmailOtpLoginOperation,
  type WalletEmailOtpOperation,
  type WalletEmailOtpExportOperation,
} from '@shared/utils/emailOtpDomain';
import type { EmailOtpBootstrapRecovery } from '../../stepUpConfirmation/otpPrompt/bootstrapRecovery';
import {
  buildEvmFamilyEcdsaSessionLanePolicy,
  deriveEvmFamilySigningKeySlotIdFromRuntimePolicyScope,
  toEvmFamilyEcdsaKeyHandle,
} from '../identity/evmFamilyEcdsaIdentity';
import {
  buildEmailOtpRoutePlan,
  type EmailOtpAuthLane,
  type EmailOtpRoutePlan,
} from '../../stepUpConfirmation/otpPrompt/authLane';
import {
  appSessionJwtFromEmailOtpAuthLane,
  appSessionSubjectFromEmailOtpAuthLane,
} from './appSessionJwtCache';
import {
  commitEmailOtpEcdsaPublicationBootstraps,
  emailOtpEcdsaPublicationChainTargets,
  projectEmailOtpExistingEcdsaKeyToChainTarget,
  resolveEmailOtpExistingEcdsaKey,
  type EmailOtpEcdsaPublicationTimings,
  type EmailOtpEcdsaPublicationPorts,
  type ResolvedEmailOtpExistingEcdsaKey,
} from './ecdsaPublication';
import {
  unlockEmailOtpMixedWallet,
  unlockEmailOtpWallet,
  type EmailOtpMixedWalletUnlockResult,
  type EmailOtpWalletUnlockResult,
} from './walletUnlock';
import type { EmailOtpEd25519YaoPendingFactorHandle } from './ed25519YaoRootVault';
import type { EmailOtpMixedWalletSigningBudgetV1 } from '../../workerManager/workerTypes';
import { disposeEmailOtpEd25519YaoPendingFactorV1 } from './ed25519YaoWorkerClient';
import {
  DEFAULT_THRESHOLD_SESSION_POLICY,
  clampThresholdSessionPolicy,
} from '../../threshold/sessionPolicy';
import {
  assertEmailOtpSigningSessionAuthLane,
  buildEmailOtpEcdsaMintingSession,
  buildEmailOtpSigningSessionRoutePlan,
  emailOtpEcdsaBootstrapRouteAuthFromRoutePlan,
  emailOtpEcdsaBootstrapRouteAuthToTransport,
  routeAuthFromEmailOtpRoutePlan,
  type EmailOtpEcdsaBootstrapAuthorization,
} from './routePlan';
import type { ThresholdEcdsaSessionRecord } from '../persistence/records';
import { thresholdEcdsaEmailOtpAuthContext } from '../persistence/records';
import {
  DEV_DEFAULT_UNLOCK_REMAINING_USES,
  normalizeStepUpOperationId,
  resolvePostExhaustionStepUpBudgetPolicy,
  resolveSigningBudgetPolicyRemainingUses,
  resolveWalletUnlockBudgetPolicyFromRequestedUses,
} from '../budget/policy';
import {
  parseEmailOtpEcdsaExportWorkerIssuedSessionHandle,
  parseEmailOtpWorkerIssuedSessionHandle,
  type EmailOtpEcdsaExportWorkerIssuedSessionHandle,
} from '@/core/platform';
import {
  buildEmailOtpExplicitExportEcdsaActivation,
  buildEmailOtpPerOperationReauthEcdsaActivation,
  buildEmailOtpSessionBootstrapEcdsaActivation,
  type ThresholdEcdsaActivationRequest,
  type ThresholdEcdsaEmailOtpExportActivationRequest,
} from '../passkey/ecdsaSessionProvision';
import type { EmailOtpEcdsaExplicitExportBootstrapResult } from '../passkey/ecdsaBootstrap';
import { buildEcdsaSessionIdentity } from '../warmCapabilities/ecdsaProvisionPlan';
import { generateSessionId } from '../passkey/prfCache';
import {
  requestBindEmailOtpEcdsaWarmSessionFromWorkerHandle,
  requestDisposeEmailOtpEcdsaClientRootHandle,
} from './workerRequests';
import type { AppOrWalletSessionAuth } from '@shared/utils/sessionTokens';

export type EmailOtpThresholdEcdsaLoginTimingBucket =
  | 'emailOtpProofVerificationMs'
  | 'ecdsaMaterialRestoreMs'
  | 'signingSessionSealApplyMs'
  | 'warmCapabilityPersistenceMs';

export type EmailOtpThresholdEcdsaLoginTimings = Record<
  EmailOtpThresholdEcdsaLoginTimingBucket,
  number
>;

export type EmailOtpThresholdEcdsaLoginResult = {
  recovery: EmailOtpBootstrapRecovery;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  warmCapability: WarmSessionEcdsaCapabilityState;
  warmCapabilities: readonly [
    WarmSessionEcdsaCapabilityState,
    ...WarmSessionEcdsaCapabilityState[],
  ];
  clientRootShareHandle: EmailOtpEcdsaSessionBootstrapHandlePayload;
  ed25519YaoRecovery:
    | { kind: 'not_requested' }
    | {
        kind: 'unlocked';
        pendingFactorHandle: EmailOtpEd25519YaoPendingFactorHandle;
        bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
      };
  timings: EmailOtpThresholdEcdsaLoginTimings;
};

export type EmailOtpThresholdEcdsaExportPreparation = {
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  timings: EmailOtpThresholdEcdsaLoginTimings;
};

type EmailOtpEcdsaCapabilityRunResult =
  | {
      kind: 'published_signing_session';
      value: EmailOtpThresholdEcdsaLoginResult;
    }
  | {
      kind: 'transient_export';
      value: EmailOtpThresholdEcdsaExportPreparation;
    };

function nowMs(): number {
  return typeof performance !== 'undefined' && typeof performance.now === 'function'
    ? performance.now()
    : Date.now();
}

function createEmailOtpThresholdEcdsaLoginTimings(): EmailOtpThresholdEcdsaLoginTimings {
  return {
    emailOtpProofVerificationMs: 0,
    ecdsaMaterialRestoreMs: 0,
    signingSessionSealApplyMs: 0,
    warmCapabilityPersistenceMs: 0,
  };
}

function addEmailOtpThresholdEcdsaLoginTiming(
  timings: EmailOtpThresholdEcdsaLoginTimings,
  bucket: EmailOtpThresholdEcdsaLoginTimingBucket,
  startedAtMs: number,
): void {
  timings[bucket] += Math.max(0, Math.round(nowMs() - startedAtMs));
}

function mergeEmailOtpEcdsaPublicationTimingsIntoLoginTimings(
  target: EmailOtpThresholdEcdsaLoginTimings,
  source: EmailOtpEcdsaPublicationTimings,
): void {
  target.signingSessionSealApplyMs += source.signingSessionSealApplyMs;
  target.warmCapabilityPersistenceMs += source.warmCapabilityPersistenceMs;
}

export type EmailOtpEcdsaProviderIdentity =
  | {
      kind: 'derive_from_route_auth';
      providerUserId?: never;
    }
  | {
      kind: 'explicit_provider_user';
      providerUserId: string;
    };

function normalizeEmailOtpProviderUserId(value: unknown, field: string): string {
  const normalized = String(value || '').trim();
  if (!normalized) {
    throw new Error(`[SigningEngine][email-otp] ${field} is required`);
  }
  return normalized;
}

export function emailOtpEcdsaProviderIdentityFromRecord(
  record: ThresholdEcdsaSessionRecord,
): EmailOtpEcdsaProviderIdentity {
  if (record.source !== 'email_otp') {
    throw new Error('Email OTP ECDSA signing refresh requires an Email OTP session record');
  }
  return {
    kind: 'explicit_provider_user',
    providerUserId: emailOtpAuthContextProviderUserId(record.emailOtpAuthContext),
  };
}

function resolveEmailOtpEcdsaProviderUserId(args: {
  identity: EmailOtpEcdsaProviderIdentity;
  routePlan: EmailOtpRoutePlan;
  walletSession: WalletSessionRef;
}): string {
  switch (args.identity.kind) {
    case 'explicit_provider_user':
      return normalizeEmailOtpProviderUserId(
        args.identity.providerUserId,
        'Email OTP provider user id',
      );
    case 'derive_from_route_auth': {
      const routeProviderUserId = appSessionSubjectFromEmailOtpAuthLane(args.routePlan.authLane);
      return normalizeEmailOtpProviderUserId(
        routeProviderUserId || args.walletSession.walletSessionUserId,
        'Email OTP provider user id',
      );
    }
  }
  args.identity satisfies never;
  throw new Error('[SigningEngine][email-otp] unsupported provider identity branch');
}

export type LoginEmailOtpEcdsaCapabilityArgs = {
  walletSession: WalletSessionRef;
  subjectId?: never;
  chainTarget: ThresholdEcdsaChainTarget;
  emailOtpAuthPolicy?: EmailOtpAuthPolicy;
  emailOtpAuthReason?: 'login' | 'sign';
  relayUrl?: string;
  challengeId?: string;
  otpCode: string;
  operation?: WalletEmailOtpLoginOperation;
  shamirPrimeB64u?: string;
  appSessionJwt?: never;
  routeAuth?: never;
  ecdsaBootstrapAuthorization: EmailOtpEcdsaBootstrapAuthorization;
  keyHandle?: string;
  participantIds?: number[];
  sessionKind?: never;
  routePlan: EmailOtpRoutePlan;
  ttlMs?: number;
  remainingUses?: number;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  publicationChainTargets?: readonly ThresholdEcdsaChainTarget[];
  emailOtpAuthorityEmail?: string;
  emailHashHex: string;
  onProgress?: (progress: EmailOtpWorkerProgressEvent) => void;
  providerIdentity: EmailOtpEcdsaProviderIdentity;
  authSubjectId?: never;
  ed25519YaoRecovery:
    | { kind: 'not_requested' }
    | {
        kind: 'requested';
        providerSubject: string;
        signerSlot: number;
      };
};

export type PrepareEmailOtpEcdsaExportCapabilityArgs = Omit<
  LoginEmailOtpEcdsaCapabilityArgs,
  | 'emailOtpAuthPolicy'
  | 'emailOtpAuthReason'
  | 'operation'
  | 'remainingUses'
  | 'publicationChainTargets'
  | 'ed25519YaoRecovery'
> & {
  emailOtpAuthPolicy: 'per_operation';
  emailOtpAuthReason: 'sign';
  operation: WalletEmailOtpExportOperation;
  remainingUses: 1;
  publicationChainTargets?: never;
  ed25519YaoRecovery: { kind: 'not_requested' };
};

function assertEmailOtpOperationMatchesRoutePlan(args: {
  operation: WalletEmailOtpOperation;
  routePlan: EmailOtpRoutePlan;
}): void {
  if (args.operation !== args.routePlan.operation) {
    throw new Error('Email OTP operation does not match its route plan');
  }
}

function assertEmailOtpEcdsaExportHandleMatchesLane(args: {
  handle: EmailOtpEcdsaExportWorkerIssuedSessionHandle;
  existingKey: ResolvedEmailOtpExistingEcdsaKey;
  chainTarget: ThresholdEcdsaChainTarget;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpPendingSingleUseAuthContext;
}): void {
  const walletKey = args.existingKey.walletKey;
  if (
    String(args.handle.walletId) !== String(walletKey.walletId) ||
    String(args.handle.evmFamilySigningKeySlotId) !== String(walletKey.evmFamilySigningKeySlotId) ||
    args.handle.authSubjectId !== emailOtpAuthContextProviderUserId(args.emailOtpAuthContext) ||
    !thresholdEcdsaChainTargetsEqual(args.handle.chainTarget, walletKey.chainTarget) ||
    !thresholdEcdsaChainTargetsEqual(args.handle.chainTarget, args.chainTarget)
  ) {
    throw new Error('Email OTP ECDSA export worker handle does not match the resolved lane');
  }
}

function requireEmailOtpEcdsaExportAuthContext(
  context: ThresholdEcdsaEmailOtpAuthContext,
): ThresholdEcdsaEmailOtpPendingSingleUseAuthContext {
  if (!isEmailOtpPendingSingleUseAuthContext(context)) {
    throw new Error('Email OTP ECDSA export requires single-use authorization');
  }
  return context;
}

function buildEmailOtpEcdsaOnlySigningBudget(args: {
  signingGrantId: string;
  ttlMs: number | undefined;
  remainingUses: number;
}): EmailOtpMixedWalletSigningBudgetV1 {
  const policy = clampThresholdSessionPolicy({
    ttlMs: args.ttlMs ?? DEFAULT_THRESHOLD_SESSION_POLICY.ttlMs,
    remainingUses: args.remainingUses,
  });
  return {
    kind: 'email_otp_mixed_wallet_signing_budget_v1',
    signingGrantId: args.signingGrantId,
    ttlMs: policy.ttlMs,
    remainingUses: policy.remainingUses,
  };
}

function buildAuthoritativeEmailOtpMixedWalletSigningBudget(args: {
  bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
  expectedRemainingUses: number;
}): EmailOtpMixedWalletSigningBudgetV1 {
  const session = args.bootstrap.session;
  const signingGrantId = String(session.signingGrantId || '').trim();
  const expiresAtMs = Math.floor(Number(session.expiresAtMs));
  const remainingUses = Math.floor(Number(session.remainingUses));
  const ttlMs = expiresAtMs - Date.now();
  if (!signingGrantId || !Number.isSafeInteger(expiresAtMs) || ttlMs < 1) {
    throw new Error('Mixed Email OTP unlock returned an invalid server signing budget');
  }
  if (remainingUses !== args.expectedRemainingUses) {
    throw new Error('Mixed Email OTP unlock changed the requested signing budget uses');
  }
  return {
    kind: 'email_otp_mixed_wallet_signing_budget_v1',
    signingGrantId,
    ttlMs,
    remainingUses,
  };
}

function resolveEmailOtpLoginSigningBudget(args: {
  workerResult: EmailOtpWalletUnlockResult | EmailOtpMixedWalletUnlockResult;
  emailOtpAuthPolicy: EmailOtpAuthPolicy;
  routePlan: EmailOtpRoutePlan;
  requestedTtlMs: number | undefined;
  requestedRemainingUses: number;
}): EmailOtpMixedWalletSigningBudgetV1 {
  switch (args.workerResult.kind) {
    case 'ecdsa':
      return buildEmailOtpEcdsaOnlySigningBudget({
        signingGrantId: buildEmailOtpEcdsaMintingSession({
          emailOtpAuthPolicy: args.emailOtpAuthPolicy,
          routePlan: args.routePlan,
          generateSigningGrantId,
        }).signingGrantId,
        ttlMs: args.requestedTtlMs,
        remainingUses: args.requestedRemainingUses,
      });
    case 'ecdsa_and_ed25519_yao_recovery':
      return buildAuthoritativeEmailOtpMixedWalletSigningBudget({
        bootstrap: args.workerResult.ed25519YaoRecovery,
        expectedRemainingUses: args.requestedRemainingUses,
      });
  }
  args.workerResult satisfies never;
  throw new Error('Unsupported Email OTP wallet unlock result');
}

function emailOtpWorkerHandleOperationFromLoginOperation(
  operation: WalletEmailOtpOperation,
): EmailOtpWorkerSessionHandleOperation {
  switch (operation) {
    case WALLET_EMAIL_OTP_REGISTRATION_OPERATION:
      return 'registration';
    case WALLET_EMAIL_OTP_UNLOCK_OPERATION:
      return 'wallet_unlock';
    case WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION:
      return 'sign';
    case WALLET_EMAIL_OTP_EXPORT_OPERATION:
      return 'export';
  }
  operation satisfies never;
  throw new Error('Unsupported Email OTP login operation for ECDSA worker handle');
}

export function buildEmailOtpExistingKeyActivation(args: {
  existingKey: ResolvedEmailOtpExistingEcdsaKey;
  chainTarget: ThresholdEcdsaChainTarget;
  thresholdSessionId: string;
  signingGrantId: string;
  ttlMs: number;
  remainingUses: number;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  relayerUrl: string;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  emailOtpWorkerSessionHandle: ReturnType<typeof parseEmailOtpWorkerIssuedSessionHandle>;
  walletSessionRouteAuth: ReturnType<typeof emailOtpEcdsaBootstrapRouteAuthToTransport>;
}): ThresholdEcdsaActivationRequest {
  if (args.emailOtpWorkerSessionHandle.action !== 'threshold_ecdsa_bootstrap') {
    throw new Error('Email OTP ECDSA activation requires a threshold ECDSA worker handle');
  }
  const sessionIdentity = buildEcdsaSessionIdentity({
    thresholdSessionId: args.thresholdSessionId,
    signingGrantId: args.signingGrantId,
  });
  const lanePolicy = buildEvmFamilyEcdsaSessionLanePolicy({
    chainTarget: args.chainTarget,
    thresholdSessionId: sessionIdentity.thresholdSessionId,
    signingGrantId: sessionIdentity.signingGrantId,
    thresholdSessionKind: 'jwt',
    ttlMs: args.ttlMs,
    remainingUses: args.remainingUses,
    runtimePolicyScope: args.runtimePolicyScope,
  });
  if (isEmailOtpSessionAuthContext(args.emailOtpAuthContext)) {
    return buildEmailOtpSessionBootstrapEcdsaActivation({
      source: 'email_otp',
      relayerUrl: args.relayerUrl,
      sessionIdentity,
      sessionKind: 'jwt',
      sessionBudgetUses: args.remainingUses,
      runtimePolicy: { kind: 'scoped_policy', scope: args.runtimePolicyScope },
      emailOtpWorkerSessionHandle: args.emailOtpWorkerSessionHandle,
      emailOtpAuthContext: args.emailOtpAuthContext,
      walletSessionRouteAuth: args.walletSessionRouteAuth,
      walletKey: args.existingKey.walletKey,
      lanePolicy,
      publicCapability: args.existingKey.publicCapability,
      existingRoleLocalMaterial: args.existingKey.persistedRoleLocalMaterial,
    });
  }
  if (isEmailOtpPendingSingleUseAuthContext(args.emailOtpAuthContext)) {
    return buildEmailOtpPerOperationReauthEcdsaActivation({
      source: 'email_otp',
      relayerUrl: args.relayerUrl,
      sessionIdentity,
      sessionKind: 'jwt',
      sessionBudgetUses: args.remainingUses,
      runtimePolicy: { kind: 'scoped_policy', scope: args.runtimePolicyScope },
      emailOtpWorkerSessionHandle: args.emailOtpWorkerSessionHandle,
      emailOtpAuthContext: args.emailOtpAuthContext,
      walletSessionRouteAuth: args.walletSessionRouteAuth,
      walletKey: args.existingKey.walletKey,
      lanePolicy,
      publicCapability: args.existingKey.publicCapability,
      existingRoleLocalMaterial: args.existingKey.persistedRoleLocalMaterial,
    });
  }
  throw new Error('Email OTP ECDSA activation cannot use a consumed single-use context');
}

export async function provisionEmailOtpExistingKeySessions(args: {
  primaryExistingKey: ResolvedEmailOtpExistingEcdsaKey;
  publicationChainTargets: readonly ThresholdEcdsaChainTarget[];
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  relayerUrl: string;
  signingGrantId: string;
  ttlMs: number;
  remainingUses: number;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  clientRootShareHandle: EmailOtpEcdsaSessionBootstrapHandlePayload;
  walletSessionRouteAuth: AppOrWalletSessionAuth;
  ports: EmailOtpEcdsaLoginPorts;
}): Promise<ThresholdEcdsaSessionBootstrapResult[]> {
  const emailOtpWorkerSessionHandle = parseEmailOtpWorkerIssuedSessionHandle(
    args.clientRootShareHandle,
  );
  if (emailOtpWorkerSessionHandle.action !== 'threshold_ecdsa_bootstrap') {
    throw new Error('Email OTP wallet unlock returned an invalid ECDSA worker handle');
  }
  const thresholdSessionId = generateSessionId('threshold-ecdsa-login');
  const bootstraps: ThresholdEcdsaSessionBootstrapResult[] = [];
  for (const chainTarget of args.publicationChainTargets) {
    const existingKey = projectEmailOtpExistingEcdsaKeyToChainTarget({
      existingKey: args.primaryExistingKey,
      chainTarget,
    });
    bootstraps.push(
      await args.ports.provisionThresholdEcdsaSession(
        buildEmailOtpExistingKeyActivation({
          existingKey,
          chainTarget,
          thresholdSessionId,
          signingGrantId: args.signingGrantId,
          ttlMs: args.ttlMs,
          remainingUses: args.remainingUses,
          runtimePolicyScope: args.runtimePolicyScope,
          relayerUrl: args.relayerUrl,
          emailOtpAuthContext: args.emailOtpAuthContext,
          emailOtpWorkerSessionHandle,
          walletSessionRouteAuth: args.walletSessionRouteAuth,
        }),
      ),
    );
  }
  const primaryBootstrap = bootstraps[0];
  const workerCtx = args.ports.getSignerWorkerContext();
  if (!primaryBootstrap || !workerCtx) {
    throw new Error('Email OTP ECDSA activation did not return a primary warm session');
  }
  const bound = await requestBindEmailOtpEcdsaWarmSessionFromWorkerHandle({
    workerCtx,
    clientRootShareHandle: args.clientRootShareHandle,
    thresholdSessionId: primaryBootstrap.session.thresholdSessionId,
    remainingUses: primaryBootstrap.session.remainingUses,
    expiresAtMs: primaryBootstrap.session.expiresAtMs,
  });
  if (!bound.ok) {
    throw new Error(bound.message || bound.code || 'Email OTP warm-session binding failed');
  }
  return bootstraps;
}

export type EmailOtpEcdsaLoginPorts = {
  configs: SeamsConfigsReadonly;
  getSignerWorkerContext: () => WorkerOperationContext | null | undefined;
  provisionThresholdEcdsaSession: (
    request: ThresholdEcdsaActivationRequest,
  ) => Promise<ThresholdEcdsaSessionBootstrapResult>;
  provisionEmailOtpEcdsaExplicitExportSession: (
    request: ThresholdEcdsaEmailOtpExportActivationRequest,
  ) => Promise<EmailOtpEcdsaExplicitExportBootstrapResult>;
  requireRelayUrl: () => string;
  requireShamirPrimeB64u: () => string;
  rememberAppSessionJwt: (args: {
    walletId: WalletSessionRef['walletId'];
    appSessionJwt: string;
  }) => void;
  publicationPorts: EmailOtpEcdsaPublicationPorts;
};

async function provisionEmailOtpExplicitExportSession(args: {
  existingKey: ResolvedEmailOtpExistingEcdsaKey;
  chainTarget: ThresholdEcdsaChainTarget;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  relayerUrl: string;
  signingGrantId: string;
  ttlMs: number;
  remainingUses: number;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpPendingSingleUseAuthContext;
  clientRootShareHandle: EmailOtpEcdsaExportWorkerIssuedSessionHandle;
  walletSessionRouteAuth: AppOrWalletSessionAuth;
  ports: EmailOtpEcdsaLoginPorts;
}): Promise<ThresholdEcdsaSessionBootstrapResult> {
  const emailOtpWorkerSessionHandle = args.clientRootShareHandle;
  const sessionIdentity = buildEcdsaSessionIdentity({
    thresholdSessionId: generateSessionId('threshold-ecdsa-export'),
    signingGrantId: args.signingGrantId,
  });
  const lanePolicy = buildEvmFamilyEcdsaSessionLanePolicy({
    chainTarget: args.chainTarget,
    thresholdSessionId: sessionIdentity.thresholdSessionId,
    signingGrantId: sessionIdentity.signingGrantId,
    thresholdSessionKind: 'jwt',
    ttlMs: args.ttlMs,
    remainingUses: args.remainingUses,
    runtimePolicyScope: args.runtimePolicyScope,
  });
  const result = await args.ports.provisionEmailOtpEcdsaExplicitExportSession(
    buildEmailOtpExplicitExportEcdsaActivation({
      source: 'email_otp',
      relayerUrl: args.relayerUrl,
      sessionIdentity,
      sessionKind: 'jwt',
      sessionBudgetUses: args.remainingUses,
      runtimePolicy: { kind: 'scoped_policy', scope: args.runtimePolicyScope },
      emailOtpWorkerSessionHandle,
      emailOtpAuthContext: args.emailOtpAuthContext,
      walletSessionRouteAuth: args.walletSessionRouteAuth,
      walletKey: args.existingKey.walletKey,
      lanePolicy,
      publicCapability: args.existingKey.publicCapability,
      existingRoleLocalMaterial: args.existingKey.persistedRoleLocalMaterial,
    }),
  );
  return result.bootstrap;
}

export type LoginEmailOtpEcdsaCapabilityForSigningArgs = {
  walletSession: WalletSessionRef;
  subjectId?: never;
  chainTarget: ThresholdEcdsaChainTarget;
  challengeId: string;
  otpCode: string;
  committedLane: EmailOtpEcdsaCommittedLane;
  remainingUses: number;
  record?: never;
  routeAuth?: never;
  authLane?: never;
};

export type LoginEmailOtpEcdsaPublicReauthCapabilityForSigningArgs = {
  walletSession: WalletSessionRef;
  chainTarget: ThresholdEcdsaChainTarget;
  challengeId: string;
  otpCode: string;
  reauthLane: EmailOtpEcdsaPublicReauthLane;
  appSessionJwt: string;
  remainingUses: number;
  committedLane?: never;
};

export type EmailOtpEcdsaTransactionStepUpInput = {
  mode: 'transaction_step_up';
  walletSession: WalletSessionRef;
  chainTarget: ThresholdEcdsaChainTarget;
  challengeId: string;
  otpCode: string;
  committedLane: EmailOtpEcdsaCommittedLane;
  remainingUses: number;
  record?: never;
  routeAuth?: never;
  authLane?: never;
  appSessionJwt?: never;
  registrationAttemptId?: never;
};

function normalizeEmailOtpEcdsaSigningRemainingUses(value: unknown): number {
  const remainingUses = Math.floor(Number(value) || 0);
  if (!Number.isFinite(remainingUses) || remainingUses <= 0) {
    throw new Error('[SigningEngine][email-otp][ecdsa] signing remainingUses is required');
  }
  return remainingUses;
}

type EmailOtpEcdsaSigningRefreshFacts = {
  keyHandle: string;
  participantIds: number[];
  emailHashHex: string;
  providerIdentity: EmailOtpEcdsaProviderIdentity;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
};

function requireEmailOtpEcdsaSigningRefreshRuntimePolicyScope(args: {
  committedLane: EmailOtpEcdsaCommittedLane;
  recordRuntimePolicyScope: ThresholdRuntimePolicyScope | undefined;
}): ThresholdRuntimePolicyScope {
  const runtimePolicyScope =
    args.recordRuntimePolicyScope ||
    parseThresholdRuntimePolicyScopeFromJwt(args.committedLane.authLane.jwt);
  if (!runtimePolicyScope) {
    throw new Error('Email OTP ECDSA signing refresh requires runtimePolicyScope');
  }
  return runtimePolicyScope;
}

function buildRecordBackedEmailOtpEcdsaSigningRefreshFacts(
  committedLane: Extract<EmailOtpEcdsaCommittedLane, { source: 'record_backed' }>,
): EmailOtpEcdsaSigningRefreshFacts {
  const record = committedLane.record;
  if (record.source !== 'email_otp') {
    throw new Error('Email OTP ECDSA signing refresh requires an Email OTP session record');
  }
  const emailOtpAuthContext = thresholdEcdsaEmailOtpAuthContext(record);
  if (!emailOtpAuthContext) {
    throw new Error('Email OTP ECDSA signing refresh requires Email OTP auth context');
  }
  return {
    keyHandle: String(toEvmFamilyEcdsaKeyHandle(record.keyHandle)),
    participantIds: [...record.participantIds],
    emailHashHex: emailOtpAuthContextEmailHashHex(emailOtpAuthContext),
    providerIdentity: emailOtpEcdsaProviderIdentityFromRecord(record),
    runtimePolicyScope: requireEmailOtpEcdsaSigningRefreshRuntimePolicyScope({
      committedLane,
      recordRuntimePolicyScope: record.runtimePolicyScope,
    }),
  };
}

function buildDurableAuthorityEmailOtpEcdsaSigningRefreshFacts(
  committedLane: Extract<EmailOtpEcdsaCommittedLane, { source: 'durable_authority_backed' }>,
): EmailOtpEcdsaSigningRefreshFacts {
  return {
    keyHandle: String(toEvmFamilyEcdsaKeyHandle(committedLane.walletSessionAuthority.keyHandle)),
    participantIds: committedLane.walletSessionAuthority.participantIds.map(Number),
    emailHashHex: committedLane.authority.verifier.emailHashHex,
    providerIdentity: {
      kind: 'explicit_provider_user',
      providerUserId: committedLane.authority.factor.providerUserId,
    },
    runtimePolicyScope: requireEmailOtpEcdsaSigningRefreshRuntimePolicyScope({
      committedLane,
      recordRuntimePolicyScope: undefined,
    }),
  };
}

function buildEmailOtpEcdsaSigningRefreshFacts(
  committedLane: EmailOtpEcdsaCommittedLane,
): EmailOtpEcdsaSigningRefreshFacts {
  switch (committedLane.source) {
    case 'record_backed':
      return buildRecordBackedEmailOtpEcdsaSigningRefreshFacts(committedLane);
    case 'durable_authority_backed':
      return buildDurableAuthorityEmailOtpEcdsaSigningRefreshFacts(committedLane);
  }
}

export async function loginWithEmailOtpEcdsaCapabilityForSigning(
  args: LoginEmailOtpEcdsaCapabilityForSigningArgs,
  ports: {
    requireRelayUrl: () => string;
    loginWithEcdsaCapabilityInternal: (
      args: LoginEmailOtpEcdsaCapabilityArgs,
    ) => Promise<EmailOtpThresholdEcdsaLoginResult>;
  },
): Promise<EmailOtpThresholdEcdsaLoginResult> {
  const operation = WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION;
  const emailOtpAuthPolicy: EmailOtpAuthPolicy = 'session';
  const remainingUses = normalizeEmailOtpEcdsaSigningRemainingUses(args.remainingUses);
  const committedLane = args.committedLane;
  const refreshFacts = buildEmailOtpEcdsaSigningRefreshFacts(committedLane);
  const routePlan = buildEmailOtpSigningSessionRoutePlan({
    authLane: assertEmailOtpSigningSessionAuthLane(committedLane.authLane),
    operation,
  });
  return await ports.loginWithEcdsaCapabilityInternal({
    walletSession: args.walletSession,
    chainTarget: args.chainTarget,
    emailOtpAuthPolicy,
    emailOtpAuthReason: 'sign',
    challengeId: args.challengeId,
    otpCode: args.otpCode,
    operation,
    keyHandle: refreshFacts.keyHandle,
    participantIds: refreshFacts.participantIds,
    routePlan,
    emailHashHex: refreshFacts.emailHashHex,
    providerIdentity: refreshFacts.providerIdentity,
    ecdsaBootstrapAuthorization: { kind: 'route_plan_auth' },
    remainingUses,
    runtimePolicyScope: refreshFacts.runtimePolicyScope,
    ed25519YaoRecovery: { kind: 'not_requested' },
  });
}

export async function loginWithEmailOtpEcdsaPublicReauthCapabilityForSigning(
  args: LoginEmailOtpEcdsaPublicReauthCapabilityForSigningArgs,
  ports: {
    loginWithEcdsaCapabilityInternal: (
      args: LoginEmailOtpEcdsaCapabilityArgs,
    ) => Promise<EmailOtpThresholdEcdsaLoginResult>;
  },
): Promise<EmailOtpThresholdEcdsaLoginResult> {
  const publicRestore = args.reauthLane.publicRestore;
  if (publicRestore.source !== 'email_otp') {
    throw new Error('Email OTP ECDSA public reauth requires Email OTP public authority');
  }
  const routePlan = buildEmailOtpRoutePlan({
    routeFamily: 'login',
    authLane: { kind: 'app_session', jwt: args.appSessionJwt },
    operation: WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
  });
  return await ports.loginWithEcdsaCapabilityInternal({
    walletSession: args.walletSession,
    chainTarget: args.chainTarget,
    emailOtpAuthPolicy: 'session',
    emailOtpAuthReason: 'sign',
    challengeId: args.challengeId,
    otpCode: args.otpCode,
    operation: WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
    routePlan,
    keyHandle: publicRestore.keyHandle,
    participantIds: publicRestore.participantIds.map(Number),
    emailHashHex: publicRestore.emailHashHex,
    providerIdentity: {
      kind: 'explicit_provider_user',
      providerUserId: publicRestore.providerSubjectId,
    },
    ecdsaBootstrapAuthorization: { kind: 'route_plan_auth' },
    remainingUses: normalizeEmailOtpEcdsaSigningRemainingUses(args.remainingUses),
    runtimePolicyScope: publicRestore.runtimePolicyScope,
    ed25519YaoRecovery: { kind: 'not_requested' },
  });
}

async function runEmailOtpEcdsaCapability(
  args: LoginEmailOtpEcdsaCapabilityArgs,
  ports: EmailOtpEcdsaLoginPorts,
): Promise<EmailOtpEcdsaCapabilityRunResult> {
  const operation = args.operation ?? args.routePlan.operation;
  assertEmailOtpOperationMatchesRoutePlan({ operation, routePlan: args.routePlan });
  const timings = createEmailOtpThresholdEcdsaLoginTimings();
  const chainTarget = args.chainTarget;
  const emailOtpAuthPolicy: EmailOtpAuthPolicy =
    args.emailOtpAuthPolicy || ports.configs.signing.emailOtp.authPolicy;
  const emailOtpAuthReason = args.emailOtpAuthReason || 'login';
  const isSigningStepUp = emailOtpAuthReason === 'sign';
  const emailOtpAuthRetention =
    isSigningStepUp && emailOtpAuthPolicy === 'per_operation' ? 'single_use' : 'session';
  const emailOtpAuthContextPolicy: EmailOtpAuthPolicy =
    emailOtpAuthRetention === 'session' ? 'session' : emailOtpAuthPolicy;
  const relayUrl = String(args.relayUrl || ports.requireRelayUrl()).trim();
  const shamirPrimeB64u = String(args.shamirPrimeB64u || ports.requireShamirPrimeB64u()).trim();
  const configuredRemainingUses = args.remainingUses;
  const defaultRemainingUses = ports.configs.signing.sessionDefaults?.remainingUses;
  const requestedRemainingUses = Math.min(
    Math.max(
      1,
      Math.floor(
        Number(
          configuredRemainingUses ?? defaultRemainingUses ?? DEV_DEFAULT_UNLOCK_REMAINING_USES,
        ) || 1,
      ),
    ),
    DEV_DEFAULT_UNLOCK_REMAINING_USES,
  );
  const requestedStepUpSignatureUses = Math.max(
    1,
    Math.floor(Number(configuredRemainingUses) || 1),
  );
  const unlockBudgetPolicy =
    resolveWalletUnlockBudgetPolicyFromRequestedUses({
      requestedRemainingUses,
      ...(configuredRemainingUses == null && defaultRemainingUses == null
        ? {}
        : { policyVersion: 'sdk_email_otp_unlock_config_v1' }),
    }) ||
    (() => {
      throw new Error('[SigningEngine][email-otp] unlock budget policy is required');
    })();
  const postExhaustionStepUpBudgetPolicy = resolvePostExhaustionStepUpBudgetPolicy({
    operationId: normalizeStepUpOperationId(operation),
    requiredSignatureUses: requestedStepUpSignatureUses,
  });
  const remainingUses = isSigningStepUp
    ? resolveSigningBudgetPolicyRemainingUses(postExhaustionStepUpBudgetPolicy)
    : resolveSigningBudgetPolicyRemainingUses(unlockBudgetPolicy);
  const workerCtx = ports.getSignerWorkerContext();
  const routePlan = args.routePlan;
  const routeAuth = routeAuthFromEmailOtpRoutePlan(routePlan);
  const bootstrapRouteAuth =
    args.ecdsaBootstrapAuthorization.kind === 'route_plan_auth'
      ? emailOtpEcdsaBootstrapRouteAuthFromRoutePlan(routePlan)
      : args.ecdsaBootstrapAuthorization.routeAuth;
  const bootstrapTransportAuth = bootstrapRouteAuth
    ? emailOtpEcdsaBootstrapRouteAuthToTransport(bootstrapRouteAuth)
    : undefined;
  const runtimePolicyScope =
    args.runtimePolicyScope ||
    parseThresholdRuntimePolicyScopeFromJwt(routeAuth?.jwt) ||
    parseThresholdRuntimePolicyScopeFromJwt(bootstrapTransportAuth?.jwt);

  if (!workerCtx) {
    throw new Error('Email OTP login requires the dedicated emailOtp worker');
  }
  if (!runtimePolicyScope) {
    throw new Error('Email OTP ECDSA login requires runtimePolicyScope');
  }
  const evmFamilySigningKeySlotId = deriveEvmFamilySigningKeySlotIdFromRuntimePolicyScope({
    walletId: args.walletSession.walletId,
    runtimePolicyScope,
  });
  const appSessionJwt = appSessionJwtFromEmailOtpAuthLane(routePlan.authLane);
  if (appSessionJwt) {
    ports.rememberAppSessionJwt({ walletId: args.walletSession.walletId, appSessionJwt });
  }
  const emailOtpProviderUserId = resolveEmailOtpEcdsaProviderUserId({
    identity: args.providerIdentity,
    routePlan,
    walletSession: args.walletSession,
  });
  const emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext =
    emailOtpAuthRetention === 'single_use'
      ? buildEmailOtpAuthContextForWalletAuthMethod({
          policy: emailOtpAuthContextPolicy,
          walletId: toWalletId(args.walletSession.walletId),
          emailHashHex: args.emailHashHex,
          retention: 'single_use',
          provider: 'google',
          providerUserId: emailOtpProviderUserId,
        })
      : buildEmailOtpAuthContextForWalletAuthMethod({
          policy: emailOtpAuthContextPolicy,
          walletId: toWalletId(args.walletSession.walletId),
          emailHashHex: args.emailHashHex,
          retention: 'session',
          reason: emailOtpAuthReason,
          provider: 'google',
          providerUserId: emailOtpProviderUserId,
        });
  const publicationChainTargets = emailOtpEcdsaPublicationChainTargets({
    configs: ports.configs,
    chainTarget,
    emailOtpAuthContext,
    ...(args.publicationChainTargets
      ? { additionalChainTargets: args.publicationChainTargets }
      : {}),
  });
  const publicationPorts = ports.publicationPorts;
  const existingKey = await resolveEmailOtpExistingEcdsaKey({
    walletId: toWalletId(args.walletSession.walletId),
    chainTarget,
    runtimePolicyScope,
    keyHandle: args.keyHandle,
    listThresholdEcdsaSessionRecordsForWallet:
      publicationPorts.listThresholdEcdsaSessionRecordsForWallet,
    listActiveEcdsaSignersForWallet: publicationPorts.listActiveEcdsaSignersForWallet,
  });
  if (!existingKey) {
    throw new Error(
      `device_link_required: local threshold ECDSA material is unavailable for ${chainTarget.kind}:${chainTarget.chainId}`,
    );
  }
  let timingStartedAtMs = nowMs();
  const unlockArgs = {
    walletSession: args.walletSession,
    relayUrl,
    shamirPrimeB64u,
    otpCode: args.otpCode,
    routePlan,
    workerCtx,
    ecdsaClientRootHandleBinding: {
      evmFamilySigningKeySlotId,
      authSubjectId: emailOtpProviderUserId,
      operation: emailOtpWorkerHandleOperationFromLoginOperation(routePlan.operation),
      chainTarget,
    },
    ...(args.challengeId ? { challengeId: args.challengeId } : {}),
    runtimePolicyScope,
    ...(args.onProgress ? { onProgress: args.onProgress } : {}),
  };
  const workerResult =
    args.ed25519YaoRecovery.kind === 'not_requested'
      ? await unlockEmailOtpWallet(unlockArgs)
      : await unlockEmailOtpMixedWallet({
          ...unlockArgs,
          providerSubject: args.ed25519YaoRecovery.providerSubject,
          signerSlot: args.ed25519YaoRecovery.signerSlot,
          remainingUses,
        });
  try {
    const exportEmailOtpAuthContext =
      operation === WALLET_EMAIL_OTP_EXPORT_OPERATION
        ? requireEmailOtpEcdsaExportAuthContext(emailOtpAuthContext)
        : null;
    const exportClientRootShareHandle =
      operation === WALLET_EMAIL_OTP_EXPORT_OPERATION
        ? parseEmailOtpEcdsaExportWorkerIssuedSessionHandle(workerResult.clientRootShareHandle)
        : null;
    if (exportClientRootShareHandle && exportEmailOtpAuthContext) {
      assertEmailOtpEcdsaExportHandleMatchesLane({
        handle: exportClientRootShareHandle,
        existingKey,
        chainTarget,
        emailOtpAuthContext: exportEmailOtpAuthContext,
      });
    }
    addEmailOtpThresholdEcdsaLoginTiming(timings, 'emailOtpProofVerificationMs', timingStartedAtMs);
    if (!bootstrapTransportAuth) {
      throw new Error('Email OTP ECDSA bootstrap requires route auth');
    }
    const signingBudget = resolveEmailOtpLoginSigningBudget({
      workerResult,
      emailOtpAuthPolicy,
      routePlan,
      requestedTtlMs: args.ttlMs,
      requestedRemainingUses: remainingUses,
    });
    const signingGrantId = signingBudget.signingGrantId;
    timingStartedAtMs = nowMs();
    if (operation === WALLET_EMAIL_OTP_EXPORT_OPERATION) {
      if (!exportClientRootShareHandle || !exportEmailOtpAuthContext) {
        throw new Error('Email OTP ECDSA export worker handle is unavailable');
      }
      const bootstrap = await provisionEmailOtpExplicitExportSession({
        existingKey,
        chainTarget,
        runtimePolicyScope,
        relayerUrl: relayUrl,
        signingGrantId,
        ttlMs: signingBudget.ttlMs,
        remainingUses: signingBudget.remainingUses,
        emailOtpAuthContext: exportEmailOtpAuthContext,
        clientRootShareHandle: exportClientRootShareHandle,
        walletSessionRouteAuth: bootstrapTransportAuth,
        ports,
      });
      addEmailOtpThresholdEcdsaLoginTiming(timings, 'ecdsaMaterialRestoreMs', timingStartedAtMs);
      return {
        kind: 'transient_export',
        value: { bootstrap, timings },
      };
    }
    const bootstraps = await provisionEmailOtpExistingKeySessions({
      primaryExistingKey: existingKey,
      publicationChainTargets,
      runtimePolicyScope,
      relayerUrl: relayUrl,
      signingGrantId,
      ttlMs: signingBudget.ttlMs,
      remainingUses: signingBudget.remainingUses,
      emailOtpAuthContext,
      clientRootShareHandle: workerResult.clientRootShareHandle,
      walletSessionRouteAuth: bootstrapTransportAuth,
      ports,
    });
    addEmailOtpThresholdEcdsaLoginTiming(timings, 'ecdsaMaterialRestoreMs', timingStartedAtMs);
    const {
      bootstrap,
      warmCapability,
      warmCapabilities,
      timings: publicationTimings,
    } = await commitEmailOtpEcdsaPublicationBootstraps(
      {
        walletId: toWalletId(args.walletSession.walletId),
        publicationChainTargets,
        bootstraps,
        signingGrantId,
        runtimePolicyScope,
        emailOtpAuthContext,
        relayerUrl: relayUrl,
        shamirPrimeB64u,
      },
      publicationPorts,
    );
    mergeEmailOtpEcdsaPublicationTimingsIntoLoginTimings(timings, publicationTimings);
    return {
      kind: 'published_signing_session',
      value: {
        recovery: workerResult.recovery,
        bootstrap,
        warmCapability,
        warmCapabilities,
        clientRootShareHandle: workerResult.clientRootShareHandle,
        ed25519YaoRecovery:
          workerResult.kind === 'ecdsa_and_ed25519_yao_recovery'
            ? {
                kind: 'unlocked',
                pendingFactorHandle: workerResult.pendingFactorHandle,
                bootstrap: workerResult.ed25519YaoRecovery,
              }
            : { kind: 'not_requested' },
        timings,
      },
    };
  } catch (error) {
    if (workerResult.kind !== 'ecdsa_and_ed25519_yao_recovery') throw error;
    try {
      const removed = await disposeEmailOtpEd25519YaoPendingFactorV1({
        workerContext: workerCtx,
        pendingFactorHandle: workerResult.pendingFactorHandle,
      });
      if (!removed) {
        throw new Error('Mixed Email OTP unlock pending Ed25519 factor was unavailable');
      }
    } catch (disposalError) {
      throw new AggregateError(
        [error, disposalError],
        'Mixed Email OTP unlock failed and pending Ed25519 factor disposal failed',
      );
    }
    throw error;
  } finally {
    if (operation === WALLET_EMAIL_OTP_EXPORT_OPERATION) {
      await requestDisposeEmailOtpEcdsaClientRootHandle({
        workerCtx,
        clientRootShareHandle: workerResult.clientRootShareHandle,
      });
    }
  }
}

export async function loginWithEmailOtpEcdsaCapability(
  args: LoginEmailOtpEcdsaCapabilityArgs,
  ports: EmailOtpEcdsaLoginPorts,
): Promise<EmailOtpThresholdEcdsaLoginResult> {
  const operation = args.operation ?? args.routePlan.operation;
  if (operation === WALLET_EMAIL_OTP_EXPORT_OPERATION) {
    throw new Error('Email OTP ECDSA export must use transient export preparation');
  }
  const result = await runEmailOtpEcdsaCapability(args, ports);
  if (result.kind !== 'published_signing_session') {
    throw new Error('Email OTP ECDSA login did not publish a signing session');
  }
  return result.value;
}

export async function prepareEmailOtpEcdsaExportCapability(
  args: PrepareEmailOtpEcdsaExportCapabilityArgs,
  ports: EmailOtpEcdsaLoginPorts,
): Promise<EmailOtpThresholdEcdsaExportPreparation> {
  const result = await runEmailOtpEcdsaCapability(args, ports);
  if (result.kind !== 'transient_export') {
    throw new Error('Email OTP ECDSA export preparation published a signing session');
  }
  return result.value;
}
