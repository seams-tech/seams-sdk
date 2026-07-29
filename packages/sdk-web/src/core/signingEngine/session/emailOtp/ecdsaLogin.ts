import type { EmailOtpAuthPolicy, SeamsConfigsReadonly } from '@/core/types/seams';
import {
  buildEmailOtpAuthContextForWalletAuthMethod,
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
import { generateSigningGrantId } from '@/core/signingEngine/threshold/sessionPolicy';
import type {
  EcdsaExplicitExportOperationAuthorization,
  ThresholdEcdsaExplicitKeyExportActivationResult,
  ThresholdEcdsaSessionBootstrapResult,
} from '@/core/signingEngine/threshold/ecdsa/activation';
import type { ActiveWalletSessionAuthorizationProjection } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type {
  EmailOtpEd25519YaoRecoveryBootstrapV1,
  EmailOtpEd25519YaoExactLocalSessionBootstrapV1,
  EmailOtpEcdsaSessionBootstrapHandlePayload,
  EmailOtpWorkerProgressEvent,
  EmailOtpWorkerSessionHandleOperation,
} from '@/core/signingEngine/workerManager/workerTypes';
import type {
  EcdsaCommittedLane,
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
import {
  disposeEmailOtpEd25519YaoActiveClientV1,
  disposeEmailOtpEd25519YaoPendingFactorV1,
} from './ed25519YaoWorkerClient';
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
  buildEmailOtpPreauthorizedSessionBootstrapEcdsaActivation,
  buildEmailOtpSessionBootstrapEcdsaActivation,
  type ThresholdEcdsaActivationRequest,
  type ThresholdEcdsaEmailOtpExportActivationRequest,
} from '../passkey/ecdsaSessionProvision';
import { buildStrictEcdsaPostRegistrationSessionActivationRequest } from '../../threshold/ecdsa/postRegistrationSessionActivation';
import type { RouterAbEcdsaPostRegistrationSessionActivationResponseV1 } from '@shared/utils/routerAbEcdsaDerivation';
import type { RouterAbEcdsaPostRegistrationSessionActivationRequestV1 } from '@shared/utils/routerAbEcdsaDerivation';
import type { EmailOtpEcdsaExplicitExportBootstrapResult } from '../passkey/ecdsaBootstrap';
import {
  buildEcdsaSessionIdentity,
  type EcdsaSessionIdentity,
} from '../warmCapabilities/ecdsaProvisionPlan';
import { generateSessionId } from '../passkey/prfCache';
import {
  requestBindEmailOtpEcdsaWarmSessionFromWorkerHandle,
  requestDisposeEmailOtpEcdsaClientRootHandle,
} from './workerRequests';
import type { AppOrWalletSessionAuth } from '@shared/utils/sessionTokens';
import type { PersistedEcdsaRoleLocalMaterial } from '../material/ecdsaRoleLocalMaterialResolver';
import type { RouterAbEd25519YaoActiveClientMetadataV1 } from '../../threshold/ed25519/yaoClient';
import { parseReusableWalletSessionMintId } from '@shared/authorization/capabilityKinds';
import { parseThresholdEcdsaSessionId } from '@shared/utils/domainIds';

export type EmailOtpThresholdEcdsaLoginTimingBucket =
  | 'emailOtpProofVerificationMs'
  | 'ecdsaMaterialRestoreMs'
  | 'signingSessionSealApplyMs'
  | 'warmCapabilityPersistenceMs';

export type EmailOtpThresholdEcdsaLoginTimings = Record<
  EmailOtpThresholdEcdsaLoginTimingBucket,
  number
>;

type EmailOtpEd25519YaoLoginMaterial =
  | { kind: 'not_requested' }
  | {
      kind: 'unlocked';
      pendingFactorHandle: EmailOtpEd25519YaoPendingFactorHandle;
      bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
    }
  | {
      kind: 'local_session';
      activeClientHandle: string;
      metadata: RouterAbEd25519YaoActiveClientMetadataV1;
      bootstrap: EmailOtpEd25519YaoExactLocalSessionBootstrapV1;
    };

export type EmailOtpThresholdEcdsaLoginResult = {
  recovery: EmailOtpBootstrapRecovery;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  authorization: ActiveWalletSessionAuthorizationProjection;
  authorizations: readonly [
    ActiveWalletSessionAuthorizationProjection,
    ...ActiveWalletSessionAuthorizationProjection[],
  ];
  clientRootShareHandle: EmailOtpEcdsaSessionBootstrapHandlePayload;
  ed25519YaoRecovery: EmailOtpEd25519YaoLoginMaterial;
  timings: EmailOtpThresholdEcdsaLoginTimings;
};

function emailOtpEd25519YaoLoginMaterialFromWorkerResult(
  workerResult: EmailOtpWalletUnlockResult | EmailOtpMixedWalletUnlockResult,
): EmailOtpEd25519YaoLoginMaterial {
  switch (workerResult.kind) {
    case 'ecdsa':
      return { kind: 'not_requested' };
    case 'ecdsa_and_ed25519_yao_recovery':
      return {
        kind: 'unlocked',
        pendingFactorHandle: workerResult.pendingFactorHandle,
        bootstrap: workerResult.ed25519YaoRecovery,
      };
    case 'ecdsa_and_ed25519_yao_local_session':
      return {
        kind: 'local_session',
        activeClientHandle: workerResult.activeClientHandle,
        metadata: workerResult.metadata,
        bootstrap: workerResult.ed25519YaoSession,
      };
  }
  workerResult satisfies never;
  throw new Error('Unsupported Email OTP Ed25519 unlock material');
}

async function disposeEmailOtpEd25519YaoWorkerResultAfterFailure(args: {
  workerResult: EmailOtpWalletUnlockResult | EmailOtpMixedWalletUnlockResult;
  workerContext: WorkerOperationContext;
}): Promise<void> {
  switch (args.workerResult.kind) {
    case 'ecdsa':
      return;
    case 'ecdsa_and_ed25519_yao_recovery': {
      const removed = await disposeEmailOtpEd25519YaoPendingFactorV1({
        workerContext: args.workerContext,
        pendingFactorHandle: args.workerResult.pendingFactorHandle,
      });
      if (!removed) {
        throw new Error('Mixed Email OTP unlock pending Ed25519 factor was unavailable');
      }
      return;
    }
    case 'ecdsa_and_ed25519_yao_local_session': {
      const removed = await disposeEmailOtpEd25519YaoActiveClientV1({
        workerContext: args.workerContext,
        activeClientHandle: args.workerResult.activeClientHandle,
      });
      if (!removed) {
        throw new Error('Mixed Email OTP unlock local Ed25519 client was unavailable');
      }
      return;
    }
  }
  args.workerResult satisfies never;
}

export type EmailOtpThresholdEcdsaExportPreparation = {
  bootstrap: ThresholdEcdsaExplicitKeyExportActivationResult;
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
        nearAccountId: string;
        expectedOperationalPublicKey: string;
        expectedThresholdSessionId: string;
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
  persistedExportMaterial: PersistedEcdsaRoleLocalMaterial;
  explicitExportAuthorization: EcdsaExplicitExportOperationAuthorization;
};

function requireEmailOtpExplicitExportInput(
  args: LoginEmailOtpEcdsaCapabilityArgs | PrepareEmailOtpEcdsaExportCapabilityArgs,
): PrepareEmailOtpEcdsaExportCapabilityArgs {
  if (
    'persistedExportMaterial' in args &&
    'explicitExportAuthorization' in args &&
    args.operation === WALLET_EMAIL_OTP_EXPORT_OPERATION
  ) {
    return args;
  }
  throw new Error('Email OTP ECDSA export requires prepared operation authorization');
}

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
  bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1 | EmailOtpEd25519YaoExactLocalSessionBootstrapV1;
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
    case 'ecdsa_and_ed25519_yao_local_session':
      return buildAuthoritativeEmailOtpMixedWalletSigningBudget({
        bootstrap:
          args.workerResult.kind === 'ecdsa_and_ed25519_yao_recovery'
            ? args.workerResult.ed25519YaoRecovery
            : args.workerResult.ed25519YaoSession,
        expectedRemainingUses: args.requestedRemainingUses,
      });
  }
  args.workerResult satisfies never;
  throw new Error('Unsupported Email OTP wallet unlock result');
}

function requirePreparedEmailOtpUnlockSessionActivation(
  value: RouterAbEcdsaPostRegistrationSessionActivationRequestV1 | null,
): RouterAbEcdsaPostRegistrationSessionActivationRequestV1 {
  if (!value) throw new Error('Mixed Email OTP recovery requires explicit wallet unlock');
  return value;
}

function requireEmailOtpUnlockSessionResponse(
  result: EmailOtpWalletUnlockResult | EmailOtpMixedWalletUnlockResult,
): RouterAbEcdsaPostRegistrationSessionActivationResponseV1 {
  if (!result.ecdsaSession) {
    throw new Error('Email OTP unlock did not return its ECDSA Wallet Session');
  }
  return result.ecdsaSession;
}

function requireEmailOtpUnlockThresholdSessionId(value: string) {
  const parsed = parseThresholdEcdsaSessionId(value);
  if (!parsed.ok) throw new Error('Failed to create Email OTP threshold session identity');
  return parsed.value;
}

function requireEmailOtpUnlockWalletSessionMintId(value: string) {
  const parsed = parseReusableWalletSessionMintId(value);
  if (!parsed.ok) throw new Error('Failed to create Email OTP Wallet Session mint identity');
  return parsed.value;
}

function requireEmailOtpWalletSessionJwt(value: unknown): string {
  const jwt = String(value || '').trim();
  if (!jwt) throw new Error('Email OTP unlock returned an empty Wallet Session JWT');
  return jwt;
}

function requireEmailOtpBootstrapTransportAuth(
  value: AppOrWalletSessionAuth | undefined,
): AppOrWalletSessionAuth {
  if (!value) throw new Error('Email OTP ECDSA bootstrap requires route auth');
  return value;
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

function emailOtpNonUnlockWorkerHandleOperationFromLoginOperation(
  operation: WalletEmailOtpOperation,
): Exclude<EmailOtpWorkerSessionHandleOperation, 'wallet_unlock'> {
  switch (operation) {
    case WALLET_EMAIL_OTP_REGISTRATION_OPERATION:
      return 'registration';
    case WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION:
      return 'sign';
    case WALLET_EMAIL_OTP_EXPORT_OPERATION:
      return 'export';
    case WALLET_EMAIL_OTP_UNLOCK_OPERATION:
      throw new Error('Email OTP wallet unlock requires first-session activation');
  }
  operation satisfies never;
  throw new Error('Unsupported Email OTP non-unlock operation');
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
  authorization:
    | {
        kind: 'route_authorized';
        routeAuth: AppOrWalletSessionAuth;
      }
    | {
        kind: 'preauthorized_wallet_unlock';
        sessionActivation: RouterAbEcdsaPostRegistrationSessionActivationResponseV1;
      };
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
    const common = {
      source: 'email_otp',
      relayerUrl: args.relayerUrl,
      sessionIdentity,
      sessionKind: 'jwt',
      sessionBudgetUses: args.remainingUses,
      runtimePolicy: { kind: 'scoped_policy', scope: args.runtimePolicyScope },
      emailOtpWorkerSessionHandle: args.emailOtpWorkerSessionHandle,
      emailOtpAuthContext: args.emailOtpAuthContext,
      walletKey: args.existingKey.walletKey,
      lanePolicy,
      publicCapability: args.existingKey.publicCapability,
      existingRoleLocalMaterial: args.existingKey.persistedRoleLocalMaterial,
    } as const;
    return args.authorization.kind === 'preauthorized_wallet_unlock'
      ? buildEmailOtpPreauthorizedSessionBootstrapEcdsaActivation({
          ...common,
          preauthorizedSessionActivation: args.authorization.sessionActivation,
        })
      : buildEmailOtpSessionBootstrapEcdsaActivation({
          ...common,
          walletSessionRouteAuth: args.authorization.routeAuth,
        });
  }
  if (isEmailOtpPendingSingleUseAuthContext(args.emailOtpAuthContext)) {
    if (args.authorization.kind === 'preauthorized_wallet_unlock') {
      throw new Error('Email OTP operation step-up cannot adopt a reusable Wallet Session');
    }
    return buildEmailOtpPerOperationReauthEcdsaActivation({
      source: 'email_otp',
      relayerUrl: args.relayerUrl,
      sessionIdentity,
      sessionKind: 'jwt',
      sessionBudgetUses: args.remainingUses,
      runtimePolicy: { kind: 'scoped_policy', scope: args.runtimePolicyScope },
      emailOtpWorkerSessionHandle: args.emailOtpWorkerSessionHandle,
      emailOtpAuthContext: args.emailOtpAuthContext,
      walletSessionRouteAuth: args.authorization.routeAuth,
      walletKey: args.existingKey.walletKey,
      lanePolicy,
      publicCapability: args.existingKey.publicCapability,
      existingRoleLocalMaterial: args.existingKey.persistedRoleLocalMaterial,
    });
  }
  throw new Error('Email OTP ECDSA activation cannot use a consumed single-use context');
}

type EmailOtpPrimaryEcdsaSessionProvisioning =
  | {
      kind: 'route_authorized';
      sessionIdentity: EcdsaSessionIdentity;
      routeAuth: AppOrWalletSessionAuth;
    }
  | {
      kind: 'preauthorized_wallet_unlock';
      request: RouterAbEcdsaPostRegistrationSessionActivationRequestV1;
      response: RouterAbEcdsaPostRegistrationSessionActivationResponseV1;
    };

function resolveEmailOtpPrimaryEcdsaSessionProvisioning(
  provisioning: EmailOtpPrimaryEcdsaSessionProvisioning,
): {
  sessionIdentity: EcdsaSessionIdentity;
  authorization: Parameters<typeof buildEmailOtpExistingKeyActivation>[0]['authorization'];
} {
  switch (provisioning.kind) {
    case 'route_authorized':
      return {
        sessionIdentity: provisioning.sessionIdentity,
        authorization: { kind: 'route_authorized', routeAuth: provisioning.routeAuth },
      };
    case 'preauthorized_wallet_unlock': {
      const policy = provisioning.request.session_policy;
      const session = provisioning.response.session;
      if (policy.threshold_session_id !== session.threshold_session_id) {
        throw new Error('Email OTP unlock returned a different prepared ECDSA session identity');
      }
      return {
        sessionIdentity: buildEcdsaSessionIdentity({
          thresholdSessionId: session.threshold_session_id,
          signingGrantId: session.signing_grant_id,
        }),
        authorization: {
          kind: 'preauthorized_wallet_unlock',
          sessionActivation: provisioning.response,
        },
      };
    }
  }
}

export async function provisionEmailOtpExistingKeySessions(args: {
  primaryExistingKey: ResolvedEmailOtpExistingEcdsaKey;
  publicationChainTargets: readonly ThresholdEcdsaChainTarget[];
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  relayerUrl: string;
  ttlMs: number;
  remainingUses: number;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  clientRootShareHandle: EmailOtpEcdsaSessionBootstrapHandlePayload;
  primarySession: EmailOtpPrimaryEcdsaSessionProvisioning;
  ports: EmailOtpEcdsaLoginPorts;
}): Promise<ThresholdEcdsaSessionBootstrapResult[]> {
  const emailOtpWorkerSessionHandle = parseEmailOtpWorkerIssuedSessionHandle(
    args.clientRootShareHandle,
  );
  if (emailOtpWorkerSessionHandle.action !== 'threshold_ecdsa_bootstrap') {
    throw new Error('Email OTP wallet unlock returned an invalid ECDSA worker handle');
  }
  const primarySession = resolveEmailOtpPrimaryEcdsaSessionProvisioning(args.primarySession);
  const provisionContext: ProvisionEmailOtpExistingKeySessionContext = {
    args,
    sessionIdentity: primarySession.sessionIdentity,
    authorization: primarySession.authorization,
    emailOtpWorkerSessionHandle,
  };
  const primaryTarget = args.publicationChainTargets[0];
  if (!primaryTarget) {
    throw new Error('Email OTP ECDSA activation requires a primary target');
  }
  const primaryBootstrap = await provisionEmailOtpExistingKeySessionForTarget(
    provisionContext,
    primaryTarget,
  );
  const additionalContext: ProvisionEmailOtpExistingKeySessionContext = {
    ...provisionContext,
    args: {
      ...args,
      primarySession: {
        kind: 'route_authorized',
        sessionIdentity: primarySession.sessionIdentity,
        routeAuth: {
          kind: 'wallet_session',
          jwt: requireEmailOtpWalletSessionJwt(primaryBootstrap.session.jwt),
        },
      },
    },
    authorization: {
      kind: 'route_authorized',
      routeAuth: {
        kind: 'wallet_session',
        jwt: requireEmailOtpWalletSessionJwt(primaryBootstrap.session.jwt),
      },
    },
  };
  const additionalBootstraps = await Promise.all(
    args.publicationChainTargets
      .slice(1)
      .map(provisionEmailOtpAdditionalExistingKeySessionForTarget.bind(null, additionalContext)),
  );
  const bootstraps = [primaryBootstrap, ...additionalBootstraps];
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

type ProvisionEmailOtpExistingKeySessionContext = {
  args: Parameters<typeof provisionEmailOtpExistingKeySessions>[0];
  sessionIdentity: EcdsaSessionIdentity;
  authorization: Parameters<typeof buildEmailOtpExistingKeyActivation>[0]['authorization'];
  emailOtpWorkerSessionHandle: ReturnType<typeof parseEmailOtpWorkerIssuedSessionHandle>;
};

async function provisionEmailOtpExistingKeySessionForTarget(
  context: ProvisionEmailOtpExistingKeySessionContext,
  chainTarget: ThresholdEcdsaChainTarget,
): Promise<ThresholdEcdsaSessionBootstrapResult> {
  const existingKey = projectEmailOtpExistingEcdsaKeyToChainTarget({
    existingKey: context.args.primaryExistingKey,
    chainTarget,
  });
  return await context.args.ports.provisionThresholdEcdsaSession(
    buildEmailOtpExistingKeyActivation({
      existingKey,
      chainTarget,
      thresholdSessionId: context.sessionIdentity.thresholdSessionId,
      signingGrantId: context.sessionIdentity.signingGrantId,
      ttlMs: context.args.ttlMs,
      remainingUses: context.args.remainingUses,
      runtimePolicyScope: context.args.runtimePolicyScope,
      relayerUrl: context.args.relayerUrl,
      emailOtpAuthContext: context.args.emailOtpAuthContext,
      emailOtpWorkerSessionHandle: context.emailOtpWorkerSessionHandle,
      authorization: context.authorization,
    }),
  );
}

async function provisionEmailOtpAdditionalExistingKeySessionForTarget(
  context: ProvisionEmailOtpExistingKeySessionContext,
  chainTarget: ThresholdEcdsaChainTarget,
): Promise<ThresholdEcdsaSessionBootstrapResult> {
  return await provisionEmailOtpExistingKeySessionForTarget(context, chainTarget);
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
  relayerUrl: string;
  persistedMaterial: PersistedEcdsaRoleLocalMaterial;
  authorization: EcdsaExplicitExportOperationAuthorization;
  ports: EmailOtpEcdsaLoginPorts;
}): Promise<ThresholdEcdsaExplicitKeyExportActivationResult> {
  return await args.ports.provisionEmailOtpEcdsaExplicitExportSession(
    buildEmailOtpExplicitExportEcdsaActivation({
      relayerUrl: args.relayerUrl,
      existingRoleLocalMaterial: args.persistedMaterial,
      authorization: args.authorization,
    }),
  );
}

export type LoginEmailOtpEcdsaCapabilityForSigningArgs = {
  walletSession: WalletSessionRef;
  subjectId?: never;
  chainTarget: ThresholdEcdsaChainTarget;
  challengeId: string;
  otpCode: string;
  committedLane: EcdsaCommittedLane;
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
  committedLane: EcdsaCommittedLane;
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

// The runtime policy scope is sealed-runtime state. It is not read back out of
// the Wallet Session JWT, which is a bearer credential here.
function requireEmailOtpEcdsaSigningRefreshRuntimePolicyScope(args: {
  recordRuntimePolicyScope: ThresholdRuntimePolicyScope | undefined;
}): ThresholdRuntimePolicyScope {
  const runtimePolicyScope = args.recordRuntimePolicyScope;
  if (!runtimePolicyScope) {
    throw new Error('Email OTP ECDSA signing refresh requires runtimePolicyScope');
  }
  return runtimePolicyScope;
}

function buildDurableAuthorityEmailOtpEcdsaSigningRefreshFacts(
  committedLane: EcdsaCommittedLane,
): EmailOtpEcdsaSigningRefreshFacts {
  if (
    committedLane.authority.factor.kind !== 'email_otp' ||
    !committedLane.authLane
  ) {
    throw new Error('[SigningEngine][email-otp][ecdsa] committed lane requires Email OTP authority');
  }
  return {
    // Exact lane signer binding, not a JWT-decoded authority structure.
    keyHandle: String(toEvmFamilyEcdsaKeyHandle(committedLane.lane.identity.signer.keyHandle)),
    participantIds: committedLane.lane.identity.signer.key.participantIds.map(Number),
    emailHashHex: committedLane.authority.verifier.emailHashHex,
    providerIdentity: {
      kind: 'explicit_provider_user',
      providerUserId: committedLane.authority.factor.providerUserId,
    },
    runtimePolicyScope: requireEmailOtpEcdsaSigningRefreshRuntimePolicyScope({
      recordRuntimePolicyScope: undefined,
    }),
  };
}

// Sealed-record authority is the only committed-lane form; the record-backed
// refresh facts had no constructible input.
function buildEmailOtpEcdsaSigningRefreshFacts(
  committedLane: EcdsaCommittedLane,
): EmailOtpEcdsaSigningRefreshFacts {
  return buildDurableAuthorityEmailOtpEcdsaSigningRefreshFacts(committedLane);
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
  args: LoginEmailOtpEcdsaCapabilityArgs | PrepareEmailOtpEcdsaExportCapabilityArgs,
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
  // Supplied by the caller from sealed runtime state; the route and bootstrap
  // tokens are bearer credentials and are not decoded for control state.
  const runtimePolicyScope = args.runtimePolicyScope;

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
    listActiveEcdsaCapabilityManifestsForWallet:
      publicationPorts.listActiveEcdsaCapabilityManifestsForWallet,
  });
  if (!existingKey) {
    throw new Error(
      `device_link_required: local threshold ECDSA material is unavailable for ${chainTarget.kind}:${chainTarget.chainId}`,
    );
  }
  const preparedUnlockSessionPolicy =
    operation === WALLET_EMAIL_OTP_UNLOCK_OPERATION
      ? clampThresholdSessionPolicy({
          ttlMs: args.ttlMs ?? DEFAULT_THRESHOLD_SESSION_POLICY.ttlMs,
          remainingUses,
        })
      : null;
  const preparedUnlockThresholdSessionId = preparedUnlockSessionPolicy
    ? requireEmailOtpUnlockThresholdSessionId(generateSessionId('threshold-ecdsa-login'))
    : null;
  const preparedUnlockSessionActivation =
    preparedUnlockSessionPolicy && preparedUnlockThresholdSessionId
      ? buildStrictEcdsaPostRegistrationSessionActivationRequest({
          publicCapability: existingKey.publicCapability,
          thresholdSessionId: preparedUnlockThresholdSessionId,
          walletSessionMintId: requireEmailOtpUnlockWalletSessionMintId(
            generateSessionId('wallet-session-mint'),
          ),
          ttlMs: preparedUnlockSessionPolicy.ttlMs,
          remainingUses: preparedUnlockSessionPolicy.remainingUses,
          runtimePolicyScope,
        })
      : null;
  let timingStartedAtMs = nowMs();
  const unlockArgs = {
    walletSession: args.walletSession,
    relayUrl,
    shamirPrimeB64u,
    otpCode: args.otpCode,
    routePlan,
    workerCtx,
    ...(args.challengeId ? { challengeId: args.challengeId } : {}),
    runtimePolicyScope,
    ...(args.onProgress ? { onProgress: args.onProgress } : {}),
  };
  const workerResult =
    args.ed25519YaoRecovery.kind === 'not_requested'
      ? await unlockEmailOtpWallet({
          ...unlockArgs,
          ...(preparedUnlockSessionActivation
            ? {
                ecdsaClientRootHandleBinding: {
                  evmFamilySigningKeySlotId,
                  authSubjectId: emailOtpProviderUserId,
                  operation: 'wallet_unlock' as const,
                  chainTarget,
                },
                ecdsaSessionActivation: preparedUnlockSessionActivation,
              }
            : {
                ecdsaClientRootHandleBinding: {
                  evmFamilySigningKeySlotId,
                  authSubjectId: emailOtpProviderUserId,
                  operation: emailOtpNonUnlockWorkerHandleOperationFromLoginOperation(
                    routePlan.operation,
                  ),
                  chainTarget,
                },
              }),
        })
      : await unlockEmailOtpMixedWallet({
          ...unlockArgs,
          ecdsaClientRootHandleBinding: {
            evmFamilySigningKeySlotId,
            authSubjectId: emailOtpProviderUserId,
            operation: 'wallet_unlock',
            chainTarget,
          },
          providerSubject: args.ed25519YaoRecovery.providerSubject,
          signerSlot: args.ed25519YaoRecovery.signerSlot,
          nearAccountId: args.ed25519YaoRecovery.nearAccountId,
          expectedOperationalPublicKey: args.ed25519YaoRecovery.expectedOperationalPublicKey,
          expectedThresholdSessionId: args.ed25519YaoRecovery.expectedThresholdSessionId,
          remainingUses,
          ecdsaSessionActivation: requirePreparedEmailOtpUnlockSessionActivation(
            preparedUnlockSessionActivation,
          ),
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
    const preparedUnlockSessionResponse = preparedUnlockSessionActivation
      ? requireEmailOtpUnlockSessionResponse(workerResult)
      : null;
    const signingBudget = preparedUnlockSessionResponse
      ? buildEmailOtpEcdsaOnlySigningBudget({
          signingGrantId: preparedUnlockSessionResponse.session.signing_grant_id,
          ttlMs: args.ttlMs,
          remainingUses,
        })
      : resolveEmailOtpLoginSigningBudget({
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
      const exportInput = requireEmailOtpExplicitExportInput(args);
      const bootstrap = await provisionEmailOtpExplicitExportSession({
        relayerUrl: relayUrl,
        persistedMaterial: exportInput.persistedExportMaterial,
        authorization: exportInput.explicitExportAuthorization,
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
      ttlMs: signingBudget.ttlMs,
      remainingUses: signingBudget.remainingUses,
      emailOtpAuthContext,
      clientRootShareHandle: workerResult.clientRootShareHandle,
      primarySession: preparedUnlockSessionActivation
        ? {
            kind: 'preauthorized_wallet_unlock',
            request: preparedUnlockSessionActivation,
            response: requireEmailOtpUnlockSessionResponse(workerResult),
          }
        : {
            kind: 'route_authorized',
            sessionIdentity: buildEcdsaSessionIdentity({
              thresholdSessionId: generateSessionId('threshold-ecdsa-login'),
              signingGrantId,
            }),
            routeAuth: requireEmailOtpBootstrapTransportAuth(bootstrapTransportAuth),
          },
      ports,
    });
    addEmailOtpThresholdEcdsaLoginTiming(timings, 'ecdsaMaterialRestoreMs', timingStartedAtMs);
    const {
      bootstrap,
      authorization,
      authorizations,
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
        authorization,
        authorizations,
        clientRootShareHandle: workerResult.clientRootShareHandle,
        ed25519YaoRecovery: emailOtpEd25519YaoLoginMaterialFromWorkerResult(workerResult),
        timings,
      },
    };
  } catch (error) {
    try {
      await disposeEmailOtpEd25519YaoWorkerResultAfterFailure({
        workerResult,
        workerContext: workerCtx,
      });
    } catch (disposalError) {
      throw new AggregateError(
        [error, disposalError],
        'Email OTP unlock failed and Ed25519 material disposal failed',
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
