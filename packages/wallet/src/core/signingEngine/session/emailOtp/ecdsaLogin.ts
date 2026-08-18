import type { EmailOtpAuthPolicy, SeamsConfigsReadonly } from '@/core/types/seams';
import {
  buildEmailOtpAuthContextForWalletAuthMethod,
  emailOtpAuthContextProviderUserId,
  isEmailOtpPendingSingleUseAuthContext,
  isEmailOtpSessionAuthContext,
  type ThresholdEcdsaEmailOtpAuthContext,
  type ThresholdEcdsaEmailOtpPendingSingleUseAuthContext,
  type ThresholdEcdsaEmailOtpSessionAuthContext,
} from '@/core/signingEngine/session/identity/laneIdentity';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  thresholdEcdsaChainTargetsEqual,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import type { resolveActiveEcdsaCapabilityRuntime } from '../material/activeEcdsaCapabilityRuntime';
import type {
  EcdsaExplicitExportOperationAuthorization,
  ThresholdEcdsaExplicitKeyExportActivationResult,
  ThresholdEcdsaSessionBootstrapResult,
} from '@/core/signingEngine/threshold/ecdsa/activation';
import {
  walletSessionAuthorizations,
  walletSessionTokenForCurve,
  type ActiveWalletSessionAuthorizationProjection,
} from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type {
  EmailOtpEd25519YaoRecoveryBootstrapV1,
  EmailOtpEcdsaSessionBootstrapHandleBinding,
  EmailOtpEcdsaSessionBootstrapHandlePayload,
  EmailOtpWorkerProgressEvent,
  EmailOtpWalletCustodyEd25519MaterialRequest,
  EmailOtpWorkerSessionHandleOperation,
} from '@/core/signingEngine/workerManager/workerTypes';
import type { EcdsaCommittedLane } from '../../flows/signEvmFamily/ecdsaSelection';
import {
  WALLET_EMAIL_OTP_EXPORT_OPERATION,
  WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
  WALLET_EMAIL_OTP_UNLOCK_OPERATION,
  type WalletEmailOtpLoginOperation,
  type WalletEmailOtpOperation,
  type WalletEmailOtpExportOperation,
} from '@shared/utils/emailOtpDomain';
import type { EmailOtpBootstrapRecovery } from '../../stepUpConfirmation/otpPrompt/bootstrapRecovery';
import {
  buildEvmFamilyEcdsaRecoveredMaterialLanePolicy,
  buildEvmFamilyEcdsaSessionLanePolicy,
  toEvmFamilyEcdsaKeyHandle,
} from '../identity/evmFamilyEcdsaIdentity';
import { type EmailOtpRoutePlan } from '../../stepUpConfirmation/otpPrompt/authLane';
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
  unlockEmailOtpWalletCapabilities,
  unlockEmailOtpWallet,
  type EmailOtpEd25519YaoUnlockResult,
  type EmailOtpWalletUnlockResult,
} from './walletUnlock';
import { disposeWalletCustodyEd25519ActiveClientV1 } from '../../walletCustody/ed25519ActiveClient';
import {
  DEFAULT_THRESHOLD_SESSION_POLICY,
  clampThresholdSessionPolicy,
} from '../../threshold/sessionPolicy';
import {
  assertEmailOtpSigningSessionAuthLane,
  buildEmailOtpSigningSessionRoutePlan,
  emailOtpEcdsaBootstrapRouteAuthFromRoutePlan,
  emailOtpEcdsaBootstrapRouteAuthToTransport,
  type EmailOtpEcdsaBootstrapAuthorization,
} from './routePlan';
import {
  DEFAULT_UNLOCK_REMAINING_USES,
  resolveWalletUnlockSessionUsesFromRequestedUses,
} from '../../threshold/sessionPolicy';
import {
  parseEmailOtpEcdsaExportWorkerIssuedSessionHandle,
  parseEmailOtpWorkerIssuedSessionHandle,
  type EmailOtpEcdsaExportWorkerIssuedSessionHandle,
} from '@/core/platform';
import {
  buildEmailOtpExplicitExportEcdsaActivation,
  buildEmailOtpPerOperationReauthEcdsaActivation,
  buildEmailOtpPreauthorizedSessionBootstrapEcdsaActivation,
  buildEmailOtpRecoveredSessionEcdsaActivation,
  buildEmailOtpSessionBootstrapEcdsaActivation,
  type ThresholdEcdsaActivationRequest,
  type ThresholdEcdsaEmailOtpExportActivationRequest,
} from '../passkey/ecdsaSessionProvision';
import { SigningSessionIds } from '../operationState/types';
import { buildStrictEcdsaPostRegistrationSessionActivationRequest } from '../../threshold/ecdsa/postRegistrationSessionActivation';

import type { RouterAbEcdsaPostRegistrationSessionActivationResponseV1 } from '@shared/utils/routerAbEcdsaDerivation';
import type { RouterAbEcdsaPostRegistrationSessionActivationRequestV1 } from '@shared/utils/routerAbEcdsaDerivation';
import type { RouterAbEcdsaPostRegistrationSessionActivationPolicyV1 } from '@shared/utils/routerAbEcdsaDerivation';
import type { EmailOtpEcdsaExplicitExportBootstrapResult } from '../passkey/ecdsaBootstrap';
import {
  buildEcdsaSessionIdentity,
  type EcdsaSessionIdentity,
} from '../warmCapabilities/ecdsaProvisionPlan';
import { generateSessionId } from '../passkey/prfCache';
import {
  requireOpaqueWalletSessionToken,
  type WalletSessionRouteAuth,
} from '@shared/utils/sessionTokens';
import type { PersistedEcdsaRoleLocalMaterial } from '../material/ecdsaRoleLocalMaterialResolver';
import type { RouterAbEd25519YaoActiveClientMetadataV1 } from '../../threshold/ed25519/yaoClient';
import { parseReusableWalletSessionMintId } from '@shared/authorization/capabilityKinds';
import {
  mpcMaterialActivationRefsEqual,
  parseProviderSubject,
  parseThresholdEcdsaSessionId,
} from '@shared/utils/domainIds';
import {
  walletAuthAuthorityRef,
  type EmailOtpProvider,
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import type { ImportWalletCustodyEcdsaContinuityInput } from '@/core/indexedDB/seamsWalletDB/ecdsaCapabilityManifestStore';
import type { EmailOtpEcdsaCustodyContinuityV1 } from '../../workerManager/workerTypes';

type EmailOtpLoginSessionPolicy = {
  readonly ttlMs: number;
  readonly remainingUses: number;
};

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
      kind: 'cache_absent';
      bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
    }
  | {
      kind: 'capability';
      activeClientHandle: string;
      metadata: RouterAbEd25519YaoActiveClientMetadataV1;
      bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
    };

export type EmailOtpThresholdEcdsaLoginResult = {
  recovery: EmailOtpBootstrapRecovery;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  authorization: ActiveWalletSessionAuthorizationProjection;
  authorizations: readonly [
    ActiveWalletSessionAuthorizationProjection,
    ...ActiveWalletSessionAuthorizationProjection[],
  ];
  emailOtpSessionHandle: EmailOtpEcdsaSessionBootstrapHandlePayload;
  ed25519YaoRecovery: EmailOtpEd25519YaoLoginMaterial;
  timings: EmailOtpThresholdEcdsaLoginTimings;
};

function emailOtpEd25519YaoLoginMaterialFromWorkerResult(
  workerResult: EmailOtpEd25519YaoUnlockResult | null,
): EmailOtpEd25519YaoLoginMaterial {
  if (!workerResult) return { kind: 'not_requested' };
  switch (workerResult.kind) {
    case 'wallet_custody_cache_absent':
      return {
        kind: 'cache_absent',
        bootstrap: workerResult.ed25519YaoRecovery,
      };
    case 'ed25519_yao_capability':
      return {
        kind: 'capability',
        activeClientHandle: workerResult.activeClientHandle,
        metadata: workerResult.metadata,
        bootstrap: workerResult.ed25519YaoCapability,
      };
  }
  workerResult satisfies never;
  throw new Error('Unsupported Email OTP Ed25519 unlock material');
}

async function disposeEmailOtpEd25519YaoWorkerResultAfterFailure(args: {
  workerResult: EmailOtpEd25519YaoUnlockResult | null;
  workerContext: WorkerOperationContext;
}): Promise<void> {
  if (!args.workerResult) return;
  switch (args.workerResult.kind) {
    case 'wallet_custody_cache_absent':
      return;
    case 'ed25519_yao_capability': {
      const removed = await disposeWalletCustodyEd25519ActiveClientV1({
        workerContext: args.workerContext,
        activeClientHandle: args.workerResult.activeClientHandle,
      });
      if (!removed) {
        throw new Error('Email OTP capability unlock local Ed25519 client was unavailable');
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

export type EmailOtpEcdsaProviderIdentity = {
  kind: 'explicit_provider_user';
  provider: EmailOtpProvider;
  providerUserId: string;
};

function normalizeEmailOtpProviderUserId(value: unknown, field: string): string {
  const normalized = String(value || '').trim();
  if (!normalized) {
    throw new Error(`[SigningEngine][email-otp] ${field} is required`);
  }
  return normalized;
}

function resolveEmailOtpEcdsaProviderIdentity(args: {
  identity: EmailOtpEcdsaProviderIdentity;
}): { provider: EmailOtpProvider; providerUserId: string } {
  return {
    provider: args.identity.provider,
    providerUserId: normalizeEmailOtpProviderUserId(
      args.identity.providerUserId,
      'Email OTP provider user id',
    ),
  };
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
  groupId?: string;
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

function requireEmailOtpExplicitExportUnsealGrant(
  authorization: EcdsaExplicitExportOperationAuthorization,
): { kind: 'email_otp_unseal_grant'; grant: string; challengeId: string } {
  switch (authorization.unseal.kind) {
    case 'email_otp_grant':
      return {
        kind: 'email_otp_unseal_grant',
        grant: authorization.unseal.grant,
        challengeId: authorization.unseal.challenge_id,
      };
    case 'not_requested':
      throw new Error('Email OTP ECDSA export requires its verified unseal grant');
    default: {
      const exhaustive: never = authorization.unseal;
      throw new Error(`Unsupported Email OTP ECDSA export unseal state: ${String(exhaustive)}`);
    }
  }
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
    String(args.handle.keyHandle) !== String(walletKey.keyHandle) ||
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
  ttlMs: number | undefined;
  remainingUses: number;
}): EmailOtpLoginSessionPolicy {
  const policy = clampThresholdSessionPolicy({
    ttlMs: args.ttlMs ?? DEFAULT_THRESHOLD_SESSION_POLICY.ttlMs,
    remainingUses: args.remainingUses,
  });
  return {
    ttlMs: policy.ttlMs,
    remainingUses: policy.remainingUses,
  };
}

function buildAuthoritativeEmailOtpMixedWalletSigningBudget(args: {
  bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
  expectedRemainingUses: number;
}): EmailOtpLoginSessionPolicy {
  const session = args.bootstrap.session;
  const expiresAtMs = Math.floor(Number(session.expiresAtMs));
  const remainingUses = Math.floor(Number(session.remainingUses));
  const ttlMs = expiresAtMs - Date.now();
  if (!Number.isSafeInteger(expiresAtMs) || ttlMs < 1) {
    throw new Error('Email OTP capability unlock returned an invalid server signing budget');
  }
  if (remainingUses !== args.expectedRemainingUses) {
    throw new Error('Email OTP capability unlock changed the requested signing budget uses');
  }
  return {
    ttlMs,
    remainingUses,
  };
}

function resolveEmailOtpLoginSigningBudget(args: {
  ecdsaResult: EmailOtpWalletUnlockResult;
  ed25519YaoResult: EmailOtpEd25519YaoUnlockResult | null;
  emailOtpAuthPolicy: EmailOtpAuthPolicy;
  routePlan: EmailOtpRoutePlan;
  requestedTtlMs: number | undefined;
  requestedRemainingUses: number;
}): EmailOtpLoginSessionPolicy {
  if (args.ed25519YaoResult) {
    return buildAuthoritativeEmailOtpMixedWalletSigningBudget({
      bootstrap:
        args.ed25519YaoResult.kind === 'wallet_custody_cache_absent'
          ? args.ed25519YaoResult.ed25519YaoRecovery
          : args.ed25519YaoResult.ed25519YaoCapability,
      expectedRemainingUses: args.requestedRemainingUses,
    });
  }
  return buildEmailOtpEcdsaOnlySigningBudget({
    ttlMs: args.requestedTtlMs,
    remainingUses: args.requestedRemainingUses,
  });
}

function requireEmailOtpUnlockSessionPolicy(
  value: RouterAbEcdsaPostRegistrationSessionActivationPolicyV1 | null,
): RouterAbEcdsaPostRegistrationSessionActivationPolicyV1 {
  if (!value) throw new Error('Email OTP capability recovery requires explicit wallet unlock');
  return value;
}

function emailOtpUnlockSessionPolicyFromActivationRequest(args: {
  readonly request: RouterAbEcdsaPostRegistrationSessionActivationRequestV1;
  readonly keyHandle: string;
}): RouterAbEcdsaPostRegistrationSessionActivationPolicyV1 {
  return {
    kind: 'router_ab_ecdsa_post_registration_session_activation_policy_v1',
    key_handle: String(args.keyHandle),
    session_policy: args.request.session_policy,
  };
}

function buildEmailOtpUnlockSessionPolicy(args: {
  readonly keyHandle: string;
  readonly thresholdSessionId: string;
  readonly walletSessionMintId: string;
  readonly ttlMs: number;
  readonly remainingUses: number;
  readonly runtimePolicyScope: ThresholdRuntimePolicyScope;
}): RouterAbEcdsaPostRegistrationSessionActivationPolicyV1 {
  return {
    kind: 'router_ab_ecdsa_post_registration_session_activation_policy_v1',
    key_handle: String(args.keyHandle),
    session_policy: {
      threshold_session_id: requireEmailOtpUnlockThresholdSessionId(args.thresholdSessionId),
      wallet_session_mint_id: requireEmailOtpUnlockWalletSessionMintId(args.walletSessionMintId),
      ttl_ms: args.ttlMs,
      remaining_uses: args.remainingUses,
      runtime_policy_scope: args.runtimePolicyScope,
    },
  };
}

function requireEmailOtpUnlockSessionResponse(
  result: EmailOtpWalletUnlockResult,
): RouterAbEcdsaPostRegistrationSessionActivationResponseV1 {
  if (!result.ecdsaSession) {
    throw new Error('Email OTP unlock did not return its ECDSA Wallet Session');
  }
  return result.ecdsaSession;
}

function requireEmailOtpEcdsaCustodySigner(
  continuity: EmailOtpEcdsaCustodyContinuityV1,
  walletId: string,
  keyHandle: string,
): EmailOtpEcdsaCustodyContinuityV1['signers'][number] {
  const first = continuity.signers[0];
  if (!first) throw new Error('Email OTP ECDSA custody continuity is empty');
  if (first.walletKey.walletId !== walletId || first.walletKey.keyHandle !== keyHandle) {
    throw new Error('Email OTP ECDSA custody continuity changed the requested wallet key');
  }
  for (const signer of continuity.signers) {
    if (
      signer.walletKey.walletId !== first.walletKey.walletId ||
      signer.walletKey.keyHandle !== first.walletKey.keyHandle ||
      signer.walletKey.ecdsaThresholdKeyId !== first.walletKey.ecdsaThresholdKeyId ||
      signer.walletKey.signingRootId !== first.walletKey.signingRootId ||
      signer.walletKey.signingRootVersion !== first.walletKey.signingRootVersion ||
      signer.walletKey.relayerKeyId !== first.walletKey.relayerKeyId ||
      JSON.stringify(signer.walletKey.publicCapability) !==
        JSON.stringify(first.walletKey.publicCapability) ||
      JSON.stringify(signer.activationReceipt) !== JSON.stringify(first.activationReceipt) ||
      JSON.stringify(signer.runtimePolicyScope) !== JSON.stringify(first.runtimePolicyScope)
    ) {
      throw new Error('Email OTP ECDSA custody continuity conflicts across targets');
    }
  }
  return first;
}

function nonEmptyEmailOtpEcdsaChainTargets(
  continuity: EmailOtpEcdsaCustodyContinuityV1,
): readonly [ThresholdEcdsaChainTarget, ...ThresholdEcdsaChainTarget[]] {
  const [first, ...rest] = continuity.signers;
  if (!first) throw new Error('Email OTP ECDSA custody continuity is empty');
  return [first.chainTarget, ...rest.map((signer) => signer.chainTarget)];
}

async function restoreEmailOtpEcdsaCustodyContinuity(args: {
  readonly restore: EmailOtpWalletUnlockResult & { readonly operation: 'wallet_unlock' };
  readonly walletId: string;
  readonly keyHandle: string;
  readonly authority: WalletAuthAuthorityRef;
  readonly restoreWalletCustodyEcdsaContinuity: EmailOtpEcdsaLoginPorts['restoreWalletCustodyEcdsaContinuity'];
}): Promise<void> {
  const custody = args.restore.ecdsaCustody;
  const signer = requireEmailOtpEcdsaCustodySigner(
    custody.continuity,
    args.walletId,
    args.keyHandle,
  );
  await args.restoreWalletCustodyEcdsaContinuity({
    authority: args.authority,
    chainTargets: nonEmptyEmailOtpEcdsaChainTargets(custody.continuity),
    walletId: signer.walletKey.walletId,
    keyHandle: signer.walletKey.keyHandle,
    ecdsaThresholdKeyId: signer.walletKey.ecdsaThresholdKeyId,
    signingRootId: signer.walletKey.signingRootId,
    signingRootVersion: signer.walletKey.signingRootVersion,
    relayerKeyId: signer.walletKey.relayerKeyId,
    participantIds: signer.walletKey.participantIds,
    publicCapability: signer.walletKey.publicCapability,
    activationReceipt: signer.activationReceipt,
    runtimePolicyScope: signer.runtimePolicyScope,
    readyStateBlobB64u: custody.readyStateBlobB64u,
    publicFacts: custody.publicFacts,
  });
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

function requireEmailOtpWalletSessionToken(value: unknown) {
  const walletSessionToken = String(value || '').trim();
  if (!walletSessionToken) {
    throw new Error('Email OTP unlock returned an empty Wallet Session token');
  }
  return requireOpaqueWalletSessionToken(walletSessionToken);
}

function requireEmailOtpBootstrapTransportAuth(
  value: WalletSessionRouteAuth | undefined,
): WalletSessionRouteAuth {
  if (!value) throw new Error('Email OTP ECDSA bootstrap requires route auth');
  return value;
}

function emailOtpNonUnlockWorkerHandleOperationFromLoginOperation(
  operation: WalletEmailOtpOperation,
): Exclude<EmailOtpWorkerSessionHandleOperation, 'wallet_unlock' | 'registration'> {
  switch (operation) {
    case WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION:
      return 'sign';
    case WALLET_EMAIL_OTP_EXPORT_OPERATION:
      return 'export';
    case WALLET_EMAIL_OTP_UNLOCK_OPERATION:
      throw new Error('Email OTP wallet unlock requires first-session activation');
    case 'registration':
      throw new Error('Email OTP ECDSA registration requires wallet-registration prepare');
  }
  operation satisfies never;
  throw new Error('Unsupported Email OTP non-unlock operation');
}

function emailOtpNonUnlockEcdsaHandleBinding(args: {
  keyHandle: string;
  authSubjectId: string;
  operation: Exclude<EmailOtpWorkerSessionHandleOperation, 'wallet_unlock' | 'registration'>;
  chainTarget: ThresholdEcdsaChainTarget;
}): Exclude<EmailOtpEcdsaSessionBootstrapHandleBinding, { operation: 'wallet_unlock' }> {
  switch (args.operation) {
    case 'sign':
      return {
        keyHandle: args.keyHandle,
        authSubjectId: args.authSubjectId,
        operation: 'sign',
        chainTarget: args.chainTarget,
      };
    case 'export':
      return {
        keyHandle: args.keyHandle,
        authSubjectId: args.authSubjectId,
        operation: 'export',
        chainTarget: args.chainTarget,
      };
  }
  args.operation satisfies never;
  throw new Error('Unsupported Email OTP non-unlock handle operation');
}

export function buildEmailOtpExistingKeyActivation(args: {
  existingKey: ResolvedEmailOtpExistingEcdsaKey;
  chainTarget: ThresholdEcdsaChainTarget;
  thresholdSessionId: string;
  ttlMs: number;
  remainingUses: number;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  relayerUrl: string;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  emailOtpWorkerSessionHandle: ReturnType<typeof parseEmailOtpWorkerIssuedSessionHandle>;
  authorization:
    | {
        kind: 'route_authorized';
        routeAuth: WalletSessionRouteAuth;
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
  });
  const lanePolicy = buildEvmFamilyEcdsaSessionLanePolicy({
    chainTarget: args.chainTarget,
    thresholdSessionId: sessionIdentity.thresholdSessionId,
    ttlMs: args.ttlMs,
    remainingUses: args.remainingUses,
    runtimePolicyScope: args.runtimePolicyScope,
  });
  if (isEmailOtpSessionAuthContext(args.emailOtpAuthContext)) {
    const common = {
      source: 'email_otp',
      relayerUrl: args.relayerUrl,
      sessionIdentity,
      sessionKind: 'opaque',
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
      sessionKind: 'opaque',
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

export function buildEmailOtpRecoveredKeyActivation(args: {
  existingKey: ResolvedEmailOtpExistingEcdsaKey;
  chainTarget: ThresholdEcdsaChainTarget;
  thresholdSessionId: string;
  ttlMs: number;
  remainingUses: number;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  relayerUrl: string;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpSessionAuthContext;
  emailOtpWorkerSessionHandle: ReturnType<typeof parseEmailOtpWorkerIssuedSessionHandle>;
  routeAuth: WalletSessionRouteAuth;
}): ThresholdEcdsaActivationRequest {
  if (args.emailOtpWorkerSessionHandle.action !== 'threshold_ecdsa_bootstrap') {
    throw new Error('Email OTP ECDSA recovery requires a threshold ECDSA worker handle');
  }
  const thresholdSessionId = SigningSessionIds.thresholdEcdsaSession(args.thresholdSessionId);
  return buildEmailOtpRecoveredSessionEcdsaActivation({
    source: 'email_otp',
    relayerUrl: args.relayerUrl,
    sessionIdentity: {
      kind: 'recovered_material_session',
      thresholdSessionId,
      materialActivation: args.existingKey.persistedRoleLocalMaterial.materialActivation,
    },
    sessionKind: 'opaque',
    sessionBudgetUses: args.remainingUses,
    runtimePolicy: { kind: 'scoped_policy', scope: args.runtimePolicyScope },
    emailOtpWorkerSessionHandle: args.emailOtpWorkerSessionHandle,
    emailOtpAuthContext: args.emailOtpAuthContext,
    walletSessionRouteAuth: args.routeAuth,
    walletKey: args.existingKey.walletKey,
    lanePolicy: buildEvmFamilyEcdsaRecoveredMaterialLanePolicy({
      chainTarget: args.chainTarget,
      thresholdSessionId,
      ttlMs: args.ttlMs,
      remainingUses: args.remainingUses,
      runtimePolicyScope: args.runtimePolicyScope,
    }),
    publicCapability: args.existingKey.publicCapability,
    existingRoleLocalMaterial: args.existingKey.persistedRoleLocalMaterial,
  });
}

type EmailOtpPrimaryEcdsaSessionProvisioning =
  | {
      kind: 'route_authorized';
      sessionIdentity: EcdsaSessionIdentity;
      routeAuth: WalletSessionRouteAuth;
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
  emailOtpSessionHandle: EmailOtpEcdsaSessionBootstrapHandlePayload;
  primarySession: EmailOtpPrimaryEcdsaSessionProvisioning;
  ports: EmailOtpEcdsaLoginPorts;
}): Promise<ThresholdEcdsaSessionBootstrapResult[]> {
  const emailOtpWorkerSessionHandle = parseEmailOtpWorkerIssuedSessionHandle(
    args.emailOtpSessionHandle,
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
  const additionalAuthorization =
    args.primarySession.kind === 'preauthorized_wallet_unlock'
      ? primarySession.authorization
      : {
          kind: 'route_authorized' as const,
          routeAuth: {
            kind: 'opaque_wallet_session' as const,
            walletSessionToken: requireEmailOtpWalletSessionToken(
              primaryBootstrap.session.walletSessionToken,
            ),
          },
        };
  const additionalContext: ProvisionEmailOtpExistingKeySessionContext = {
    ...provisionContext,
    args: {
      ...args,
      primarySession: {
        kind: 'route_authorized',
        sessionIdentity: primarySession.sessionIdentity,
        routeAuth: {
          kind: 'opaque_wallet_session',
          walletSessionToken: requireEmailOtpWalletSessionToken(
            primaryBootstrap.session.walletSessionToken,
          ),
        },
      },
    },
    authorization: additionalAuthorization,
  };
  const additionalBootstraps = await Promise.all(
    args.publicationChainTargets
      .slice(1)
      .map(provisionEmailOtpAdditionalExistingKeySessionForTarget.bind(null, additionalContext)),
  );
  const bootstraps = [primaryBootstrap, ...additionalBootstraps];
  if (!primaryBootstrap) {
    throw new Error('Email OTP ECDSA activation did not return a primary warm session');
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
  loadWalletCustodyEd25519Material: (args: {
    nearAccountId: string;
    signerSlot: number;
  }) => Promise<EmailOtpWalletCustodyEd25519MaterialRequest>;
  restoreWalletCustodyEcdsaContinuity: (
    args: Omit<ImportWalletCustodyEcdsaContinuityInput, 'store'>,
  ) => Promise<unknown>;
  provisionThresholdEcdsaSession: (
    request: ThresholdEcdsaActivationRequest,
  ) => Promise<ThresholdEcdsaSessionBootstrapResult>;
  provisionEmailOtpEcdsaExplicitExportSession: (
    request: ThresholdEcdsaEmailOtpExportActivationRequest,
  ) => Promise<EmailOtpEcdsaExplicitExportBootstrapResult>;
  requireRelayUrl: () => string;
  requireSigningSessionSealGroupId: () => string;
  resolveCurrentEcdsaCapabilityRuntime: typeof resolveActiveEcdsaCapabilityRuntime;
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

// The runtime policy scope is sealed-runtime state and is never derived from the opaque token.
function requireEmailOtpEcdsaSigningRefreshRuntimePolicyScope(args: {
  runtimePolicyScope: ThresholdRuntimePolicyScope | null | undefined;
}): ThresholdRuntimePolicyScope {
  const runtimePolicyScope = args.runtimePolicyScope;
  if (!runtimePolicyScope) {
    throw new Error('Email OTP ECDSA signing refresh requires runtimePolicyScope');
  }
  return runtimePolicyScope;
}

function buildDurableAuthorityEmailOtpEcdsaSigningRefreshFacts(
  committedLane: EcdsaCommittedLane,
): Omit<EmailOtpEcdsaSigningRefreshFacts, 'runtimePolicyScope'> {
  if (committedLane.authority.factor.kind !== 'email_otp' || !committedLane.authLane) {
    throw new Error(
      '[SigningEngine][email-otp][ecdsa] committed lane requires Email OTP authority',
    );
  }
  return {
    // Exact lane signer binding, not a JWT-decoded authority structure.
    keyHandle: String(toEvmFamilyEcdsaKeyHandle(committedLane.lane.identity.signer.keyHandle)),
    participantIds: committedLane.lane.identity.signer.key.participantIds.map(Number),
    emailHashHex: committedLane.authority.verifier.emailHashHex,
    providerIdentity: {
      kind: 'explicit_provider_user',
      provider: committedLane.authority.factor.provider,
      providerUserId: committedLane.authority.factor.providerUserId,
    },
  };
}

// Sealed-record authority is the only committed-lane form; the record-backed
// refresh facts had no constructible input.
async function buildEmailOtpEcdsaSigningRefreshFacts(args: {
  committedLane: EcdsaCommittedLane;
  chainTarget: ThresholdEcdsaChainTarget;
  resolveCurrentEcdsaCapabilityRuntime: typeof resolveActiveEcdsaCapabilityRuntime;
}): Promise<EmailOtpEcdsaSigningRefreshFacts> {
  const runtimeResolution = await args.resolveCurrentEcdsaCapabilityRuntime({
    walletId: toWalletId(args.committedLane.lane.identity.signer.walletId),
    chainTarget: args.chainTarget,
  });
  if (runtimeResolution.kind !== 'resolved') {
    throw new Error(
      `[SigningEngine][email-otp][ecdsa] signing refresh runtime unavailable: ${runtimeResolution.reason}`,
    );
  }
  if (
    !mpcMaterialActivationRefsEqual(
      runtimeResolution.runtime.materialActivation,
      args.committedLane.lane.materialActivation,
    )
  ) {
    throw new Error(
      '[SigningEngine][email-otp][ecdsa] signing refresh runtime material activation mismatch',
    );
  }
  const facts = buildDurableAuthorityEmailOtpEcdsaSigningRefreshFacts(args.committedLane);
  return {
    ...facts,
    runtimePolicyScope: requireEmailOtpEcdsaSigningRefreshRuntimePolicyScope({
      runtimePolicyScope: runtimeResolution.runtime.runtimePolicyScope,
    }),
  };
}

export async function loginWithEmailOtpEcdsaCapabilityForSigning(
  args: LoginEmailOtpEcdsaCapabilityForSigningArgs,
  ports: {
    requireRelayUrl: () => string;
    resolveCurrentEcdsaCapabilityRuntime: typeof resolveActiveEcdsaCapabilityRuntime;
    loginWithEcdsaCapabilityInternal: (
      args: LoginEmailOtpEcdsaCapabilityArgs,
    ) => Promise<EmailOtpThresholdEcdsaLoginResult>;
  },
): Promise<EmailOtpThresholdEcdsaLoginResult> {
  const operation = WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION;
  const emailOtpAuthPolicy: EmailOtpAuthPolicy = 'session';
  const remainingUses = normalizeEmailOtpEcdsaSigningRemainingUses(args.remainingUses);
  const committedLane = args.committedLane;
  const refreshFacts = await buildEmailOtpEcdsaSigningRefreshFacts({
    committedLane,
    chainTarget: args.chainTarget,
    resolveCurrentEcdsaCapabilityRuntime: ports.resolveCurrentEcdsaCapabilityRuntime,
  });
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

async function reusableEd25519WalletSessionTokenForEcdsaUnlock(args: {
  walletId: WalletSessionRef['walletId'];
  authority: ResolvedEmailOtpExistingEcdsaKey['persistedRoleLocalMaterial']['authority'];
}): Promise<string | null> {
  const read = await walletSessionAuthorizations.readActiveForWallet(toWalletId(args.walletId));
  if (read.kind !== 'found') return null;
  const projection = read.projection;
  if (
    projection.authMethod !== 'email_otp' ||
    projection.authority.authorityDigest !== args.authority.authorityDigest ||
    projection.expiresAtMs <= Date.now()
  ) {
    return null;
  }
  const walletSessionToken = walletSessionTokenForCurve(projection, 'ed25519');
  return walletSessionToken ? String(walletSessionToken) : null;
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
  const groupId = String(args.groupId || ports.requireSigningSessionSealGroupId()).trim();
  const configuredRemainingUses = args.remainingUses;
  const defaultRemainingUses = ports.configs.signing.sessionDefaults?.remainingUses;
  const requestedRemainingUses = Math.min(
    Math.max(
      1,
      Math.floor(
        Number(configuredRemainingUses ?? defaultRemainingUses ?? DEFAULT_UNLOCK_REMAINING_USES) ||
          1,
      ),
    ),
    DEFAULT_UNLOCK_REMAINING_USES,
  );
  const requestedStepUpSignatureUses = Math.max(
    1,
    Math.floor(Number(configuredRemainingUses) || 1),
  );
  const unlockRemainingUses =
    resolveWalletUnlockSessionUsesFromRequestedUses({
      requestedRemainingUses,
    }) ||
    (() => {
      throw new Error('[SigningEngine][email-otp] unlock session uses are required');
    })();
  const remainingUses = isSigningStepUp ? requestedStepUpSignatureUses : unlockRemainingUses;
  const workerCtx = ports.getSignerWorkerContext();
  const routePlan = args.routePlan;
  const bootstrapRouteAuth =
    args.ecdsaBootstrapAuthorization.kind === 'route_plan_auth'
      ? emailOtpEcdsaBootstrapRouteAuthFromRoutePlan(routePlan)
      : args.ecdsaBootstrapAuthorization.routeAuth;
  const bootstrapTransportAuth = bootstrapRouteAuth
    ? emailOtpEcdsaBootstrapRouteAuthToTransport(bootstrapRouteAuth)
    : undefined;
  // Runtime policy comes from sealed runtime state.
  const requestedRuntimePolicyScope = args.runtimePolicyScope;

  if (!workerCtx) {
    throw new Error('Email OTP login requires the dedicated emailOtp worker');
  }
  const emailOtpProviderIdentity = resolveEmailOtpEcdsaProviderIdentity({
    identity: args.providerIdentity,
  });
  const emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext =
    emailOtpAuthRetention === 'single_use'
      ? buildEmailOtpAuthContextForWalletAuthMethod({
          policy: emailOtpAuthContextPolicy,
          walletId: toWalletId(args.walletSession.walletId),
          emailHashHex: args.emailHashHex,
          retention: 'single_use',
          provider: emailOtpProviderIdentity.provider,
          providerUserId: emailOtpProviderIdentity.providerUserId,
        })
      : buildEmailOtpAuthContextForWalletAuthMethod({
          policy: emailOtpAuthContextPolicy,
          walletId: toWalletId(args.walletSession.walletId),
          emailHashHex: args.emailHashHex,
          retention: 'session',
          reason: emailOtpAuthReason,
          provider: emailOtpProviderIdentity.provider,
          providerUserId: emailOtpProviderIdentity.providerUserId,
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
  const isWalletUnlock = operation === WALLET_EMAIL_OTP_UNLOCK_OPERATION;
  const requestedKeyHandle = String(args.keyHandle || '').trim();
  let existingKey = await resolveEmailOtpExistingEcdsaKey({
    walletId: toWalletId(args.walletSession.walletId),
    chainTarget,
    scope: requestedRuntimePolicyScope
      ? { kind: 'exact', runtimePolicyScope: requestedRuntimePolicyScope }
      : { kind: 'durable_manifest' },
    keyHandle: args.keyHandle,
    listActiveEcdsaCapabilityManifestsForWallet:
      publicationPorts.listActiveEcdsaCapabilityManifestsForWallet,
  });
  if (!existingKey && !isWalletUnlock) {
    throw new Error(
      `device_link_required: local threshold ECDSA material is unavailable for ${chainTarget.kind}:${chainTarget.chainId}`,
    );
  }
  const ecdsaKeyHandle = String(existingKey?.keyHandle || requestedKeyHandle).trim();
  if (!ecdsaKeyHandle) {
    throw new Error('Email OTP ECDSA wallet unlock requires an exact key handle');
  }
  const runtimePolicyScope = existingKey?.runtimePolicyScope || requestedRuntimePolicyScope;
  if (!runtimePolicyScope) {
    throw new Error('Email OTP ECDSA wallet unlock requires runtime policy scope');
  }
  const walletCustodyEd25519Material =
    args.ed25519YaoRecovery.kind === 'requested'
      ? await ports.loadWalletCustodyEd25519Material({
          nearAccountId: args.ed25519YaoRecovery.nearAccountId,
          signerSlot: args.ed25519YaoRecovery.signerSlot,
        })
      : null;
  const reusableEd25519WalletSessionToken =
    isWalletUnlock && args.ed25519YaoRecovery.kind === 'not_requested'
      ? existingKey
        ? await reusableEd25519WalletSessionTokenForEcdsaUnlock({
            walletId: args.walletSession.walletId,
            authority: existingKey.persistedRoleLocalMaterial.authority,
          })
        : null
      : null;
  const preparedUnlockSessionPolicy = isWalletUnlock
    ? clampThresholdSessionPolicy({
        ttlMs: args.ttlMs ?? DEFAULT_THRESHOLD_SESSION_POLICY.ttlMs,
        remainingUses,
      })
    : null;
  const preparedUnlockThresholdSessionId = preparedUnlockSessionPolicy
    ? requireEmailOtpUnlockThresholdSessionId(generateSessionId('threshold-ecdsa-login'))
    : null;
  const preparedUnlockSessionActivation =
    preparedUnlockSessionPolicy && preparedUnlockThresholdSessionId && existingKey
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
  const preparedUnlockSessionPolicyWire =
    preparedUnlockSessionPolicy && preparedUnlockThresholdSessionId
      ? buildEmailOtpUnlockSessionPolicy({
          keyHandle: ecdsaKeyHandle,
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
  const exportInput =
    operation === WALLET_EMAIL_OTP_EXPORT_OPERATION
      ? requireEmailOtpExplicitExportInput(args)
      : null;
  const unlockArgs = exportInput
    ? {
        walletSession: args.walletSession,
        relayUrl,
        groupId,
        verification: requireEmailOtpExplicitExportUnsealGrant(
          exportInput.explicitExportAuthorization,
        ),
        routePlan,
        workerCtx,
        runtimePolicyScope,
        ...(args.onProgress ? { onProgress: args.onProgress } : {}),
      }
    : {
        walletSession: args.walletSession,
        relayUrl,
        groupId,
        verification: {
          kind: 'otp' as const,
          ...(args.challengeId ? { challengeId: args.challengeId } : {}),
          otpCode: args.otpCode,
        },
        routePlan,
        workerCtx,
        runtimePolicyScope,
        ...(args.onProgress ? { onProgress: args.onProgress } : {}),
      };
  const unlockResult =
    args.ed25519YaoRecovery.kind === 'not_requested'
      ? await unlockEmailOtpWallet({
          ...unlockArgs,
          ...(preparedUnlockSessionPolicyWire
            ? {
                ecdsaSessionHandleBinding: {
                  keyHandle: ecdsaKeyHandle,
                  authSubjectId: emailOtpProviderIdentity.providerUserId,
                  operation: 'wallet_unlock' as const,
                  chainTarget,
                },
                ecdsaSessionPolicy: preparedUnlockSessionActivation
                  ? emailOtpUnlockSessionPolicyFromActivationRequest({
                      request: preparedUnlockSessionActivation,
                      keyHandle: ecdsaKeyHandle,
                    })
                  : preparedUnlockSessionPolicyWire,
                walletSessionAuthorization: reusableEd25519WalletSessionToken
                  ? {
                      kind: 'reuse_ed25519_wallet_session' as const,
                      walletSessionToken: reusableEd25519WalletSessionToken,
                    }
                  : { kind: 'verified_wallet_unlock' as const },
              }
            : {
                ecdsaSessionHandleBinding: emailOtpNonUnlockEcdsaHandleBinding({
                  keyHandle: ecdsaKeyHandle,
                  authSubjectId: emailOtpProviderIdentity.providerUserId,
                  operation: emailOtpNonUnlockWorkerHandleOperationFromLoginOperation(
                    routePlan.operation,
                  ),
                  chainTarget,
                }),
              }),
        })
      : await unlockEmailOtpWalletCapabilities({
          ...unlockArgs,
          ecdsaSessionHandleBinding: {
            keyHandle: ecdsaKeyHandle,
            authSubjectId: emailOtpProviderIdentity.providerUserId,
            operation: 'wallet_unlock',
            chainTarget,
          },
          providerSubject: args.ed25519YaoRecovery.providerSubject,
          signerSlot: args.ed25519YaoRecovery.signerSlot,
          nearAccountId: args.ed25519YaoRecovery.nearAccountId,
          expectedOperationalPublicKey: args.ed25519YaoRecovery.expectedOperationalPublicKey,
          expectedThresholdSessionId: args.ed25519YaoRecovery.expectedThresholdSessionId,
          walletCustodyEd25519Material: walletCustodyEd25519Material || { kind: 'absent' },
          remainingUses,
          ecdsaSessionPolicy: preparedUnlockSessionActivation
            ? emailOtpUnlockSessionPolicyFromActivationRequest({
                request: preparedUnlockSessionActivation,
                keyHandle: ecdsaKeyHandle,
              })
            : requireEmailOtpUnlockSessionPolicy(preparedUnlockSessionPolicyWire),
        });
  const workerResult =
    unlockResult.kind === 'wallet_unlock_capabilities' ? unlockResult.ecdsa : unlockResult;
  const ed25519YaoResult =
    unlockResult.kind === 'wallet_unlock_capabilities' ? unlockResult.ed25519Yao : null;
  try {
    if (workerResult.operation === 'wallet_unlock' && !existingKey) {
      const restoreAuthority = await walletAuthAuthorityRef({
        authority: emailOtpAuthContext.authority,
      });
      await restoreEmailOtpEcdsaCustodyContinuity({
        restore: workerResult,
        walletId: String(args.walletSession.walletId),
        keyHandle: ecdsaKeyHandle,
        authority: restoreAuthority,
        restoreWalletCustodyEcdsaContinuity: ports.restoreWalletCustodyEcdsaContinuity,
      });
    }
    if (!existingKey) {
      existingKey = await resolveEmailOtpExistingEcdsaKey({
        walletId: toWalletId(args.walletSession.walletId),
        chainTarget,
        scope: { kind: 'exact', runtimePolicyScope },
        keyHandle: ecdsaKeyHandle,
        listActiveEcdsaCapabilityManifestsForWallet:
          publicationPorts.listActiveEcdsaCapabilityManifestsForWallet,
      });
      if (!existingKey) {
        throw new Error('Email OTP ECDSA custody restore did not publish the canonical key');
      }
    }
    const effectivePreparedUnlockSessionActivation =
      preparedUnlockSessionActivation ||
      (preparedUnlockSessionPolicyWire
        ? buildStrictEcdsaPostRegistrationSessionActivationRequest({
            publicCapability: existingKey.publicCapability,
            thresholdSessionId: preparedUnlockSessionPolicyWire.session_policy.threshold_session_id,
            walletSessionMintId:
              preparedUnlockSessionPolicyWire.session_policy.wallet_session_mint_id,
            ttlMs: preparedUnlockSessionPolicyWire.session_policy.ttl_ms,
            remainingUses: preparedUnlockSessionPolicyWire.session_policy.remaining_uses,
            runtimePolicyScope,
          })
        : null);
    const exportEmailOtpAuthContext =
      operation === WALLET_EMAIL_OTP_EXPORT_OPERATION
        ? requireEmailOtpEcdsaExportAuthContext(emailOtpAuthContext)
        : null;
    const exportEmailOtpSessionHandle =
      operation === WALLET_EMAIL_OTP_EXPORT_OPERATION
        ? parseEmailOtpEcdsaExportWorkerIssuedSessionHandle(workerResult.emailOtpSessionHandle)
        : null;
    if (exportEmailOtpSessionHandle && exportEmailOtpAuthContext) {
      assertEmailOtpEcdsaExportHandleMatchesLane({
        handle: exportEmailOtpSessionHandle,
        existingKey,
        chainTarget,
        emailOtpAuthContext: exportEmailOtpAuthContext,
      });
    }
    addEmailOtpThresholdEcdsaLoginTiming(timings, 'emailOtpProofVerificationMs', timingStartedAtMs);
    const preparedUnlockSessionResponse = effectivePreparedUnlockSessionActivation
      ? requireEmailOtpUnlockSessionResponse(workerResult)
      : null;
    const sessionPolicy = preparedUnlockSessionResponse
      ? buildEmailOtpEcdsaOnlySigningBudget({
          ttlMs: args.ttlMs,
          remainingUses,
        })
      : resolveEmailOtpLoginSigningBudget({
          ecdsaResult: workerResult,
          ed25519YaoResult,
          emailOtpAuthPolicy,
          routePlan,
          requestedTtlMs: args.ttlMs,
          requestedRemainingUses: remainingUses,
        });
    timingStartedAtMs = nowMs();
    if (operation === WALLET_EMAIL_OTP_EXPORT_OPERATION) {
      if (!exportEmailOtpSessionHandle || !exportEmailOtpAuthContext) {
        throw new Error('Email OTP ECDSA export worker handle is unavailable');
      }
      const preparedExportInput = requireEmailOtpExplicitExportInput(args);
      const bootstrap = await provisionEmailOtpExplicitExportSession({
        relayerUrl: relayUrl,
        persistedMaterial: preparedExportInput.persistedExportMaterial,
        authorization: preparedExportInput.explicitExportAuthorization,
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
      ttlMs: sessionPolicy.ttlMs,
      remainingUses: sessionPolicy.remainingUses,
      emailOtpAuthContext,
      emailOtpSessionHandle: workerResult.emailOtpSessionHandle,
      primarySession: effectivePreparedUnlockSessionActivation
        ? {
            kind: 'preauthorized_wallet_unlock',
            request: effectivePreparedUnlockSessionActivation,
            response: requireEmailOtpUnlockSessionResponse(workerResult),
          }
        : {
            kind: 'route_authorized',
            sessionIdentity: buildEcdsaSessionIdentity({
              thresholdSessionId: generateSessionId('threshold-ecdsa-login'),
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
        runtimePolicyScope,
        authority: existingKey.persistedRoleLocalMaterial.authority,
        emailOtpAuthContext,
        relayerUrl: relayUrl,
        groupId,
      },
      publicationPorts,
    );
    mergeEmailOtpEcdsaPublicationTimingsIntoLoginTimings(timings, publicationTimings);
    return {
      kind: 'published_signing_session',
      value: {
        recovery: unlockResult.recovery,
        bootstrap,
        authorization,
        authorizations,
        emailOtpSessionHandle: workerResult.emailOtpSessionHandle,
        ed25519YaoRecovery: emailOtpEd25519YaoLoginMaterialFromWorkerResult(ed25519YaoResult),
        timings,
      },
    };
  } catch (error) {
    try {
      await disposeEmailOtpEd25519YaoWorkerResultAfterFailure({
        workerResult: ed25519YaoResult,
        workerContext: workerCtx,
      });
    } catch (disposalError) {
      throw new AggregateError(
        [error, disposalError],
        'Email OTP unlock failed and Ed25519 material disposal failed',
      );
    }
    throw error;
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
