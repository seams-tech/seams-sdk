import type { EmailOtpAuthPolicy, SeamsConfigsReadonly } from '@/core/types/seams';
import {
  buildEmailOtpAuthContextForWalletAuthMethod,
  emailOtpAuthContextEmailHashHex,
  emailOtpAuthContextProvider,
  emailOtpAuthContextProviderUserId,
  emailOtpAuthContextReason,
  emailOtpAuthContextRetention,
  type ThresholdEcdsaEmailOtpAuthContext,
} from '@/core/signingEngine/session/identity/laneIdentity';
import { toWalletSessionUserId } from '@/core/signingEngine/session/identity/emailOtpHssIdentity';
import type {
  ThresholdEcdsaChainTarget,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import {
  generateSigningGrantId,
  parseThresholdRuntimePolicyScopeFromJwt,
} from '@/core/signingEngine/threshold/sessionPolicy';
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import type { WarmSessionEcdsaCapabilityState } from '@/core/signingEngine/session/warmCapabilities/types';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type {
  EmailOtpEcdsaSessionBootstrapHandlePayload,
  EmailOtpWorkerProgressEvent,
  EmailOtpWorkerSessionHandleOperation,
} from '@/core/signingEngine/workerManager/workerTypes';
import type { EmailOtpEcdsaCommittedLane } from '../../flows/signEvmFamily/ecdsaSelection';
import {
  WALLET_EMAIL_OTP_EXPORT_OPERATION,
  WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
  WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
  WALLET_EMAIL_OTP_UNLOCK_OPERATION,
  type WalletEmailOtpLoginOperation,
  type WalletEmailOtpOperation,
} from '@shared/utils/emailOtpDomain';
import {
  ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
  type RouterAbEd25519NormalSigningState,
} from '@shared/utils/signingSessionSeal';
import type { EmailOtpEcdsaBootstrapStrictPayload } from '@/core/signingEngine/workerManager/workerTypes';
import type { EmailOtpBootstrapRecovery } from '../../stepUpConfirmation/otpPrompt/bootstrapRecovery';
import {
  deriveEvmFamilySigningKeySlotIdFromRuntimePolicyScope,
  toEvmFamilyEcdsaKeyHandle,
} from '../identity/evmFamilyEcdsaIdentity';
import {
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
  emailOtpEcdsaPublicationTargetPlans,
  type EmailOtpEcdsaPublicationTimings,
  type EmailOtpEcdsaPublicationPorts,
} from './ecdsaPublication';
import { unlockEmailOtpWallet } from './walletUnlock';
import {
  assertEmailOtpSigningSessionAuthLane,
  buildEmailOtpEcdsaMintingSession,
  buildEmailOtpSigningSessionRoutePlan,
  emailOtpEcdsaBootstrapRouteAuthFromRoutePlan,
  emailOtpEcdsaBootstrapRouteAuthToTransport,
  routeAuthFromEmailOtpRoutePlan,
  walletSessionRouteAuthFromEcdsaBootstrap,
  thresholdSessionIdFromEcdsaBootstrap,
  type EmailOtpEcdsaBootstrapAuthorization,
  signingGrantIdFromEcdsaBootstrap,
} from './routePlan';
import {
  type EmailOtpEd25519SessionReconstructionPlan,
  type EmailOtpThresholdEd25519ProvisioningResult,
  type ReconstructEmailOtpEd25519SessionArgs,
} from './provisioning';
import type {
  ThresholdEcdsaSessionRecord,
  ThresholdEd25519SessionRecord,
} from '../persistence/records';
import { thresholdEcdsaEmailOtpAuthContext } from '../persistence/records';
import {
  tryActivateEmailOtpEd25519UnlockFromSealedMaterial,
} from './ed25519Warmup';
import type {
  EmailOtpEd25519RecoveryCodeSigningSessionHydration,
} from './recoveryCodeWarmSessionHydration';
import {
  DEV_DEFAULT_UNLOCK_REMAINING_USES,
  normalizeStepUpOperationId,
  resolvePostExhaustionStepUpBudgetPolicy,
  resolveSigningBudgetPolicyRemainingUses,
  resolveWalletUnlockBudgetPolicyFromRequestedUses,
} from '../budget/policy';

export type EmailOtpThresholdEcdsaLoginTimingBucket =
  | 'emailOtpProofVerificationMs'
  | 'ecdsaMaterialRestoreMs'
  | 'signingSessionSealApplyMs'
  | 'warmCapabilityPersistenceMs'
  | 'ed25519MaterialRestoreMs';

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
  ed25519Reconstruction: EmailOtpEd25519ReconstructionResult;
  timings: EmailOtpThresholdEcdsaLoginTimings;
};

export type EmailOtpEd25519ReconstructionResult =
  | {
      kind: 'completed';
      sessionMaterial: EmailOtpThresholdEd25519ProvisioningResult;
    }
  | {
      kind: 'deferred';
      reason:
        | 'missing_client_seed_material'
        | 'missing_ed25519_key_identity'
        | 'missing_route_auth'
        | 'missing_runtime_policy_scope'
        | 'not_needed_for_ecdsa';
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
    ed25519MaterialRestoreMs: 0,
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

function routerAbNormalSigningStateFromConfigs(
  configs: SeamsConfigsReadonly,
): RouterAbEd25519NormalSigningState {
  const normalSigning = configs.signing.routerAb.normalSigning;
  switch (normalSigning.mode) {
    case 'enabled':
      return {
        kind: ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
        signingWorkerId: normalSigning.signingWorkerId,
      };
    case 'disabled':
      throw new Error(
        '[SigningEngine][email-otp] Router A/B normal signing must be enabled for Ed25519 reconstruction',
      );
    default: {
      const exhaustive: never = normalSigning;
      throw new Error(
        `[SigningEngine][email-otp] Unsupported Router A/B normal-signing mode: ${String(
          (exhaustive as { mode?: unknown })?.mode || '',
        )}`,
      );
    }
  }
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
  ed25519ReconstructionMode: 'await' | 'skip';
  ed25519SessionReconstruction: EmailOtpEd25519SessionReconstructionPlan;
  providerIdentity: EmailOtpEcdsaProviderIdentity;
  authSubjectId?: never;
  includeEcdsaExportArtifact?: boolean;
};

function buildEd25519ReconstructionAuthContext(args: {
  ecdsaAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  providerUserId: string;
}): ThresholdEcdsaEmailOtpAuthContext {
  const providerUserId = normalizeEmailOtpProviderUserId(
    args.providerUserId,
    'Email OTP Ed25519 reconstruction provider user id',
  );
  if (emailOtpAuthContextReason(args.ecdsaAuthContext) === 'sign') {
    const retention = emailOtpAuthContextRetention(args.ecdsaAuthContext);
    const provider = emailOtpAuthContextProvider(args.ecdsaAuthContext);
    if (retention === 'single_use') {
      return buildEmailOtpAuthContextForWalletAuthMethod({
        policy: args.ecdsaAuthContext.policy,
        walletId: args.ecdsaAuthContext.authority.walletId,
        emailHashHex: emailOtpAuthContextEmailHashHex(args.ecdsaAuthContext),
        retention: 'single_use',
        provider,
        providerUserId,
      });
    }
    return buildEmailOtpAuthContextForWalletAuthMethod({
      policy: args.ecdsaAuthContext.policy,
      walletId: args.ecdsaAuthContext.authority.walletId,
      emailHashHex: emailOtpAuthContextEmailHashHex(args.ecdsaAuthContext),
      retention: 'session',
      reason: 'sign',
      provider,
      providerUserId,
    });
  }
  return buildEmailOtpAuthContextForWalletAuthMethod({
    policy: 'session',
    walletId: args.ecdsaAuthContext.authority.walletId,
    emailHashHex: emailOtpAuthContextEmailHashHex(args.ecdsaAuthContext),
    retention: 'session',
    reason: 'login',
    provider: emailOtpAuthContextProvider(args.ecdsaAuthContext),
    providerUserId,
  });
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

export type EmailOtpEcdsaLoginPorts = {
  configs: SeamsConfigsReadonly;
  getSignerWorkerContext: () => WorkerOperationContext | null | undefined;
  requireRelayUrl: () => string;
  requireShamirPrimeB64u: () => string;
  requireRpId: (operation: string) => string;
  rememberAppSessionJwt: (args: {
    walletSession: WalletSessionRef;
    appSessionJwt?: string;
  }) => void;
  publicationPorts: EmailOtpEcdsaPublicationPorts;
  reconstructEd25519Session: (
    args: ReconstructEmailOtpEd25519SessionArgs,
  ) => Promise<EmailOtpThresholdEd25519ProvisioningResult>;
  getThresholdEd25519SessionRecordByThresholdSessionId: (
    thresholdSessionId: string,
  ) => ThresholdEd25519SessionRecord | null;
  recoveryCodeSigningSessionHydration: EmailOtpEd25519RecoveryCodeSigningSessionHydration;
};

export type LoginEmailOtpEcdsaCapabilityForSigningArgs = {
  walletSession: WalletSessionRef;
  subjectId?: never;
  chainTarget: ThresholdEcdsaChainTarget;
  challengeId: string;
  otpCode: string;
  committedLane: EmailOtpEcdsaCommittedLane;
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
  committedLane: EmailOtpEcdsaCommittedLane;
  record?: never;
  routeAuth?: never;
  authLane?: never;
  appSessionJwt?: never;
  registrationAttemptId?: never;
};

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
  const emailOtpAuthPolicy: EmailOtpAuthPolicy = 'per_operation';
  const remainingUses = 1;
  const committedLane = args.committedLane;
  if (committedLane.source !== 'record_backed') {
    throw new Error(
      'Email OTP ECDSA signing refresh requires a record-backed committed lane with bound authority',
    );
  }
  const record = committedLane.record;
  if (record.source !== 'email_otp') {
    throw new Error('Email OTP ECDSA signing refresh requires an Email OTP session record');
  }
  const emailOtpAuthContext = thresholdEcdsaEmailOtpAuthContext(record);
  if (!emailOtpAuthContext) {
    throw new Error('Email OTP ECDSA signing refresh requires Email OTP auth context');
  }
  const routePlan = buildEmailOtpSigningSessionRoutePlan({
    authLane: assertEmailOtpSigningSessionAuthLane(committedLane.authLane),
    operation,
  });
  const keyHandle = String(toEvmFamilyEcdsaKeyHandle(record.keyHandle));
  return await ports.loginWithEcdsaCapabilityInternal({
    walletSession: args.walletSession,
    chainTarget: args.chainTarget,
    emailOtpAuthPolicy,
    emailOtpAuthReason: 'sign',
    challengeId: args.challengeId,
    otpCode: args.otpCode,
    operation,
    keyHandle,
    participantIds: record.participantIds,
    routePlan,
    emailHashHex: emailOtpAuthContextEmailHashHex(emailOtpAuthContext),
    providerIdentity: emailOtpEcdsaProviderIdentityFromRecord(record),
    ecdsaBootstrapAuthorization: { kind: 'route_plan_auth' },
    remainingUses,
    ...(record.runtimePolicyScope ? { runtimePolicyScope: record.runtimePolicyScope } : {}),
    ed25519ReconstructionMode: 'skip',
    ed25519SessionReconstruction: {
      kind: 'defer',
      reason: 'not_needed_for_ecdsa',
    },
  });
}

export async function loginWithEmailOtpEcdsaCapability(
  args: LoginEmailOtpEcdsaCapabilityArgs,
  ports: EmailOtpEcdsaLoginPorts,
): Promise<EmailOtpThresholdEcdsaLoginResult> {
  const timings = createEmailOtpThresholdEcdsaLoginTimings();
  const chainTarget = args.chainTarget;
  const emailOtpAuthPolicy: EmailOtpAuthPolicy =
    args.emailOtpAuthPolicy || ports.configs.signing.emailOtp.authPolicy;
  const emailOtpAuthReason = args.emailOtpAuthReason || 'login';
  const emailOtpAuthRetention =
    emailOtpAuthReason === 'sign' && emailOtpAuthPolicy === 'per_operation'
      ? 'single_use'
      : 'session';
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
    operationId: normalizeStepUpOperationId(
      args.operation || WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
    ),
    requiredSignatureUses: requestedStepUpSignatureUses,
  });
  const remainingUses =
    emailOtpAuthRetention === 'single_use'
      ? resolveSigningBudgetPolicyRemainingUses(postExhaustionStepUpBudgetPolicy)
      : resolveSigningBudgetPolicyRemainingUses(unlockBudgetPolicy);
  const workerCtx = ports.getSignerWorkerContext();
  const rpId = ports.requireRpId('Email OTP login');
  const routePlan = args.routePlan;
  const mintingSession = buildEmailOtpEcdsaMintingSession({
    emailOtpAuthPolicy,
    routePlan,
    generateSigningGrantId,
  });
  const signingGrantId = mintingSession.signingGrantId;
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
    ports.rememberAppSessionJwt({ walletSession: args.walletSession, appSessionJwt });
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
  const keyHandle = String(args.keyHandle || '').trim();
  const publicationTargetPlans = emailOtpEcdsaPublicationTargetPlans({
    walletId: toWalletId(args.walletSession.walletId),
    runtimePolicyScope,
    chainTarget,
    publicationChainTargets,
    ...(keyHandle ? { keyHandle } : {}),
  });
  const walletSessionUserId = toWalletSessionUserId(args.walletSession.walletId);
  let timingStartedAtMs = nowMs();
  const workerResult = await unlockEmailOtpWallet({
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
  });
  addEmailOtpThresholdEcdsaLoginTiming(
    timings,
    'emailOtpProofVerificationMs',
    timingStartedAtMs,
  );
  const bootstrapAuth = {
    sessionKind: 'jwt' as const,
    routeAuth:
      bootstrapTransportAuth ||
      (() => {
        throw new Error('Email OTP ECDSA bootstrap requires route auth');
      })(),
  };
  const bootstrapPayload: EmailOtpEcdsaBootstrapStrictPayload = {
    relayUrl,
    walletId: String(args.walletSession.walletId),
    walletSessionUserId,
    userId: emailOtpProviderUserId,
    clientRootShareHandle: workerResult.clientRootShareHandle,
    chainTarget,
    publicationTargetPlans,
    runtimePolicyScope,
    ...(Array.isArray(args.participantIds) && args.participantIds.length > 0
      ? { participantIds: args.participantIds }
      : {}),
    ...bootstrapAuth,
    signingGrantId,
    ...(typeof args.ttlMs === 'number' ? { ttlMs: args.ttlMs } : {}),
    ...(typeof remainingUses === 'number' ? { remainingUses } : {}),
    ...(args.includeEcdsaExportArtifact ? { includeEcdsaExportArtifact: true } : {}),
  };
  timingStartedAtMs = nowMs();
  const bootstrapResult = await workerCtx.requestWorkerOperation({
    kind: 'emailOtp',
    request: {
      type: 'bootstrapEmailOtpEcdsaSessionsFromWorkerHandle',
      timeoutMs: 60_000,
      payload: bootstrapPayload,
      onEvent: args.onProgress,
    },
  });
  addEmailOtpThresholdEcdsaLoginTiming(timings, 'ecdsaMaterialRestoreMs', timingStartedAtMs);
  const ed25519ReconstructionAuthContext = buildEd25519ReconstructionAuthContext({
    ecdsaAuthContext: emailOtpAuthContext,
    providerUserId: emailOtpProviderUserId,
  });
  const { bootstrap, warmCapability, warmCapabilities, timings: publicationTimings } =
    await commitEmailOtpEcdsaPublicationBootstraps(
      {
        walletId: toWalletId(args.walletSession.walletId),
        publicationChainTargets,
        bootstraps: bootstrapResult.bootstraps,
        signingGrantId,
        emailOtpAuthContext,
        relayerUrl: relayUrl,
        shamirPrimeB64u,
      },
      ports.publicationPorts,
    );
  mergeEmailOtpEcdsaPublicationTimingsIntoLoginTimings(timings, publicationTimings);
  const thresholdEd25519RecoveryCodeSecret32B64u = String(
    workerResult.recovery?.thresholdEd25519RecoveryCodeSecret32B64u || '',
  ).trim();
  let ed25519Reconstruction: EmailOtpEd25519ReconstructionResult = {
    kind: 'deferred',
    reason: 'missing_client_seed_material',
  };
  if (thresholdEd25519RecoveryCodeSecret32B64u) {
    const freshWalletSessionRouteAuth = walletSessionRouteAuthFromEcdsaBootstrap(bootstrap);
    const shouldAwaitEd25519Reconstruction = args.ed25519ReconstructionMode === 'await';
    const reconstructionAuth = freshWalletSessionRouteAuth || bootstrapTransportAuth;
    const ed25519ReconstructionPlan = args.ed25519SessionReconstruction;
    const resolvedEd25519Reconstruction =
      ed25519ReconstructionPlan.kind === 'reconstruct'
        ? {
            ed25519Key: ed25519ReconstructionPlan.ed25519Key,
            runtimePolicyScope: ed25519ReconstructionPlan.runtimePolicyScope,
          }
        : ed25519ReconstructionPlan.reason === 'missing_runtime_policy_scope' && runtimePolicyScope
          ? {
              ed25519Key: ed25519ReconstructionPlan.ed25519Key,
              runtimePolicyScope,
            }
          : null;
    if (resolvedEd25519Reconstruction && reconstructionAuth) {
      const ed25519ReconstructionArgs: ReconstructEmailOtpEd25519SessionArgs = {
        kind: 'session_ed25519_reconstruction',
        relayUrl,
        rpId,
        recoveryCodeSecret32B64u: thresholdEd25519RecoveryCodeSecret32B64u,
        emailOtpAuthContext: ed25519ReconstructionAuthContext,
        routeAuth: reconstructionAuth,
        runtimePolicyScope: resolvedEd25519Reconstruction.runtimePolicyScope,
        routerAbNormalSigning: routerAbNormalSigningStateFromConfigs(ports.configs),
        ed25519Key: resolvedEd25519Reconstruction.ed25519Key,
        ...(typeof args.ttlMs === 'number' ? { ttlMs: args.ttlMs } : {}),
        ...(typeof remainingUses === 'number' ? { remainingUses } : {}),
        signingGrantId: signingGrantIdFromEcdsaBootstrap(bootstrap, signingGrantId),
        ecdsaThresholdSessionId: thresholdSessionIdFromEcdsaBootstrap(bootstrap),
      };
      if (shouldAwaitEd25519Reconstruction) {
        timingStartedAtMs = nowMs();
        const sealedActivation = await tryActivateEmailOtpEd25519UnlockFromSealedMaterial({
          walletId: toWalletId(args.walletSession.walletId),
          rpId,
          recoveryCodeSecret32B64u: thresholdEd25519RecoveryCodeSecret32B64u,
          emailOtpAuthContext: ed25519ReconstructionAuthContext,
          ed25519Key: resolvedEd25519Reconstruction.ed25519Key,
          workerCtx,
          getThresholdEd25519SessionRecordByThresholdSessionId:
            ports.getThresholdEd25519SessionRecordByThresholdSessionId,
          recoveryCodeSigningSessionHydration: ports.recoveryCodeSigningSessionHydration,
        });
        const sessionMaterial =
          sealedActivation.kind === 'activated'
            ? sealedActivation.result
            : await ports.reconstructEd25519Session(ed25519ReconstructionArgs);
        addEmailOtpThresholdEcdsaLoginTiming(
          timings,
          'ed25519MaterialRestoreMs',
          timingStartedAtMs,
        );
        timings.warmCapabilityPersistenceMs +=
          sessionMaterial.reconstructionTimings.warmCapabilityPersistenceMs;
        ed25519Reconstruction = {
          kind: 'completed',
          sessionMaterial,
        };
      } else {
        ed25519Reconstruction = {
          kind: 'deferred',
          reason: 'not_needed_for_ecdsa',
        };
      }
    } else if (shouldAwaitEd25519Reconstruction) {
      ed25519Reconstruction = {
        kind: 'deferred',
        reason:
          resolvedEd25519Reconstruction && !reconstructionAuth
            ? 'missing_route_auth'
            : ed25519ReconstructionPlan.kind === 'defer'
              ? ed25519ReconstructionPlan.reason
              : 'missing_ed25519_key_identity',
      };
    } else {
      ed25519Reconstruction = {
        kind: 'deferred',
        reason: 'not_needed_for_ecdsa',
      };
    }
  }
  return {
    recovery: workerResult.recovery,
    bootstrap,
    warmCapability,
    warmCapabilities,
    clientRootShareHandle: workerResult.clientRootShareHandle,
    ed25519Reconstruction,
    timings,
  };
}
