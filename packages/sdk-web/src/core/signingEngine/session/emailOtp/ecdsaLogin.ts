import { toAccountId } from '@/core/types/accountIds';
import type { EmailOtpAuthPolicy, SeamsConfigsReadonly } from '@/core/types/seams';
import type { ThresholdEcdsaEmailOtpAuthContext } from '@/core/signingEngine/session/identity/laneIdentity';
import {
  toEmailOtpAuthSubjectId,
  toWalletSessionUserId,
} from '@/core/signingEngine/session/identity/emailOtpHssIdentity';
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
import type { AppOrWalletSessionAuth } from '@shared/utils/sessionTokens';
import {
  WALLET_EMAIL_OTP_EXPORT_OPERATION,
  WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
  WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
  WALLET_EMAIL_OTP_UNLOCK_OPERATION,
  type WalletEmailOtpLoginOperation,
  type WalletEmailOtpOperation,
} from '@shared/utils/emailOtpDomain';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import {
  ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
  type RouterAbEd25519NormalSigningState,
} from '@shared/utils/signingSessionSeal';
import type { EmailOtpEcdsaBootstrapStrictPayload } from '@/core/signingEngine/workerManager/workerTypes';
import type { EmailOtpBootstrapRecovery } from '../../stepUpConfirmation/otpPrompt/bootstrapRecovery';
import { toEvmFamilyEcdsaKeyHandle } from '../identity/evmFamilyEcdsaIdentity';
import {
  authLaneToRouteAuth,
  resolveEmailOtpAuthLane,
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
  type EmailOtpEcdsaPublicationPorts,
} from './ecdsaPublication';
import { unlockEmailOtpWallet } from './walletUnlock';
import {
  assertEmailOtpSigningSessionAuthLane,
  buildEmailOtpEcdsaMintingSession,
  buildEmailOtpSigningSessionRoutePlan,
  buildFreshEmailOtpRoutePlan,
  emailOtpEcdsaBootstrapRouteAuthFromRoutePlan,
  emailOtpEcdsaBootstrapRouteAuthToTransport,
  routeAuthFromEmailOtpRoutePlan,
  walletSessionRouteAuthFromEcdsaBootstrap,
  thresholdSessionIdFromEcdsaBootstrap,
  type EmailOtpEcdsaBootstrapAuthorization,
  signingGrantIdFromEcdsaBootstrap,
} from './routePlan';
import type {
  EmailOtpEd25519SessionReconstructionPlan,
  EmailOtpThresholdEd25519ProvisioningResult,
  ReconstructEmailOtpEd25519SessionArgs,
} from './provisioning';
import type { ThresholdEcdsaSessionRecord } from '../persistence/records';
import {
  DEV_DEFAULT_UNLOCK_REMAINING_USES,
  normalizeStepUpOperationId,
  resolvePostExhaustionStepUpBudgetPolicy,
  resolveSigningBudgetPolicyRemainingUses,
  resolveWalletUnlockBudgetPolicyFromRequestedUses,
} from '../budget/policy';

export type EmailOtpThresholdEcdsaLoginResult = {
  recovery: EmailOtpBootstrapRecovery;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  warmCapability: WarmSessionEcdsaCapabilityState;
  clientRootShareHandle: EmailOtpEcdsaSessionBootstrapHandlePayload;
  ed25519Reconstruction: EmailOtpEd25519ReconstructionResult;
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
  appSessionJwt?: string;
  routeAuth?: AppOrWalletSessionAuth;
  ecdsaBootstrapAuthorization: EmailOtpEcdsaBootstrapAuthorization;
  keyHandle?: string;
  participantIds?: number[];
  sessionKind?: 'jwt';
  routePlan?: EmailOtpRoutePlan;
  ttlMs?: number;
  remainingUses?: number;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  publicationChainTargets?: readonly ThresholdEcdsaChainTarget[];
  onProgress?: (progress: EmailOtpWorkerProgressEvent) => void;
  ed25519ReconstructionMode: 'await' | 'skip';
  ed25519SessionReconstruction: EmailOtpEd25519SessionReconstructionPlan;
  authSubjectId?: string;
  includeEcdsaExportArtifact?: boolean;
};

function buildEd25519ReconstructionAuthContext(args: {
  ecdsaAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  authSubjectId?: string;
}): ThresholdEcdsaEmailOtpAuthContext {
  const authSubjectId = String(args.authSubjectId || '').trim();
  if (args.ecdsaAuthContext.reason === 'sign') {
    const context: ThresholdEcdsaEmailOtpAuthContext = {
      policy: args.ecdsaAuthContext.policy,
      retention: args.ecdsaAuthContext.retention,
      reason: 'sign',
      authMethod: SIGNER_AUTH_METHODS.emailOtp,
    };
    if (authSubjectId) context.authSubjectId = authSubjectId;
    return context;
  }
  const context: ThresholdEcdsaEmailOtpAuthContext = {
    policy: 'session',
    retention: 'session',
    reason: 'login',
    authMethod: SIGNER_AUTH_METHODS.emailOtp,
  };
  if (authSubjectId) context.authSubjectId = authSubjectId;
  return context;
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
};

export type LoginEmailOtpEcdsaCapabilityForSigningArgs = {
  walletSession: WalletSessionRef;
  subjectId?: never;
  chainTarget: ThresholdEcdsaChainTarget;
  challengeId: string;
  otpCode: string;
  record?: ThresholdEcdsaSessionRecord;
  routeAuth?: AppOrWalletSessionAuth;
  authLane?: EmailOtpAuthLane;
};

type EmailOtpEcdsaSigningBaseInput = {
  walletSession: WalletSessionRef;
  chainTarget: ThresholdEcdsaChainTarget;
  challengeId: string;
  otpCode: string;
};

export type EmailOtpEcdsaLoginReconnectInput = EmailOtpEcdsaSigningBaseInput & {
  mode: 'login_reconnect';
  appSessionJwt: string;
  record?: never;
  routeAuth?: never;
  authLane?: never;
  registrationAttemptId?: never;
};

export type EmailOtpEcdsaTransactionStepUpInput = EmailOtpEcdsaSigningBaseInput &
  (
    | {
        mode: 'transaction_step_up';
        record?: ThresholdEcdsaSessionRecord;
        authLane: EmailOtpAuthLane;
        routeAuth?: never;
        appSessionJwt?: never;
        registrationAttemptId?: never;
      }
    | {
        mode: 'transaction_step_up';
        record: ThresholdEcdsaSessionRecord;
        routeAuth: AppOrWalletSessionAuth;
        authLane?: never;
        appSessionJwt?: never;
        registrationAttemptId?: never;
      }
  );

export type EmailOtpEcdsaSigningInput =
  | EmailOtpEcdsaLoginReconnectInput
  | EmailOtpEcdsaTransactionStepUpInput;

async function resolveEmailOtpEcdsaSigningInput(
  args: LoginEmailOtpEcdsaCapabilityForSigningArgs,
  ports: {
    requireRelayUrl: () => string;
    resolveAppSessionJwt: (args: {
      walletSession: WalletSessionRef;
      relayUrl: string;
    }) => Promise<string>;
  },
): Promise<EmailOtpEcdsaSigningInput> {
  const base = {
    walletSession: args.walletSession,
    chainTarget: args.chainTarget,
    challengeId: args.challengeId,
    otpCode: args.otpCode,
  };
  if (!args.record) {
    const providedAuthLane = args.authLane;
    if (providedAuthLane) {
      return {
        ...base,
        mode: 'transaction_step_up',
        authLane: providedAuthLane,
      };
    }
    const relayUrl = ports.requireRelayUrl();
    const appSessionJwt = await ports.resolveAppSessionJwt({
      walletSession: args.walletSession,
      relayUrl,
    });
    return {
      ...base,
      mode: 'login_reconnect',
      appSessionJwt,
    };
  }
  if (args.authLane) {
    return {
      ...base,
      mode: 'transaction_step_up',
      record: args.record,
      authLane: args.authLane,
    };
  }
  if (args.routeAuth) {
    return {
      ...base,
      mode: 'transaction_step_up',
      record: args.record,
      routeAuth: args.routeAuth,
    };
  }
  throw new Error('Email OTP transaction step-up requires authLane or routeAuth');
}

export async function loginWithEmailOtpEcdsaCapabilityForSigning(
  args: LoginEmailOtpEcdsaCapabilityForSigningArgs,
  ports: {
    requireRelayUrl: () => string;
    resolveAppSessionJwt: (args: {
      walletSession: WalletSessionRef;
      relayUrl: string;
    }) => Promise<string>;
    loginWithEcdsaCapabilityInternal: (
      args: LoginEmailOtpEcdsaCapabilityArgs,
    ) => Promise<EmailOtpThresholdEcdsaLoginResult>;
  },
): Promise<EmailOtpThresholdEcdsaLoginResult> {
  const operation = WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION;
  const emailOtpAuthPolicy: EmailOtpAuthPolicy = 'per_operation';
  const remainingUses = 1;
  const signingInput = await resolveEmailOtpEcdsaSigningInput(args, ports);
  if (signingInput.mode === 'login_reconnect' || !signingInput.record) {
    const relayUrl = ports.requireRelayUrl();
    const authLane =
      signingInput.mode === 'transaction_step_up'
        ? signingInput.authLane
        : resolveEmailOtpAuthLane({
            appSessionJwt: signingInput.appSessionJwt,
            sessionKind: 'jwt',
          });
    const routePlan = buildFreshEmailOtpRoutePlan({
      freshRouteFamily: 'login',
      authLane:
        authLane ||
        (() => {
          throw new Error('Email OTP login requires route auth');
        })(),
      operation,
    });
    return await ports.loginWithEcdsaCapabilityInternal({
      walletSession: signingInput.walletSession,
      relayUrl,
      chainTarget: signingInput.chainTarget,
      emailOtpAuthPolicy,
      emailOtpAuthReason: 'sign',
      challengeId: signingInput.challengeId,
      otpCode: signingInput.otpCode,
      operation,
      routePlan,
      ecdsaBootstrapAuthorization: { kind: 'route_plan_auth' },
      remainingUses,
      ed25519ReconstructionMode: 'skip',
      ed25519SessionReconstruction: {
        kind: 'defer',
        reason: 'not_needed_for_ecdsa',
      },
    });
  }
  const record = signingInput.record;
  const explicitAuthLane = 'authLane' in signingInput ? signingInput.authLane : undefined;
  const explicitRouteAuth = explicitAuthLane
    ? authLaneToRouteAuth(explicitAuthLane)
    : signingInput.routeAuth;
  const routePlan = buildEmailOtpSigningSessionRoutePlan({
    authLane: assertEmailOtpSigningSessionAuthLane(
      explicitAuthLane?.kind === 'signing_session'
        ? explicitAuthLane
        : resolveEmailOtpAuthLane({
            routeAuth: explicitRouteAuth,
            thresholdSessionId: record.thresholdSessionId,
            authorizingSigningGrantId: record.signingGrantId,
            curve: 'ecdsa',
            chainTarget: record.chainTarget,
          }),
    ),
    operation,
  });
  const keyHandle = String(toEvmFamilyEcdsaKeyHandle(record.keyHandle));
  return await ports.loginWithEcdsaCapabilityInternal({
    walletSession: signingInput.walletSession,
    chainTarget: record.chainTarget,
    emailOtpAuthPolicy,
    emailOtpAuthReason: 'sign',
    challengeId: signingInput.challengeId,
    otpCode: signingInput.otpCode,
    operation,
    keyHandle,
    participantIds: record.participantIds,
    sessionKind: 'jwt',
    routePlan,
    authSubjectId: record.source === 'email_otp' ? record.emailOtpAuthContext.authSubjectId : undefined,
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
  const nearAccountId = toAccountId(args.walletSession.walletId);
  const chainTarget = args.chainTarget;
  const emailOtpAuthPolicy: EmailOtpAuthPolicy =
    args.emailOtpAuthPolicy || ports.configs.signing.emailOtp.authPolicy;
  const emailOtpAuthReason = args.emailOtpAuthReason || 'login';
  const emailOtpAuthRetention =
    emailOtpAuthReason === 'sign' && emailOtpAuthPolicy === 'per_operation'
      ? 'single_use'
      : 'session';
  const emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext = {
    policy: emailOtpAuthPolicy,
    retention: emailOtpAuthRetention,
    reason: emailOtpAuthReason,
    authMethod: SIGNER_AUTH_METHODS.emailOtp,
  };
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
  const sessionKind = args.sessionKind || 'jwt';
  const rpId = ports.requireRpId('Email OTP login');
  const routePlan =
    args.routePlan ||
    buildFreshEmailOtpRoutePlan({
      freshRouteFamily: 'login',
      authLane:
        resolveEmailOtpAuthLane({
          routeAuth: args.routeAuth,
          appSessionJwt: args.appSessionJwt,
          sessionKind,
          curve: 'ecdsa',
          chainTarget,
        }) ||
        (() => {
          throw new Error('Email OTP login requires route auth');
        })(),
      operation: args.operation,
    });
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
    parseThresholdRuntimePolicyScopeFromJwt(args.appSessionJwt) ||
    parseThresholdRuntimePolicyScopeFromJwt(routeAuth?.jwt) ||
    parseThresholdRuntimePolicyScopeFromJwt(bootstrapTransportAuth?.jwt);

  if (!workerCtx) {
    throw new Error('Email OTP login requires the dedicated emailOtp worker');
  }
  if (!runtimePolicyScope) {
    throw new Error('Email OTP ECDSA login requires runtimePolicyScope');
  }
  const appSessionJwt = appSessionJwtFromEmailOtpAuthLane(routePlan.authLane);
  if (appSessionJwt) {
    ports.rememberAppSessionJwt({ walletSession: args.walletSession, appSessionJwt });
  }
  const authSubjectId = appSessionSubjectFromEmailOtpAuthLane(routePlan.authLane);
  const emailOtpContextAuthSubjectId = authSubjectId
    ? toEmailOtpAuthSubjectId(authSubjectId)
    : undefined;
  const publicationChainTargets = emailOtpEcdsaPublicationChainTargets({
    configs: ports.configs,
    primaryChain: chainTarget,
    emailOtpAuthContext,
    ...(args.publicationChainTargets
      ? { additionalChainTargets: args.publicationChainTargets }
      : {}),
  });
  const emailOtpAuthSubjectId = toEmailOtpAuthSubjectId(
    args.walletSession.walletSessionUserId || nearAccountId,
  );
  const walletSessionUserId = toWalletSessionUserId(args.walletSession.walletId || nearAccountId);
  const workerResult = await unlockEmailOtpWallet({
    walletSession: args.walletSession,
    relayUrl,
    shamirPrimeB64u,
    otpCode: args.otpCode,
    routePlan,
    workerCtx,
    ecdsaClientRootHandleBinding: {
      rpId,
      authSubjectId: emailOtpAuthSubjectId,
      operation: emailOtpWorkerHandleOperationFromLoginOperation(routePlan.operation),
      chainTarget,
    },
    ...(args.challengeId ? { challengeId: args.challengeId } : {}),
    runtimePolicyScope,
    ...(args.onProgress ? { onProgress: args.onProgress } : {}),
  });
  const bootstrapAuth = {
    sessionKind: 'jwt' as const,
    routeAuth:
      bootstrapTransportAuth ||
      (() => {
        throw new Error('Email OTP ECDSA bootstrap requires route auth');
      })(),
  };
  const keyHandle = String(args.keyHandle || '').trim();
  const bootstrapPayload: EmailOtpEcdsaBootstrapStrictPayload = {
    relayUrl,
    walletId: String(args.walletSession.walletId),
    walletSessionUserId,
    userId: emailOtpAuthSubjectId,
    rpId,
    clientRootShareHandle: workerResult.clientRootShareHandle,
    chainTarget,
    publicationChainTargets,
    runtimePolicyScope,
    ...(keyHandle ? { keyHandle } : {}),
    ...(Array.isArray(args.participantIds) && args.participantIds.length > 0
      ? { participantIds: args.participantIds }
      : {}),
    ...bootstrapAuth,
    signingGrantId,
    ...(typeof args.ttlMs === 'number' ? { ttlMs: args.ttlMs } : {}),
    ...(typeof remainingUses === 'number' ? { remainingUses } : {}),
    ...(args.includeEcdsaExportArtifact ? { includeEcdsaExportArtifact: true } : {}),
  };
  const bootstrapResult = await workerCtx.requestWorkerOperation({
    kind: 'emailOtp',
    request: {
      type: 'bootstrapEmailOtpEcdsaSessionsFromWorkerHandle',
      timeoutMs: 60_000,
      payload: bootstrapPayload,
      onEvent: args.onProgress,
    },
  });
  const resolvedEmailOtpAuthContext = {
    ...emailOtpAuthContext,
    ...(emailOtpContextAuthSubjectId ? { authSubjectId: emailOtpContextAuthSubjectId } : {}),
  };
  const ed25519ReconstructionAuthContext = buildEd25519ReconstructionAuthContext({
    ecdsaAuthContext: emailOtpAuthContext,
    authSubjectId: emailOtpContextAuthSubjectId,
  });
  const { bootstrap, warmCapability } = await commitEmailOtpEcdsaPublicationBootstraps(
    {
      walletId: toWalletId(args.walletSession.walletId),
      publicationChainTargets,
      bootstraps: bootstrapResult.bootstraps,
      signingGrantId,
      emailOtpAuthContext: resolvedEmailOtpAuthContext,
      relayerUrl: relayUrl,
      shamirPrimeB64u,
    },
    ports.publicationPorts,
  );
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
        : ed25519ReconstructionPlan.reason === 'missing_runtime_policy_scope' &&
          runtimePolicyScope
        ? {
            ed25519Key: ed25519ReconstructionPlan.ed25519Key,
            runtimePolicyScope,
          }
        : null;
    if (resolvedEd25519Reconstruction && reconstructionAuth) {
      const ed25519ReconstructionArgs: ReconstructEmailOtpEd25519SessionArgs = {
        kind: 'session_ed25519_reconstruction',
        nearAccountId,
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
        signingGrantId: signingGrantIdFromEcdsaBootstrap(
          bootstrap,
          signingGrantId,
        ),
        ecdsaThresholdSessionId: thresholdSessionIdFromEcdsaBootstrap(bootstrap),
      };
      if (shouldAwaitEd25519Reconstruction) {
        const sessionMaterial = await ports.reconstructEd25519Session(
          ed25519ReconstructionArgs,
        );
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
    clientRootShareHandle: workerResult.clientRootShareHandle,
    ed25519Reconstruction,
  };
}
