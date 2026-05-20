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
import {
  toWalletId,
  walletSubjectIdFromWalletProfile,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import { generateWalletSigningSessionId } from '@/core/signingEngine/threshold/sessionPolicy';
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import type { WarmSessionEcdsaCapabilityState } from '@/core/signingEngine/session/warmCapabilities/types';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type { EmailOtpWorkerProgressEvent } from '@/core/signingEngine/workerManager/workerTypes';
import type { AppOrThresholdSessionAuth } from '@shared/utils/sessionTokens';
import {
  WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
  type WalletEmailOtpLoginOperation,
} from '@shared/utils/emailOtpDomain';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
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
  routeAuthFromEmailOtpRoutePlan,
  thresholdSessionAuthFromEcdsaBootstrap,
  thresholdSessionIdFromEcdsaBootstrap,
  walletSigningSessionIdFromEcdsaBootstrap,
} from './routePlan';
import type {
  EmailOtpThresholdEd25519ProvisioningResult,
  ProvisionEmailOtpThresholdEd25519CapabilityArgs,
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
  clientRootShare32B64u: string;
  ed25519Provisioning?: EmailOtpThresholdEd25519ProvisioningResult;
};

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
  routeAuth?: AppOrThresholdSessionAuth;
  keyHandle?: string;
  participantIds?: number[];
  ed25519ParticipantIds?: number[];
  sessionKind?: 'jwt' | 'cookie';
  routePlan?: EmailOtpRoutePlan;
  ttlMs?: number;
  remainingUses?: number;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  onProgress?: (progress: EmailOtpWorkerProgressEvent) => void;
  ed25519ProvisioningMode?: 'schedule' | 'await' | 'skip';
  authSubjectId?: string;
  includeEcdsaExportArtifact?: boolean;
};

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
  provisionEd25519Capability: (
    args: ProvisionEmailOtpThresholdEd25519CapabilityArgs,
  ) => Promise<EmailOtpThresholdEd25519ProvisioningResult>;
  scheduleEd25519CapabilityProvisioning: (
    args: ProvisionEmailOtpThresholdEd25519CapabilityArgs,
  ) => void;
};

export type LoginEmailOtpEcdsaCapabilityForSigningArgs = {
  walletSession: WalletSessionRef;
  subjectId?: never;
  chainTarget: ThresholdEcdsaChainTarget;
  challengeId: string;
  otpCode: string;
  record?: ThresholdEcdsaSessionRecord;
  routeAuth?: AppOrThresholdSessionAuth;
  authLane?: EmailOtpAuthLane;
};

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
  const record = args.record;
  const operation = WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION;
  const emailOtpAuthPolicy: EmailOtpAuthPolicy = 'per_operation';
  const remainingUses = 1;
  if (!record) {
    const relayUrl = ports.requireRelayUrl();
    const providedAuthLane = args.authLane;
    const appSessionJwt = providedAuthLane
      ? ''
      : await ports.resolveAppSessionJwt({
          walletSession: args.walletSession,
          relayUrl,
        });
    const routePlan = buildFreshEmailOtpRoutePlan({
      freshRouteFamily: 'login',
      authLane:
        providedAuthLane ||
        resolveEmailOtpAuthLane({
          appSessionJwt,
          sessionKind: 'jwt',
        }) ||
        (() => {
          throw new Error('Email OTP login requires route auth');
        })(),
      operation,
    });
    return await ports.loginWithEcdsaCapabilityInternal({
      walletSession: args.walletSession,
      relayUrl,
      chainTarget: args.chainTarget,
      emailOtpAuthPolicy,
      emailOtpAuthReason: 'sign',
      challengeId: args.challengeId,
      otpCode: args.otpCode,
      operation,
      routePlan,
      remainingUses,
    });
  }
  const explicitAuthLane = args.authLane;
  const explicitRouteAuth = explicitAuthLane
    ? authLaneToRouteAuth(explicitAuthLane)
    : args.routeAuth;
  const routePlan = buildEmailOtpSigningSessionRoutePlan({
    authLane: assertEmailOtpSigningSessionAuthLane(
      explicitAuthLane?.kind === 'signing_session'
        ? explicitAuthLane
        : resolveEmailOtpAuthLane({
            routeAuth: explicitRouteAuth,
            thresholdSessionId: record.thresholdSessionId,
            authorizingWalletSigningSessionId: record.walletSigningSessionId,
            curve: 'ecdsa',
            chainTarget: record.chainTarget,
          }),
    ),
    operation,
  });
  const keyHandle = String(toEvmFamilyEcdsaKeyHandle(record.keyHandle));
  return await ports.loginWithEcdsaCapabilityInternal({
    walletSession: args.walletSession,
    chainTarget: record.chainTarget,
    emailOtpAuthPolicy,
    emailOtpAuthReason: 'sign',
    challengeId: args.challengeId,
    otpCode: args.otpCode,
    operation,
    keyHandle,
    participantIds: record.participantIds,
    sessionKind: record.thresholdSessionKind,
    routePlan,
    authSubjectId: record.emailOtpAuthContext?.authSubjectId,
    remainingUses,
    ...(record.runtimePolicyScope ? { runtimePolicyScope: record.runtimePolicyScope } : {}),
  });
}

export async function loginWithEmailOtpEcdsaCapability(
  args: LoginEmailOtpEcdsaCapabilityArgs,
  ports: EmailOtpEcdsaLoginPorts,
): Promise<EmailOtpThresholdEcdsaLoginResult> {
  const nearAccountId = toAccountId(args.walletSession.walletId);
  const subjectId = walletSubjectIdFromWalletProfile({
    walletId: args.walletSession.walletId,
  });
  const chainTarget = args.chainTarget;
  const emailOtpAuthPolicy: EmailOtpAuthPolicy =
    args.emailOtpAuthPolicy || ports.configs.signing.emailOtp.authPolicy;
  const emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext = {
    policy: emailOtpAuthPolicy,
    retention: emailOtpAuthPolicy === 'per_operation' ? 'single_use' : 'session',
    reason: args.emailOtpAuthReason || 'login',
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
  });
  const remainingUses =
    emailOtpAuthPolicy === 'per_operation'
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
    generateWalletSigningSessionId,
  });
  const walletSigningSessionId = mintingSession.walletSigningSessionId;
  const routeAuth = routeAuthFromEmailOtpRoutePlan(routePlan);

  if (!workerCtx) {
    throw new Error('Email OTP login requires the dedicated emailOtp worker');
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
    ...(args.challengeId ? { challengeId: args.challengeId } : {}),
    ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
    ...(args.onProgress ? { onProgress: args.onProgress } : {}),
  });
  const bootstrapResult = await workerCtx.requestWorkerOperation({
    kind: 'emailOtp',
    request: {
      type: 'bootstrapEmailOtpEcdsaSessionsFromClientRootShare',
      timeoutMs: 60_000,
      payload: {
        relayUrl,
        walletId: String(args.walletSession.walletId),
        subjectId,
        walletSessionUserId,
        userId: emailOtpAuthSubjectId,
        rpId,
        clientRootShare32B64u: workerResult.clientRootShare32B64u,
        chainTarget,
        publicationChainTargets,
        ...(args.keyHandle ? { keyHandle: args.keyHandle } : {}),
        ...(Array.isArray(args.participantIds) && args.participantIds.length > 0
          ? { participantIds: args.participantIds }
          : {}),
        sessionKind,
        walletSigningSessionId,
        ...(routeAuth ? { routeAuth } : {}),
        ...(typeof args.ttlMs === 'number' ? { ttlMs: args.ttlMs } : {}),
        ...(typeof remainingUses === 'number' ? { remainingUses } : {}),
        ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
        ...(args.includeEcdsaExportArtifact ? { includeEcdsaExportArtifact: true } : {}),
      },
      onEvent: args.onProgress,
    },
  });
  const resolvedEmailOtpAuthContext = {
    ...emailOtpAuthContext,
    ...(emailOtpContextAuthSubjectId ? { authSubjectId: emailOtpContextAuthSubjectId } : {}),
  };
  const { bootstrap, warmCapability } = await commitEmailOtpEcdsaPublicationBootstraps(
    {
      walletId: toWalletId(args.walletSession.walletId),
      publicationChainTargets,
      bootstraps: bootstrapResult.bootstraps,
      walletSigningSessionId,
      emailOtpAuthContext: resolvedEmailOtpAuthContext,
      relayerUrl: relayUrl,
      shamirPrimeB64u,
    },
    ports.publicationPorts,
  );
  const thresholdEd25519PrfFirstB64u = String(
    workerResult.recovery?.thresholdEd25519PrfFirstB64u || '',
  ).trim();
  let ed25519Provisioning: EmailOtpThresholdEd25519ProvisioningResult | undefined;
  if (thresholdEd25519PrfFirstB64u) {
    const freshThresholdSessionAuth = thresholdSessionAuthFromEcdsaBootstrap(bootstrap);
    const ed25519ProvisioningArgs: ProvisionEmailOtpThresholdEd25519CapabilityArgs = {
      kind: 'companion_to_ecdsa_provisioning',
      nearAccountId,
      relayUrl,
      rpId,
      prfFirstB64u: thresholdEd25519PrfFirstB64u,
      emailOtpAuthContext,
      ...(appSessionJwt ? { appSessionJwt } : {}),
      ...(freshThresholdSessionAuth || routeAuth
        ? { routeAuth: freshThresholdSessionAuth || routeAuth }
        : {}),
      ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
      ...(Array.isArray(args.ed25519ParticipantIds)
        ? { participantIds: args.ed25519ParticipantIds }
        : Array.isArray(args.participantIds)
          ? { participantIds: args.participantIds }
          : {}),
      ...(typeof args.ttlMs === 'number' ? { ttlMs: args.ttlMs } : {}),
      ...(typeof remainingUses === 'number' ? { remainingUses } : {}),
      walletSigningSessionId: walletSigningSessionIdFromEcdsaBootstrap(
        bootstrap,
        walletSigningSessionId,
      ),
      ecdsaThresholdSessionId: thresholdSessionIdFromEcdsaBootstrap(bootstrap),
    };
    const shouldAwaitEd25519Provisioning =
      args.ed25519ProvisioningMode === 'await' ||
      (!args.ed25519ProvisioningMode && resolvedEmailOtpAuthContext.retention === 'session');
    if (shouldAwaitEd25519Provisioning) {
      // Session-mode OTP unlock should not report completion until both signing
      // lanes are durable; otherwise a quick refresh can strand the wallet.
      ed25519Provisioning = await ports.provisionEd25519Capability(ed25519ProvisioningArgs);
    } else if (args.ed25519ProvisioningMode !== 'skip') {
      ports.scheduleEd25519CapabilityProvisioning(ed25519ProvisioningArgs);
    }
  }
  return {
    recovery: workerResult.recovery,
    bootstrap,
    warmCapability,
    clientRootShare32B64u: workerResult.clientRootShare32B64u,
    ...(ed25519Provisioning ? { ed25519Provisioning } : {}),
  };
}
