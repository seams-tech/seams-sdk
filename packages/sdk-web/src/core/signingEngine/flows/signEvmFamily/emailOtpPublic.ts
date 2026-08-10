import {
  enrollEmailOtpWallet,
  prepareEmailOtpRegistrationEnrollmentMaterial,
} from '../../session/emailOtp/workerEnrollment';
import type { EmailOtpAuthPolicy } from '@/core/types/seams';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import type {
  WalletEmailOtpChannel,
  WalletEmailOtpLoginOperation,
} from '@shared/utils/emailOtpDomain';
import type { AppOrWalletSessionAuth } from '@shared/utils/sessionTokens';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdRuntimePolicyScope } from '../../threshold/sessionPolicy';
import type { EmailOtpWorkerProgressEvent } from '../../workerManager/workerTypes';
import type { EmailOtpEcdsaBootstrapAuthorization } from '../../session/emailOtp/routePlan';
import {
  requestEmailOtpSigningSessionChallenge as requestEmailOtpSigningSessionChallengeValue,
  resolveEmailOtpEcdsaSigningSessionAuth,
  refreshEmailOtpSigningSession as refreshEmailOtpSigningSessionValue,
} from './emailOtpSigningSession';
import type {
  EmailOtpEcdsaProviderIdentity,
  EmailOtpThresholdEcdsaLoginResult,
  LoginEmailOtpEcdsaCapabilityArgs,
} from '../../session/emailOtp/ecdsaLogin';
import {
  resolveEmailOtpAuthLane,
  type EmailOtpRoutePlan,
} from '../../stepUpConfirmation/otpPrompt/authLane';
import { buildFreshEmailOtpRoutePlan } from '../../session/emailOtp/routePlan';

export type LoginWithEmailOtpEcdsaCapabilityInternalArgs = {
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
  appSessionJwt?: string;
  routeAuth?: AppOrWalletSessionAuth;
  keyHandle?: string;
  participantIds?: number[];
  publicationChainTargets?: readonly ThresholdEcdsaChainTarget[];
  sessionKind?: 'jwt';
  ttlMs?: number;
  remainingUses?: number;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  ecdsaBootstrapAuthorization: EmailOtpEcdsaBootstrapAuthorization;
  providerIdentity: EmailOtpEcdsaProviderIdentity;
  emailHashHex: string;
  authSubjectId?: never;
  onProgress?: (progress: EmailOtpWorkerProgressEvent) => void;
  ed25519YaoRecovery?: LoginEmailOtpEcdsaCapabilityArgs['ed25519YaoRecovery'];
};

export type LoginWithEmailOtpEcdsaCapabilityInternalResult = EmailOtpThresholdEcdsaLoginResult;

export type EnrollEmailOtpInternalArgs = {
  walletId: WalletId;
  otpCode: string;
  relayUrl?: string;
  challengeId?: string;
  groupId?: string;
  appSessionJwt?: string;
  clientSecret32?: Uint8Array;
  otpChannel?: WalletEmailOtpChannel;
};

export type EnrollEmailOtpInternalResult = Awaited<ReturnType<typeof enrollEmailOtpWallet>>;

type PrepareEmailOtpRegistrationEnrollmentMaterialInternalArgsBase = {
  walletId: WalletId;
  userId: string;
  relayUrl?: string;
  groupId?: string;
  appSessionJwt: string;
  otpChannel?: WalletEmailOtpChannel;
  clientSecret32?: Uint8Array;
};

export type PrepareEmailOtpRegistrationEnrollmentMaterialInternalArgs =
  PrepareEmailOtpRegistrationEnrollmentMaterialInternalArgsBase;

export type PrepareEmailOtpRegistrationEnrollmentMaterialInternalResult = Awaited<
  ReturnType<typeof prepareEmailOtpRegistrationEnrollmentMaterial>
>;

export type EmailOtpPublicDeps = {
  relayerUrl: string;
  groupId: string;
  getSignerWorkerContext: () => WorkerOperationContext;
  withThresholdEcdsaSigningQueue: Parameters<
    typeof refreshEmailOtpSigningSessionValue
  >[0]['withThresholdEcdsaSigningQueue'];
  emailOtpSessions: {
    requestTransactionSigningChallenge: Parameters<
      typeof requestEmailOtpSigningSessionChallengeValue
    >[0]['emailOtpSessions']['requestTransactionSigningChallenge'];
    loginWithEcdsaCapabilityInternal: (
      args: LoginEmailOtpEcdsaCapabilityArgs,
    ) => Promise<LoginWithEmailOtpEcdsaCapabilityInternalResult>;
  };
};

function buildEmailOtpEcdsaFreshRoutePlanFromBoundary(
  args: {
    routeAuth?: AppOrWalletSessionAuth;
    appSessionJwt?: string;
    sessionKind?: 'jwt';
    chainTarget: ThresholdEcdsaChainTarget;
    operation?: WalletEmailOtpLoginOperation;
  },
  freshRouteFamily: 'login' | 'registration',
): EmailOtpRoutePlan {
  const authLane = resolveEmailOtpAuthLane({
    routeAuth: args.routeAuth,
    appSessionJwt: args.appSessionJwt,
    sessionKind: args.sessionKind || 'jwt',
    curve: 'ecdsa',
    chainTarget: args.chainTarget,
  });
  if (!authLane) {
    throw new Error(`Email OTP ECDSA ${freshRouteFamily} requires route auth`);
  }
  return buildFreshEmailOtpRoutePlan({
    freshRouteFamily,
    authLane,
    operation: args.operation,
  });
}

function emailOtpEcdsaLoginCoreArgsFromBoundary(
  args: LoginWithEmailOtpEcdsaCapabilityInternalArgs,
): LoginEmailOtpEcdsaCapabilityArgs {
  return {
    walletSession: args.walletSession,
    chainTarget: args.chainTarget,
    otpCode: args.otpCode,
    routePlan: buildEmailOtpEcdsaFreshRoutePlanFromBoundary(args, 'login'),
    ecdsaBootstrapAuthorization: args.ecdsaBootstrapAuthorization,
    emailHashHex: args.emailHashHex,
    providerIdentity: args.providerIdentity,
    ed25519YaoRecovery: args.ed25519YaoRecovery ?? { kind: 'not_requested' },
    ...(args.emailOtpAuthPolicy ? { emailOtpAuthPolicy: args.emailOtpAuthPolicy } : {}),
    ...(args.emailOtpAuthReason ? { emailOtpAuthReason: args.emailOtpAuthReason } : {}),
    ...(args.relayUrl ? { relayUrl: args.relayUrl } : {}),
    ...(args.challengeId ? { challengeId: args.challengeId } : {}),
    ...(args.operation ? { operation: args.operation } : {}),
    ...(args.groupId ? { groupId: args.groupId } : {}),
    ...(args.keyHandle ? { keyHandle: args.keyHandle } : {}),
    ...(args.participantIds ? { participantIds: args.participantIds } : {}),
    ...(args.publicationChainTargets
      ? { publicationChainTargets: args.publicationChainTargets }
      : {}),
    ...(typeof args.ttlMs === 'number' ? { ttlMs: args.ttlMs } : {}),
    ...(typeof args.remainingUses === 'number' ? { remainingUses: args.remainingUses } : {}),
    ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
    ...(args.onProgress ? { onProgress: args.onProgress } : {}),
  };
}

export async function loginWithEmailOtpEcdsaCapabilityInternal(
  deps: EmailOtpPublicDeps,
  args: LoginWithEmailOtpEcdsaCapabilityInternalArgs,
): Promise<LoginWithEmailOtpEcdsaCapabilityInternalResult> {
  return await deps.emailOtpSessions.loginWithEcdsaCapabilityInternal(
    emailOtpEcdsaLoginCoreArgsFromBoundary(args),
  );
}

export async function requestEmailOtpSigningSessionChallenge(
  deps: EmailOtpPublicDeps,
  args: {
    walletSession: WalletSessionRef;
    chainTarget: ThresholdEcdsaChainTarget;
  },
): Promise<{ challengeId: string; emailHint?: string }> {
  return await requestEmailOtpSigningSessionChallengeValue(
    {
      resolveSigningSessionAuth: resolveEmailOtpEcdsaSigningSessionAuth,
      withThresholdEcdsaSigningQueue: deps.withThresholdEcdsaSigningQueue,
      emailOtpSessions: {
        requestTransactionSigningChallenge: (challengeArgs) =>
          deps.emailOtpSessions.requestTransactionSigningChallenge(challengeArgs),
        loginWithEcdsaCapabilityInternal: ({ publicFacts, ...loginArgs }) =>
          deps.emailOtpSessions.loginWithEcdsaCapabilityInternal({
            ...loginArgs,
            keyHandle: String(publicFacts.keyHandle),
            participantIds: publicFacts.participantIds.map((participantId) =>
              Number(participantId),
            ),
            ecdsaBootstrapAuthorization: { kind: 'route_plan_auth' },
            ed25519YaoRecovery: { kind: 'not_requested' },
          }),
      },
    },
    {
      walletSession: args.walletSession,
      chainTarget: args.chainTarget,
    },
  );
}

export async function refreshEmailOtpSigningSession(
  deps: EmailOtpPublicDeps,
  args: {
    walletSession: WalletSessionRef;
    chainTarget: ThresholdEcdsaChainTarget;
    challengeId: string;
    otpCode: string;
    ttlMs?: number;
    remainingUses?: number;
  },
): Promise<LoginWithEmailOtpEcdsaCapabilityInternalResult> {
  const refreshed = await refreshEmailOtpSigningSessionValue(
    {
      resolveSigningSessionAuth: resolveEmailOtpEcdsaSigningSessionAuth,
      withThresholdEcdsaSigningQueue: deps.withThresholdEcdsaSigningQueue,
      emailOtpSessions: {
        requestTransactionSigningChallenge: (challengeArgs) =>
          deps.emailOtpSessions.requestTransactionSigningChallenge(challengeArgs),
        loginWithEcdsaCapabilityInternal: (loginArgs) =>
          deps.emailOtpSessions.loginWithEcdsaCapabilityInternal({
            ...loginArgs,
            ed25519YaoRecovery: { kind: 'not_requested' },
          }),
      },
    },
    {
      walletSession: args.walletSession,
      chainTarget: args.chainTarget,
      challengeId: args.challengeId,
      otpCode: args.otpCode,
      ...(typeof args.ttlMs === 'number' ? { ttlMs: args.ttlMs } : {}),
      ...(typeof args.remainingUses === 'number' ? { remainingUses: args.remainingUses } : {}),
    },
  );
  return { ...refreshed, ed25519YaoRecovery: { kind: 'not_requested' } };
}

export async function enrollEmailOtpInternal(
  deps: EmailOtpPublicDeps,
  args: EnrollEmailOtpInternalArgs,
): Promise<EnrollEmailOtpInternalResult> {
  const walletId = toWalletId(args.walletId);
  const relayUrl = String(args.relayUrl || deps.relayerUrl || '').trim();
  if (!relayUrl) {
    throw new Error('Missing relayer url (configs.network.relayer.url)');
  }
  const groupId = String(args.groupId || deps.groupId || '').trim();
  if (!groupId) {
    throw new Error('Missing shamir prime for Email OTP runtime');
  }
  return await enrollEmailOtpWallet({
    relayUrl,
    walletId: String(walletId),
    userId: String(walletId),
    challengeId: args.challengeId,
    otpCode: args.otpCode,
    groupId,
    workerCtx: deps.getSignerWorkerContext(),
    appSessionJwt: args.appSessionJwt,
    otpChannel: args.otpChannel,
    ...(args.clientSecret32 ? { clientSecret32: args.clientSecret32 } : {}),
  });
}

export async function prepareEmailOtpRegistrationEnrollmentMaterialInternal(
  deps: EmailOtpPublicDeps,
  args: PrepareEmailOtpRegistrationEnrollmentMaterialInternalArgs,
): Promise<PrepareEmailOtpRegistrationEnrollmentMaterialInternalResult> {
  const walletId = toWalletId(args.walletId);
  const relayUrl = String(args.relayUrl || deps.relayerUrl || '').trim();
  if (!relayUrl) {
    throw new Error('Missing relayer url (configs.network.relayer.url)');
  }
  const groupId = String(args.groupId || deps.groupId || '').trim();
  if (!groupId) {
    throw new Error('Missing shamir prime for Email OTP runtime');
  }
  const userId = String(args.userId).trim();
  if (!userId) {
    throw new Error('Email OTP registration enrollment material requires userId');
  }
  return await prepareEmailOtpRegistrationEnrollmentMaterial({
    relayUrl,
    walletId: String(walletId),
    userId,
    groupId,
    workerCtx: deps.getSignerWorkerContext(),
    appSessionJwt: args.appSessionJwt,
    otpChannel: args.otpChannel,
    ecdsaSessionHandle: { kind: 'not_requested' },
    ...(args.clientSecret32 ? { clientSecret32: args.clientSecret32 } : {}),
  });
}
