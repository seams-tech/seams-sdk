import {
  enrollEmailOtpWallet,
  prepareEmailOtpRegistrationEnrollmentMaterial,
  rotateEmailOtpRecoveryCodesWithWorker,
} from '../../session/emailOtp/workerEnrollment';
import type { EmailOtpAuthPolicy } from '@/core/types/seams';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import type {
  WalletEmailOtpChannel,
  WalletEmailOtpLoginOperation,
} from '@shared/utils/emailOtpDomain';
import type { AppOrWalletSessionAuth } from '@shared/utils/sessionTokens';
import type { EmailOtpBootstrapRecovery } from '../../stepUpConfirmation/otpPrompt/bootstrapRecovery';
import type { ThresholdEcdsaSessionStoreDeps } from '../../session/persistence/records';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdRuntimePolicyScope } from '../../threshold/sessionPolicy';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import type { WarmSessionEcdsaCapabilityState } from '../../session/warmCapabilities/types';
import type { EmailOtpWorkerProgressEvent } from '../../workerManager/workerTypes';
import type { EmailOtpEcdsaBootstrapAuthorization } from '../../session/emailOtp/routePlan';
import {
  requestEmailOtpSigningSessionChallenge as requestEmailOtpSigningSessionChallengeValue,
  refreshEmailOtpSigningSession as refreshEmailOtpSigningSessionValue,
} from './emailOtpSigningSession';
import type {
  EmailOtpEcdsaProviderIdentity,
  EmailOtpThresholdEcdsaLoginResult,
  EmailOtpThresholdEcdsaLoginTimings,
  LoginEmailOtpEcdsaCapabilityArgs,
} from '../../session/emailOtp/ecdsaLogin';
import type { EnrollAndLoginEmailOtpEcdsaCapabilityArgs } from '../../session/emailOtp/ecdsaEnrollment';
import type { EmailOtpEcdsaPublicationTimings } from '../../session/emailOtp/ecdsaPublication';
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
  shamirPrimeB64u?: string;
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
  includeEcdsaExportArtifact?: boolean;
  ed25519YaoRecovery?: Extract<
    LoginEmailOtpEcdsaCapabilityArgs['ed25519YaoRecovery'],
    { kind: 'requested' }
  >;
};

export type LoginWithEmailOtpEcdsaCapabilityInternalResult = {
  recovery: EmailOtpBootstrapRecovery;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  warmCapability: WarmSessionEcdsaCapabilityState;
  warmCapabilities: readonly [
    WarmSessionEcdsaCapabilityState,
    ...WarmSessionEcdsaCapabilityState[],
  ];
  timings: EmailOtpThresholdEcdsaLoginTimings;
  ed25519YaoRecovery: EmailOtpThresholdEcdsaLoginResult['ed25519YaoRecovery'];
};

export type EnrollEmailOtpInternalArgs = {
  walletId: WalletId;
  otpCode: string;
  relayUrl?: string;
  challengeId?: string;
  shamirPrimeB64u?: string;
  appSessionJwt?: string;
  clientSecret32?: Uint8Array;
  otpChannel?: WalletEmailOtpChannel;
};

export type RotateEmailOtpRecoveryCodesInternalArgs = {
  walletId: WalletId;
  relayUrl?: string;
  appSessionJwt?: string;
};

export type EnrollAndLoginWithEmailOtpEcdsaCapabilityInternalArgs = {
  walletSession: WalletSessionRef;
  subjectId?: never;
  chainTarget: ThresholdEcdsaChainTarget;
  emailOtpAuthPolicy?: EmailOtpAuthPolicy;
  otpCode: string;
  relayUrl?: string;
  challengeId?: string;
  shamirPrimeB64u?: string;
  appSessionJwt?: string;
  routeAuth?: AppOrWalletSessionAuth;
  participantIds?: number[];
  keyHandle?: string;
  sessionKind?: 'jwt';
  ttlMs?: number;
  remainingUses?: number;
  clientSecret32?: Uint8Array;
  otpChannel?: WalletEmailOtpChannel;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  registrationAttemptId?: string;
  emailHashHex: string;
  onProgress?: (progress: EmailOtpWorkerProgressEvent) => void;
};

export type EnrollEmailOtpInternalResult = Awaited<ReturnType<typeof enrollEmailOtpWallet>>;

export type RotateEmailOtpRecoveryCodesInternalResult = Awaited<
  ReturnType<typeof rotateEmailOtpRecoveryCodesWithWorker>
>;

export type PrepareEmailOtpRegistrationEnrollmentMaterialEd25519YaoFactor =
  | {
      kind: 'ed25519_yao_factor_requested';
      providerSubject: string;
    }
  | {
      kind: 'ed25519_yao_factor_not_requested';
      providerSubject?: never;
    };

type PrepareEmailOtpRegistrationEnrollmentMaterialInternalArgsBase = {
  walletId: WalletId;
  userId: string;
  relayUrl?: string;
  shamirPrimeB64u?: string;
  appSessionJwt: string;
  otpChannel?: WalletEmailOtpChannel;
  clientSecret32?: Uint8Array;
};

export type PrepareEmailOtpRegistrationEnrollmentMaterialInternalArgs =
  PrepareEmailOtpRegistrationEnrollmentMaterialInternalArgsBase & {
    ed25519YaoFactor: PrepareEmailOtpRegistrationEnrollmentMaterialEd25519YaoFactor;
  };

export type PrepareEmailOtpRegistrationEnrollmentMaterialInternalResult = Awaited<
  ReturnType<typeof prepareEmailOtpRegistrationEnrollmentMaterial>
>;

export type EnrollAndLoginWithEmailOtpEcdsaCapabilityInternalResult = {
  enrollment: EnrollEmailOtpInternalResult;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  warmCapability: WarmSessionEcdsaCapabilityState;
  timings: EmailOtpEcdsaPublicationTimings;
};

export type EmailOtpPublicDeps = {
  ecdsaSessions: ThresholdEcdsaSessionStoreDeps;
  relayerUrl: string;
  shamirPrimeB64u: string;
  getSignerWorkerContext: () => WorkerOperationContext;
  emailOtpSessions: {
    requestTransactionSigningChallenge: Parameters<
      typeof requestEmailOtpSigningSessionChallengeValue
    >[0]['emailOtpSessions']['requestTransactionSigningChallenge'];
    loginWithEcdsaCapabilityInternal: (
      args: LoginEmailOtpEcdsaCapabilityArgs,
    ) => Promise<LoginWithEmailOtpEcdsaCapabilityInternalResult>;
    enrollAndLoginWithEcdsaCapabilityInternal: (
      args: EnrollAndLoginEmailOtpEcdsaCapabilityArgs,
    ) => Promise<EnrollAndLoginWithEmailOtpEcdsaCapabilityInternalResult>;
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
    ...(args.shamirPrimeB64u ? { shamirPrimeB64u: args.shamirPrimeB64u } : {}),
    ...(args.keyHandle ? { keyHandle: args.keyHandle } : {}),
    ...(args.participantIds ? { participantIds: args.participantIds } : {}),
    ...(args.publicationChainTargets
      ? { publicationChainTargets: args.publicationChainTargets }
      : {}),
    ...(typeof args.ttlMs === 'number' ? { ttlMs: args.ttlMs } : {}),
    ...(typeof args.remainingUses === 'number' ? { remainingUses: args.remainingUses } : {}),
    ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
    ...(args.onProgress ? { onProgress: args.onProgress } : {}),
    ...(args.includeEcdsaExportArtifact
      ? { includeEcdsaExportArtifact: args.includeEcdsaExportArtifact }
      : {}),
  };
}

function emailOtpEcdsaEnrollmentCoreArgsFromBoundary(
  args: EnrollAndLoginWithEmailOtpEcdsaCapabilityInternalArgs,
): EnrollAndLoginEmailOtpEcdsaCapabilityArgs {
  return {
    walletSession: args.walletSession,
    chainTarget: args.chainTarget,
    otpCode: args.otpCode,
    routePlan: buildEmailOtpEcdsaFreshRoutePlanFromBoundary(args, 'registration'),
    emailHashHex: args.emailHashHex,
    ...(args.emailOtpAuthPolicy ? { emailOtpAuthPolicy: args.emailOtpAuthPolicy } : {}),
    ...(args.relayUrl ? { relayUrl: args.relayUrl } : {}),
    ...(args.challengeId ? { challengeId: args.challengeId } : {}),
    ...(args.shamirPrimeB64u ? { shamirPrimeB64u: args.shamirPrimeB64u } : {}),
    ...(args.participantIds ? { participantIds: args.participantIds } : {}),
    ...(args.keyHandle ? { keyHandle: args.keyHandle } : {}),
    ...(typeof args.ttlMs === 'number' ? { ttlMs: args.ttlMs } : {}),
    ...(typeof args.remainingUses === 'number' ? { remainingUses: args.remainingUses } : {}),
    ...(args.clientSecret32 ? { clientSecret32: args.clientSecret32 } : {}),
    ...(args.otpChannel ? { otpChannel: args.otpChannel } : {}),
    ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
    ...(args.registrationAttemptId ? { registrationAttemptId: args.registrationAttemptId } : {}),
    ...(args.onProgress ? { onProgress: args.onProgress } : {}),
  };
}

function emailOtpRegistrationEd25519YaoFactorRequestFromBoundary(
  args: PrepareEmailOtpRegistrationEnrollmentMaterialInternalArgs,
):
  | { kind: 'requested'; providerSubject: string }
  | { kind: 'not_requested'; providerSubject?: never } {
  switch (args.ed25519YaoFactor.kind) {
    case 'ed25519_yao_factor_requested': {
      const providerSubject = String(args.ed25519YaoFactor.providerSubject).trim();
      if (!providerSubject || providerSubject !== String(args.userId).trim()) {
        throw new Error('Email OTP Ed25519 Yao factor requires the exact provider subject');
      }
      return { kind: 'requested', providerSubject };
    }
    case 'ed25519_yao_factor_not_requested':
      return { kind: 'not_requested' };
    default:
      throw new Error('Unsupported Email OTP Ed25519 Yao factor request');
  }
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
      ecdsaSessions: deps.ecdsaSessions,
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
      ecdsaSessions: deps.ecdsaSessions,
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
  const shamirPrimeB64u = String(args.shamirPrimeB64u || deps.shamirPrimeB64u || '').trim();
  if (!shamirPrimeB64u) {
    throw new Error('Missing shamir prime for Email OTP runtime');
  }
  return await enrollEmailOtpWallet({
    relayUrl,
    walletId: String(walletId),
    userId: String(walletId),
    challengeId: args.challengeId,
    otpCode: args.otpCode,
    shamirPrimeB64u,
    workerCtx: deps.getSignerWorkerContext(),
    appSessionJwt: args.appSessionJwt,
    otpChannel: args.otpChannel,
    ...(args.clientSecret32 ? { clientSecret32: args.clientSecret32 } : {}),
  });
}

export async function rotateEmailOtpRecoveryCodesInternal(
  deps: EmailOtpPublicDeps,
  args: RotateEmailOtpRecoveryCodesInternalArgs,
): Promise<RotateEmailOtpRecoveryCodesInternalResult> {
  const walletId = toWalletId(args.walletId);
  const relayUrl = String(args.relayUrl || deps.relayerUrl || '').trim();
  if (!relayUrl) {
    throw new Error('Missing relayer url (configs.network.relayer.url)');
  }
  return await rotateEmailOtpRecoveryCodesWithWorker({
    relayUrl,
    walletId: String(walletId),
    userId: String(walletId),
    workerCtx: deps.getSignerWorkerContext(),
    appSessionJwt: args.appSessionJwt,
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
  const shamirPrimeB64u = String(args.shamirPrimeB64u || deps.shamirPrimeB64u || '').trim();
  if (!shamirPrimeB64u) {
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
    shamirPrimeB64u,
    workerCtx: deps.getSignerWorkerContext(),
    appSessionJwt: args.appSessionJwt,
    otpChannel: args.otpChannel,
    ecdsaClientRootHandle: { kind: 'not_requested' },
    ed25519YaoFactor: emailOtpRegistrationEd25519YaoFactorRequestFromBoundary(args),
    ...(args.clientSecret32 ? { clientSecret32: args.clientSecret32 } : {}),
  });
}

export async function enrollAndLoginWithEmailOtpEcdsaCapabilityInternal(
  deps: EmailOtpPublicDeps,
  args: EnrollAndLoginWithEmailOtpEcdsaCapabilityInternalArgs,
): Promise<EnrollAndLoginWithEmailOtpEcdsaCapabilityInternalResult> {
  return await deps.emailOtpSessions.enrollAndLoginWithEcdsaCapabilityInternal(
    emailOtpEcdsaEnrollmentCoreArgsFromBoundary(args),
  );
}
