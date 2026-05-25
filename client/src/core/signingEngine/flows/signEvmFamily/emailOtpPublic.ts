import { enrollEmailOtpWallet } from '@/core/SeamsPasskey/emailOtp';
import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { EmailOtpAuthPolicy } from '@/core/types/seams';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import type { WalletEmailOtpChannel, WalletEmailOtpLoginOperation } from '@shared/utils/emailOtpDomain';
import type { AppOrThresholdSessionAuth } from '@shared/utils/sessionTokens';
import type { EmailOtpBootstrapRecovery } from '../../stepUpConfirmation/otpPrompt/bootstrapRecovery';
import type { ThresholdEcdsaSessionStoreDeps } from '../../session/persistence/records';
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
import type { EmailOtpEd25519SessionReconstructionPlan } from '../../session/emailOtp/provisioning';

export type LoginWithEmailOtpEcdsaCapabilityInternalArgs = {
  walletSession: WalletSessionRef;
  subjectId?: never;
  chainTarget: ThresholdEcdsaChainTarget;
  emailOtpAuthPolicy?: EmailOtpAuthPolicy;
  otpCode: string;
  operation?: WalletEmailOtpLoginOperation;
  shamirPrimeB64u?: string;
  appSessionJwt?: string;
  routeAuth?: AppOrThresholdSessionAuth;
  keyHandle?: string;
  participantIds?: number[];
  sessionKind?: 'jwt' | 'cookie';
  ttlMs?: number;
  remainingUses?: number;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  ecdsaBootstrapAuthorization: EmailOtpEcdsaBootstrapAuthorization;
  ed25519ReconstructionMode: 'await' | 'skip';
  ed25519SessionReconstruction: EmailOtpEd25519SessionReconstructionPlan;
  onProgress?: (progress: EmailOtpWorkerProgressEvent) => void;
};

export type LoginWithEmailOtpEcdsaCapabilityInternalResult = {
  recovery: EmailOtpBootstrapRecovery;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  warmCapability: WarmSessionEcdsaCapabilityState;
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
  routeAuth?: AppOrThresholdSessionAuth;
  participantIds?: number[];
  ed25519ParticipantIds?: number[];
  keyHandle?: string;
  sessionKind?: 'jwt' | 'cookie';
  ttlMs?: number;
  remainingUses?: number;
  clientSecret32?: Uint8Array;
  otpChannel?: WalletEmailOtpChannel;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  registrationAttemptId?: string;
  onProgress?: (progress: EmailOtpWorkerProgressEvent) => void;
};

export type EnrollEmailOtpInternalResult = Awaited<ReturnType<typeof enrollEmailOtpWallet>>;

export type EnrollAndLoginWithEmailOtpEcdsaCapabilityInternalResult = {
  enrollment: EnrollEmailOtpInternalResult;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  warmCapability: WarmSessionEcdsaCapabilityState;
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
      args: LoginWithEmailOtpEcdsaCapabilityInternalArgs,
    ) => Promise<LoginWithEmailOtpEcdsaCapabilityInternalResult>;
    enrollAndLoginWithEcdsaCapabilityInternal: (
      args: EnrollAndLoginWithEmailOtpEcdsaCapabilityInternalArgs,
    ) => Promise<EnrollAndLoginWithEmailOtpEcdsaCapabilityInternalResult>;
  };
};

export async function loginWithEmailOtpEcdsaCapabilityInternal(
  deps: EmailOtpPublicDeps,
  args: LoginWithEmailOtpEcdsaCapabilityInternalArgs,
): Promise<LoginWithEmailOtpEcdsaCapabilityInternalResult> {
  return await deps.emailOtpSessions.loginWithEcdsaCapabilityInternal(args);
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
            ed25519SessionReconstruction: {
              kind: 'defer',
              reason: 'not_needed_for_ecdsa',
            },
            ed25519ReconstructionMode: 'skip',
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
  return await refreshEmailOtpSigningSessionValue(
    {
      ecdsaSessions: deps.ecdsaSessions,
      emailOtpSessions: {
        requestTransactionSigningChallenge: (challengeArgs) =>
          deps.emailOtpSessions.requestTransactionSigningChallenge(challengeArgs),
        loginWithEcdsaCapabilityInternal: (loginArgs) =>
          deps.emailOtpSessions.loginWithEcdsaCapabilityInternal({
            ...loginArgs,
            ed25519SessionReconstruction: {
              kind: 'defer',
              reason: 'not_needed_for_ecdsa',
            },
            ed25519ReconstructionMode: loginArgs.ed25519ReconstructionMode,
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
}

export async function enrollEmailOtpInternal(
  deps: EmailOtpPublicDeps,
  args: EnrollEmailOtpInternalArgs,
): Promise<EnrollEmailOtpInternalResult> {
  const walletId = toAccountId(args.walletId);
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

export async function enrollAndLoginWithEmailOtpEcdsaCapabilityInternal(
  deps: EmailOtpPublicDeps,
  args: EnrollAndLoginWithEmailOtpEcdsaCapabilityInternalArgs,
): Promise<EnrollAndLoginWithEmailOtpEcdsaCapabilityInternalResult> {
  return await deps.emailOtpSessions.enrollAndLoginWithEcdsaCapabilityInternal(args);
}

export function createEmailOtpPublicApi(deps: EmailOtpPublicDeps) {
  return {
    loginWithEmailOtpEcdsaCapabilityInternal: (
      args: LoginWithEmailOtpEcdsaCapabilityInternalArgs,
    ) => loginWithEmailOtpEcdsaCapabilityInternal(deps, args),
    requestEmailOtpSigningSessionChallenge: (args: {
      walletSession: WalletSessionRef;
      chainTarget: ThresholdEcdsaChainTarget;
    }) => requestEmailOtpSigningSessionChallenge(deps, args),
    refreshEmailOtpSigningSession: (args: {
      walletSession: WalletSessionRef;
      chainTarget: ThresholdEcdsaChainTarget;
      challengeId: string;
      otpCode: string;
      ttlMs?: number;
      remainingUses?: number;
    }) => refreshEmailOtpSigningSession(deps, args),
    enrollEmailOtpInternal: (args: EnrollEmailOtpInternalArgs) => enrollEmailOtpInternal(deps, args),
    enrollAndLoginWithEmailOtpEcdsaCapabilityInternal: (
      args: EnrollAndLoginWithEmailOtpEcdsaCapabilityInternalArgs,
    ) => enrollAndLoginWithEmailOtpEcdsaCapabilityInternal(deps, args),
  };
}

export type EmailOtpPublicApi = ReturnType<typeof createEmailOtpPublicApi>;
