import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { EmailOtpAuthPolicy, SeamsConfigsReadonly } from '@/core/types/seams';
import type { EmailOtpEnrollmentResult } from '@/core/SeamsPasskey/emailOtp';
import type { ThresholdEcdsaEmailOtpAuthContext } from '@/core/signingEngine/session/identity/laneIdentity';
import {
  toEmailOtpAuthSubjectId,
  toWalletSessionUserId,
} from '@/core/signingEngine/session/identity/emailOtpHssIdentity';
import type {
  ThresholdEcdsaChainTarget,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { walletSubjectIdFromWalletProfile } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import { generateWalletSigningSessionId } from '@/core/signingEngine/threshold/sessionPolicy';
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import type { WarmSessionEcdsaCapabilityState } from '@/core/signingEngine/session/warmCapabilities/types';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type { EmailOtpWorkerProgressEvent } from '@/core/signingEngine/workerManager/workerTypes';
import type { AppOrThresholdSessionAuth } from '@shared/utils/sessionTokens';
import { type WalletEmailOtpChannel } from '@shared/utils/emailOtpDomain';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import {
  resolveEmailOtpAuthLane,
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
import { enrollEmailOtpWalletWithRoutePlan } from './walletEnrollment';
import {
  buildEmailOtpEcdsaMintingSession,
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

export type EmailOtpThresholdEcdsaEnrollmentResult = {
  enrollment: EmailOtpEnrollmentResult;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  warmCapability: WarmSessionEcdsaCapabilityState;
};

export type EnrollAndLoginEmailOtpEcdsaCapabilityArgs = {
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
  keyHandle?: string;
  participantIds?: number[];
  sessionKind?: 'jwt' | 'cookie';
  routePlan?: EmailOtpRoutePlan;
  ttlMs?: number;
  remainingUses?: number;
  clientSecret32?: Uint8Array;
  otpChannel?: WalletEmailOtpChannel;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  registrationAttemptId?: string;
  onProgress?: (progress: EmailOtpWorkerProgressEvent) => void;
};

export type EmailOtpEcdsaEnrollmentPorts = {
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
};

export async function enrollAndLoginWithEmailOtpEcdsaCapability(
  args: EnrollAndLoginEmailOtpEcdsaCapabilityArgs,
  ports: EmailOtpEcdsaEnrollmentPorts,
): Promise<EmailOtpThresholdEcdsaEnrollmentResult> {
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
    reason: 'login',
    authMethod: SIGNER_AUTH_METHODS.emailOtp,
  };
  const relayUrl = String(args.relayUrl || ports.requireRelayUrl()).trim();
  const shamirPrimeB64u = String(args.shamirPrimeB64u || ports.requireShamirPrimeB64u()).trim();
  const sessionKind = args.sessionKind || 'jwt';
  const routePlan =
    args.routePlan ||
    buildFreshEmailOtpRoutePlan({
      freshRouteFamily: 'registration',
      authLane:
        resolveEmailOtpAuthLane({
          routeAuth: args.routeAuth,
          appSessionJwt: args.appSessionJwt,
          sessionKind,
          curve: 'ecdsa',
          chainTarget,
        }) ||
        (() => {
          throw new Error('Email OTP registration requires route auth');
        })(),
    });
  const mintingSession = buildEmailOtpEcdsaMintingSession({
    emailOtpAuthPolicy,
    routePlan,
    generateWalletSigningSessionId,
  });
  const walletSigningSessionId = mintingSession.walletSigningSessionId;
  const routeAuth = routeAuthFromEmailOtpRoutePlan(routePlan);
  const workerCtx = ports.getSignerWorkerContext();
  if (!workerCtx) {
    throw new Error('Email OTP enrollment login requires the dedicated emailOtp worker');
  }
  const rpId = ports.requireRpId('Email OTP enrollment login');
  const appSessionJwt = appSessionJwtFromEmailOtpAuthLane(routePlan.authLane);
  if (appSessionJwt) {
    ports.rememberAppSessionJwt({ walletSession: args.walletSession, appSessionJwt });
  }
  const authSubjectId = appSessionSubjectFromEmailOtpAuthLane(routePlan.authLane);
  const emailOtpContextAuthSubjectId = authSubjectId
    ? toEmailOtpAuthSubjectId(authSubjectId)
    : undefined;
  const remainingUses =
    typeof args.remainingUses === 'number'
      ? args.remainingUses
      : emailOtpAuthPolicy === 'per_operation'
        ? 1
        : undefined;
  const emailOtpAuthSubjectId = toEmailOtpAuthSubjectId(
    args.walletSession.walletSessionUserId || nearAccountId,
  );
  const walletSessionUserId = toWalletSessionUserId(
    args.walletSession.walletId || nearAccountId,
  );
  const publicationChainTargets = emailOtpEcdsaPublicationChainTargets({
    configs: ports.configs,
    primaryChain: chainTarget,
    emailOtpAuthContext,
  });
  const enrollment = await enrollEmailOtpWalletWithRoutePlan({
    relayUrl,
    walletId: String(args.walletSession.walletId),
    userId: emailOtpAuthSubjectId,
    ...(args.challengeId ? { challengeId: args.challengeId } : {}),
    otpCode: args.otpCode,
    shamirPrimeB64u,
    routePlan,
    workerCtx,
    ...(args.clientSecret32 ? { clientSecret32: args.clientSecret32 } : {}),
    ...(args.otpChannel ? { otpChannel: args.otpChannel } : {}),
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
        clientRootShare32B64u: enrollment.clientRootShare32B64u,
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
      walletId: args.walletSession.walletId,
      publicationChainTargets,
      bootstraps: bootstrapResult.bootstraps,
      walletSigningSessionId,
      emailOtpAuthContext: resolvedEmailOtpAuthContext,
      relayerUrl: relayUrl,
      shamirPrimeB64u,
    },
    ports.publicationPorts,
  );
  const thresholdEd25519PrfFirstB64u = String(enrollment.thresholdEd25519PrfFirstB64u || '').trim();
  if (thresholdEd25519PrfFirstB64u) {
    const freshThresholdSessionAuth = thresholdSessionAuthFromEcdsaBootstrap(bootstrap);
    await ports.provisionEd25519Capability({
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
      ...(args.registrationAttemptId ? { registrationAttemptId: args.registrationAttemptId } : {}),
      ...(Array.isArray(args.participantIds) ? { participantIds: args.participantIds } : {}),
      ...(typeof args.ttlMs === 'number' ? { ttlMs: args.ttlMs } : {}),
      ...(typeof remainingUses === 'number' ? { remainingUses } : {}),
      walletSigningSessionId: walletSigningSessionIdFromEcdsaBootstrap(
        bootstrap,
        walletSigningSessionId,
      ),
      ecdsaThresholdSessionId: thresholdSessionIdFromEcdsaBootstrap(bootstrap),
    });
  }
  return {
    enrollment,
    bootstrap,
    warmCapability,
  };
}
