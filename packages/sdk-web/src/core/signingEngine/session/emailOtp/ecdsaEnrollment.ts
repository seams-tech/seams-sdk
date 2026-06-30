import type { EmailOtpAuthPolicy, SeamsConfigsReadonly } from '@/core/types/seams';
import type { EmailOtpEnrollmentResult } from '@/core/signingEngine/session/emailOtp/publicTypes';
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
  generateSigningGrantId,
  parseThresholdRuntimePolicyScopeFromJwt,
  type ThresholdRuntimePolicyScope,
} from '@/core/signingEngine/threshold/sessionPolicy';
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import type { WarmSessionEcdsaCapabilityState } from '@/core/signingEngine/session/warmCapabilities/types';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type {
  EmailOtpEcdsaBootstrapStrictPayload,
  EmailOtpWorkerProgressEvent,
} from '@/core/signingEngine/workerManager/workerTypes';
import type { AppOrWalletSessionAuth } from '@shared/utils/sessionTokens';
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
} from './routePlan';
import {
  DEV_DEFAULT_UNLOCK_REMAINING_USES,
  resolveSigningBudgetPolicyRemainingUses,
  resolveWalletUnlockBudgetPolicyFromRequestedUses,
} from '../budget/policy';
import { deriveEvmFamilySigningKeySlotIdFromRuntimePolicyScope } from '../identity/evmFamilyEcdsaIdentity';

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
  routeAuth?: AppOrWalletSessionAuth;
  keyHandle?: string;
  participantIds?: number[];
  sessionKind?: 'jwt';
  routePlan?: EmailOtpRoutePlan;
  ttlMs?: number;
  remainingUses?: number;
  clientSecret32?: Uint8Array;
  otpChannel?: WalletEmailOtpChannel;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  registrationAttemptId?: string;
  onProgress?: (progress: EmailOtpWorkerProgressEvent) => void;
};

type EmailOtpEcdsaRegistrationBaseInput = {
  mode: 'registration_bootstrap';
  walletSession: WalletSessionRef;
  chainTarget: ThresholdEcdsaChainTarget;
  routePlan: EmailOtpRoutePlan;
  registrationAttemptId: string;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
};

type EmailOtpEcdsaRegistrationJwtAuthInput = {
  sessionKind: 'jwt';
  routeAuth: AppOrWalletSessionAuth;
};

type EmailOtpEcdsaNewRegistrationKeyInput = {
  keyMode: 'new_role_local_key';
  keyHandle?: never;
};

type EmailOtpEcdsaExistingRegistrationKeyInput = {
  keyMode: 'existing_role_local_key';
  keyHandle: string;
};

export type EmailOtpEcdsaRegistrationBootstrapInput = EmailOtpEcdsaRegistrationBaseInput &
  EmailOtpEcdsaRegistrationJwtAuthInput &
  (EmailOtpEcdsaNewRegistrationKeyInput | EmailOtpEcdsaExistingRegistrationKeyInput);

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
};

function requiredEmailOtpEcdsaEnrollmentString(value: unknown, field: string): string {
  const normalized = String(value ?? '').trim();
  if (!normalized) {
    throw new Error(`Email OTP ECDSA registration requires ${field}`);
  }
  return normalized;
}

async function resolveEmailOtpEcdsaRegistrationBootstrapInput(args: {
  request: EnrollAndLoginEmailOtpEcdsaCapabilityArgs;
  routePlan: EmailOtpRoutePlan;
  routeAuth: AppOrWalletSessionAuth | undefined;
  runtimePolicyScope: ThresholdRuntimePolicyScope | undefined;
  walletSessionUserId: string;
}): Promise<EmailOtpEcdsaRegistrationBootstrapInput> {
  const registrationAttemptId = requiredEmailOtpEcdsaEnrollmentString(
    args.request.registrationAttemptId,
    'registrationAttemptId',
  );
  if (!args.runtimePolicyScope) {
    throw new Error('Email OTP ECDSA registration requires runtimePolicyScope');
  }
  const base = {
    mode: 'registration_bootstrap' as const,
    walletSession: args.request.walletSession,
    chainTarget: args.request.chainTarget,
    routePlan: args.routePlan,
    registrationAttemptId,
    runtimePolicyScope: args.runtimePolicyScope,
  };
  const authInput = {
    sessionKind: 'jwt' as const,
    routeAuth:
      args.routeAuth ||
      (() => {
        throw new Error('Email OTP ECDSA registration requires route auth');
      })(),
  };
  const keyHandle = String(args.request.keyHandle || '').trim();
  if (keyHandle) {
    return {
      ...base,
      ...authInput,
      keyMode: 'existing_role_local_key',
      keyHandle,
    };
  }
  return {
    ...base,
    ...authInput,
    keyMode: 'new_role_local_key',
  };
}

export async function enrollAndLoginWithEmailOtpEcdsaCapability(
  args: EnrollAndLoginEmailOtpEcdsaCapabilityArgs,
  ports: EmailOtpEcdsaEnrollmentPorts,
): Promise<EmailOtpThresholdEcdsaEnrollmentResult> {
  const chainTarget = args.chainTarget;
  const emailOtpAuthPolicy: EmailOtpAuthPolicy =
    args.emailOtpAuthPolicy || ports.configs.signing.emailOtp.authPolicy;
  const emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext = {
    policy: emailOtpAuthPolicy,
    retention: 'session',
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
    generateSigningGrantId,
  });
  const signingGrantId = mintingSession.signingGrantId;
  const routeAuth = routeAuthFromEmailOtpRoutePlan(routePlan);
  const runtimePolicyScope =
    args.runtimePolicyScope ||
    parseThresholdRuntimePolicyScopeFromJwt(args.appSessionJwt) ||
    parseThresholdRuntimePolicyScopeFromJwt(routeAuth?.jwt);
  const workerCtx = ports.getSignerWorkerContext();
  if (!workerCtx) {
    throw new Error('Email OTP enrollment login requires the dedicated emailOtp worker');
  }
  const appSessionJwt = appSessionJwtFromEmailOtpAuthLane(routePlan.authLane);
  if (appSessionJwt) {
    ports.rememberAppSessionJwt({ walletSession: args.walletSession, appSessionJwt });
  }
  const authSubjectId = appSessionSubjectFromEmailOtpAuthLane(routePlan.authLane);
  const emailOtpContextAuthSubjectId = authSubjectId
    ? toEmailOtpAuthSubjectId(authSubjectId)
    : undefined;
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
        : { policyVersion: 'sdk_email_otp_registration_config_v1' }),
    }) ||
    (() => {
      throw new Error('[SigningEngine][email-otp] registration budget policy is required');
    })();
  const remainingUses = resolveSigningBudgetPolicyRemainingUses(unlockBudgetPolicy);
  const emailOtpAuthSubjectId = toEmailOtpAuthSubjectId(args.walletSession.walletSessionUserId);
  const walletSessionUserId = toWalletSessionUserId(args.walletSession.walletId);
  const registrationInput = await resolveEmailOtpEcdsaRegistrationBootstrapInput({
    request: args,
    routePlan,
    routeAuth,
    runtimePolicyScope,
    walletSessionUserId,
  });
  const evmFamilySigningKeySlotId = deriveEvmFamilySigningKeySlotIdFromRuntimePolicyScope({
    walletId: args.walletSession.walletId,
    runtimePolicyScope: registrationInput.runtimePolicyScope,
  });
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
    googleEmailOtpRegistrationAttemptId: registrationInput.registrationAttemptId,
    ecdsaClientRootHandleBinding: {
      evmFamilySigningKeySlotId,
      authSubjectId: emailOtpAuthSubjectId,
      operation: 'registration',
      chainTarget,
    },
    ...(args.clientSecret32 ? { clientSecret32: args.clientSecret32 } : {}),
    ...(args.otpChannel ? { otpChannel: args.otpChannel } : {}),
    ...(args.onProgress ? { onProgress: args.onProgress } : {}),
  });
  const bootstrapPayloadBase = {
    relayUrl,
    walletId: String(args.walletSession.walletId),
    walletSessionUserId,
    userId: emailOtpAuthSubjectId,
    evmFamilySigningKeySlotId,
    clientRootShareHandle: enrollment.clientRootShareHandle,
    chainTarget,
    publicationChainTargets,
    ...(registrationInput.keyMode === 'existing_role_local_key'
      ? { keyHandle: registrationInput.keyHandle }
      : {}),
    runtimePolicyScope: registrationInput.runtimePolicyScope,
    ...(Array.isArray(args.participantIds) && args.participantIds.length > 0
      ? { participantIds: args.participantIds }
      : {}),
    signingGrantId,
    ...(typeof args.ttlMs === 'number' ? { ttlMs: args.ttlMs } : {}),
    remainingUses,
  };
  const bootstrapPayload: EmailOtpEcdsaBootstrapStrictPayload =
    registrationInput.keyMode === 'existing_role_local_key'
      ? {
          ...bootstrapPayloadBase,
          sessionKind: 'jwt',
          routeAuth: registrationInput.routeAuth,
          keyHandle: registrationInput.keyHandle,
        }
      : {
          ...bootstrapPayloadBase,
          sessionKind: 'jwt',
          routeAuth: registrationInput.routeAuth,
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
  const { bootstrap, warmCapability } = await commitEmailOtpEcdsaPublicationBootstraps(
    {
      walletId: args.walletSession.walletId,
      publicationChainTargets,
      bootstraps: bootstrapResult.bootstraps,
      signingGrantId,
      emailOtpAuthContext: resolvedEmailOtpAuthContext,
      relayerUrl: relayUrl,
      shamirPrimeB64u,
    },
    ports.publicationPorts,
  );
  return {
    enrollment,
    bootstrap,
    warmCapability,
  };
}
