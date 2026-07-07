import type { EmailOtpAuthPolicy } from '@/core/types/seams';
import { SigningEventPhase } from '@/core/types/sdkSentEvents';
import { WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION } from '@shared/utils/emailOtpDomain';
import {
  buildEmailOtpRoutePlan,
  type EmailOtpSigningSessionAuthLane,
} from '../../stepUpConfirmation/otpPrompt/authLane';
import type { EmailOtpBootstrapRecovery } from '../../stepUpConfirmation/otpPrompt/bootstrapRecovery';
import {
  createSigningBoundaryTraceEvent,
  emitSigningBoundaryTrace,
} from '../../session/operationState/trace';
import type { EmailOtpEcdsaSigningBootstrapResult } from '../../interfaces/operationDeps';
import type { ThresholdEcdsaSessionStoreDeps } from '../../session/persistence/records';
import {
  getThresholdEcdsaSessionRecordForWalletTarget,
  thresholdEcdsaEmailOtpAuthContext,
} from '../../session/persistence/records';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdRuntimePolicyScope } from '../../threshold/sessionPolicy';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import type { WarmSessionEcdsaCapabilityState } from '../../session/warmCapabilities/types';
import type { RequestEmailOtpChallengeArgs } from '../../session/emailOtp/exportRecoveryRuntime';
import type { EmailOtpThresholdEcdsaLoginTimings } from '../../session/emailOtp/ecdsaLogin';
import {
  toVerifiedEcdsaPublicFactsFromRecord,
  type VerifiedEcdsaPublicFacts,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import type { EvmFamilyChain, EvmFamilyLifecycleEventCallback } from './types';
import { emitEvmFamilySigningEvent } from './events';
import { type ResolvedEvmFamilyEcdsaSigningLane } from './ecdsaLanes';
import {
  throwEmailOtpSigningSessionAuthStateError,
  type EmailOtpEcdsaBootstrapAuthorization,
} from '../../session/emailOtp/routePlan';
import type { ReauthAnchorIdentity } from '../../session/operationState/transactionState';
import {
  emailOtpEcdsaProviderIdentityFromRecord,
  type EmailOtpEcdsaProviderIdentity,
  type EmailOtpEd25519ReconstructionResult,
} from '../../session/emailOtp/ecdsaLogin';
import {
  resolveEmailOtpEcdsaSigningSessionAuthorityFromRecord,
  type EmailOtpEcdsaSigningSessionAuthority,
} from '../../session/emailOtp/ecdsaSigningSessionAuthority';
import { emailOtpAuthContextEmailHashHex } from '../../session/identity/laneIdentity';
import type { EmailOtpEcdsaCommittedLane } from './ecdsaSelection';

type WalletSessionEmailOtpChallengeArgs = Extract<
  RequestEmailOtpChallengeArgs,
  { kind: 'wallet_session_challenge' }
>;

export type EmailOtpEcdsaSigningSessionDeps = {
  ecdsaSessions: ThresholdEcdsaSessionStoreDeps;
  emailOtpSessions: {
    requestTransactionSigningChallenge: (
      args: WalletSessionEmailOtpChallengeArgs,
    ) => Promise<{ challengeId: string; emailHint?: string }>;
    loginWithEcdsaCapabilityInternal: (args: {
      walletSession: WalletSessionRef;
      subjectId?: never;
      chainTarget: ThresholdEcdsaChainTarget;
      emailOtpAuthPolicy?: EmailOtpAuthPolicy;
      emailOtpAuthReason?: 'login' | 'sign';
      challengeId?: string;
      otpCode: string;
      operation?: typeof WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION;
      routePlan: ReturnType<typeof buildEmailOtpRoutePlan>;
      publicFacts: VerifiedEcdsaPublicFacts;
      participantIds?: never;
      ttlMs?: number;
      remainingUses?: number;
      runtimePolicyScope?: ThresholdRuntimePolicyScope;
      routeAuth?: never;
      ecdsaBootstrapAuthorization: EmailOtpEcdsaBootstrapAuthorization;
      ed25519ReconstructionMode: 'await' | 'skip';
      providerIdentity: EmailOtpEcdsaProviderIdentity;
      emailHashHex: string;
      authSubjectId?: never;
    }) => Promise<{
      recovery: EmailOtpBootstrapRecovery;
      bootstrap: ThresholdEcdsaSessionBootstrapResult;
      warmCapability: WarmSessionEcdsaCapabilityState;
      warmCapabilities: readonly [
        WarmSessionEcdsaCapabilityState,
        ...WarmSessionEcdsaCapabilityState[],
      ];
      ed25519Reconstruction: EmailOtpEd25519ReconstructionResult;
      timings: EmailOtpThresholdEcdsaLoginTimings;
    }>;
  };
};

export type EvmFamilyEmailOtpTransactionSigningBridge = {
  challenge: () => Promise<{ challengeId: string; email: string }>;
  complete: (input: {
    challengeId: string;
    code: string;
  }) => Promise<EmailOtpEcdsaSigningBootstrapResult>;
};

export function createEmailOtpEcdsaTransactionSigningBridge(args: {
  walletId: string;
  walletSession: WalletSessionRef;
  chain: EvmFamilyChain;
  chainTarget: ThresholdEcdsaChainTarget;
  selectedLane?: ResolvedEvmFamilyEcdsaSigningLane;
  committedLane: EmailOtpEcdsaCommittedLane;
  remainingUses: number;
  reauthSource: { kind: 'material' } | { kind: 'reauth_anchor'; anchor: ReauthAnchorIdentity };
  onEvent?: EvmFamilyLifecycleEventCallback;
  requestEmailOtpTransactionSigningChallenge?: (args: {
    walletSession: WalletSessionRef;
    chain: EvmFamilyChain;
    authLane: Extract<EmailOtpSigningSessionAuthLane, { curve: 'ecdsa' }>;
  }) => Promise<{ challengeId: string; emailHint?: string }>;
  loginWithEmailOtpEcdsaCapabilityForSigning?: (args: {
    walletSession: WalletSessionRef;
    subjectId?: never;
    chainTarget: ThresholdEcdsaChainTarget;
    challengeId: string;
    otpCode: string;
    committedLane: EmailOtpEcdsaCommittedLane;
    remainingUses: number;
  }) => Promise<EmailOtpEcdsaSigningBootstrapResult>;
}): EvmFamilyEmailOtpTransactionSigningBridge {
  const committedAuthLane = args.committedLane.authLane;

  return {
    challenge: async () => {
      if (typeof args.requestEmailOtpTransactionSigningChallenge !== 'function') {
        throw new Error('[SigningEngine] Email OTP ECDSA signing step-up is not configured');
      }
      emitEvmFamilySigningEvent(args.onEvent, {
        phase: SigningEventPhase.STEP_06_AUTH_EMAIL_OTP_CHALLENGE_STARTED,
        status: 'running',
        walletId: args.walletId,
        interaction: { kind: 'none', overlay: 'none' },
      });
      emitSigningBoundaryTrace(
        'evm-family',
        createSigningBoundaryTraceEvent({
          event: 'auth_side_effect_started',
          lane: args.selectedLane,
          sideEffect: 'email_otp_challenge',
          phase: 'confirmed',
        }),
      );
      const challenge = await args.requestEmailOtpTransactionSigningChallenge({
        walletSession: args.walletSession,
        chain: args.chain,
        authLane: committedAuthLane,
      });
      const challengeId = String(challenge.challengeId || '').trim();
      if (!challengeId) {
        throw new Error('[SigningEngine] Email OTP challenge response did not include challengeId');
      }
      emitEvmFamilySigningEvent(args.onEvent, {
        phase: SigningEventPhase.STEP_06_AUTH_EMAIL_OTP_INPUT_REQUIRED,
        status: 'waiting_for_user',
        walletId: args.walletId,
        interaction: { kind: 'otp_input', overlay: 'show' },
        ...(challenge.emailHint ? { data: { emailHint: challenge.emailHint } } : {}),
      });
      return {
        challengeId,
        email: String(challenge.emailHint || '').trim(),
      };
    },
    complete: async ({ challengeId, code }) => {
      if (typeof args.loginWithEmailOtpEcdsaCapabilityForSigning !== 'function') {
        throw new Error('[SigningEngine] Email OTP ECDSA signing step-up is not configured');
      }
      return await args.loginWithEmailOtpEcdsaCapabilityForSigning({
        walletSession: args.walletSession,
        chainTarget: args.chainTarget,
        challengeId,
        otpCode: code,
        committedLane: args.committedLane,
        remainingUses: args.remainingUses,
      });
    },
  };
}

function resolveEmailOtpEcdsaSigningSessionAuth(
  deps: Pick<EmailOtpEcdsaSigningSessionDeps, 'ecdsaSessions'>,
  args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
  },
): {
  record: NonNullable<ReturnType<typeof getThresholdEcdsaSessionRecordForWalletTarget>>;
  authority: EmailOtpEcdsaSigningSessionAuthority;
} {
  const record = getThresholdEcdsaSessionRecordForWalletTarget(deps.ecdsaSessions, {
    walletId: args.walletId,
    chainTarget: args.chainTarget,
    source: 'email_otp',
  });
  const authorityResolution = resolveEmailOtpEcdsaSigningSessionAuthorityFromRecord(record);
  if (authorityResolution.kind !== 'ready') {
    throwEmailOtpSigningSessionAuthStateError({
      kind: 'auth_lane_missing',
      source: 'evm_signing_refresh',
      expectedCurve: 'ecdsa',
    });
  }
  const emailOtpAuthContext = thresholdEcdsaEmailOtpAuthContext(record);
  if (!emailOtpAuthContext) {
    throw new Error('Email OTP signing-session auth requires Email OTP auth context');
  }
  return {
    record,
    authority: authorityResolution.authority,
  };
}

export async function requestEmailOtpSigningSessionChallenge(
  deps: EmailOtpEcdsaSigningSessionDeps,
  args: {
    walletSession: WalletSessionRef;
    chainTarget: ThresholdEcdsaChainTarget;
  },
): Promise<{ challengeId: string; emailHint?: string }> {
  const { authority } = resolveEmailOtpEcdsaSigningSessionAuth(deps, {
    walletId: args.walletSession.walletId,
    chainTarget: args.chainTarget,
  });
  return await deps.emailOtpSessions.requestTransactionSigningChallenge({
    kind: 'wallet_session_challenge',
    walletSession: args.walletSession,
    chain: args.chainTarget.kind,
    authLane: authority.authLane,
  });
}

export async function refreshEmailOtpSigningSession(
  deps: EmailOtpEcdsaSigningSessionDeps,
  args: {
    walletSession: WalletSessionRef;
    chainTarget: ThresholdEcdsaChainTarget;
    challengeId: string;
    otpCode: string;
    ttlMs?: number;
    remainingUses?: number;
  },
): Promise<{
  recovery: EmailOtpBootstrapRecovery;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  warmCapability: WarmSessionEcdsaCapabilityState;
  warmCapabilities: readonly [
    WarmSessionEcdsaCapabilityState,
    ...WarmSessionEcdsaCapabilityState[],
  ];
  ed25519Reconstruction: EmailOtpEd25519ReconstructionResult;
  timings: EmailOtpThresholdEcdsaLoginTimings;
}> {
  const { record, authority } = resolveEmailOtpEcdsaSigningSessionAuth(deps, {
    walletId: args.walletSession.walletId,
    chainTarget: args.chainTarget,
  });
  const routePlan = buildEmailOtpRoutePlan({
    routeFamily: 'signing_session',
    authLane: authority.authLane,
    operation: WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
  });
  const publicFacts = await toVerifiedEcdsaPublicFactsFromRecord({ record });
  if (record.source !== 'email_otp') {
    throw new Error('Email OTP signing-session refresh requires an Email OTP session record');
  }
  const emailOtpAuthContext = thresholdEcdsaEmailOtpAuthContext(record);
  if (!emailOtpAuthContext) {
    throw new Error('Email OTP signing-session refresh requires Email OTP auth context');
  }
  return await deps.emailOtpSessions.loginWithEcdsaCapabilityInternal({
    walletSession: args.walletSession,
    chainTarget: args.chainTarget,
    emailOtpAuthPolicy: 'session',
    emailOtpAuthReason: 'sign',
    challengeId: args.challengeId,
    otpCode: args.otpCode,
    operation: WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
    routePlan,
    publicFacts,
    ecdsaBootstrapAuthorization: { kind: 'route_plan_auth' },
    providerIdentity: emailOtpEcdsaProviderIdentityFromRecord(record),
    emailHashHex: emailOtpAuthContextEmailHashHex(emailOtpAuthContext),
    ...(typeof args.ttlMs === 'number' ? { ttlMs: args.ttlMs } : {}),
    ...(typeof args.remainingUses === 'number' ? { remainingUses: args.remainingUses } : {}),
    ...(record.runtimePolicyScope ? { runtimePolicyScope: record.runtimePolicyScope } : {}),
    ed25519ReconstructionMode: 'await',
  });
}
