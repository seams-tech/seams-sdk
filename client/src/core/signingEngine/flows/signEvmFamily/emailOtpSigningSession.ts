import type { EmailOtpAuthPolicy } from '@/core/types/seams';
import { SigningEventPhase } from '@/core/types/sdkSentEvents';
import { WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION } from '@shared/utils/emailOtpDomain';
import type { AppOrThresholdSessionAuth } from '@shared/utils/sessionTokens';
import {
  buildEmailOtpRoutePlan,
  toAuthorizingWalletSigningSessionId,
  type EmailOtpAuthLane,
} from '../../stepUpConfirmation/otpPrompt/authLane';
import type { EmailOtpBootstrapRecovery } from '../../stepUpConfirmation/otpPrompt/bootstrapRecovery';
import {
  createSigningBoundaryTraceEvent,
  emitSigningBoundaryTrace,
} from '../../session/operationState/trace';
import type { EmailOtpEcdsaSigningBootstrapResult } from '../../interfaces/operationDeps';
import type { ThresholdEcdsaSessionStoreDeps } from '../../session/persistence/records';
import { getThresholdEcdsaSessionRecordForWalletTarget } from '../../session/persistence/records';
import type { ThresholdEcdsaSessionRecord } from '../../session/persistence/records';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdRuntimePolicyScope } from '../../threshold/sessionPolicy';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import type { WarmSessionEcdsaCapabilityState } from '../../session/warmCapabilities/types';
import type { RequestEmailOtpChallengeArgs } from '../../session/emailOtp/exportRecoveryRuntime';
import {
  toVerifiedEcdsaPublicFactsFromRecord,
  type VerifiedEcdsaPublicFacts,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import type { EvmFamilyChain, EvmFamilyLifecycleEventCallback } from './types';
import { emitEvmFamilySigningEvent } from './events';
import {
  emailOtpEcdsaAuthLaneFromRecord,
  isEmailOtpThresholdEcdsaSigningContext,
  type ResolvedEvmFamilyEcdsaSigningLane,
} from './ecdsaLanes';
import {
  getEcdsaMaterialRecord,
  type EcdsaMaterialState,
} from './ecdsaMaterialState';
import { EMAIL_OTP_SIGNING_SESSION_AUTH_UNAVAILABLE } from '../../session/emailOtp/exportRecovery';
import type { EmailOtpEcdsaBootstrapAuthorization } from '../../session/emailOtp/routePlan';
import type { ReauthAnchorIdentity } from '../../session/operationState/transactionState';
import type { EmailOtpEd25519ReconstructionResult } from '../../session/emailOtp/ecdsaLogin';

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
      routePlan?: ReturnType<typeof buildEmailOtpRoutePlan>;
      publicFacts: VerifiedEcdsaPublicFacts;
      participantIds?: never;
      sessionKind?: 'jwt' | 'cookie';
      ttlMs?: number;
      remainingUses?: number;
      runtimePolicyScope?: ThresholdRuntimePolicyScope;
      routeAuth?: AppOrThresholdSessionAuth;
      ecdsaBootstrapAuthorization: EmailOtpEcdsaBootstrapAuthorization;
      ed25519ReconstructionMode: 'await' | 'skip';
    }) => Promise<{
      recovery: EmailOtpBootstrapRecovery;
      bootstrap: ThresholdEcdsaSessionBootstrapResult;
      warmCapability: WarmSessionEcdsaCapabilityState;
      ed25519Reconstruction: EmailOtpEd25519ReconstructionResult;
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

function emailOtpReauthAuthorityFromAnchor(
  anchor: ReauthAnchorIdentity,
): { thresholdSessionId: string; chainTarget: ThresholdEcdsaChainTarget } | null {
  const identity = anchor.laneIdentity;
  if (identity.curve !== 'ecdsa') return null;
  if (identity.authMethod !== 'email_otp') return null;
  return {
    thresholdSessionId: String(identity.thresholdSessionId),
    chainTarget: identity.chainTarget,
  };
}

export function createEmailOtpEcdsaTransactionSigningBridge(args: {
  walletId: string;
  walletSession: WalletSessionRef;
  chain: EvmFamilyChain;
  chainTarget: ThresholdEcdsaChainTarget;
  selectedLane?: ResolvedEvmFamilyEcdsaSigningLane;
  material?: EcdsaMaterialState;
  signingSessionRecord: ThresholdEcdsaSessionRecord | null;
  reauthSource: { kind: 'material' } | { kind: 'reauth_anchor'; anchor: ReauthAnchorIdentity };
  onEvent?: EvmFamilyLifecycleEventCallback;
  requestEmailOtpTransactionSigningChallenge?: (args: {
    walletSession: WalletSessionRef;
    chain: EvmFamilyChain;
    authLane?: EmailOtpAuthLane;
  }) => Promise<{ challengeId: string; emailHint?: string }>;
  resolveEmailOtpSigningSessionAuthLane?: (args: {
    walletId: WalletId;
    thresholdSessionId: string;
    curve: 'ecdsa';
    chain: EvmFamilyChain;
    chainTarget: ThresholdEcdsaChainTarget;
  }) => EmailOtpAuthLane | null | Promise<EmailOtpAuthLane | null>;
  loginWithEmailOtpEcdsaCapabilityForSigning?: (args: {
    walletSession: WalletSessionRef;
    subjectId?: never;
    chainTarget: ThresholdEcdsaChainTarget;
    challengeId: string;
    otpCode: string;
    record?: ThresholdEcdsaSessionRecord;
    authLane?: EmailOtpAuthLane;
    remainingUses?: number;
  }) => Promise<EmailOtpEcdsaSigningBootstrapResult>;
}): EvmFamilyEmailOtpTransactionSigningBridge {
  const materialRecord = args.material ? getEcdsaMaterialRecord(args.material) : undefined;
  const materialIsEmailOtp = materialRecord
    ? isEmailOtpThresholdEcdsaSigningContext({ record: materialRecord })
    : false;
  const resolveEmailOtpRecord = () =>
    args.signingSessionRecord || (materialIsEmailOtp ? materialRecord : undefined);
  const anchorAuthority =
    args.reauthSource.kind === 'reauth_anchor'
      ? emailOtpReauthAuthorityFromAnchor(args.reauthSource.anchor)
      : null;
  const resolveAuthLane = async () => {
    const emailOtpRecord = resolveEmailOtpRecord();
    const authority = emailOtpRecord
      ? {
          thresholdSessionId: emailOtpRecord.thresholdSessionId,
          chainTarget: emailOtpRecord.chainTarget,
        }
      : anchorAuthority;
    if (!authority) return undefined;
    const resolvedAuthLane = await args.resolveEmailOtpSigningSessionAuthLane?.({
      walletId: args.walletSession.walletId,
      thresholdSessionId: authority.thresholdSessionId,
      curve: 'ecdsa',
      chain: args.chain,
      chainTarget: authority.chainTarget,
    });
    return (
      resolvedAuthLane ||
      (emailOtpRecord ? emailOtpEcdsaAuthLaneFromRecord(emailOtpRecord) : undefined)
    );
  };

  return {
    challenge: async () => {
      if (typeof args.requestEmailOtpTransactionSigningChallenge !== 'function') {
        throw new Error('[SigningEngine] Email OTP per-operation signing is not configured');
      }
      emitEvmFamilySigningEvent(args.onEvent, {
        phase: SigningEventPhase.STEP_06_AUTH_EMAIL_OTP_CHALLENGE_STARTED,
        status: 'running',
        accountId: args.walletId,
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
      const authLane = await resolveAuthLane();
      if (args.reauthSource.kind === 'reauth_anchor' && !authLane) {
        throw new Error(EMAIL_OTP_SIGNING_SESSION_AUTH_UNAVAILABLE);
      }
      const challenge = await args.requestEmailOtpTransactionSigningChallenge({
        walletSession: args.walletSession,
        chain: args.chain,
        ...(authLane ? { authLane } : {}),
      });
      const challengeId = String(challenge.challengeId || '').trim();
      if (!challengeId) {
        throw new Error('[SigningEngine] Email OTP challenge response did not include challengeId');
      }
      emitEvmFamilySigningEvent(args.onEvent, {
        phase: SigningEventPhase.STEP_06_AUTH_EMAIL_OTP_INPUT_REQUIRED,
        status: 'waiting_for_user',
        accountId: args.walletId,
        interaction: { kind: 'otp_input', overlay: 'show' },
        ...(challenge.emailHint ? { data: { emailHint: challenge.emailHint } } : {}),
      });
      return {
        challengeId,
        email: String(challenge.emailHint || '').trim(),
      };
    },
    complete: async ({ challengeId, code }) => {
      const emailOtpRecord = resolveEmailOtpRecord();
      if (typeof args.loginWithEmailOtpEcdsaCapabilityForSigning !== 'function') {
        throw new Error('[SigningEngine] Email OTP per-operation signing is not configured');
      }
      const authLane = await resolveAuthLane();
      if (args.reauthSource.kind === 'reauth_anchor' && !authLane) {
        throw new Error(EMAIL_OTP_SIGNING_SESSION_AUTH_UNAVAILABLE);
      }
      const bootstrapChainTarget =
        emailOtpRecord?.chainTarget ||
        anchorAuthority?.chainTarget ||
        args.chainTarget;
      return await args.loginWithEmailOtpEcdsaCapabilityForSigning({
        walletSession: args.walletSession,
        chainTarget: bootstrapChainTarget,
        challengeId,
        otpCode: code,
        ...(emailOtpRecord ? { record: emailOtpRecord } : {}),
        ...(authLane ? { authLane } : {}),
        remainingUses: 1,
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
  authLane: EmailOtpAuthLane;
} {
  const record = getThresholdEcdsaSessionRecordForWalletTarget(deps.ecdsaSessions, {
    walletId: args.walletId,
    chainTarget: args.chainTarget,
    source: 'email_otp',
  });
  const jwt = String(record.thresholdSessionAuthToken || '').trim();
  if (!jwt) {
    throw new Error('Email OTP signing-session refresh requires threshold-session auth');
  }
  const walletSigningSessionId = String(record.walletSigningSessionId || '').trim();
  if (!walletSigningSessionId) {
    throw new Error('Email OTP signing-session refresh requires wallet signing-session identity');
  }
  const authLane: EmailOtpAuthLane = {
    kind: 'signing_session',
    jwt,
    thresholdSessionId: record.thresholdSessionId,
    authorizingWalletSigningSessionId: toAuthorizingWalletSigningSessionId(walletSigningSessionId),
    curve: 'ecdsa',
    chainTarget: args.chainTarget,
  };
  return {
    record,
    authLane,
  };
}

export async function requestEmailOtpSigningSessionChallenge(
  deps: EmailOtpEcdsaSigningSessionDeps,
  args: {
    walletSession: WalletSessionRef;
    chainTarget: ThresholdEcdsaChainTarget;
  },
): Promise<{ challengeId: string; emailHint?: string }> {
  const { authLane } = resolveEmailOtpEcdsaSigningSessionAuth(deps, {
    walletId: args.walletSession.walletId,
    chainTarget: args.chainTarget,
  });
  return await deps.emailOtpSessions.requestTransactionSigningChallenge({
    kind: 'wallet_session_challenge',
    walletSession: args.walletSession,
    chain: args.chainTarget.kind,
    authLane,
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
  ed25519Reconstruction: EmailOtpEd25519ReconstructionResult;
}> {
  const { record, authLane } = resolveEmailOtpEcdsaSigningSessionAuth(deps, {
    walletId: args.walletSession.walletId,
    chainTarget: args.chainTarget,
  });
  const routePlan = buildEmailOtpRoutePlan({
    routeFamily: 'signing_session',
    authLane,
    operation: WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
  });
  const publicFacts = await toVerifiedEcdsaPublicFactsFromRecord({ record });
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
    sessionKind: record.thresholdSessionKind,
    ecdsaBootstrapAuthorization: { kind: 'route_plan_auth' },
    ...(typeof args.ttlMs === 'number' ? { ttlMs: args.ttlMs } : {}),
    ...(typeof args.remainingUses === 'number' ? { remainingUses: args.remainingUses } : {}),
    ...(record.runtimePolicyScope ? { runtimePolicyScope: record.runtimePolicyScope } : {}),
    ed25519ReconstructionMode: 'await',
  });
}
