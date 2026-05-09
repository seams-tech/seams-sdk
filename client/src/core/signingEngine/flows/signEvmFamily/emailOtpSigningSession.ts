import type { AccountId } from '@/core/types/accountIds';
import type { EmailOtpAuthPolicy } from '@/core/types/seams';
import { SigningEventPhase } from '@/core/types/sdkSentEvents';
import { WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION } from '@shared/utils/emailOtpDomain';
import type { AppOrThresholdSessionAuth } from '@shared/utils/sessionTokens';
import {
  buildEmailOtpRoutePlan,
  type EmailOtpAuthLane,
} from '../../stepUpConfirmation/otpPrompt/authLane';
import type { EmailOtpBootstrapRecovery } from '../../stepUpConfirmation/otpPrompt/bootstrapRecovery';
import {
  createSigningBoundaryTraceEvent,
  emitSigningBoundaryTrace,
} from '../../session/operationState/trace';
import type { ThresholdEcdsaSessionStoreDeps } from '../../session/persistence/records';
import { getThresholdEcdsaSessionRecordForTarget } from '../../session/persistence/records';
import type { ThresholdEcdsaSessionRecord } from '../../session/persistence/records';
import type {
  ThresholdEcdsaChainTarget,
  WalletSubjectId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdRuntimePolicyScope } from '../../threshold/sessionPolicy';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import type { ThresholdEcdsaSmartAccountBootstrapInput } from '../../session/warmCapabilities/ecdsaBootstrapPersistence';
import type { WarmSessionEcdsaCapabilityState } from '../../session/warmCapabilities/types';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import type { EvmFamilyChain, EvmFamilyLifecycleEventCallback } from './types';
import { emitEvmFamilySigningEvent } from './events';
import {
  emailOtpEcdsaAuthLaneFromRecord,
  isEmailOtpThresholdEcdsaSigningContext,
  type ResolvedEvmFamilyEcdsaSigningLane,
} from './ecdsaLanes';

export type EmailOtpEcdsaSigningSessionDeps = {
  ecdsaSessions: ThresholdEcdsaSessionStoreDeps;
  emailOtpSessions: {
    requestTransactionSigningChallenge: (args: {
      nearAccountId: AccountId | string;
      chain: ThresholdEcdsaChainTarget['kind'];
      authLane: EmailOtpAuthLane;
    }) => Promise<{ challengeId: string; emailHint?: string }>;
    loginWithEcdsaCapabilityInternal: (args: {
      nearAccountId: AccountId | string;
      subjectId: WalletSubjectId;
      chainTarget: ThresholdEcdsaChainTarget;
      emailOtpAuthPolicy?: EmailOtpAuthPolicy;
      emailOtpAuthReason?: 'login' | 'sign';
      challengeId?: string;
      otpCode: string;
      operation?: typeof WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION;
      routePlan?: ReturnType<typeof buildEmailOtpRoutePlan>;
      ecdsaThresholdKeyId?: string;
      participantIds?: number[];
      sessionKind?: 'jwt' | 'cookie';
      walletSigningSessionId?: string;
      ttlMs?: number;
      remainingUses?: number;
      runtimePolicyScope?: ThresholdRuntimePolicyScope;
      routeAuth?: AppOrThresholdSessionAuth;
      smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
      ed25519ProvisioningMode?: 'await' | 'skip';
    }) => Promise<{
      recovery: EmailOtpBootstrapRecovery;
      bootstrap: ThresholdEcdsaSessionBootstrapResult;
      warmCapability: WarmSessionEcdsaCapabilityState;
    }>;
  };
};

export type EvmFamilyEmailOtpTransactionSigningBridge = {
  challenge: () => Promise<{ challengeId: string; email: string }>;
  complete: (input: {
    challengeId: string;
    code: string;
  }) => Promise<ThresholdEcdsaSecp256k1KeyRef>;
};

export function createEmailOtpEcdsaTransactionSigningBridge(args: {
  nearAccountId: string;
  chain: EvmFamilyChain;
  chainTarget: ThresholdEcdsaChainTarget;
  selectedLane?: ResolvedEvmFamilyEcdsaSigningLane;
  warmRecord?: ThresholdEcdsaSessionRecord;
  warmKeyRef?: ThresholdEcdsaSecp256k1KeyRef;
  emailOtpReauthRecord?: ThresholdEcdsaSessionRecord;
  onEvent?: EvmFamilyLifecycleEventCallback;
  requestEmailOtpTransactionSigningChallenge?: (args: {
    nearAccountId: string;
    chain: EvmFamilyChain;
    authLane?: EmailOtpAuthLane;
  }) => Promise<{ challengeId: string; emailHint?: string }>;
  resolveEmailOtpSigningSessionAuthLane?: (args: {
    thresholdSessionId: string;
    curve: 'ecdsa';
    chain: EvmFamilyChain;
  }) => EmailOtpAuthLane | null | Promise<EmailOtpAuthLane | null>;
  loginWithEmailOtpEcdsaCapabilityForSigning?: (args: {
    nearAccountId: string;
    subjectId: WalletSubjectId;
    chainTarget: ThresholdEcdsaChainTarget;
    challengeId: string;
    otpCode: string;
    record?: ThresholdEcdsaSessionRecord;
    authLane?: EmailOtpAuthLane;
    remainingUses?: number;
  }) => Promise<ThresholdEcdsaSecp256k1KeyRef>;
}): EvmFamilyEmailOtpTransactionSigningBridge {
  const resolveEmailOtpRecord = () =>
    args.emailOtpReauthRecord ||
    (isEmailOtpThresholdEcdsaSigningContext({
      ...(args.warmRecord ? { record: args.warmRecord } : {}),
      ...(args.warmKeyRef ? { keyRef: args.warmKeyRef } : {}),
    })
      ? args.warmRecord
      : undefined);
  const resolveAuthLane = async () => {
    const emailOtpRecord = resolveEmailOtpRecord();
    if (!emailOtpRecord) return undefined;
    const resolvedAuthLane = await args.resolveEmailOtpSigningSessionAuthLane?.({
      thresholdSessionId: emailOtpRecord.thresholdSessionId,
      curve: 'ecdsa',
      chain: args.chain,
    });
    return resolvedAuthLane || emailOtpEcdsaAuthLaneFromRecord(emailOtpRecord);
  };

  return {
    challenge: async () => {
      if (typeof args.requestEmailOtpTransactionSigningChallenge !== 'function') {
        throw new Error('[SigningEngine] Email OTP per-operation signing is not configured');
      }
      emitEvmFamilySigningEvent(args.onEvent, {
        phase: SigningEventPhase.STEP_06_AUTH_EMAIL_OTP_CHALLENGE_STARTED,
        status: 'running',
        accountId: args.nearAccountId,
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
      const challenge = await args.requestEmailOtpTransactionSigningChallenge({
        nearAccountId: args.nearAccountId,
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
        accountId: args.nearAccountId,
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
      if (!args.selectedLane?.subjectId) {
        throw new Error('[SigningEngine] Email OTP ECDSA reauth requires selected subject');
      }
      return await args.loginWithEmailOtpEcdsaCapabilityForSigning({
        nearAccountId: args.nearAccountId,
        subjectId: args.selectedLane.subjectId,
        chainTarget: args.chainTarget,
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
    subjectId: WalletSubjectId;
    chainTarget: ThresholdEcdsaChainTarget;
  },
): {
  record: NonNullable<ReturnType<typeof getThresholdEcdsaSessionRecordForTarget>>;
  authLane: EmailOtpAuthLane;
} {
  const record = getThresholdEcdsaSessionRecordForTarget(deps.ecdsaSessions, {
    subjectId: args.subjectId,
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
    walletSigningSessionId,
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
    nearAccountId: AccountId | string;
    subjectId: WalletSubjectId;
    chainTarget: ThresholdEcdsaChainTarget;
  },
): Promise<{ challengeId: string; emailHint?: string }> {
  const { authLane } = resolveEmailOtpEcdsaSigningSessionAuth(deps, {
    subjectId: args.subjectId,
    chainTarget: args.chainTarget,
  });
  return await deps.emailOtpSessions.requestTransactionSigningChallenge({
    nearAccountId: args.nearAccountId,
    chain: args.chainTarget.kind,
    authLane,
  });
}

export async function refreshEmailOtpSigningSession(
  deps: EmailOtpEcdsaSigningSessionDeps,
  args: {
    nearAccountId: AccountId | string;
    subjectId: WalletSubjectId;
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
}> {
  const { record, authLane } = resolveEmailOtpEcdsaSigningSessionAuth(deps, {
    subjectId: args.subjectId,
    chainTarget: args.chainTarget,
  });
  const routePlan = buildEmailOtpRoutePlan({
    routeFamily: 'signing_session',
    authLane,
    operation: WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
  });
  return await deps.emailOtpSessions.loginWithEcdsaCapabilityInternal({
    nearAccountId: args.nearAccountId,
    subjectId: record.subjectId,
    chainTarget: args.chainTarget,
    emailOtpAuthPolicy: 'session',
    emailOtpAuthReason: 'sign',
    challengeId: args.challengeId,
    otpCode: args.otpCode,
    operation: WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
    routePlan,
    ecdsaThresholdKeyId: record.ecdsaThresholdKeyId,
    participantIds: record.participantIds,
    sessionKind: record.thresholdSessionKind,
    walletSigningSessionId: record.walletSigningSessionId,
    ...(typeof args.ttlMs === 'number' ? { ttlMs: args.ttlMs } : {}),
    ...(typeof args.remainingUses === 'number' ? { remainingUses: args.remainingUses } : {}),
    ...(record.runtimePolicyScope ? { runtimePolicyScope: record.runtimePolicyScope } : {}),
    ed25519ProvisioningMode: 'await',
  });
}
