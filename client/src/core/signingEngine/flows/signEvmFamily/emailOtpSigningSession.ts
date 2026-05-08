import type { AccountId } from '@/core/types/accountIds';
import type { EmailOtpAuthPolicy } from '@/core/types/seams';
import { WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION } from '@shared/utils/emailOtpDomain';
import type { AppOrThresholdSessionAuth } from '@shared/utils/sessionTokens';
import {
  buildEmailOtpRoutePlan,
  type EmailOtpAuthLane,
} from '../../stepUpConfirmation/otpPrompt/authLane';
import type { EmailOtpBootstrapRecovery } from '../../stepUpConfirmation/otpPrompt/bootstrapRecovery';
import type { ThresholdEcdsaSessionStoreDeps } from '../../session/persistence/records';
import { getThresholdEcdsaSessionRecordForTarget } from '../../session/persistence/records';
import type {
  ThresholdEcdsaChainTarget,
  WalletSubjectId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdRuntimePolicyScope } from '../../threshold/sessionPolicy';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import type { ThresholdEcdsaSmartAccountBootstrapInput } from '../../session/warmSigning/ecdsaBootstrapPersistence';
import type { WarmSessionEcdsaCapabilityState } from '../../session/warmSigning/types';

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
