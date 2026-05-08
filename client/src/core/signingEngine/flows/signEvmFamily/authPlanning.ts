import type { AccountAuthMetadata } from '@/core/signingEngine/interfaces/accountAuthMetadata';
import {
  SigningAuthPlanKind,
  type SigningAuthPlan,
} from '@/core/signingEngine/stepUpConfirmation/types';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import type { EmailOtpAuthLane } from '../../stepUpConfirmation/otpPrompt/authLane';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import type { WarmSessionStatusReader, WarmSessionStatusResult } from '../../uiConfirm/types';
import type {
  SigningSessionCoordinator,
  SigningSessionReadiness,
} from '../../session/SigningSessionCoordinator';
import { resolveEmailOtpEcdsaWorkerSessionId } from '../../session/availability/readiness';
import type { SigningSessionPlan } from '../../session/signingSession/types';
import { SigningOperationIntent, SigningSessionPlanKind } from '../../session/signingSession/types';
import type { PreparedThresholdSigningOperation } from '../../session/signingSession/preparedOperation';
import { signingAuthPlanFromSigningSessionPlan } from '../shared/signingConfirmation';
import type { ThresholdEcdsaSessionRecord } from '../../session/persistence/records';
import type {
  ThresholdEcdsaChainTarget,
  WalletSubjectId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  isEmailOtpThresholdEcdsaSigningContext,
  type ResolvedEvmFamilyEcdsaSigningLane,
} from './ecdsaLanes';
import type { EvmFamilyEcdsaSessionReaderDeps } from '../../interfaces/operationDeps';
import {
  createEmailOtpEcdsaTransactionSigningBridge,
  type EvmFamilyEmailOtpTransactionSigningBridge,
} from './emailOtpSigningSession';
import type {
  EvmFamilyChain,
  EvmFamilyLifecycleEventCallback,
  EvmFamilySenderSignatureAlgorithm,
} from './types';

export type EvmFamilyPreConfirmSigningDeps = EvmFamilyEcdsaSessionReaderDeps & {
  touchConfirm: WarmSessionStatusReader;
  getEmailOtpWarmSessionStatus?: (sessionId: string) => Promise<WarmSessionStatusResult>;
  signingSessionCoordinator: SigningSessionCoordinator;
};
export type EvmFamilyWarmSessionReadinessDeps = EvmFamilyPreConfirmSigningDeps;

export type EvmFamilyConfirmedEmailOtpDeps = {
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
};

export type EvmFamilyConfirmedSigningDeps = EvmFamilyConfirmedEmailOtpDeps;

export type EvmFamilyTransactionStepUpDeps = EvmFamilyPreConfirmSigningDeps;

type ResolveEvmFamilyTransactionStepUpBaseArgs = {
  deps: EvmFamilyTransactionStepUpDeps;
  confirmedDeps: EvmFamilyConfirmedSigningDeps;
  nearAccountId: string;
  chain: EvmFamilyChain;
  chainTarget: ThresholdEcdsaChainTarget;
  accountAuth: AccountAuthMetadata;
  onEvent?: EvmFamilyLifecycleEventCallback;
};

export type ResolveEvmFamilyTransactionStepUpArgs =
  | (ResolveEvmFamilyTransactionStepUpBaseArgs & {
      senderSignatureAlgorithm: 'secp256k1';
      preparedOperation: PreparedThresholdSigningOperation<
        ResolvedEvmFamilyEcdsaSigningLane,
        Record<string, unknown>
      >;
    })
  | (ResolveEvmFamilyTransactionStepUpBaseArgs & {
      senderSignatureAlgorithm: Exclude<EvmFamilySenderSignatureAlgorithm, 'secp256k1'>;
      preparedOperation?: never;
    });

export async function resolveEvmFamilyEcdsaPlannerReadiness(args: {
  deps: Pick<EvmFamilyPreConfirmSigningDeps, 'touchConfirm' | 'getEmailOtpWarmSessionStatus'>;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  record?: ThresholdEcdsaSessionRecord;
  keyRef?: ThresholdEcdsaSecp256k1KeyRef;
}): Promise<{
  readiness: SigningSessionReadiness;
  expiresAtMs: number;
  remainingUses: number;
  signingRootId?: string;
}> {
  const thresholdSessionId = args.lane.thresholdSessionId;
  const base = {
    thresholdSessionId,
  };
  const record = args.record;
  if (!record) {
    return {
      readiness: {
        status: 'missing_session',
        ...base,
      },
      expiresAtMs: 0,
      remainingUses: 0,
    };
  }

  const signingRootId = record.runtimePolicyScope
    ? signingRootScopeFromRuntimePolicyScope(record.runtimePolicyScope).signingRootId
    : undefined;
  const buildBackingReadiness = (input: { expiresAtMs: number; remainingUses: number }) => ({
    readiness: {
      status: 'ready' as const,
      thresholdSessionId,
    },
    expiresAtMs: Math.floor(Number(input.expiresAtMs) || 0),
    remainingUses: Math.floor(Number(input.remainingUses) || 0),
    ...(signingRootId ? { signingRootId } : {}),
  });

  if (isEmailOtpThresholdEcdsaSigningContext({ record, keyRef: args.keyRef })) {
    const emailOtpWorkerSessionId = resolveEmailOtpEcdsaWorkerSessionId(record);
    const readEmailOtpStatus = async () => {
      if (emailOtpWorkerSessionId && typeof args.deps.getEmailOtpWarmSessionStatus === 'function') {
        return await args.deps
          .getEmailOtpWarmSessionStatus(emailOtpWorkerSessionId)
          .catch(() => null);
      }
      return await args.deps.touchConfirm
        .getWarmSessionStatus({ sessionId: record.thresholdSessionId })
        .catch(() => null);
    };
    let status = await readEmailOtpStatus();
    const statusExpiresAtMs = status?.ok ? status.expiresAtMs : 0;
    const statusRemainingUses = status?.ok ? status.remainingUses : 0;
    return buildBackingReadiness({
      expiresAtMs: Math.floor(Number(statusExpiresAtMs) || 0),
      remainingUses: Math.floor(Number(statusRemainingUses) || 0),
    });
  }

  const expiresAtMs = record.expiresAtMs;
  const remainingUses = record.remainingUses;
  return buildBackingReadiness({ expiresAtMs, remainingUses });
}

export async function resolveEvmFamilyTransactionStepUp(
  args: ResolveEvmFamilyTransactionStepUpArgs,
): Promise<{
  signingAuthPlan: SigningAuthPlan;
  signingSessionPlan?: SigningSessionPlan;
  emailOtpSigning?: {
    prepare: () => Promise<{ challengeId: string; emailHint?: string }>;
    resend?: () => Promise<{ challengeId: string; emailHint?: string }>;
    complete: (otpCode: string, challengeId?: string) => Promise<ThresholdEcdsaSecp256k1KeyRef>;
  };
}> {
  const preparedEcdsaMetadata =
    args.senderSignatureAlgorithm === 'secp256k1'
      ? (args.preparedOperation.metadata as {
          warmRecord?: ThresholdEcdsaSessionRecord;
          warmKeyRef?: ThresholdEcdsaSecp256k1KeyRef;
          emailOtpReauthRecord?: ThresholdEcdsaSessionRecord;
          signingRootId?: string;
        })
      : null;
  const preparedEcdsaLane =
    args.senderSignatureAlgorithm === 'secp256k1' ? args.preparedOperation.lane : undefined;
  const laneWarmRecord = preparedEcdsaMetadata?.warmRecord;
  const laneWarmKeyRef = preparedEcdsaMetadata?.warmKeyRef;
  const confirmedEmailOtpDeps = args.confirmedDeps;
  const emailOtpReauthRecord =
    args.senderSignatureAlgorithm === 'secp256k1' &&
    preparedEcdsaLane?.authMethod === SIGNER_AUTH_METHODS.emailOtp
      ? preparedEcdsaMetadata?.emailOtpReauthRecord || preparedEcdsaMetadata?.warmRecord
      : undefined;
  const emailOtpAuthBridge =
    args.senderSignatureAlgorithm === 'secp256k1'
      ? createEmailOtpEcdsaTransactionSigningBridge({
          nearAccountId: args.nearAccountId,
          chain: args.chain,
          chainTarget: args.chainTarget,
          selectedLane: preparedEcdsaLane,
          warmRecord: laneWarmRecord,
          warmKeyRef: laneWarmKeyRef,
          emailOtpReauthRecord,
          onEvent: args.onEvent,
          requestEmailOtpTransactionSigningChallenge:
            confirmedEmailOtpDeps.requestEmailOtpTransactionSigningChallenge,
          resolveEmailOtpSigningSessionAuthLane:
            confirmedEmailOtpDeps.resolveEmailOtpSigningSessionAuthLane,
          loginWithEmailOtpEcdsaCapabilityForSigning:
            confirmedEmailOtpDeps.loginWithEmailOtpEcdsaCapabilityForSigning,
        })
      : null;
  const signingIntent = SigningOperationIntent.TransactionSign;
  const signingCurve = args.senderSignatureAlgorithm === 'secp256k1' ? 'ecdsa' : undefined;
  let plannedEcdsaSigningAuthPlan: SigningAuthPlan | null = null;
  let plannedSigningSessionPlan: SigningSessionPlan | undefined;
  if (args.senderSignatureAlgorithm === 'secp256k1') {
    const preparedOperation = args.preparedOperation;
    const signingSessionPlan = preparedOperation.signingSessionPlan;
    plannedSigningSessionPlan = signingSessionPlan;
    if (signingSessionPlan.kind === SigningSessionPlanKind.WarmSession) {
      plannedEcdsaSigningAuthPlan = signingAuthPlanFromSigningSessionPlan({
        plan: signingSessionPlan,
        accountId: args.nearAccountId,
        intent: signingIntent,
        ...(signingCurve ? { curve: signingCurve } : {}),
        ...(preparedOperation.metadata.signingRootId
          ? { signingRootId: String(preparedOperation.metadata.signingRootId) }
          : {}),
        expiresAtMs: preparedOperation.expiresAtMs,
        remainingUses: preparedOperation.remainingUses,
      });
    } else if (signingSessionPlan.kind === SigningSessionPlanKind.EmailOtpReauth) {
      plannedEcdsaSigningAuthPlan = signingAuthPlanFromSigningSessionPlan({
        plan: signingSessionPlan,
        accountId: args.nearAccountId,
        intent: signingIntent,
        ...(signingCurve ? { curve: signingCurve } : {}),
      });
    } else if (signingSessionPlan.kind === SigningSessionPlanKind.PasskeyReauth) {
      plannedEcdsaSigningAuthPlan = signingAuthPlanFromSigningSessionPlan({
        plan: signingSessionPlan,
        accountId: args.nearAccountId,
        intent: signingIntent,
        ...(signingCurve ? { curve: signingCurve } : {}),
      });
    } else {
      throw new Error(
        `[SigningEngine] ECDSA signing session is not ready: ${signingSessionPlan.reason}`,
      );
    }
  }
  const directAuthPlan = plannedEcdsaSigningAuthPlan ? null : await resolveDirectSigningAuthPlan();
  const signingAuthPlan = plannedEcdsaSigningAuthPlan || directAuthPlan!.signingAuthPlan;
  const activeEmailOtpAuthBridge = directAuthPlan?.emailOtpAuthBridge || emailOtpAuthBridge;
  if (signingAuthPlan.kind !== SigningAuthPlanKind.EmailOtpReauth || !activeEmailOtpAuthBridge) {
    return {
      signingAuthPlan,
      ...(plannedSigningSessionPlan ? { signingSessionPlan: plannedSigningSessionPlan } : {}),
    };
  }

  let activeChallenge: { challengeId: string; email: string } | null = null;
  const prepareChallenge = async (): Promise<{ challengeId: string; emailHint?: string }> => {
    activeChallenge = await activeEmailOtpAuthBridge.challenge();
    return {
      challengeId: activeChallenge.challengeId,
      ...(activeChallenge.email ? { emailHint: activeChallenge.email } : {}),
    };
  };
  return {
    signingAuthPlan,
    ...(plannedSigningSessionPlan ? { signingSessionPlan: plannedSigningSessionPlan } : {}),
    emailOtpSigning: {
      prepare: prepareChallenge,
      resend: async () => {
        return await prepareChallenge();
      },
      complete: async (otpCode: string, challengeId?: string) => {
        const resolvedChallengeId = String(
          challengeId || activeChallenge?.challengeId || '',
        ).trim();
        if (!resolvedChallengeId) {
          throw new Error('[SigningEngine] Email OTP challenge was not prepared before completion');
        }
        const proof = await activeEmailOtpAuthBridge.complete({
          challengeId: resolvedChallengeId,
          code: otpCode,
        });
        return proof;
      },
    },
  };

  async function resolveDirectSigningAuthPlan(): Promise<{
    signingAuthPlan: SigningAuthPlan;
    emailOtpAuthBridge?: EvmFamilyEmailOtpTransactionSigningBridge;
  }> {
    const linkedAuthMethods = Array.isArray(args.accountAuth.linkedAuthMethods)
      ? args.accountAuth.linkedAuthMethods
      : [];
    if (!linkedAuthMethods.includes(args.accountAuth.primaryAuthMethod)) {
      throw new Error(
        `[SigningEngine] primary auth method is not linked: ${String(
          args.accountAuth.primaryAuthMethod || '',
        )}`,
      );
    }
    if (args.accountAuth.primaryAuthMethod === SIGNER_AUTH_METHODS.passkey) {
      return {
        signingAuthPlan: {
          kind: SigningAuthPlanKind.PasskeyReauth,
          method: 'passkey',
        },
      };
    }
    if (args.accountAuth.primaryAuthMethod === SIGNER_AUTH_METHODS.emailOtp) {
      if (!emailOtpAuthBridge) {
        throw new Error('[SigningEngine] Email OTP transaction signing requires ECDSA lane state');
      }
      return {
        signingAuthPlan: {
          kind: SigningAuthPlanKind.EmailOtpReauth,
          method: 'email_otp',
        },
        emailOtpAuthBridge,
      };
    }
    throw new Error(
      `[SigningEngine] unsupported primary auth method: ${String(
        args.accountAuth.primaryAuthMethod || '',
      )}`,
    );
  }
}
