import {
  createEmailOtpWalletAuthAdapter,
  createPasskeyWalletAuthAdapter,
  type AccountAuthMetadata,
  type ResolveWalletAuthPlanInput,
} from '@/core/signingEngine/auth';
import {
  SigningAuthPlanKind,
  type SigningAuthPlan,
} from '@/core/signingEngine/touchConfirm/shared/confirmTypes';
import { SigningEventPhase } from '@/core/types/sdkSentEvents';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import type { EmailOtpAuthLane } from '../../emailOtp/authLane';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import type { WarmSessionStatusReader, WarmSessionStatusResult } from '../../touchConfirm';
import type {
  SigningSessionCoordinator,
  SigningSessionReadiness,
} from '../../session/SigningSessionCoordinator';
import { resolveEmailOtpEcdsaWorkerSessionId } from '../../session/signingSession/readiness';
import {
  createSigningBoundaryTraceEvent,
  emitSigningBoundaryTrace,
} from '../../session/signingSession/trace';
import type { SigningLaneContext, SigningSessionPlan } from '../../session/signingSession/types';
import { SigningOperationIntent, SigningSessionPlanKind } from '../../session/signingSession/types';
import type { PreparedThresholdSigningOperation } from '../../session/signingSession/preparedOperation';
import { signingAuthPlanFromSigningSessionPlan } from '../../orchestration/shared/touchConfirmSigning';
import type { ThresholdEcdsaSessionRecord } from '../thresholdLifecycle/thresholdSessionStore';
import type {
  ThresholdEcdsaChainTarget,
  WalletSubjectId,
} from '../../session/signingSession/ecdsaChainTarget';
import {
  emailOtpEcdsaAuthLaneFromRecord,
  isEmailOtpThresholdEcdsaSigningContext,
  type EvmFamilyEcdsaSessionReaderDeps,
  type ResolvedEvmFamilyEcdsaSigningLane,
} from './ecdsaLanes';
import { emitEvmFamilySigningEvent } from './events';
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

export type EvmFamilyTransactionWalletAuthDeps = EvmFamilyPreConfirmSigningDeps;

type ResolveEvmFamilyTransactionWalletAuthBaseArgs = {
  deps: EvmFamilyTransactionWalletAuthDeps;
  confirmedDeps: EvmFamilyConfirmedSigningDeps;
  nearAccountId: string;
  chain: EvmFamilyChain;
  chainId: number;
  chainTarget: ThresholdEcdsaChainTarget;
  accountAuth: AccountAuthMetadata;
  forceFreshAuth?: boolean;
  onEvent?: EvmFamilyLifecycleEventCallback;
};

export type ResolveEvmFamilyTransactionWalletAuthArgs =
  | (ResolveEvmFamilyTransactionWalletAuthBaseArgs & {
      senderSignatureAlgorithm: 'secp256k1';
      preparedOperation: PreparedThresholdSigningOperation<
        ResolvedEvmFamilyEcdsaSigningLane,
        Record<string, unknown>
      >;
    })
  | (ResolveEvmFamilyTransactionWalletAuthBaseArgs & {
      senderSignatureAlgorithm: Exclude<EvmFamilySenderSignatureAlgorithm, 'secp256k1'>;
      preparedOperation?: never;
    });

export async function resolveEvmFamilyEcdsaPlannerReadiness(args: {
  deps: Pick<EvmFamilyPreConfirmSigningDeps, 'touchConfirm' | 'getEmailOtpWarmSessionStatus'>;
  lane: SigningLaneContext;
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
    backingMaterialSessionId: args.lane.backingMaterialSessionId,
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
      ...(args.lane.backingMaterialSessionId
        ? { backingMaterialSessionId: args.lane.backingMaterialSessionId }
        : {}),
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

export async function resolveEvmFamilyTransactionWalletAuth(
  args: ResolveEvmFamilyTransactionWalletAuthArgs,
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
  const passkeyAuthAdapter = createPasskeyWalletAuthAdapter({
    challenge: async () => ({}),
    complete: async () => ({
      method: 'passkey',
      webauthnAuthentication: {},
    }),
  });
  const emailOtpAuthAdapter = createEmailOtpWalletAuthAdapter({
    challenge: async () => {
      if (typeof confirmedEmailOtpDeps.requestEmailOtpTransactionSigningChallenge !== 'function') {
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
          lane: preparedEcdsaLane,
          sideEffect: 'email_otp_challenge',
          phase: 'confirmed',
        }),
      );
      const emailOtpRecord =
        emailOtpReauthRecord ||
        (isEmailOtpThresholdEcdsaSigningContext({
          ...(laneWarmRecord ? { record: laneWarmRecord } : {}),
          ...(laneWarmKeyRef ? { keyRef: laneWarmKeyRef } : {}),
        })
          ? laneWarmRecord
          : undefined);
      const resolvedAuthLane = emailOtpRecord
        ? await confirmedEmailOtpDeps.resolveEmailOtpSigningSessionAuthLane?.({
            thresholdSessionId: emailOtpRecord.thresholdSessionId,
            curve: 'ecdsa',
            chain: args.chain,
          })
        : null;
      const authLane = emailOtpRecord
        ? resolvedAuthLane || emailOtpEcdsaAuthLaneFromRecord(emailOtpRecord)
        : undefined;
      const challenge = await confirmedEmailOtpDeps.requestEmailOtpTransactionSigningChallenge({
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
      const emailOtpRecord =
        emailOtpReauthRecord ||
        (isEmailOtpThresholdEcdsaSigningContext({
          ...(laneWarmRecord ? { record: laneWarmRecord } : {}),
          ...(laneWarmKeyRef ? { keyRef: laneWarmKeyRef } : {}),
        })
          ? laneWarmRecord
          : undefined);
      if (typeof confirmedEmailOtpDeps.loginWithEmailOtpEcdsaCapabilityForSigning !== 'function') {
        throw new Error('[SigningEngine] Email OTP per-operation signing is not configured');
      }
      const resolvedAuthLane = emailOtpRecord
        ? await confirmedEmailOtpDeps.resolveEmailOtpSigningSessionAuthLane?.({
            thresholdSessionId: emailOtpRecord.thresholdSessionId,
            curve: 'ecdsa',
            chain: args.chain,
          })
        : null;
      const authLane = emailOtpRecord
        ? resolvedAuthLane || emailOtpEcdsaAuthLaneFromRecord(emailOtpRecord)
        : undefined;
      if (!preparedEcdsaLane?.subjectId) {
        throw new Error('[SigningEngine] Email OTP ECDSA reauth requires selected subject');
      }
      const refreshed = await confirmedEmailOtpDeps.loginWithEmailOtpEcdsaCapabilityForSigning({
        nearAccountId: args.nearAccountId,
        subjectId: preparedEcdsaLane.subjectId,
        chainTarget: args.chainTarget,
        challengeId,
        otpCode: code,
        ...(emailOtpRecord ? { record: emailOtpRecord } : {}),
        ...(authLane ? { authLane } : {}),
        remainingUses: 1,
      });
      return {
        method: 'email_otp',
        emailOtpAuthentication: refreshed,
      };
    },
  });
  const authInput: ResolveWalletAuthPlanInput = {
    accountId: args.nearAccountId,
    accountAuth: args.accountAuth,
    intent: SigningOperationIntent.TransactionSign,
    curve: args.senderSignatureAlgorithm === 'secp256k1' ? 'ecdsa' : undefined,
  };
  let plannedEcdsaSigningAuthPlan: SigningAuthPlan | null = null;
  let emailOtpAuthBridge: Awaited<
    ReturnType<typeof emailOtpAuthAdapter.createEmailOtpReauthPlan>
  > | null = null;
  let plannedSigningSessionPlan: SigningSessionPlan | undefined;
  if (args.senderSignatureAlgorithm === 'secp256k1') {
    const preparedOperation = args.preparedOperation;
    const signingSessionPlan = preparedOperation.signingSessionPlan;
    plannedSigningSessionPlan = signingSessionPlan;
    if (signingSessionPlan.kind === SigningSessionPlanKind.WarmSession) {
      plannedEcdsaSigningAuthPlan = signingAuthPlanFromSigningSessionPlan({
        plan: signingSessionPlan,
        accountId: authInput.accountId,
        intent: SigningOperationIntent.TransactionSign,
        ...(authInput.curve ? { curve: authInput.curve } : {}),
        ...(preparedOperation.metadata.signingRootId
          ? { signingRootId: String(preparedOperation.metadata.signingRootId) }
          : {}),
        expiresAtMs: preparedOperation.expiresAtMs,
        remainingUses: preparedOperation.remainingUses,
      });
    } else if (signingSessionPlan.kind === SigningSessionPlanKind.EmailOtpReauth) {
      plannedEcdsaSigningAuthPlan = signingAuthPlanFromSigningSessionPlan({
        plan: signingSessionPlan,
        accountId: authInput.accountId,
        intent: SigningOperationIntent.TransactionSign,
        ...(authInput.curve ? { curve: authInput.curve } : {}),
      });
      emailOtpAuthBridge = await emailOtpAuthAdapter.createEmailOtpReauthPlan(authInput);
    } else if (signingSessionPlan.kind === SigningSessionPlanKind.PasskeyReauth) {
      plannedEcdsaSigningAuthPlan = signingAuthPlanFromSigningSessionPlan({
        plan: signingSessionPlan,
        accountId: authInput.accountId,
        intent: SigningOperationIntent.TransactionSign,
        ...(authInput.curve ? { curve: authInput.curve } : {}),
      });
      await passkeyAuthAdapter.createPasskeyReauthPlan(authInput);
    } else {
      throw new Error(
        `[SigningEngine] ECDSA signing session is not ready: ${signingSessionPlan.reason}`,
      );
    }
  }
  const directAuthPlan = plannedEcdsaSigningAuthPlan ? null : await resolveDirectSigningAuthPlan();
  const signingAuthPlan = plannedEcdsaSigningAuthPlan || directAuthPlan!.signingAuthPlan;
  emailOtpAuthBridge = emailOtpAuthBridge || directAuthPlan?.emailOtpAuthBridge || null;
  if (signingAuthPlan.kind !== SigningAuthPlanKind.EmailOtpReauth || !emailOtpAuthBridge) {
    return {
      signingAuthPlan,
      ...(plannedSigningSessionPlan ? { signingSessionPlan: plannedSigningSessionPlan } : {}),
    };
  }

  const activeEmailOtpAuthBridge = emailOtpAuthBridge;
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
        return proof.emailOtpAuthentication as ThresholdEcdsaSecp256k1KeyRef;
      },
    },
  };

  async function resolveDirectSigningAuthPlan(): Promise<{
    signingAuthPlan: SigningAuthPlan;
    emailOtpAuthBridge?: Awaited<ReturnType<typeof emailOtpAuthAdapter.createEmailOtpReauthPlan>>;
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
      await passkeyAuthAdapter.createPasskeyReauthPlan(authInput);
      return {
        signingAuthPlan: {
          kind: SigningAuthPlanKind.PasskeyReauth,
          method: 'passkey',
        },
      };
    }
    if (args.accountAuth.primaryAuthMethod === SIGNER_AUTH_METHODS.emailOtp) {
      const directEmailOtpAuthBridge =
        await emailOtpAuthAdapter.createEmailOtpReauthPlan(authInput);
      return {
        signingAuthPlan: {
          kind: SigningAuthPlanKind.EmailOtpReauth,
          method: 'email_otp',
        },
        emailOtpAuthBridge: directEmailOtpAuthBridge,
      };
    }
    throw new Error(
      `[SigningEngine] unsupported primary auth method: ${String(
        args.accountAuth.primaryAuthMethod || '',
      )}`,
    );
  }
}
