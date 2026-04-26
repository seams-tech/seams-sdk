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
import {
  createSigningSessionPlanner,
  type SigningSessionReadiness,
} from '../../session/SigningSessionPlanner';
import {
  createSigningBoundaryTraceEvent,
  emitSigningBoundaryTrace,
  emitSigningPlannerDecisionTrace,
} from '../../session/SigningSessionTrace';
import type {
  SigningLaneContext,
  SigningSessionPlan,
} from '../../session/signingSessionTypes';
import type { WalletSigningBudgetLedger } from '../../session/WalletSigningBudgetLedger';
import {
  SigningOperationIntent,
  SigningSessionPlanKind,
} from '../../session/signingSessionTypes';
import { signingAuthPlanFromSigningSessionPlan } from '../../orchestration/shared/touchConfirmSigning';
import type {
  ThresholdEcdsaSessionRecord,
} from '../thresholdLifecycle/thresholdSessionStore';
import {
  emailOtpEcdsaAuthLaneFromRecord,
  isEmailOtpThresholdEcdsaSigningContext,
  type EvmFamilyEcdsaAuthMethod,
} from './ecdsaLanes';
import { emitEvmFamilySigningEvent } from './events';
import type {
  EvmFamilyChain,
  EvmFamilyLifecycleEventCallback,
  EvmFamilySenderSignatureAlgorithm,
} from './types';

export type EvmFamilyPreConfirmSigningDeps = {
  touchConfirm: WarmSessionStatusReader;
  getEmailOtpWarmSessionStatus?: (sessionId: string) => Promise<WarmSessionStatusResult>;
  walletSigningBudgetLedger?: WalletSigningBudgetLedger;
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
  }) => EmailOtpAuthLane | null;
  loginWithEmailOtpEcdsaCapabilityForSigning?: (args: {
    nearAccountId: string;
    chain: EvmFamilyChain;
    challengeId: string;
    otpCode: string;
    record?: ThresholdEcdsaSessionRecord;
    authLane?: EmailOtpAuthLane;
  }) => Promise<ThresholdEcdsaSecp256k1KeyRef>;
};

export type EvmFamilyConfirmedSigningDeps = EvmFamilyConfirmedEmailOtpDeps;

export type EvmFamilyTransactionWalletAuthDeps = EvmFamilyPreConfirmSigningDeps;

type ResolveEvmFamilyTransactionWalletAuthBaseArgs = {
  deps: EvmFamilyTransactionWalletAuthDeps;
  confirmedDeps: EvmFamilyConfirmedSigningDeps;
  nearAccountId: string;
  chain: EvmFamilyChain;
  accountAuth: AccountAuthMetadata;
  forceFreshAuth?: boolean;
  onEvent?: EvmFamilyLifecycleEventCallback;
};

export type ResolveEvmFamilyTransactionWalletAuthArgs =
  | (ResolveEvmFamilyTransactionWalletAuthBaseArgs & {
      senderSignatureAlgorithm: 'secp256k1';
      ecdsaSigningLane?: SigningLaneContext;
      ecdsaAuthMethod: EvmFamilyEcdsaAuthMethod;
      ecdsaWarmRecord?: ThresholdEcdsaSessionRecord;
      ecdsaWarmKeyRef?: ThresholdEcdsaSecp256k1KeyRef;
      emailOtpReauthRecord?: ThresholdEcdsaSessionRecord;
    })
  | (ResolveEvmFamilyTransactionWalletAuthBaseArgs & {
      senderSignatureAlgorithm: Exclude<EvmFamilySenderSignatureAlgorithm, 'secp256k1'>;
      ecdsaSigningLane?: never;
      ecdsaAuthMethod?: never;
      ecdsaWarmRecord?: never;
      ecdsaWarmKeyRef?: never;
      emailOtpReauthRecord?: never;
    });

async function resolveEvmFamilyEcdsaPlannerReadiness(args: {
  deps: Pick<
    EvmFamilyPreConfirmSigningDeps,
    'touchConfirm' | 'getEmailOtpWarmSessionStatus' | 'walletSigningBudgetLedger'
  >;
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
  const walletBudgetStatus = await readEvmFamilyWalletBudgetStatus({
    deps: args.deps,
    lane: args.lane,
  });
  const buildBudgetAwareReadiness = (input: {
    expiresAtMs: number;
    remainingUses: number;
  }) => {
    const budget = applyEvmFamilyWalletBudgetStatus({
      walletBudgetStatus,
      expiresAtMs: input.expiresAtMs,
      remainingUses: input.remainingUses,
    });
    return {
      readiness: {
        status: budget.status,
        ...base,
      },
      expiresAtMs: budget.expiresAtMs,
      remainingUses: budget.remainingUses,
      ...(signingRootId ? { signingRootId } : {}),
    };
  };

  if (isEmailOtpThresholdEcdsaSigningContext({ record, keyRef: args.keyRef })) {
    const emailOtpWorkerSessionId =
      record.clientAdditiveShareHandle?.kind === 'email_otp_worker_session'
        ? String(record.clientAdditiveShareHandle.sessionId || '').trim()
        : String(record.thresholdSessionId || '').trim();
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
    return buildBudgetAwareReadiness({
      expiresAtMs: Math.floor(Number(statusExpiresAtMs) || 0),
      remainingUses: Math.floor(Number(statusRemainingUses) || 0),
    });
  }

  const expiresAtMs = record.expiresAtMs;
  const remainingUses = record.remainingUses;
  return buildBudgetAwareReadiness({ expiresAtMs, remainingUses });
}

async function readEvmFamilyWalletBudgetStatus(args: {
  deps: Pick<EvmFamilyPreConfirmSigningDeps, 'walletSigningBudgetLedger'>;
  lane: SigningLaneContext;
}) {
  const walletSigningSessionId = String(args.lane.walletSigningSessionId || '').trim();
  if (!walletSigningSessionId || !args.deps.walletSigningBudgetLedger) return null;
  try {
    return await args.deps.walletSigningBudgetLedger.getAvailableStatus({
      nearAccountId: args.lane.accountId,
      walletSigningSessionId,
      ...(args.lane.backingMaterialSessionId
        ? { targetBackingMaterialSessionIds: [args.lane.backingMaterialSessionId] }
        : {}),
      ...(args.lane.thresholdSessionId
        ? { targetThresholdSessionIds: [args.lane.thresholdSessionId] }
        : {}),
    });
  } catch {
    return {
      sessionId: walletSigningSessionId,
      status: 'unavailable' as const,
    };
  }
}

function applyEvmFamilyWalletBudgetStatus(args: {
  walletBudgetStatus: Awaited<ReturnType<typeof readEvmFamilyWalletBudgetStatus>>;
  expiresAtMs: number;
  remainingUses: number;
}): {
  status: SigningSessionReadiness['status'];
  expiresAtMs: number;
  remainingUses: number;
} {
  let expiresAtMs = Math.floor(Number(args.expiresAtMs) || 0);
  let remainingUses = Math.max(0, Math.floor(Number(args.remainingUses) || 0));
  const walletBudgetStatus = args.walletBudgetStatus;
  if (walletBudgetStatus) {
    if (walletBudgetStatus.status === 'not_found') {
      return { status: 'missing_session', expiresAtMs: 0, remainingUses: 0 };
    }
    if (walletBudgetStatus.status === 'unavailable') {
      return { status: 'status_unavailable', expiresAtMs: 0, remainingUses: 0 };
    }
    if (walletBudgetStatus.status === 'expired') {
      return { status: 'expired', expiresAtMs: 0, remainingUses: 0 };
    }
    if (walletBudgetStatus.status === 'exhausted') {
      return { status: 'exhausted', expiresAtMs, remainingUses: 0 };
    }
    const budgetRemainingUses = Math.max(
      0,
      Math.floor(Number(walletBudgetStatus.remainingUses) || 0),
    );
    const budgetExpiresAtMs = Math.floor(Number(walletBudgetStatus.expiresAtMs) || 0);
    remainingUses = Math.min(remainingUses, budgetRemainingUses);
    if (budgetExpiresAtMs > 0) expiresAtMs = Math.min(expiresAtMs, budgetExpiresAtMs);
  }
  return {
    status: readinessStatusFromBudget(expiresAtMs, remainingUses),
    expiresAtMs,
    remainingUses,
  };
}

function readinessStatusFromBudget(
  expiresAtMs: unknown,
  remainingUses: unknown,
): SigningSessionReadiness['status'] {
  const normalizedExpiresAtMs = Math.floor(Number(expiresAtMs) || 0);
  const normalizedRemainingUses = Math.floor(Number(remainingUses) || 0);
  if (normalizedExpiresAtMs <= 0) return 'missing_session';
  if (normalizedExpiresAtMs <= Date.now()) return 'expired';
  if (normalizedRemainingUses <= 0) return 'exhausted';
  return 'ready';
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
  const laneWarmRecord = args.ecdsaWarmRecord;
  const laneWarmKeyRef = args.ecdsaWarmKeyRef;
  const confirmedEmailOtpDeps = args.confirmedDeps;
  const emailOtpReauthRecord =
    args.ecdsaAuthMethod === SIGNER_AUTH_METHODS.emailOtp
      ? args.emailOtpReauthRecord || args.ecdsaWarmRecord
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
      if (
        typeof confirmedEmailOtpDeps.requestEmailOtpTransactionSigningChallenge !== 'function'
      ) {
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
          lane:
            args.senderSignatureAlgorithm === 'secp256k1'
              ? args.ecdsaSigningLane
              : undefined,
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
      const authLane = emailOtpRecord
        ? confirmedEmailOtpDeps.resolveEmailOtpSigningSessionAuthLane?.({
            thresholdSessionId: emailOtpRecord.thresholdSessionId,
            curve: 'ecdsa',
            chain: args.chain,
          }) || emailOtpEcdsaAuthLaneFromRecord(emailOtpRecord, args.chain)
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
      if (
        typeof confirmedEmailOtpDeps.loginWithEmailOtpEcdsaCapabilityForSigning !== 'function'
      ) {
        throw new Error('[SigningEngine] Email OTP per-operation signing is not configured');
      }
      const authLane = emailOtpRecord
        ? confirmedEmailOtpDeps.resolveEmailOtpSigningSessionAuthLane?.({
            thresholdSessionId: emailOtpRecord.thresholdSessionId,
            curve: 'ecdsa',
            chain: args.chain,
          }) || emailOtpEcdsaAuthLaneFromRecord(emailOtpRecord, args.chain)
        : undefined;
      const refreshed = await confirmedEmailOtpDeps.loginWithEmailOtpEcdsaCapabilityForSigning({
        nearAccountId: args.nearAccountId,
        chain: args.chain,
        challengeId,
        otpCode: code,
        ...(emailOtpRecord ? { record: emailOtpRecord } : {}),
        ...(authLane ? { authLane } : {}),
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
  let emailOtpAuthBridge:
    | Awaited<ReturnType<typeof emailOtpAuthAdapter.createEmailOtpReauthPlan>>
    | null = null;
  let plannedSigningSessionPlan: SigningSessionPlan | undefined;
  if (args.senderSignatureAlgorithm === 'secp256k1') {
    const ecdsaSigningLane = args.ecdsaSigningLane;
    if (!ecdsaSigningLane) {
      if (args.ecdsaAuthMethod !== SIGNER_AUTH_METHODS.emailOtp) {
        throw new Error(
          '[SigningEngine] ECDSA signing lane is required for transaction auth planning',
        );
      }
    } else {
      const readiness = await resolveEvmFamilyEcdsaPlannerReadiness({
        deps: args.deps,
        lane: ecdsaSigningLane,
        ...(laneWarmRecord ? { record: laneWarmRecord } : {}),
        ...(laneWarmKeyRef ? { keyRef: laneWarmKeyRef } : {}),
      });
      emitSigningBoundaryTrace(
        'evm-family',
        createSigningBoundaryTraceEvent({
          event: 'pre_confirm_readiness_checked',
          lane: ecdsaSigningLane,
          readinessStatus: readiness.readiness.status,
          phase: 'pre_confirm',
        }),
      );
      const signingSessionPlan = createSigningSessionPlanner({
        onTrace: (event) => emitSigningPlannerDecisionTrace('evm-family', event),
      }).plan({
        lane: ecdsaSigningLane,
        readiness: readiness.readiness,
        forceFreshAuth: args.forceFreshAuth,
      });
      plannedSigningSessionPlan = signingSessionPlan;
      if (signingSessionPlan.kind === SigningSessionPlanKind.WarmSession) {
        plannedEcdsaSigningAuthPlan = signingAuthPlanFromSigningSessionPlan({
          plan: signingSessionPlan,
          accountId: authInput.accountId,
          intent: SigningOperationIntent.TransactionSign,
          ...(authInput.curve ? { curve: authInput.curve } : {}),
          ...(readiness.signingRootId ? { signingRootId: readiness.signingRootId } : {}),
          expiresAtMs: readiness.expiresAtMs,
          remainingUses: readiness.remainingUses,
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
    emailOtpAuthBridge?:
      Awaited<ReturnType<typeof emailOtpAuthAdapter.createEmailOtpReauthPlan>>;
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
      const directEmailOtpAuthBridge = await emailOtpAuthAdapter.createEmailOtpReauthPlan(authInput);
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
