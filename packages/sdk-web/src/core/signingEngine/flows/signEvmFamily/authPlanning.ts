import type { AccountAuthMetadata } from '@/core/signingEngine/interfaces/accountAuthMetadata';
import {
  SigningAuthPlanKind,
  type SigningAuthPlan,
} from '@/core/signingEngine/stepUpConfirmation/types';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import type { EmailOtpAuthLane } from '../../stepUpConfirmation/otpPrompt/authLane';
import type { EmailOtpEcdsaSigningBootstrapResult } from '../../interfaces/operationDeps';
import type { WarmSessionStatusReader, WarmSessionStatusResult } from '../../uiConfirm/uiConfirm.types';
import type {
  SigningSessionCoordinator,
  SigningSessionReadiness,
} from '../../session/SigningSessionCoordinator';
import {
  isSigningSessionBudgetAdmissionBlockedError,
  type SigningSessionBudgetStatusAuth,
} from '../../session/budget/budget';
import type { SigningSessionPlan } from '../../session/operationState/types';
import { SigningOperationIntent, SigningSessionPlanKind } from '../../session/operationState/types';
import { signingLaneAuthMethod } from '../../session/identity/signingLaneAuthBinding';
import type { PreparedThresholdSigningOperation } from '../../session/operationState/preparedOperation';
import { signingAuthPlanFromSigningSessionPlan } from '../shared/signingConfirmation';
import type { ThresholdEcdsaSessionRecord } from '../../session/persistence/records';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  isEmailOtpThresholdEcdsaSigningContext,
  type ResolvedEvmFamilyEcdsaSigningLane,
} from './ecdsaLanes';
import type { EvmFamilyEcdsaSessionReaderDeps } from '../../interfaces/operationDeps';
import {
  createEmailOtpEcdsaTransactionSigningBridge,
  type EvmFamilyEmailOtpTransactionSigningBridge,
} from './emailOtpSigningSession';
import {
  getEcdsaMaterialRecord,
  resolveEmailOtpEcdsaReadinessSource,
  type EcdsaMaterialState,
} from './ecdsaMaterialState';
import type {
  ReadyEvmFamilyEcdsaSigningSelection,
  ReauthRequiredEvmFamilyEcdsaSigningSelection,
} from './ecdsaSelection';
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
};

export type EvmFamilyConfirmedSigningDeps = EvmFamilyConfirmedEmailOtpDeps;

export type EvmFamilyTransactionStepUpDeps = EvmFamilyPreConfirmSigningDeps;

type ResolveEvmFamilyTransactionStepUpBaseArgs = {
  deps: EvmFamilyTransactionStepUpDeps;
  confirmedDeps: EvmFamilyConfirmedSigningDeps;
  walletSession: WalletSessionRef;
  chain: EvmFamilyChain;
  chainTarget: ThresholdEcdsaChainTarget;
  accountAuth: AccountAuthMetadata;
  onEvent?: EvmFamilyLifecycleEventCallback;
};

function assertNeverEcdsaReadinessSource(value: never): never {
  throw new Error(`[SigningEngine][ecdsa] unsupported readiness source: ${String(value)}`);
}

type EvmFamilyPlannerReadiness = {
  readiness: SigningSessionReadiness;
  expiresAtMs: number;
  remainingUses: number;
};

function buildMissingEcdsaPlannerReadiness(
  thresholdSessionId: SigningSessionReadiness['thresholdSessionId'],
): EvmFamilyPlannerReadiness {
  return {
    readiness: {
      status: 'missing_session',
      thresholdSessionId,
    },
    expiresAtMs: 0,
    remainingUses: 0,
  };
}

function buildReadyEcdsaBackingReadiness(input: {
  thresholdSessionId: SigningSessionReadiness['thresholdSessionId'];
  expiresAtMs: number;
  remainingUses: number;
}): EvmFamilyPlannerReadiness {
  const expiresAtMs = Math.floor(Number(input.expiresAtMs) || 0);
  const remainingUses = Math.floor(Number(input.remainingUses) || 0);
  return {
    readiness: {
      status: 'ready',
      thresholdSessionId: input.thresholdSessionId,
      expiresAtMs,
      remainingUses,
    },
    expiresAtMs,
    remainingUses,
  };
}

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
  deps: Pick<
    EvmFamilyPreConfirmSigningDeps,
    'touchConfirm' | 'getEmailOtpWarmSessionStatus' | 'signingSessionCoordinator'
  >;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  material: EcdsaMaterialState;
}): Promise<EvmFamilyPlannerReadiness> {
  const thresholdSessionId = args.lane.thresholdSessionId;
  const record = getEcdsaMaterialRecord(args.material);
  if (!record) {
    return buildMissingEcdsaPlannerReadiness(thresholdSessionId);
  }

  const materialIsEmailOtp = isEmailOtpThresholdEcdsaSigningContext({ record });
  if (materialIsEmailOtp) {
    const readinessSource = resolveEmailOtpEcdsaReadinessSource({
      record,
      nowMs: Date.now(),
    });
    switch (readinessSource.kind) {
      case 'persisted_record_policy':
        return buildMissingEcdsaPlannerReadiness(thresholdSessionId);
      case 'worker_session_status': {
        const status =
          typeof args.deps.getEmailOtpWarmSessionStatus === 'function'
            ? await args.deps
                .getEmailOtpWarmSessionStatus(readinessSource.workerSessionId)
                .catch(() => null)
            : null;
        const statusExpiresAtMs = status?.ok ? status.expiresAtMs : 0;
        const statusRemainingUses = status?.ok ? status.remainingUses : 0;
        return buildReadyEcdsaBackingReadiness({
          thresholdSessionId,
          expiresAtMs: Math.floor(Number(statusExpiresAtMs) || 0),
          remainingUses: Math.floor(Number(statusRemainingUses) || 0),
        });
      }
      case 'unavailable':
        return buildMissingEcdsaPlannerReadiness(thresholdSessionId);
      default:
        return assertNeverEcdsaReadinessSource(readinessSource);
    }
  }

  const trustedPasskeyReadiness = await resolvePasskeyEcdsaTrustedBudgetReadiness({
    deps: args.deps,
    lane: args.lane,
    material: args.material,
  });
  if (trustedPasskeyReadiness) return trustedPasskeyReadiness;
  if (args.material.kind !== 'ready_to_sign') {
    return buildMissingEcdsaPlannerReadiness(thresholdSessionId);
  }

  const expiresAtMs = record.expiresAtMs;
  const remainingUses = record.remainingUses;
  return buildReadyEcdsaBackingReadiness({ thresholdSessionId, expiresAtMs, remainingUses });
}

async function resolvePasskeyEcdsaTrustedBudgetReadiness(args: {
  deps: Pick<EvmFamilyPreConfirmSigningDeps, 'signingSessionCoordinator'>;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  material: EcdsaMaterialState;
}): Promise<{
  readiness: SigningSessionReadiness;
  expiresAtMs: number;
  remainingUses: number;
} | null> {
  const record = getEcdsaMaterialRecord(args.material);
  if (
    !record ||
    args.material.kind !== 'ready_to_sign' ||
    signingLaneAuthMethod(args.lane.auth) !== SIGNER_AUTH_METHODS.passkey
  ) {
    return null;
  }
  const signerSession = args.material.signerSession;
  const walletSessionJwt =
    signerSession.routerAbEcdsaHssNormalSigning.credential.walletSessionJwt;
  const trustedStatusAuth: SigningSessionBudgetStatusAuth = {
    relayerUrl: signerSession.transport.relayerUrl,
    thresholdSessionId: String(signerSession.session.thresholdSessionId),
    walletSessionJwt,
  };
  try {
    const budgetIdentity = await args.deps.signingSessionCoordinator.prepareBudgetIdentity({
      lane: args.lane,
      trustedStatusAuth,
      operationUsesNeeded: 1,
    });
    return {
      readiness: {
        status: 'ready',
        thresholdSessionId: args.lane.thresholdSessionId,
        expiresAtMs: Math.floor(Number(budgetIdentity.status.expiresAtMs) || 0),
        remainingUses: Math.floor(Number(budgetIdentity.status.remainingUses) || 0),
      },
      expiresAtMs: Math.floor(Number(budgetIdentity.status.expiresAtMs) || 0),
      remainingUses: Math.floor(Number(budgetIdentity.status.remainingUses) || 0),
    };
  } catch (error: unknown) {
    if (!isSigningSessionBudgetAdmissionBlockedError(error)) return null;
    return {
      readiness: {
        status: 'exhausted',
        thresholdSessionId: args.lane.thresholdSessionId,
        expiresAtMs: 0,
        remainingUses: 0,
      },
      expiresAtMs: 0,
      remainingUses: 0,
    };
  }
}

export async function resolveEvmFamilyTransactionStepUp(
  args: ResolveEvmFamilyTransactionStepUpArgs,
): Promise<{
  signingAuthPlan: SigningAuthPlan;
  signingSessionPlan?: SigningSessionPlan;
  emailOtpSigning?: {
    prepare: () => Promise<{ challengeId: string; emailHint?: string }>;
    resend?: () => Promise<{ challengeId: string; emailHint?: string }>;
    complete: (
      otpCode: string,
      challengeId?: string,
    ) => Promise<EmailOtpEcdsaSigningBootstrapResult>;
  };
}> {
  const walletId = toWalletId(args.walletSession.walletId);
  const preparedEcdsaMetadata =
    args.senderSignatureAlgorithm === 'secp256k1'
      ? (args.preparedOperation.metadata as {
          selection:
            | ReadyEvmFamilyEcdsaSigningSelection
            | ReauthRequiredEvmFamilyEcdsaSigningSelection;
          material: EcdsaMaterialState;
        })
      : null;
  const preparedEcdsaLane =
    args.senderSignatureAlgorithm === 'secp256k1' ? args.preparedOperation.lane : undefined;
  const preparedSelection = preparedEcdsaMetadata?.selection;
  const preparedMaterial = preparedEcdsaMetadata?.material;
  const laneWarmRecord = preparedMaterial ? getEcdsaMaterialRecord(preparedMaterial) : undefined;
  const confirmedEmailOtpDeps = args.confirmedDeps;
  const emailOtpReauthRecord =
    args.senderSignatureAlgorithm === 'secp256k1' &&
    preparedEcdsaLane &&
    signingLaneAuthMethod(preparedEcdsaLane.auth) === SIGNER_AUTH_METHODS.emailOtp
      ? preparedSelection?.kind === 'reauth_required'
        ? getEcdsaMaterialRecord(preparedSelection.material) || laneWarmRecord
        : laneWarmRecord
      : undefined;
  const emailOtpAuthBridge =
    args.senderSignatureAlgorithm === 'secp256k1'
      ? createEmailOtpEcdsaTransactionSigningBridge({
          walletId,
          walletSession: args.walletSession,
          chain: args.chain,
          chainTarget: args.chainTarget,
          selectedLane: preparedEcdsaLane,
          material: preparedMaterial,
          signingSessionRecord: emailOtpReauthRecord || null,
          reauthSource:
            preparedSelection?.kind === 'reauth_required' &&
            'reauthAnchor' in preparedSelection &&
            preparedSelection.reauthAnchor
              ? { kind: 'reauth_anchor', anchor: preparedSelection.reauthAnchor }
              : { kind: 'material' },
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
  let plannedEcdsaSigningAuthPlan: SigningAuthPlan | null = null;
  let plannedSigningSessionPlan: SigningSessionPlan | undefined;
  if (args.senderSignatureAlgorithm === 'secp256k1') {
    const preparedOperation = args.preparedOperation;
    const signingSessionPlan = preparedOperation.signingSessionPlan;
    plannedSigningSessionPlan = signingSessionPlan;
    if (signingSessionPlan.kind === SigningSessionPlanKind.NotReady) {
      throw new Error(
        `[SigningEngine] ECDSA signing session is not ready: ${signingSessionPlan.reason}`,
      );
    }
    plannedEcdsaSigningAuthPlan = signingAuthPlanFromSigningSessionPlan({
      plan: signingSessionPlan,
      accountId: walletId,
      intent: signingIntent,
      curve: 'ecdsa',
      expiresAtMs: preparedOperation.expiresAtMs,
      remainingUses: preparedOperation.remainingUses,
    });
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
