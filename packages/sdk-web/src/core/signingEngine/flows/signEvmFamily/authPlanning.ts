import type { AccountAuthMetadata } from '@/core/signingEngine/interfaces/accountAuthMetadata';
import {
  SigningAuthPlanKind,
  type SigningAuthPlan,
} from '@/core/signingEngine/stepUpConfirmation/types';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import type { EmailOtpSigningSessionAuthLane } from '../../stepUpConfirmation/otpPrompt/authLane';
import type { EmailOtpEcdsaSigningBootstrapResult } from '../../interfaces/operationDeps';
import type {
  WarmSessionStatusReader,
  WarmSessionStatusResult,
} from '../../uiConfirm/uiConfirm.types';
import type {
  SigningSessionCoordinator,
  SigningSessionReadiness,
} from '../../session/SigningSessionCoordinator';
import type { SigningSessionBudgetStatusAuth } from '../../session/budget/budget';
import {
  decideSigningGrantAdmissionError,
  waitForSigningGrantAdmissionRetry,
} from '../../session/budget/admission';
import {
  normalizeStepUpOperationId,
  resolvePostExhaustionStepUpBudgetPolicy,
  resolveSigningBudgetPolicyRemainingUses,
} from '../../session/budget/policy';
import type { SigningSessionPlan } from '../../session/operationState/types';
import { SigningOperationIntent, SigningSessionPlanKind } from '../../session/operationState/types';
import { signingLaneAuthMethod } from '../../session/identity/signingLaneAuthBinding';
import type { PreparedThresholdSigningOperation } from '../../session/operationState/preparedOperation';
import { signingAuthPlanFromSigningSessionPlan } from '../shared/signingConfirmation';
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
  type EmailOtpEcdsaStepUpAuthority,
  type EvmFamilyEmailOtpTransactionSigningBridge,
} from './emailOtpSigningSession';
import {
  getEcdsaMaterialRecord,
  resolveEmailOtpEcdsaReadinessSource,
  type EcdsaMaterialState,
  type ReadyEcdsaMaterial,
} from './ecdsaMaterialState';
import type {
  EmailOtpEcdsaCommittedLane,
  EmailOtpEcdsaPublicReauthLane,
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
    authority:
      | {
          kind: 'live_session';
          authLane: Extract<EmailOtpSigningSessionAuthLane, { curve: 'ecdsa' }>;
          reauthLane?: never;
        }
      | {
          kind: 'public_reauth_anchor';
          reauthLane: EmailOtpEcdsaPublicReauthLane;
          authLane?: never;
        };
  }) => Promise<{ challengeId: string; emailHint?: string }>;
  loginWithEmailOtpEcdsaCapabilityForSigning?: (args: {
    walletSession: WalletSessionRef;
    subjectId?: never;
    chainTarget: ThresholdEcdsaChainTarget;
    challengeId: string;
    otpCode: string;
    authority: EmailOtpEcdsaStepUpAuthority;
    remainingUses: number;
  }) => Promise<EmailOtpEcdsaSigningBootstrapResult>;
};

function emailOtpStepUpAuthority(
  selection: Extract<
    ReadyEvmFamilyEcdsaSigningSelection | ReauthRequiredEvmFamilyEcdsaSigningSelection,
    { authMethod: 'email_otp' }
  >,
): EmailOtpEcdsaStepUpAuthority {
  if (selection.kind === 'ready' || selection.reason === 'missing_hot_material') {
    return { kind: 'live_session', committedLane: selection.committedLane };
  }
  return { kind: 'public_reauth_anchor', reauthLane: selection.reauthLane };
}

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

type BaseEvmFamilyPlannerReadiness = {
  readiness: SigningSessionReadiness;
  expiresAtMs: number;
  remainingUses: number;
};

export type EvmFamilyPlannerReadiness =
  | (BaseEvmFamilyPlannerReadiness & {
      trustedBudgetStatusAuth: {
        kind: 'trusted_budget_status_auth';
        auth: SigningSessionBudgetStatusAuth;
      };
    })
  | (BaseEvmFamilyPlannerReadiness & {
      trustedBudgetStatusAuth: {
        kind: 'no_trusted_budget_status_auth';
      };
    });

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
    trustedBudgetStatusAuth: {
      kind: 'no_trusted_budget_status_auth',
    },
  };
}

function buildReadyEcdsaBackingReadiness(input: {
  thresholdSessionId: SigningSessionReadiness['thresholdSessionId'];
  expiresAtMs: number;
  remainingUses: number;
  trustedStatusAuth?: SigningSessionBudgetStatusAuth;
}): EvmFamilyPlannerReadiness {
  const expiresAtMs = Math.floor(Number(input.expiresAtMs) || 0);
  const remainingUses = Math.floor(Number(input.remainingUses) || 0);
  if (input.trustedStatusAuth) {
    return {
      readiness: {
        status: 'ready',
        thresholdSessionId: input.thresholdSessionId,
        expiresAtMs,
        remainingUses,
      },
      expiresAtMs,
      remainingUses,
      trustedBudgetStatusAuth: {
        kind: 'trusted_budget_status_auth',
        auth: input.trustedStatusAuth,
      },
    };
  }
  return {
    readiness: {
      status: 'ready',
      thresholdSessionId: input.thresholdSessionId,
      expiresAtMs,
      remainingUses,
    },
    expiresAtMs,
    remainingUses,
    trustedBudgetStatusAuth: {
      kind: 'no_trusted_budget_status_auth',
    },
  };
}

function resolveEvmFamilyEmailOtpStepUpRemainingUses(
  operation: PreparedThresholdSigningOperation['operation'],
): number {
  const policy = resolvePostExhaustionStepUpBudgetPolicy({
    operationId: normalizeStepUpOperationId(
      operation?.operationId || 'evm-family-email-otp-post-exhaustion-step-up',
    ),
    requiredSignatureUses: 1,
  });
  return resolveSigningBudgetPolicyRemainingUses(policy);
}

function trustedBudgetStatusAuthFromReadyEcdsaMaterial(
  material: ReadyEcdsaMaterial,
): SigningSessionBudgetStatusAuth {
  const signerSession = material.signerSession;
  const walletSessionJwt = signerSession.routerAbEcdsaDerivationNormalSigning.credential.walletSessionJwt;
  return {
    relayerUrl: signerSession.transport.relayerUrl,
    thresholdSessionId: String(signerSession.session.thresholdSessionId),
    walletSessionJwt,
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
        if (args.material.kind === 'ready_to_sign') {
          return buildReadyEcdsaBackingReadiness({
            thresholdSessionId,
            expiresAtMs: readinessSource.expiresAtMs,
            remainingUses: readinessSource.remainingUses,
            trustedStatusAuth: trustedBudgetStatusAuthFromReadyEcdsaMaterial(args.material),
          });
        }
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
          ...(args.material.kind === 'ready_to_sign'
            ? { trustedStatusAuth: trustedBudgetStatusAuthFromReadyEcdsaMaterial(args.material) }
            : {}),
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
  trustedBudgetStatusAuth: {
    kind: 'trusted_budget_status_auth';
    auth: SigningSessionBudgetStatusAuth;
  };
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
  const walletSessionJwt = signerSession.routerAbEcdsaDerivationNormalSigning.credential.walletSessionJwt;
  const trustedStatusAuth: SigningSessionBudgetStatusAuth = {
    relayerUrl: signerSession.transport.relayerUrl,
    thresholdSessionId: String(signerSession.session.thresholdSessionId),
    walletSessionJwt,
  };
  return await resolvePasskeyEcdsaTrustedBudgetReadinessFromAuth({
    ...args,
    trustedStatusAuth,
    inFlightRetry: 'available',
  });
}

export async function resolvePasskeyEcdsaTrustedBudgetReadinessFromAuth(args: {
  deps: Pick<EvmFamilyPreConfirmSigningDeps, 'signingSessionCoordinator'>;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  trustedStatusAuth: SigningSessionBudgetStatusAuth;
  inFlightRetry: 'available' | 'spent';
}): Promise<{
  readiness: SigningSessionReadiness;
  expiresAtMs: number;
  remainingUses: number;
  trustedBudgetStatusAuth: {
    kind: 'trusted_budget_status_auth';
    auth: SigningSessionBudgetStatusAuth;
  };
}> {
  try {
    const budgetIdentity = await args.deps.signingSessionCoordinator.prepareBudgetIdentity({
      lane: args.lane,
      trustedStatusAuth: args.trustedStatusAuth,
      operationUsesNeeded: 1,
    });
    const expiresAtMs = Math.floor(Number(budgetIdentity.status.expiresAtMs) || 0);
    const remainingUses = Math.floor(Number(budgetIdentity.status.remainingUses) || 0);
    const readiness: SigningSessionReadiness =
      remainingUses <= 0
        ? {
            status: 'exhausted',
            thresholdSessionId: args.lane.thresholdSessionId,
            expiresAtMs,
            remainingUses: 0,
          }
        : expiresAtMs <= Date.now()
          ? {
              status: 'expired',
              thresholdSessionId: args.lane.thresholdSessionId,
              expiresAtMs,
            }
          : {
              status: 'ready',
              thresholdSessionId: args.lane.thresholdSessionId,
              expiresAtMs,
              remainingUses,
            };
    return {
      readiness,
      expiresAtMs,
      remainingUses,
      trustedBudgetStatusAuth: {
        kind: 'trusted_budget_status_auth',
        auth: args.trustedStatusAuth,
      },
    };
  } catch (error: unknown) {
    const admissionDecision = decideSigningGrantAdmissionError(error);
    if (!admissionDecision) {
      return {
        readiness: {
          status: 'missing_session',
          thresholdSessionId: args.lane.thresholdSessionId,
        },
        expiresAtMs: 0,
        remainingUses: 0,
        trustedBudgetStatusAuth: {
          kind: 'trusted_budget_status_auth',
          auth: args.trustedStatusAuth,
        },
      };
    }
    if (
      admissionDecision.kind === 'wait_and_retry_admission' &&
      args.inFlightRetry === 'available'
    ) {
      await waitForSigningGrantAdmissionRetry(admissionDecision.retryAfterMs);
      return await resolvePasskeyEcdsaTrustedBudgetReadinessFromAuth({
        ...args,
        inFlightRetry: 'spent',
      });
    }
    if (admissionDecision.kind === 'wait_and_retry_admission') {
      return {
        readiness: {
          status: 'missing_session',
          thresholdSessionId: args.lane.thresholdSessionId,
        },
        expiresAtMs: 0,
        remainingUses: 0,
        trustedBudgetStatusAuth: {
          kind: 'trusted_budget_status_auth',
          auth: args.trustedStatusAuth,
        },
      };
    }
    return {
      readiness: {
        status: 'exhausted',
        thresholdSessionId: args.lane.thresholdSessionId,
        expiresAtMs: 0,
        remainingUses: 0,
      },
      expiresAtMs: 0,
      remainingUses: 0,
      trustedBudgetStatusAuth: {
        kind: 'trusted_budget_status_auth',
        auth: args.trustedStatusAuth,
      },
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
  const confirmedEmailOtpDeps = args.confirmedDeps;
  const emailOtpAuthority =
    args.senderSignatureAlgorithm === 'secp256k1' &&
    preparedEcdsaLane &&
    signingLaneAuthMethod(preparedEcdsaLane.auth) === SIGNER_AUTH_METHODS.emailOtp &&
    preparedSelection?.authMethod === SIGNER_AUTH_METHODS.emailOtp
      ? emailOtpStepUpAuthority(preparedSelection)
      : undefined;
  const emailOtpAuthBridge =
    args.senderSignatureAlgorithm === 'secp256k1' && emailOtpAuthority
      ? createEmailOtpEcdsaTransactionSigningBridge({
          walletId,
          walletSession: args.walletSession,
          chain: args.chain,
          chainTarget: args.chainTarget,
          selectedLane: preparedEcdsaLane,
          authority: emailOtpAuthority,
          onEvent: args.onEvent,
          requestEmailOtpTransactionSigningChallenge:
            confirmedEmailOtpDeps.requestEmailOtpTransactionSigningChallenge,
          loginWithEmailOtpEcdsaCapabilityForSigning:
            confirmedEmailOtpDeps.loginWithEmailOtpEcdsaCapabilityForSigning,
          remainingUses: resolveEvmFamilyEmailOtpStepUpRemainingUses(
            args.preparedOperation.operation,
          ),
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
      accountId: String(walletId),
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
