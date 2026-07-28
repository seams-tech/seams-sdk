import type { AccountAuthMetadata } from '@/core/signingEngine/interfaces/accountAuthMetadata';
import {
  SigningAuthPlanKind,
  type SigningAuthPlan,
} from '@/core/signingEngine/stepUpConfirmation/types';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import type { EmailOtpSigningSessionAuthLane } from '../../stepUpConfirmation/otpPrompt/authLane';
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
import type { ResolvedEvmFamilyEcdsaSigningLane } from './ecdsaLanes';
import type { EvmFamilyEcdsaSessionReaderDeps } from '../../interfaces/operationDeps';
import type { EmailOtpTransactionSigningChallenge } from '../../session/emailOtp/publicTypes';
import {
  createEmailOtpEcdsaTransactionSigningBridge,
  type EmailOtpEcdsaStepUpAuthority,
  type EvmFamilyEmailOtpTransactionSigningBridge,
} from './emailOtpSigningSession';
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

export type EvmFamilyPreConfirmSigningDeps = EvmFamilyEcdsaSessionReaderDeps;
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
  }) => Promise<EmailOtpTransactionSigningChallenge>;
};

function emailOtpStepUpAuthority(
  selection: Extract<
    ReadyEvmFamilyEcdsaSigningSelection | ReauthRequiredEvmFamilyEcdsaSigningSelection,
    { authMethod: 'email_otp' }
  >,
): EmailOtpEcdsaStepUpAuthority {
  if (selection.kind === 'ready') {
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

export type ResolveEvmFamilyTransactionStepUpArgs =
  | (ResolveEvmFamilyTransactionStepUpBaseArgs & {
      senderSignatureAlgorithm: 'secp256k1';
      ecdsaAuthorization: 'reusable_wallet_session';
      preparedOperation: PreparedThresholdSigningOperation<
        ResolvedEvmFamilyEcdsaSigningLane,
        Record<string, unknown>
      >;
    })
  // Auth-neutral ECDSA material: the reusable-session planner never ran, so
  // there is no prepared threshold operation and no signing session plan to
  // derive a warm-session plan from. The operation is authorized directly on
  // the capability's own factor.
  | (ResolveEvmFamilyTransactionStepUpBaseArgs & {
      senderSignatureAlgorithm: 'secp256k1';
      ecdsaAuthorization: 'operation_step_up';
      preparedOperation?: never;
    })
  | (ResolveEvmFamilyTransactionStepUpBaseArgs & {
      senderSignatureAlgorithm: Exclude<EvmFamilySenderSignatureAlgorithm, 'secp256k1'>;
      ecdsaAuthorization?: never;
      preparedOperation?: never;
    });

export async function resolveEvmFamilyTransactionStepUp(
  args: ResolveEvmFamilyTransactionStepUpArgs,
): Promise<{
  signingAuthPlan: SigningAuthPlan;
  signingSessionPlan?: SigningSessionPlan;
  emailOtpSigning?: {
    prepare: () => Promise<{ challengeId: string; emailHint?: string }>;
    resend?: () => Promise<{ challengeId: string; emailHint?: string }>;
  };
}> {
  const walletId = toWalletId(args.walletSession.walletId);
  // Only a reusable-session preparation carries a threshold operation. Every
  // warm-session fact below is derived from it, so an auth-neutral operation
  // simply has none of them.
  const reusableSessionEcdsaOperation =
    args.senderSignatureAlgorithm === 'secp256k1' &&
    args.ecdsaAuthorization === 'reusable_wallet_session'
      ? args.preparedOperation
      : null;
  const preparedEcdsaMetadata = reusableSessionEcdsaOperation
    ? (reusableSessionEcdsaOperation.metadata as {
        selection:
          | ReadyEvmFamilyEcdsaSigningSelection
          | ReauthRequiredEvmFamilyEcdsaSigningSelection;
      })
    : null;
  const preparedEcdsaLane = reusableSessionEcdsaOperation?.lane;
  const preparedSelection = preparedEcdsaMetadata?.selection;
  const confirmedEmailOtpDeps = args.confirmedDeps;
  const emailOtpAuthority =
    preparedEcdsaLane &&
    signingLaneAuthMethod(preparedEcdsaLane.auth) === SIGNER_AUTH_METHODS.emailOtp &&
    preparedSelection?.authMethod === SIGNER_AUTH_METHODS.emailOtp
      ? emailOtpStepUpAuthority(preparedSelection)
      : undefined;
  const emailOtpAuthBridge = emailOtpAuthority
    ? createEmailOtpEcdsaTransactionSigningBridge({
        walletId,
        walletSession: args.walletSession,
        chain: args.chain,
        ...(preparedEcdsaLane ? { selectedLane: preparedEcdsaLane } : {}),
        authority: emailOtpAuthority,
        onEvent: args.onEvent,
        requestEmailOtpTransactionSigningChallenge:
          confirmedEmailOtpDeps.requestEmailOtpTransactionSigningChallenge,
      })
    : null;
  const signingIntent = SigningOperationIntent.TransactionSign;
  let plannedEcdsaSigningAuthPlan: SigningAuthPlan | null = null;
  let plannedSigningSessionPlan: SigningSessionPlan | undefined;
  if (reusableSessionEcdsaOperation) {
    const preparedOperation = reusableSessionEcdsaOperation;
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

  const prepareChallenge = async (): Promise<{ challengeId: string; emailHint?: string }> => {
    const activeChallenge = await activeEmailOtpAuthBridge.challenge();
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
        if (args.ecdsaAuthorization === 'operation_step_up') {
          // The Email OTP challenge is still requested through a warm-session
          // or public-reauth authority, neither of which an auth-neutral
          // candidate has. Passkey material reaches operation step-up; Email
          // OTP material needs a capability-bound challenge authority first.
          throw new Error(
            '[SigningEngine] Email OTP operation step-up requires a capability-bound challenge authority',
          );
        }
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
