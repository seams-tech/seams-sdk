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
      preparedOperation: PreparedThresholdSigningOperation<
        ResolvedEvmFamilyEcdsaSigningLane,
        Record<string, unknown>
      >;
    })
  | (ResolveEvmFamilyTransactionStepUpBaseArgs & {
      senderSignatureAlgorithm: Exclude<EvmFamilySenderSignatureAlgorithm, 'secp256k1'>;
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
  const preparedEcdsaMetadata =
    args.senderSignatureAlgorithm === 'secp256k1'
      ? (args.preparedOperation.metadata as {
          selection:
            | ReadyEvmFamilyEcdsaSigningSelection
            | ReauthRequiredEvmFamilyEcdsaSigningSelection;
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
          selectedLane: preparedEcdsaLane,
          authority: emailOtpAuthority,
          onEvent: args.onEvent,
          requestEmailOtpTransactionSigningChallenge:
            confirmedEmailOtpDeps.requestEmailOtpTransactionSigningChallenge,
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
