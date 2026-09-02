import type { AccountAuthMetadata } from '@/core/signingEngine/interfaces/accountAuthMetadata';
import {
  SigningAuthPlanKind,
  type SigningAuthPlan,
} from '@/core/signingEngine/stepUpConfirmation/types';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import type { SigningSessionPlan } from '../../session/operationState/types';
import { SigningOperationIntent, SigningSessionPlanKind } from '../../session/operationState/types';
import { signingLaneAuthMethod } from '../../session/identity/signingLaneAuthBinding';
import type { PreparedThresholdSigningOperation } from '../../session/operationState/preparedOperation';
import { signingAuthPlanFromSigningSessionPlan } from '../shared/signingConfirmation';
import type {
  ThresholdEcdsaChainTarget,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ResolvedEvmFamilyEcdsaSigningLane } from './ecdsaLanes';
import type { EmailOtpTransactionSigningChallenge } from '../../session/emailOtp/publicTypes';
import {
  createEmailOtpEcdsaTransactionSigningBridge,
  emailOtpEcdsaCapabilityStepUpAuthority,
  type EmailOtpEcdsaChallengeAuthority,
  type EmailOtpEcdsaStepUpAuthority,
  type EvmFamilyEmailOtpTransactionSigningBridge,
} from './emailOtpSigningSession';
import {
  isEmailOtpWalletAuthAuthority,
  isPasskeyWalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';
import type { CanonicalEvmFamilyEcdsaSigningCapability } from '../../session/material/ecdsaSigningCapability';
import type {
  EcdsaCommittedLane,
  EmailOtpEcdsaCommittedLane,
  ReadyEvmFamilyEcdsaSigningSelection,
} from './ecdsaSelection';
import type {
  EvmFamilyChain,
  EvmFamilyLifecycleEventCallback,
  EvmFamilySenderSignatureAlgorithm,
} from './types';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';

export type EvmFamilyConfirmedEmailOtpDeps = {
  requestEmailOtpTransactionSigningChallenge?: (args: {
    walletSession: WalletSessionRef;
    chain: EvmFamilyChain;
    authority: EmailOtpEcdsaChallengeAuthority;
    operationFingerprintDigest: DigestB64u;
  }) => Promise<EmailOtpTransactionSigningChallenge>;
};

function isEmailOtpEcdsaCommittedLane(
  committedLane: EcdsaCommittedLane,
): committedLane is EmailOtpEcdsaCommittedLane {
  return isEmailOtpWalletAuthAuthority(committedLane.authority);
}

function emailOtpStepUpAuthority(args: {
  selection: ReadyEvmFamilyEcdsaSigningSelection;
  operationFingerprintDigest: DigestB64u;
}): EmailOtpEcdsaStepUpAuthority {
  const committedLane = args.selection.committedLane;
  if (!isEmailOtpEcdsaCommittedLane(committedLane)) {
    throw new Error('[SigningEngine][ecdsa] Email OTP step-up requires Email OTP authority');
  }
  if (committedLane.authLane) {
    return { kind: 'live_session', committedLane };
  }
  return {
    kind: 'capability_step_up',
    capabilityAuthority: committedLane.authority,
    materialActivation: committedLane.authorization.runtime.materialActivation,
    operationFingerprint: `sha256:${String(args.operationFingerprintDigest)}`,
  };
}

function emailOtpStepUpAuthorityForSelection(args: {
  selection: ReadyEvmFamilyEcdsaSigningSelection | undefined;
  operationFingerprintDigest: DigestB64u;
}): EmailOtpEcdsaStepUpAuthority | undefined {
  if (!args.selection) return undefined;
  return isEmailOtpWalletAuthAuthority(args.selection.committedLane.authority)
    ? emailOtpStepUpAuthority({
        selection: args.selection,
        operationFingerprintDigest: args.operationFingerprintDigest,
      })
    : undefined;
}

type ResolveEvmFamilyTransactionStepUpBaseArgs = {
  confirmedDeps: EvmFamilyConfirmedEmailOtpDeps;
  walletSession: WalletSessionRef;
  chain: EvmFamilyChain;
  chainTarget: ThresholdEcdsaChainTarget;
  accountAuth: AccountAuthMetadata;
  operationFingerprintDigest: DigestB64u;
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
  // the capability's own factor, which is why the capability itself is
  // required here -- it is the authority an Email OTP challenge is minted for.
  | (ResolveEvmFamilyTransactionStepUpBaseArgs & {
      senderSignatureAlgorithm: 'secp256k1';
      ecdsaAuthorization: 'operation_step_up';
      preparedOperation?: never;
      capability: CanonicalEvmFamilyEcdsaSigningCapability;
      materialActivation: MpcMaterialActivationRef;
      operationFingerprint: string;
    })
  | (ResolveEvmFamilyTransactionStepUpBaseArgs & {
      senderSignatureAlgorithm: Exclude<EvmFamilySenderSignatureAlgorithm, 'secp256k1'>;
      ecdsaAuthorization?: never;
      preparedOperation?: never;
      capability?: never;
      materialActivation?: never;
      operationFingerprint?: never;
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
        selection: ReadyEvmFamilyEcdsaSigningSelection;
      })
    : null;
  const preparedEcdsaLane = reusableSessionEcdsaOperation?.lane;
  const preparedSelection = preparedEcdsaMetadata?.selection;
  const confirmedEmailOtpDeps = args.confirmedDeps;
  // Auth-neutral material has no lane and no selection to read an authority
  // from. The capability is the authority, and it is validated against the
  // exact material activation before any challenge is minted.
  const capabilityStepUpAuthority =
    args.ecdsaAuthorization === 'operation_step_up' &&
    isEmailOtpWalletAuthAuthority(args.capability.authority)
      ? emailOtpEcdsaCapabilityStepUpAuthority({
          capability: args.capability,
          materialActivation: args.materialActivation,
          operationFingerprint: args.operationFingerprint,
        })
      : undefined;
  const emailOtpAuthority =
    capabilityStepUpAuthority ??
    (preparedEcdsaLane &&
    signingLaneAuthMethod(preparedEcdsaLane.auth) === SIGNER_AUTH_METHODS.emailOtp
      ? emailOtpStepUpAuthorityForSelection({
          selection: preparedSelection,
          operationFingerprintDigest: args.operationFingerprintDigest,
        })
      : undefined);
  const emailOtpAuthBridge = emailOtpAuthority
    ? createEmailOtpEcdsaTransactionSigningBridge({
        walletId,
        walletSession: args.walletSession,
        chain: args.chain,
        ...(preparedEcdsaLane ? { selectedLane: preparedEcdsaLane } : {}),
        authority: emailOtpAuthority,
        operationFingerprintDigest: args.operationFingerprintDigest,
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
    if (args.ecdsaAuthorization === 'operation_step_up') {
      if (isPasskeyWalletAuthAuthority(args.capability.authority)) {
        return {
          signingAuthPlan: {
            kind: SigningAuthPlanKind.PasskeyReauth,
            method: 'passkey',
          },
        };
      }
      if (isEmailOtpWalletAuthAuthority(args.capability.authority)) {
        if (!emailOtpAuthBridge) {
          throw new Error(
            '[SigningEngine] Email OTP step-up authority is unavailable for the selected capability',
          );
        }
        return {
          signingAuthPlan: {
            kind: SigningAuthPlanKind.EmailOtpReauth,
            method: 'email_otp',
          },
          emailOtpAuthBridge,
        };
      }
      args.capability.authority satisfies never;
    }
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
