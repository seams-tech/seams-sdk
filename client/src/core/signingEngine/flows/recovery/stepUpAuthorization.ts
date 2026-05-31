import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  SigningAuthPlanKind,
  type EmailOtpConfirmPrompt,
  type EmailOtpStepUpAuthorization,
  type PasskeyStepUpAuthorization,
  type SigningAuthPlan,
  type UserConfirmDecision,
} from '@/core/signingEngine/stepUpConfirmation/types';
import { normalizeAuthenticationCredential } from '@/core/signingEngine/webauthnAuth/credentials/helpers';
import type { WalletAuthCurve, WalletAuthIntent } from '@/core/types/seams';

type ExportIntent = Extract<WalletAuthIntent, 'ed25519_export' | 'ecdsa_export'>;
type ExportChain = 'near' | ThresholdEcdsaChainTarget['kind'];

type NearExportAuthorizationIdentity = {
  nearAccountId: AccountId;
  walletSessionUserId?: never;
  publicKey: string;
  curve: 'ed25519';
  intent: 'ed25519_export';
  chain: 'near';
};

type EcdsaExportAuthorizationIdentity = {
  walletSessionUserId: string;
  publicKey: string;
  curve: 'ecdsa';
  intent: 'ecdsa_export';
  chain: ThresholdEcdsaChainTarget['kind'];
};

type ExportAuthorizationIdentity =
  | NearExportAuthorizationIdentity
  | EcdsaExportAuthorizationIdentity;

export type ExportPasskeyStepUpAuthorization =
  | (PasskeyStepUpAuthorization<
      Extract<SigningAuthPlan, { kind: typeof SigningAuthPlanKind.PasskeyReauth }>,
      NearExportAuthorizationIdentity
    > &
      NearExportAuthorizationIdentity)
  | (PasskeyStepUpAuthorization<
      Extract<SigningAuthPlan, { kind: typeof SigningAuthPlanKind.PasskeyReauth }>,
      EcdsaExportAuthorizationIdentity
    > &
      EcdsaExportAuthorizationIdentity);

export type ExportEmailOtpStepUpAuthorization =
  | (EmailOtpStepUpAuthorization<
      Extract<SigningAuthPlan, { kind: typeof SigningAuthPlanKind.EmailOtpReauth }>,
      NearExportAuthorizationIdentity
    > &
      NearExportAuthorizationIdentity)
  | (EmailOtpStepUpAuthorization<
      Extract<SigningAuthPlan, { kind: typeof SigningAuthPlanKind.EmailOtpReauth }>,
      EcdsaExportAuthorizationIdentity
    > &
      EcdsaExportAuthorizationIdentity);

export type ExportStepUpAuthorization =
  | ExportPasskeyStepUpAuthorization
  | ExportEmailOtpStepUpAuthorization;

export function buildExportStepUpAuthorization(
  args:
    | ({
        method: 'passkey';
        decision: UserConfirmDecision;
      } & NearExportAuthorizationIdentity)
    | ({
        method: 'passkey';
        decision: UserConfirmDecision;
      } & EcdsaExportAuthorizationIdentity),
): ExportPasskeyStepUpAuthorization;
export function buildExportStepUpAuthorization(
  args:
    | ({
        method: 'email_otp';
        decision: Pick<
          UserConfirmDecision,
          'confirmed' | 'error' | 'otpCode' | 'emailOtpChallengeId'
        >;
        emailOtpPrompt: EmailOtpConfirmPrompt;
      } & NearExportAuthorizationIdentity)
    | ({
        method: 'email_otp';
        decision: Pick<
          UserConfirmDecision,
          'confirmed' | 'error' | 'otpCode' | 'emailOtpChallengeId'
        >;
        emailOtpPrompt: EmailOtpConfirmPrompt;
      } & EcdsaExportAuthorizationIdentity),
): ExportEmailOtpStepUpAuthorization;
export function buildExportStepUpAuthorization(
  args:
    | ({
        method: 'passkey';
        decision: UserConfirmDecision;
      } & ExportAuthorizationIdentity)
    | ({
        method: 'email_otp';
        decision: Pick<
          UserConfirmDecision,
          'confirmed' | 'error' | 'otpCode' | 'emailOtpChallengeId'
        >;
        emailOtpPrompt: EmailOtpConfirmPrompt;
      } & ExportAuthorizationIdentity),
): ExportStepUpAuthorization {
  const publicKey = String(args.publicKey || '').trim();
  if (!publicKey) {
    throw new Error('[SigningEngine][export] missing export step-up authorization public key');
  }

  const identity =
    args.curve === 'ecdsa'
      ? {
          walletSessionUserId: String(args.walletSessionUserId || '').trim(),
          publicKey,
          curve: 'ecdsa' as const,
          intent: 'ecdsa_export' as const,
          chain: args.chain,
        }
      : {
          nearAccountId: toAccountId(args.nearAccountId),
          publicKey,
          curve: 'ed25519' as const,
          intent: 'ed25519_export' as const,
          chain: 'near' as const,
        };
  if (
    (identity.curve === 'ecdsa' && !identity.walletSessionUserId) ||
    (identity.curve === 'ed25519' && !identity.nearAccountId)
  ) {
    throw new Error('[SigningEngine][export] missing export step-up authorization identity');
  }

  if (args.method === 'email_otp') {
    if (!args.decision.confirmed) {
      throw new Error(args.decision.error || 'User cancelled Email OTP export request');
    }
    const otpCode = String(args.decision.otpCode || '')
      .replace(/\D/g, '')
      .slice(0, 6);
    if (otpCode.length !== 6) {
      throw new Error('Email OTP export requires a 6-digit code');
    }
    const challengeId = String(
      args.decision.emailOtpChallengeId || args.emailOtpPrompt.challengeId || '',
    ).trim();
    if (!challengeId) {
      throw new Error('Email OTP export challenge response did not include challengeId');
    }
    return {
      kind: 'email_otp',
      signingAuthPlan: {
        kind: SigningAuthPlanKind.EmailOtpReauth,
        method: 'email_otp',
        emailOtpPrompt: args.emailOtpPrompt,
      },
      challengeId,
      otpCode,
      ...identity,
      ...(args.emailOtpPrompt.emailHint ? { emailHint: args.emailOtpPrompt.emailHint } : {}),
    };
  }

  if (!args.decision.confirmed) {
    throw new Error(args.decision.error || 'User cancelled export request');
  }
  if (!args.decision.credential) {
    throw new Error('[SigningEngine][export] missing WebAuthn credential for export authorization');
  }
  return {
    kind: 'passkey',
    signingAuthPlan: {
      kind: SigningAuthPlanKind.PasskeyReauth,
      method: 'passkey',
    },
    credential: normalizeAuthenticationCredential(args.decision.credential),
    ...identity,
  };
}
