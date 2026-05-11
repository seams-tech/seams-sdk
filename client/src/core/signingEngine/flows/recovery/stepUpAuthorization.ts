import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { UserConfirmDecision } from '@/core/signingEngine/stepUpConfirmation/channel/confirmTypes';
import {
  SigningAuthPlanKind,
  type EmailOtpConfirmPrompt,
  type EmailOtpStepUpAuthorization,
  type PasskeyStepUpAuthorization,
  type SigningAuthPlan,
  type WarmSessionStepUpAuthorization,
} from '@/core/signingEngine/stepUpConfirmation/types';
import { normalizeAuthenticationCredential } from '@/core/signingEngine/webauthnAuth/credentials/helpers';
import type { WalletAuthCurve, WalletAuthIntent } from '@/core/types/seams';

type ExportIntent = Extract<WalletAuthIntent, 'ed25519_export' | 'ecdsa_export'>;
type ExportChain = 'near' | ThresholdEcdsaChainTarget['kind'];

type ExportAuthorizationIdentity = {
  nearAccountId: AccountId;
  publicKey: string;
  curve: WalletAuthCurve;
  intent: ExportIntent;
  chain: ExportChain;
};

export type ExportWarmSessionStepUpAuthorization = WarmSessionStepUpAuthorization<
  Extract<SigningAuthPlan, { kind: typeof SigningAuthPlanKind.WarmSession }>
> &
  ExportAuthorizationIdentity;

export type ExportPasskeyStepUpAuthorization = PasskeyStepUpAuthorization<
  Extract<SigningAuthPlan, { kind: typeof SigningAuthPlanKind.PasskeyReauth }>,
  ExportAuthorizationIdentity
>;

export type ExportEmailOtpStepUpAuthorization = EmailOtpStepUpAuthorization<
  Extract<SigningAuthPlan, { kind: typeof SigningAuthPlanKind.EmailOtpReauth }>,
  ExportAuthorizationIdentity
>;

export type ExportStepUpAuthorization =
  | ExportWarmSessionStepUpAuthorization
  | ExportPasskeyStepUpAuthorization
  | ExportEmailOtpStepUpAuthorization;

export function buildExportStepUpAuthorization(args:
  | ({
      method: 'passkey';
      decision: UserConfirmDecision;
    } & ExportAuthorizationIdentity)
  | ({
      method: 'email_otp';
      decision: Pick<UserConfirmDecision, 'confirmed' | 'error' | 'otpCode' | 'emailOtpChallengeId'>;
      emailOtpPrompt: EmailOtpConfirmPrompt;
    } & ExportAuthorizationIdentity),
): ExportStepUpAuthorization {
  const identity = {
    nearAccountId: toAccountId(args.nearAccountId),
    publicKey: String(args.publicKey || '').trim(),
    curve: args.curve,
    intent: args.intent,
    chain: args.chain,
  };
  if (!identity.nearAccountId || !identity.publicKey) {
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
