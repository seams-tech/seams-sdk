import { normalizeAuthenticationCredential } from '@/core/signingEngine/webauthnAuth/credentials/helpers';
import type { ConfirmIntentDigestSigningOperationResult } from '../shared/signingConfirmation';
import type { EvmFamilyPasskeyReconnectPlan, EvmFamilyPreparedStepUpAuth } from './requireEvmFamilyStepUpAuth';
import type {
  EmailOtpConfirmPrompt,
  EmailOtpStepUpAuthorization,
  PasskeyStepUpAuthorization,
  SigningAuthPlan,
  WarmSessionStepUpAuthorization,
} from '@/core/signingEngine/stepUpConfirmation/types';

export type EvmFamilyEcdsaWarmSessionStepUpAuthorization = WarmSessionStepUpAuthorization<
  Extract<SigningAuthPlan, { kind: 'warmSession' }>
>;

export type EvmFamilyEcdsaEmailOtpStepUpAuthorization = EmailOtpStepUpAuthorization<
  Extract<SigningAuthPlan, { kind: 'emailOtpReauth' }>
>;

export type EvmFamilyEcdsaPasskeyStepUpAuthorization = PasskeyStepUpAuthorization<
  Extract<SigningAuthPlan, { kind: 'passkeyReauth' }>,
  {
    plannedPasskeyReconnect?: EvmFamilyPasskeyReconnectPlan;
  }
>;

export type EvmFamilyEcdsaStepUpAuthorization =
  | EvmFamilyEcdsaWarmSessionStepUpAuthorization
  | EvmFamilyEcdsaEmailOtpStepUpAuthorization
  | EvmFamilyEcdsaPasskeyStepUpAuthorization;

export function buildEvmFamilyWarmSessionStepUpAuthorization(args: {
  signingAuthPlan: Extract<SigningAuthPlan, { kind: 'warmSession' }>;
}): EvmFamilyEcdsaWarmSessionStepUpAuthorization {
  return {
    kind: 'warm_session',
    signingAuthPlan: args.signingAuthPlan,
    sessionId: args.signingAuthPlan.sessionId,
    expiresAtMs: args.signingAuthPlan.expiresAtMs,
    remainingUses: args.signingAuthPlan.remainingUses,
  };
}

export function buildEvmFamilyEmailOtpStepUpAuthorization(args: {
  signingAuthPlan: Extract<SigningAuthPlan, { kind: 'emailOtpReauth' }>;
  prompt: EmailOtpConfirmPrompt;
  confirmation: Pick<
    ConfirmIntentDigestSigningOperationResult,
    'otpCode' | 'emailOtpChallengeId'
  >;
}): EvmFamilyEcdsaEmailOtpStepUpAuthorization {
  return {
    kind: 'email_otp',
    signingAuthPlan: args.signingAuthPlan,
    challengeId: normalizeChallengeId(
      args.confirmation.emailOtpChallengeId,
      args.prompt,
      'EVM-family step-up authorization',
    ),
    otpCode: normalizeOtpCode(args.confirmation.otpCode),
    ...(args.prompt.emailHint ? { emailHint: args.prompt.emailHint } : {}),
  };
}

export function buildEvmFamilyPasskeyStepUpAuthorization(args: {
  signingAuthPlan: Extract<SigningAuthPlan, { kind: 'passkeyReauth' }>;
  confirmation: Pick<ConfirmIntentDigestSigningOperationResult, 'credential'>;
  plannedPasskeyReconnect?: EvmFamilyPasskeyReconnectPlan;
}): EvmFamilyEcdsaPasskeyStepUpAuthorization {
  if (!args.confirmation.credential) {
    throw new Error(
      '[chains] missing WebAuthn credential for EVM-family step-up authorization',
    );
  }
  return {
    kind: 'passkey',
    signingAuthPlan: args.signingAuthPlan,
    credential: normalizeAuthenticationCredential(args.confirmation.credential),
    ...(args.plannedPasskeyReconnect
      ? { plannedPasskeyReconnect: args.plannedPasskeyReconnect }
      : {}),
  };
}

export function buildEvmFamilyEcdsaStepUpAuthorization(args: {
  prepared: EvmFamilyPreparedStepUpAuth;
  confirmation: ConfirmIntentDigestSigningOperationResult;
}): EvmFamilyEcdsaStepUpAuthorization {
  if (args.prepared.kind === 'warm_session') {
    return buildEvmFamilyWarmSessionStepUpAuthorization({
      signingAuthPlan: args.prepared.confirmationAuthPayload.signingAuthPlan,
    });
  }

  if (args.prepared.kind === 'email_otp') {
    return buildEvmFamilyEmailOtpStepUpAuthorization({
      signingAuthPlan: args.prepared.confirmationAuthPayload.signingAuthPlan,
      prompt: args.prepared.emailOtpPrompt,
      confirmation: args.confirmation,
    });
  }

  return buildEvmFamilyPasskeyStepUpAuthorization({
    signingAuthPlan: args.prepared.confirmationAuthPayload.signingAuthPlan,
    confirmation: args.confirmation,
    ...(args.prepared.plannedPasskeyReconnect
      ? { plannedPasskeyReconnect: args.prepared.plannedPasskeyReconnect }
      : {}),
  });
}

function normalizeOtpCode(otpCodeRaw: unknown): string {
  const otpCode = String(otpCodeRaw || '').trim();
  if (!/^\d{6}$/.test(otpCode)) {
    throw new Error('[chains] missing Email OTP code from touchConfirm');
  }
  return otpCode;
}

function normalizeChallengeId(
  challengeIdRaw: unknown,
  prompt: EmailOtpConfirmPrompt,
  context: string,
): string {
  const challengeId = String(challengeIdRaw || prompt.challengeId || '').trim();
  if (!challengeId) {
    throw new Error(`[chains] missing Email OTP challenge id for ${context}`);
  }
  return challengeId;
}
