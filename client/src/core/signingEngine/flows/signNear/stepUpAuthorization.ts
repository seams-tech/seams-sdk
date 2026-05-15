import { normalizeAuthenticationCredential } from '@/core/signingEngine/webauthnAuth/credentials/helpers';
import type { ConfirmTransactionSigningOperationResult } from '../shared/signingConfirmation';
import type { NearPreparedStepUpAuth } from './requireNearStepUpAuth';
import type {
  NearEd25519EmailOtpStepUpAuthorization,
  NearEd25519PasskeyStepUpAuthorization,
  NearEd25519StepUpAuthorization,
  NearEd25519WarmSessionStepUpAuthorization,
  NearPasskeyReconnectPlan,
} from '@/core/signingEngine/interfaces/near';
import type {
  EmailOtpConfirmPrompt,
} from '@/core/signingEngine/stepUpConfirmation/types';

export type {
  NearEd25519EmailOtpStepUpAuthorization,
  NearEd25519PasskeyStepUpAuthorization,
  NearEd25519StepUpAuthorization,
  NearEd25519WarmSessionStepUpAuthorization,
  NearPasskeyReconnectPlan,
} from '@/core/signingEngine/interfaces/near';

export function buildNearEd25519StepUpAuthorization(args: {
  prepared: NearPreparedStepUpAuth;
  confirmation: ConfirmTransactionSigningOperationResult;
}): NearEd25519StepUpAuthorization {
  if (args.prepared.kind === 'warm_session') {
    const signingAuthPlan = args.prepared.confirmationAuthPayload.signingAuthPlan;
    return {
      kind: 'warm_session',
      signingAuthPlan,
      sessionId: signingAuthPlan.sessionId,
      expiresAtMs: signingAuthPlan.expiresAtMs,
      remainingUses: signingAuthPlan.remainingUses,
    };
  }

  if (args.prepared.kind === 'email_otp') {
    const otpCode = normalizeOtpCode(args.confirmation.otpCode);
    const challengeId = normalizeChallengeId(
      args.confirmation.emailOtpChallengeId,
      args.prepared.emailOtpPrompt,
      'NEAR step-up authorization',
    );
    return {
      kind: 'email_otp',
      signingAuthPlan: args.prepared.confirmationAuthPayload.signingAuthPlan,
      challengeId,
      otpCode,
      ...(args.prepared.emailOtpPrompt.emailHint
        ? { emailHint: args.prepared.emailOtpPrompt.emailHint }
        : {}),
    };
  }

  if (!args.confirmation.credential) {
    throw new Error('[SigningEngine] missing WebAuthn credential for NEAR step-up authorization');
  }
  return {
    kind: 'passkey',
    signingAuthPlan: args.prepared.confirmationAuthPayload.signingAuthPlan,
    credential: normalizeAuthenticationCredential(args.confirmation.credential),
    plannedPasskeyReconnect: args.prepared.plannedPasskeyReconnect,
  };
}

function normalizeOtpCode(otpCodeRaw: unknown): string {
  const otpCode = String(otpCodeRaw || '').trim();
  if (!/^\d{6}$/.test(otpCode)) {
    throw new Error('[SigningEngine] missing Email OTP code from touchConfirm');
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
    throw new Error(`[SigningEngine] missing Email OTP challenge id for ${context}`);
  }
  return challengeId;
}
