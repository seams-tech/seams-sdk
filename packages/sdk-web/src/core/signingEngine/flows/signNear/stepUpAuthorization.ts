import { normalizeAuthenticationCredential } from '@/core/signingEngine/webauthnAuth/credentials/helpers';
import type { ConfirmTransactionSigningOperationResult } from '../shared/signingConfirmation';
import type { NearPreparedStepUpAuth } from './requireNearStepUpAuth';
import type {
  NearEd25519EmailOtpStepUpAuthorization,
  NearEd25519EmailOtpMaterialRestoreAuthorization,
  NearEd25519PasskeyStepUpAuthorization,
  NearEd25519StepUpAuthorization,
  NearEd25519WarmSessionStepUpAuthorization,
  NearPasskeyReconnectPlan,
} from '@/core/signingEngine/interfaces/near';
import type {
  EmailOtpConfirmPrompt,
  SigningAuthPlan,
} from '@/core/signingEngine/stepUpConfirmation/types';

export type {
  NearEd25519EmailOtpStepUpAuthorization,
  NearEd25519PasskeyStepUpAuthorization,
  NearEd25519StepUpAuthorization,
  NearEd25519WarmSessionStepUpAuthorization,
  NearPasskeyReconnectPlan,
} from '@/core/signingEngine/interfaces/near';

export function buildNearEd25519WarmSessionStepUpAuthorization(
  signingAuthPlan: Extract<SigningAuthPlan, { kind: 'warmSession' }>,
): NearEd25519WarmSessionStepUpAuthorization {
  return {
    kind: 'warm_session',
    signingAuthPlan,
    sessionId: signingAuthPlan.sessionId,
    expiresAtMs: signingAuthPlan.expiresAtMs,
    remainingUses: signingAuthPlan.remainingUses,
  };
}

export function buildNearEd25519StepUpAuthorization(args: {
  prepared: NearPreparedStepUpAuth;
  confirmation: ConfirmTransactionSigningOperationResult;
  emailOtpMaterialRestoreAuthorization?: NearEd25519EmailOtpMaterialRestoreAuthorization;
}): NearEd25519StepUpAuthorization {
  if (args.prepared.kind === 'warm_session') {
    return buildNearEd25519WarmSessionStepUpAuthorization(
      args.prepared.confirmationAuthPayload.signingAuthPlan,
    );
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
      ed25519MaterialRestoreAuthorization:
        args.emailOtpMaterialRestoreAuthorization ||
        unavailableEmailOtpMaterialRestoreAuthorization(),
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

function unavailableEmailOtpMaterialRestoreAuthorization(): NearEd25519EmailOtpMaterialRestoreAuthorization {
  return {
    kind: 'ed25519_email_otp_material_unseal_authorization_unavailable',
    reason: 'no_recovery_code_material',
  };
}
