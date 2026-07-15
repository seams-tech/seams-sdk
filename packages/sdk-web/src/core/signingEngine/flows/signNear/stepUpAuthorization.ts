import { normalizeAuthenticationCredential } from '@/core/signingEngine/webauthnAuth/credentials/helpers';
import type { ConfirmNearStepUpSigningOperationResult } from '../shared/signingConfirmation';
import type { NearPreparedStepUpAuth } from './requireNearStepUpAuth';
import type {
  NearEd25519EmailOtpStepUpAuthorization,
  NearEd25519PasskeyStepUpAuthorization,
  NearEd25519StepUpAuthorization,
  NearEd25519WarmSessionStepUpAuthorization,
  NearPasskeyReconnectPlan,
} from '@/core/signingEngine/interfaces/near';
import type {
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
  confirmation: ConfirmNearStepUpSigningOperationResult;
}): NearEd25519StepUpAuthorization {
  if (args.prepared.kind === 'warm_session') {
    return buildNearEd25519WarmSessionStepUpAuthorization(
      args.prepared.confirmationAuthPayload.signingAuthPlan,
    );
  }

  if (args.prepared.kind === 'email_otp') {
    return {
      kind: 'email_otp',
      signingAuthPlan: args.prepared.confirmationAuthPayload.signingAuthPlan,
      challengeId: normalizeNearEmailOtpChallengeId(
        args.confirmation.emailOtpChallengeId,
        args.prepared.emailOtpPrompt.challengeId,
      ),
      otpCode: normalizeNearEmailOtpCode(args.confirmation.otpCode),
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

function normalizeNearEmailOtpCode(value: unknown): string {
  const otpCode = String(value || '').trim();
  if (!/^\d{6}$/.test(otpCode)) {
    throw new Error('[SigningEngine] missing Email OTP code for NEAR step-up authorization');
  }
  return otpCode;
}

function normalizeNearEmailOtpChallengeId(value: unknown, fallback: string): string {
  const challengeId = String(value || fallback || '').trim();
  if (!challengeId) {
    throw new Error('[SigningEngine] missing Email OTP challenge id for NEAR step-up authorization');
  }
  return challengeId;
}
