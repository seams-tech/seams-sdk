import { prepareEmailOtpSigningPrompt } from '@/core/signingEngine/stepUpConfirmation/otpPrompt/signingPrompt';
import type {
  EmailOtpConfirmPrompt,
  SigningAuthPlan,
} from '@/core/signingEngine/stepUpConfirmation/types';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import { SigningAuthPlanKind } from '@/core/signingEngine/stepUpConfirmation/types';
import type {
  EvmFamilyThresholdEcdsaOperation,
  EvmFamilyThresholdEcdsaReauthResult,
} from './thresholdAdmission';
import { resolveSigningConfirmationAuth } from '../shared/signingConfirmation';

export type EvmFamilyPasskeyReconnectPlan = {
  sessionId: string;
  walletSigningSessionId: string;
  sessionPolicyDigest32: string;
};

export type EvmFamilyPasskeyReconnectPlanner = {
  prepare: (args: { usesNeeded: number }) => Promise<EvmFamilyPasskeyReconnectPlan>;
};

export type EvmFamilyEmailOtpStepUpRuntime = {
  prepare: () => Promise<{ challengeId: string; emailHint?: string }>;
  resend?: () => Promise<{ challengeId: string; emailHint?: string }>;
  complete: (
    otpCode: string,
    challengeId?: string,
  ) => Promise<EvmFamilyThresholdEcdsaReauthResult>;
};

export type EvmFamilyPasskeyStepUpRuntime = EvmFamilyPasskeyReconnectPlanner & {
  reconnect: (args: {
    credential: WebAuthnAuthenticationCredential;
    usesNeeded: number;
    sessionId: string;
    walletSigningSessionId: string;
  }) => Promise<EvmFamilyThresholdEcdsaReauthResult>;
};

export type EvmFamilyThresholdReconnectRuntime = {
  ensureThresholdEcdsaKeyRefReady: () => Promise<EvmFamilyThresholdEcdsaReauthResult>;
};

export type EvmFamilyThresholdEcdsaStepUpRuntime = {
  emailOtpSigning?: EvmFamilyEmailOtpStepUpRuntime;
  passkeyReconnect?: EvmFamilyPasskeyStepUpRuntime;
  thresholdReconnect?: EvmFamilyThresholdReconnectRuntime;
  onAuthSideEffectStarted?: (sideEffect: 'passkey_reauth' | 'threshold_reconnect') => void;
};

export type EvmFamilyThresholdEcdsaStepUp =
  | {
      kind: 'not_required';
    }
  | {
      kind: 'required_not_admitted';
      authPlan: {
        kind: 'planned';
        signingAuthPlan: SigningAuthPlan;
      };
      runtime: EvmFamilyThresholdEcdsaStepUpRuntime;
    }
  | {
      kind: 'required_admitted';
      authPlan: {
        kind: 'planned';
        signingAuthPlan: SigningAuthPlan;
      };
      operation: EvmFamilyThresholdEcdsaOperation;
      runtime: EvmFamilyThresholdEcdsaStepUpRuntime;
    };

export type EvmFamilyPreparedStepUpAuth = {
  confirmationAuthPayload: { signingAuthPlan: SigningAuthPlan };
  emailOtpPrompt?: EmailOtpConfirmPrompt;
  plannedPasskeyReconnect?: EvmFamilyPasskeyReconnectPlan;
};

export function signingAuthPlanFromThresholdEcdsaStepUp(
  stepUp: EvmFamilyThresholdEcdsaStepUp,
): SigningAuthPlan | undefined {
  if (stepUp.kind === 'not_required') return undefined;
  return stepUp.authPlan.signingAuthPlan;
}

export async function requireEvmFamilyStepUpAuth(args: {
  thresholdEcdsaStepUp: EvmFamilyThresholdEcdsaStepUp;
  hasThresholdEcdsaRequest: boolean;
  needsWebAuthn: boolean;
  explicitAuthErrorLabel: 'EVM' | 'Tempo';
}): Promise<EvmFamilyPreparedStepUpAuth> {
  const signingAuthPlan = signingAuthPlanFromThresholdEcdsaStepUp(args.thresholdEcdsaStepUp);
  const stepUpRuntime =
    args.thresholdEcdsaStepUp.kind === 'not_required'
      ? undefined
      : args.thresholdEcdsaStepUp.runtime;
  const emailOtpPrompt = await prepareEmailOtpSigningPrompt(stepUpRuntime?.emailOtpSigning);
  const confirmationAuthInput = signingAuthPlan
    ? {
        kind: 'signing_plan' as const,
        signingAuthPlan,
        emailOtpPrompt: emailOtpPrompt || null,
      }
    : emailOtpPrompt
      ? {
          kind: 'email_otp' as const,
          emailOtpPrompt,
        }
      : !args.hasThresholdEcdsaRequest && args.needsWebAuthn
        ? {
            kind: 'passkey' as const,
          }
        : null;
  if (!confirmationAuthInput) {
    throw new Error(
      `[chains] ${args.explicitAuthErrorLabel} signing requires explicit auth input`,
    );
  }
  const confirmationAuthPayload = (
    await resolveSigningConfirmationAuth(confirmationAuthInput)
  ).confirmationAuthPayload;
  const plannedPasskeyReconnect =
    confirmationAuthPayload.signingAuthPlan.kind === SigningAuthPlanKind.PasskeyReauth &&
    stepUpRuntime?.passkeyReconnect?.prepare
      ? await stepUpRuntime.passkeyReconnect.prepare({ usesNeeded: 1 })
      : undefined;
  return {
    confirmationAuthPayload,
    ...(emailOtpPrompt ? { emailOtpPrompt } : {}),
    ...(plannedPasskeyReconnect ? { plannedPasskeyReconnect } : {}),
  };
}
