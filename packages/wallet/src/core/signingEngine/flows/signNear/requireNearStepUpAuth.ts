import { prepareStepUpAuth } from '@/core/signingEngine/stepUpConfirmation/requireStepUpAuth';
import type {
  EmailOtpConfirmPrompt,
  SigningAuthPlan,
  StepUpPolicy,
} from '@/core/signingEngine/stepUpConfirmation/types';
import {
  isEmailOtpSigningAuthPlan,
  isPasskeySigningAuthPlan,
  isWarmSessionSigningAuthPlan,
} from '@/core/signingEngine/stepUpConfirmation/types';
import type {
  NearEmailOtpEd25519StepUpHook,
  NearPasskeyEd25519OperationStepUpHook,
  NearPasskeyOperationStepUpPlan,
} from '@/core/signingEngine/interfaces/near';
import type { NearTransactionSigningLane } from '@/core/signingEngine/session/operationState/lanes';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  signingLaneAuthMethod,
  type SigningLaneAuthBinding,
} from '@/core/signingEngine/session/identity/signingLaneAuthBinding';

type NearPreparedStepUpAuthBase = {
  confirmationAuthPayload: { signingAuthPlan: SigningAuthPlan };
};

export type NearWarmSessionStepUpAuth = NearPreparedStepUpAuthBase & {
  kind: 'warm_session';
  confirmationAuthPayload: {
    signingAuthPlan: Extract<SigningAuthPlan, { kind: 'warmSession'; curve: 'ed25519' }>;
  };
};

export type NearPasskeyStepUpAuth = NearPreparedStepUpAuthBase & {
  kind: 'passkey';
  confirmationAuthPayload: {
    signingAuthPlan: Extract<SigningAuthPlan, { kind: 'passkeyReauth' }>;
  };
  plannedPasskeyOperationStepUp: NearPasskeyOperationStepUpPlan;
};

export type NearEmailOtpStepUpAuth = NearPreparedStepUpAuthBase & {
  kind: 'email_otp';
  confirmationAuthPayload: {
    signingAuthPlan: Extract<SigningAuthPlan, { kind: 'emailOtpReauth' }>;
  };
  emailOtpPrompt: EmailOtpConfirmPrompt;
};

export type NearPreparedStepUpAuth =
  | NearWarmSessionStepUpAuth
  | NearEmailOtpStepUpAuth
  | NearPasskeyStepUpAuth;

export async function requireNearStepUpAuth(args: {
  signingAuthPlan: SigningAuthPlan;
  signingLaneAuth: SigningLaneAuthBinding;
  requiredSignatureUses: number;
  operationFingerprintDigest: DigestB64u;
  passkeyEd25519OperationStepUp?: NearPasskeyEd25519OperationStepUpHook | null;
  emailOtpEd25519StepUp?: NearEmailOtpEd25519StepUpHook | null;
}): Promise<NearPreparedStepUpAuth> {
  if (isEmailOtpSigningAuthPlan(args.signingAuthPlan) && !args.emailOtpEd25519StepUp) {
    throw new Error('[SigningEngine][near] Email OTP step-up runner is unavailable');
  }
  if (isPasskeySigningAuthPlan(args.signingAuthPlan) && !args.passkeyEd25519OperationStepUp) {
    throw new Error('[SigningEngine][near] Passkey operation step-up runner is unavailable');
  }

  let plannedPasskeyOperationStepUp: NearPasskeyOperationStepUpPlan | null = null;
  const prepared = await prepareStepUpAuth({
    operation: {
      kind: 'near_ed25519_step_up' as const,
      requiredSignatureUses: args.requiredSignatureUses,
    },
    selectedLane: { authMethod: signingLaneAuthMethod(args.signingLaneAuth) },
    policy: stepUpPolicyFromSigningAuthPlan(args.signingAuthPlan),
    methods: {
      ...(args.emailOtpEd25519StepUp
        ? {
            emailOtp: {
              method: 'email_otp' as const,
              prepareChallenge: async () =>
                await args.emailOtpEd25519StepUp!.prepare({
                  operationFingerprintDigest: args.operationFingerprintDigest,
                }),
              ...(args.emailOtpEd25519StepUp.resend
                ? {
                    resendChallenge: async () =>
                      await args.emailOtpEd25519StepUp!.resend!({
                        operationFingerprintDigest: args.operationFingerprintDigest,
                      }),
                  }
                : {}),
              complete: completeNearEmailOtpPreparation,
            },
          }
        : {}),
      passkey: {
        method: 'passkey' as const,
        prepare: async () => {
          if (!args.passkeyEd25519OperationStepUp) {
            throw new Error(
              '[SigningEngine][near] Passkey operation step-up runner is unavailable',
            );
          }
          plannedPasskeyOperationStepUp = await args.passkeyEd25519OperationStepUp.prepare();
          return {};
        },
        complete: completeNearPasskeyPreparation,
      },
    },
  });

  const signingAuthPlan = args.signingAuthPlan;
  if (prepared.method === 'warm_session') {
    if (!isEd25519WarmSessionSigningAuthPlan(signingAuthPlan)) {
      throw new Error('[SigningEngine][near] warm-session step-up requires a warm-session plan');
    }
    return {
      kind: 'warm_session',
      confirmationAuthPayload: {
        signingAuthPlan,
      },
    };
  }
  if (prepared.method === 'email_otp') {
    if (!isEmailOtpSigningAuthPlan(signingAuthPlan)) {
      throw new Error('[SigningEngine][near] Email OTP step-up requires an Email OTP plan');
    }
    const signingAuthPlanWithPrompt: Extract<SigningAuthPlan, { kind: 'emailOtpReauth' }> = {
      kind: 'emailOtpReauth',
      method: 'email_otp',
      emailOtpPrompt: prepared.prompt,
    };
    return {
      kind: 'email_otp',
      confirmationAuthPayload: { signingAuthPlan: signingAuthPlanWithPrompt },
      emailOtpPrompt: prepared.prompt,
    };
  }
  if (!isPasskeySigningAuthPlan(signingAuthPlan)) {
    throw new Error('[SigningEngine][near] passkey step-up requires a passkey plan');
  }
  return {
    kind: 'passkey',
    confirmationAuthPayload: {
      signingAuthPlan,
    },
    plannedPasskeyOperationStepUp: requirePlannedPasskeyOperationStepUp(
      plannedPasskeyOperationStepUp,
    ),
  };
}

export function signingAuthPlanForNearMaterialRequirement(
  auth: SigningLaneAuthBinding,
): SigningAuthPlan {
  switch (auth.kind) {
    case 'passkey':
      return { kind: 'passkeyReauth', method: 'passkey' };
    case 'email_otp':
      return { kind: 'emailOtpReauth', method: 'email_otp' };
    default:
      auth satisfies never;
      throw new Error('[SigningEngine][near] unsupported material auth requirement');
  }
}

async function completeNearEmailOtpPreparation(): Promise<void> {}

async function completeNearPasskeyPreparation(): Promise<void> {}

function requirePlannedPasskeyOperationStepUp(
  planned: NearPasskeyOperationStepUpPlan | null,
): NearPasskeyOperationStepUpPlan {
  if (!planned) {
    throw new Error('[SigningEngine][near] Passkey operation step-up plan is required');
  }
  return planned;
}

function stepUpPolicyFromSigningAuthPlan(signingAuthPlan: SigningAuthPlan): StepUpPolicy {
  if (isWarmSessionSigningAuthPlan(signingAuthPlan)) {
    if (signingAuthPlan.curve !== 'ed25519') {
      throw new Error('[SigningEngine][near] warm-session step-up requires an Ed25519 auth plan');
    }
    return {
      kind: 'reuse_warm_session',
      authorization: {
        method: signingAuthPlan.method,
        curve: 'ed25519',
        thresholdSessionId: signingAuthPlan.thresholdSessionId,
        expiresAtMs: signingAuthPlan.expiresAtMs,
        remainingUses: signingAuthPlan.remainingUses,
      },
    };
  }
  return { kind: 'use_selected_lane' };
}

function isEd25519WarmSessionSigningAuthPlan(
  plan: SigningAuthPlan,
): plan is Extract<SigningAuthPlan, { kind: 'warmSession'; curve: 'ed25519' }> {
  return isWarmSessionSigningAuthPlan(plan) && plan.curve === 'ed25519';
}
