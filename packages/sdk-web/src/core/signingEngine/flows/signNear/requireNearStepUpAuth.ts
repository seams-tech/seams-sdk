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
  NearEmailOtpEd25519ReconnectHook,
  NearPasskeyEd25519ReconnectHook,
  NearPasskeyReconnectPlan,
} from '@/core/signingEngine/interfaces/near';
import type { NearTransactionSigningLane } from '@/core/signingEngine/session/operationState/lanes';
import { signingLaneAuthMethod } from '@/core/signingEngine/session/identity/signingLaneAuthBinding';

type NearPreparedStepUpAuthBase = {
  confirmationAuthPayload: { signingAuthPlan: SigningAuthPlan };
};

export type NearWarmSessionStepUpAuth = NearPreparedStepUpAuthBase & {
  kind: 'warm_session';
  confirmationAuthPayload: {
    signingAuthPlan: Extract<SigningAuthPlan, { kind: 'warmSession' }>;
  };
};

export type NearPasskeyStepUpAuth = NearPreparedStepUpAuthBase & {
  kind: 'passkey';
  confirmationAuthPayload: {
    signingAuthPlan: Extract<SigningAuthPlan, { kind: 'passkeyReauth' }>;
  };
  plannedPasskeyReconnect: NearPasskeyReconnectPlan;
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
  signingLane: NearTransactionSigningLane;
  requiredSignatureUses: number;
  passkeyEd25519Reconnect?: NearPasskeyEd25519ReconnectHook | null;
  emailOtpEd25519Reconnect?: NearEmailOtpEd25519ReconnectHook | null;
}): Promise<NearPreparedStepUpAuth> {
  if (isEmailOtpSigningAuthPlan(args.signingAuthPlan) && !args.emailOtpEd25519Reconnect) {
    throw new Error('[SigningEngine][near] Email OTP reconnect runner is unavailable');
  }
  if (isPasskeySigningAuthPlan(args.signingAuthPlan) && !args.passkeyEd25519Reconnect) {
    throw new Error('[SigningEngine][near] passkey reconnect runner is unavailable');
  }

  let plannedPasskeyReconnect: NearPasskeyReconnectPlan | null = null;
  const prepared = await prepareStepUpAuth({
    operation: {
      kind: 'near_ed25519_step_up' as const,
      requiredSignatureUses: args.requiredSignatureUses,
    },
    selectedLane: { authMethod: signingLaneAuthMethod(args.signingLane.auth) },
    policy: stepUpPolicyFromSigningAuthPlan(args.signingAuthPlan),
    methods: {
      ...(args.emailOtpEd25519Reconnect
        ? {
            emailOtp: {
              method: 'email_otp' as const,
              prepareChallenge: async () => await args.emailOtpEd25519Reconnect!.prepare(),
              ...(args.emailOtpEd25519Reconnect.resend
                ? {
                    resendChallenge: async () =>
                      await args.emailOtpEd25519Reconnect!.resend!(),
                  }
                : {}),
              complete: completeNearEmailOtpPreparation,
            },
          }
        : {}),
      passkey: {
        method: 'passkey' as const,
        prepare: async () => {
          if (!args.passkeyEd25519Reconnect) {
            throw new Error('[SigningEngine][near] passkey reconnect runner is unavailable');
          }
          plannedPasskeyReconnect = await args.passkeyEd25519Reconnect.prepare({
            requiredSignatureUses: args.requiredSignatureUses,
          });
          return {};
        },
        complete: async ({ confirmation }) => {
          if (!args.passkeyEd25519Reconnect) {
            throw new Error('[SigningEngine][near] passkey reconnect runner is unavailable');
          }
          return await args.passkeyEd25519Reconnect.reconnect({
            authorization: {
              kind: 'passkey',
              signingAuthPlan: isPasskeySigningAuthPlan(args.signingAuthPlan)
                ? args.signingAuthPlan
                : {
                    kind: 'passkeyReauth',
                    method: 'passkey',
                  },
              credential: confirmation.credential,
              plannedPasskeyReconnect: requirePlannedPasskeyReconnect(plannedPasskeyReconnect),
            },
            requiredSignatureUses: args.requiredSignatureUses,
          });
        },
      },
    },
  });

  const signingAuthPlan = args.signingAuthPlan;
  if (prepared.method === 'warm_session') {
    if (!isWarmSessionSigningAuthPlan(args.signingAuthPlan)) {
      throw new Error('[SigningEngine][near] warm-session step-up requires a warm-session plan');
    }
    return {
      kind: 'warm_session',
      confirmationAuthPayload: {
        signingAuthPlan: args.signingAuthPlan,
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
    plannedPasskeyReconnect: requirePlannedPasskeyReconnect(plannedPasskeyReconnect),
  };
}

async function completeNearEmailOtpPreparation(): Promise<void> {}

function requirePlannedPasskeyReconnect(
  plannedPasskeyReconnect: NearPasskeyReconnectPlan | null,
): NearPasskeyReconnectPlan {
  if (!plannedPasskeyReconnect) {
    throw new Error('[SigningEngine][near] passkey reconnect plan is required');
  }
  return plannedPasskeyReconnect;
}

function stepUpPolicyFromSigningAuthPlan(signingAuthPlan: SigningAuthPlan): StepUpPolicy {
  if (isWarmSessionSigningAuthPlan(signingAuthPlan)) {
    return {
      kind: 'reuse_warm_session',
      authorization: {
        method: signingAuthPlan.method,
        sessionId: signingAuthPlan.sessionId,
        expiresAtMs: signingAuthPlan.expiresAtMs,
        remainingUses: signingAuthPlan.remainingUses,
      },
    };
  }
  return { kind: 'use_selected_lane' };
}
