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
  NearEmailOtpSigningHook,
  NearPasskeyEd25519ReconnectHook,
} from '@/core/signingEngine/interfaces/near';
import type { NearTransactionSigningLane } from '@/core/signingEngine/session/operationState/lanes';

export type NearPasskeyReconnectPlan = {
  sessionId: string;
  walletSigningSessionId: string;
  sessionPolicyDigest32: string;
};

type NearPreparedStepUpAuthBase = {
  confirmationAuthPayload: { signingAuthPlan: SigningAuthPlan };
};

export type NearWarmSessionStepUpAuth = NearPreparedStepUpAuthBase & {
  kind: 'warm_session';
  confirmationAuthPayload: {
    signingAuthPlan: Extract<SigningAuthPlan, { kind: 'warmSession' }>;
  };
};

export type NearEmailOtpStepUpAuth = NearPreparedStepUpAuthBase & {
  kind: 'email_otp';
  confirmationAuthPayload: {
    signingAuthPlan: Extract<SigningAuthPlan, { kind: 'emailOtpReauth' }>;
  };
  emailOtpPrompt: EmailOtpConfirmPrompt;
};

export type NearPasskeyStepUpAuth = NearPreparedStepUpAuthBase & {
  kind: 'passkey';
  confirmationAuthPayload: {
    signingAuthPlan: Extract<SigningAuthPlan, { kind: 'passkeyReauth' }>;
  };
  plannedPasskeyReconnect: NearPasskeyReconnectPlan;
};

export type NearPreparedStepUpAuth =
  | NearWarmSessionStepUpAuth
  | NearEmailOtpStepUpAuth
  | NearPasskeyStepUpAuth;

export async function requireNearStepUpAuth(args: {
  signingAuthPlan: SigningAuthPlan;
  signingLane: NearTransactionSigningLane;
  usesNeeded: number;
  emailOtpSigning?: NearEmailOtpSigningHook;
  passkeyEd25519Reconnect?: NearPasskeyEd25519ReconnectHook;
}): Promise<NearPreparedStepUpAuth> {
  if (isEmailOtpSigningAuthPlan(args.signingAuthPlan) && !args.emailOtpSigning) {
    throw new Error('[email-otp] verify Email OTP again before NEAR threshold signing');
  }
  if (isPasskeySigningAuthPlan(args.signingAuthPlan) && !args.passkeyEd25519Reconnect) {
    throw new Error('[SigningEngine][near] passkey reconnect runner is unavailable');
  }

  let plannedPasskeyReconnect: NearPasskeyReconnectPlan | null = null;
  const prepared = await prepareStepUpAuth({
    operation: {
      kind: 'near_ed25519_step_up' as const,
      usesNeeded: args.usesNeeded,
    },
    selectedLane: { authMethod: args.signingLane.authMethod },
    policy: stepUpPolicyFromSigningAuthPlan(args.signingAuthPlan),
    methods: {
      ...(args.emailOtpSigning
        ? {
            emailOtp: {
              method: 'email_otp' as const,
              prepareChallenge: async () => await args.emailOtpSigning!.prepare(),
              ...(args.emailOtpSigning.resend
                ? {
                    resendChallenge: async () => await args.emailOtpSigning!.resend!(),
                  }
                : {}),
              complete: async ({ confirmation, prompt }) =>
                await args.emailOtpSigning!.complete({
                  kind: 'email_otp',
                  signingAuthPlan: isEmailOtpSigningAuthPlan(args.signingAuthPlan)
                    ? args.signingAuthPlan
                    : {
                        kind: 'emailOtpReauth',
                        method: 'email_otp',
                        emailOtpPrompt: prompt,
                      },
                  challengeId: String(prompt.challengeId || '').trim(),
                  otpCode: String(confirmation.otpCode || '').trim(),
                  ...(prompt.emailHint ? { emailHint: prompt.emailHint } : {}),
                }),
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
            usesNeeded: args.usesNeeded,
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
            usesNeeded: args.usesNeeded,
          });
        },
      },
    },
  });

  const signingAuthPlan =
    prepared.method === 'email_otp'
      ? { ...args.signingAuthPlan, emailOtpPrompt: prepared.prompt }
      : args.signingAuthPlan;
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
    return {
      kind: 'email_otp',
      confirmationAuthPayload: {
        signingAuthPlan,
      },
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
