import { prepareStepUpAuth } from '@/core/signingEngine/stepUpConfirmation/requireStepUpAuth';
import type {
  EmailOtpConfirmPrompt,
  SigningAuthPlan,
  StepUpPolicy,
} from '@/core/signingEngine/stepUpConfirmation/types';
import {
  isEmailOtpSigningAuthPlan,
  isWarmSessionSigningAuthPlan,
} from '@/core/signingEngine/stepUpConfirmation/types';
import type {
  NearEmailOtpSigningHook,
  NearPasskeyEd25519ReconnectHook,
} from '@/core/signingEngine/interfaces/near';
import type { NearTransactionSigningLane } from '@/core/signingEngine/session/operationState/lanes';
import type { WebAuthnAuthenticationCredential } from '@/core/types';

export type NearPasskeyReconnectPlan = {
  sessionId: string;
  walletSigningSessionId?: string;
  sessionPolicyDigest32: string;
};

export type NearPreparedStepUpAuth = {
  confirmationAuthPayload: { signingAuthPlan: SigningAuthPlan };
  emailOtpPrompt?: EmailOtpConfirmPrompt;
  plannedPasskeyReconnect?: NearPasskeyReconnectPlan;
  shouldReconnectWithPasskeyEd25519: boolean;
};

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

  let plannedPasskeyReconnect: NearPasskeyReconnectPlan | undefined;
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
                await args.emailOtpSigning!.complete(confirmation.otpCode, prompt.challengeId),
            },
          }
        : {}),
      passkey: {
        method: 'passkey' as const,
        prepare: async () => {
          plannedPasskeyReconnect = args.passkeyEd25519Reconnect?.prepare
            ? await args.passkeyEd25519Reconnect.prepare({ usesNeeded: args.usesNeeded })
            : undefined;
          return {};
        },
        complete: async ({ confirmation }) => {
          if (!args.passkeyEd25519Reconnect) {
            throw new Error('[SigningEngine][near] passkey reconnect runner is unavailable');
          }
          return await args.passkeyEd25519Reconnect.reconnect({
            credential: confirmation.credential as WebAuthnAuthenticationCredential,
            usesNeeded: args.usesNeeded,
            ...(plannedPasskeyReconnect?.sessionId
              ? { sessionId: plannedPasskeyReconnect.sessionId }
              : {}),
            ...(plannedPasskeyReconnect?.walletSigningSessionId
              ? { walletSigningSessionId: plannedPasskeyReconnect.walletSigningSessionId }
              : {}),
          });
        },
      },
    },
  });

  const signingAuthPlan =
    prepared.method === 'email_otp'
      ? { ...args.signingAuthPlan, emailOtpPrompt: prepared.prompt }
      : args.signingAuthPlan;
  return {
    confirmationAuthPayload: { signingAuthPlan },
    ...(prepared.method === 'email_otp' ? { emailOtpPrompt: prepared.prompt } : {}),
    ...(plannedPasskeyReconnect ? { plannedPasskeyReconnect } : {}),
    shouldReconnectWithPasskeyEd25519:
      prepared.method === 'passkey' && Boolean(args.passkeyEd25519Reconnect),
  };
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
