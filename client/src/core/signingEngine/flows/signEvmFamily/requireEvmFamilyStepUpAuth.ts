import { prepareStepUpAuth } from '@/core/signingEngine/stepUpConfirmation/requireStepUpAuth';
import type {
  EmailOtpConfirmPrompt,
  SigningAuthPlan,
  StepUpPolicy,
} from '@/core/signingEngine/stepUpConfirmation/types';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import {
  isEmailOtpSigningAuthPlan,
  isPasskeySigningAuthPlan,
  isWarmSessionSigningAuthPlan,
} from '@/core/signingEngine/stepUpConfirmation/types';
import type {
  EvmFamilyThresholdEcdsaOperation,
  EvmFamilyThresholdEcdsaReauthResult,
} from './thresholdAdmission';

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
  const selectedLane = resolveEvmFamilyStepUpLane({
    signingAuthPlan,
    hasEmailOtpSigning: Boolean(stepUpRuntime?.emailOtpSigning),
    hasThresholdEcdsaRequest: args.hasThresholdEcdsaRequest,
    needsWebAuthn: args.needsWebAuthn,
  });
  if (!selectedLane) {
    throw new Error(
      `[chains] ${args.explicitAuthErrorLabel} signing requires explicit auth input`,
    );
  }
  let plannedPasskeyReconnect: EvmFamilyPasskeyReconnectPlan | undefined;
  const prepared = await prepareStepUpAuth({
    operation: {
      kind: 'evm_family_threshold_ecdsa_step_up' as const,
      usesNeeded: 1,
    },
    selectedLane,
    policy: stepUpPolicyFromSigningAuthPlan(signingAuthPlan),
    methods: {
      ...(stepUpRuntime?.emailOtpSigning
        ? {
            emailOtp: {
              method: 'email_otp' as const,
              prepareChallenge: async () => await stepUpRuntime.emailOtpSigning!.prepare(),
              ...(stepUpRuntime.emailOtpSigning.resend
                ? {
                    resendChallenge: async () => await stepUpRuntime.emailOtpSigning!.resend!(),
                  }
                : {}),
              complete: async ({ confirmation, prompt }) =>
                await stepUpRuntime.emailOtpSigning!.complete(
                  confirmation.otpCode,
                  prompt.challengeId,
                ),
            },
          }
        : {}),
      passkey: {
        method: 'passkey' as const,
        prepare: async () => {
          if (stepUpRuntime?.passkeyReconnect) {
            plannedPasskeyReconnect = await stepUpRuntime.passkeyReconnect.prepare({
              usesNeeded: 1,
            });
          }
          return {};
        },
        complete: async ({ confirmation }) => {
          if (!stepUpRuntime?.passkeyReconnect) {
            throw new Error('[chains] passkey reconnect runner is unavailable');
          }
          return await stepUpRuntime.passkeyReconnect.reconnect({
            credential: confirmation.credential as WebAuthnAuthenticationCredential,
            usesNeeded: 1,
            sessionId: plannedPasskeyReconnect?.sessionId || '',
            walletSigningSessionId: plannedPasskeyReconnect?.walletSigningSessionId || '',
          });
        },
      },
    },
  });
  const confirmationAuthPayload = {
    signingAuthPlan: signingAuthPlanFromPreparedEvmFamilyStepUp({
      signingAuthPlan,
      prepared,
    }),
  };
  const emailOtpPrompt = prepared.method === 'email_otp' ? prepared.prompt : undefined;
  return {
    confirmationAuthPayload,
    ...(emailOtpPrompt ? { emailOtpPrompt } : {}),
    ...(plannedPasskeyReconnect ? { plannedPasskeyReconnect } : {}),
  };
}

function resolveEvmFamilyStepUpLane(args: {
  signingAuthPlan?: SigningAuthPlan;
  hasEmailOtpSigning: boolean;
  hasThresholdEcdsaRequest: boolean;
  needsWebAuthn: boolean;
}): { authMethod: 'passkey' | 'email_otp' } | null {
  if (args.signingAuthPlan) {
    if (isEmailOtpSigningAuthPlan(args.signingAuthPlan)) return { authMethod: 'email_otp' };
    if (isPasskeySigningAuthPlan(args.signingAuthPlan)) return { authMethod: 'passkey' };
    return { authMethod: args.signingAuthPlan.method };
  }
  if (args.hasEmailOtpSigning) return { authMethod: 'email_otp' };
  if (!args.hasThresholdEcdsaRequest && args.needsWebAuthn) return { authMethod: 'passkey' };
  return null;
}

function stepUpPolicyFromSigningAuthPlan(signingAuthPlan?: SigningAuthPlan): StepUpPolicy {
  if (signingAuthPlan && isWarmSessionSigningAuthPlan(signingAuthPlan)) {
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

function signingAuthPlanFromPreparedEvmFamilyStepUp(args: {
  signingAuthPlan?: SigningAuthPlan;
  prepared: Awaited<ReturnType<typeof prepareStepUpAuth>>;
}): SigningAuthPlan {
  if (args.signingAuthPlan) {
    return args.prepared.method === 'email_otp' &&
      isEmailOtpSigningAuthPlan(args.signingAuthPlan)
      ? { ...args.signingAuthPlan, emailOtpPrompt: args.prepared.prompt }
      : args.signingAuthPlan;
  }
  if (args.prepared.method === 'email_otp') {
    return {
      kind: 'emailOtpReauth',
      method: 'email_otp',
      emailOtpPrompt: args.prepared.prompt,
    };
  }
  if (args.prepared.method === 'passkey') {
    return {
      kind: 'passkeyReauth',
      method: 'passkey',
    };
  }
  throw new Error('[chains] warm-session step-up requires an existing signing auth plan');
}
