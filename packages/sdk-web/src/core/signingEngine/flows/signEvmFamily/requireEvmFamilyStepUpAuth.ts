import { prepareStepUpAuth } from '@/core/signingEngine/stepUpConfirmation/requireStepUpAuth';
import type {
  EmailOtpConfirmPrompt,
  SigningAuthPlan,
  StepUpPolicy,
  WebAuthnChallenge,
} from '@/core/signingEngine/stepUpConfirmation/types';
import {
  isEmailOtpSigningAuthPlan,
  isPasskeySigningAuthPlan,
  isWarmSessionSigningAuthPlan,
} from '@/core/signingEngine/stepUpConfirmation/types';
import type {
  EvmFamilyThresholdEcdsaOperation,
  EvmFamilyThresholdEcdsaReauthResult,
} from './thresholdAdmission';
import type { ReadyEcdsaSignerSession } from '../../session/identity/evmFamilyEcdsaIdentity';
import type { EcdsaRoleLocalReadyRecord } from '@/core/platform/types';
import type {
  EvmFamilyEcdsaEmailOtpStepUpAuthorization,
  EvmFamilyEcdsaPasskeyStepUpAuthorization,
  EvmFamilyEcdsaWarmSessionStepUpAuthorization,
} from './stepUpAuthorization';
import type { EvmFamilySigningAuthSideEffect } from './freshAuthRetryPolicy';

export type EvmFamilyPasskeyReconnectPlan = {
  webauthnChallenge: Extract<WebAuthnChallenge, { kind: 'ecdsa_role_local_bootstrap' }>;
};

export type EvmFamilyPasskeyReconnectPlanner = {
  prepare: (args: { usesNeeded: number }) => Promise<EvmFamilyPasskeyReconnectPlan>;
};

export type EvmFamilyEmailOtpStepUpRuntime = {
  prepare: () => Promise<{ challengeId: string; emailHint?: string }>;
  resend?: () => Promise<{ challengeId: string; emailHint?: string }>;
  complete: (
    authorization: EvmFamilyEcdsaEmailOtpStepUpAuthorization,
  ) => Promise<EvmFamilyThresholdEcdsaReauthResult>;
};

export type EvmFamilyPasskeyStepUpRuntime = EvmFamilyPasskeyReconnectPlanner & {
  reconnect: (args: {
    authorization: EvmFamilyEcdsaPasskeyStepUpAuthorization;
    usesNeeded: number;
  }) => Promise<EvmFamilyThresholdEcdsaReauthResult>;
};

export type EvmFamilyThresholdReconnectRuntime = {
  ensureThresholdEcdsaReadyMaterial: (args: {
    authorization: EvmFamilyEcdsaWarmSessionStepUpAuthorization;
    usesNeeded: number;
  }) => Promise<EvmFamilyThresholdEcdsaReauthResult>;
};

export type EvmFamilyThresholdEcdsaStepUpRuntime = {
  emailOtpSigning?: EvmFamilyEmailOtpStepUpRuntime;
  passkeyReconnect?: EvmFamilyPasskeyStepUpRuntime;
  thresholdReconnect?: EvmFamilyThresholdReconnectRuntime;
  onAuthSideEffectStarted?: (sideEffect: EvmFamilySigningAuthSideEffect) => void;
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
      signerSession: ReadyEcdsaSignerSession;
      singleUseEmailOtpSession: boolean;
      roleLocalReadyRecordForWorkerRestore: EcdsaRoleLocalReadyRecord | null;
      runtime: EvmFamilyThresholdEcdsaStepUpRuntime;
    };

type EvmFamilyPreparedStepUpAuthBase = {
  kind: 'warm_session' | 'email_otp' | 'passkey';
  confirmationAuthPayload: { signingAuthPlan: SigningAuthPlan };
};

export type EvmFamilyWarmSessionStepUpAuth = EvmFamilyPreparedStepUpAuthBase & {
  kind: 'warm_session';
  confirmationAuthPayload: {
    signingAuthPlan: Extract<SigningAuthPlan, { kind: 'warmSession' }>;
  };
};

export type EvmFamilyEmailOtpStepUpAuth = EvmFamilyPreparedStepUpAuthBase & {
  kind: 'email_otp';
  confirmationAuthPayload: {
    signingAuthPlan: Extract<SigningAuthPlan, { kind: 'emailOtpReauth' }>;
  };
  emailOtpPrompt: EmailOtpConfirmPrompt;
};

export type EvmFamilyPasskeyStepUpAuth = EvmFamilyPreparedStepUpAuthBase & {
  kind: 'passkey';
  confirmationAuthPayload: {
    signingAuthPlan: Extract<SigningAuthPlan, { kind: 'passkeyReauth' }>;
  };
  plannedPasskeyReconnect: EvmFamilyPasskeyReconnectPlan;
};

export type EvmFamilyPreparedStepUpAuth =
  | EvmFamilyWarmSessionStepUpAuth
  | EvmFamilyEmailOtpStepUpAuth
  | EvmFamilyPasskeyStepUpAuth;

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
  requiredSignatureUses: number;
  explicitAuthErrorLabel: 'EVM' | 'Tempo';
}): Promise<EvmFamilyPreparedStepUpAuth> {
  const requiredSignatureUses = Math.max(
    1,
    Math.floor(Number(args.requiredSignatureUses) || 1),
  );
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
      usesNeeded: requiredSignatureUses,
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
                await stepUpRuntime.emailOtpSigning!.complete({
                  kind: 'email_otp',
                  signingAuthPlan: isEmailOtpSigningAuthPlan(signingAuthPlan)
                    ? signingAuthPlan
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
          if (stepUpRuntime?.passkeyReconnect) {
            plannedPasskeyReconnect = await stepUpRuntime.passkeyReconnect.prepare({
              usesNeeded: requiredSignatureUses,
            });
          }
          return {};
        },
        complete: async ({ confirmation }) => {
          if (!stepUpRuntime?.passkeyReconnect) {
            throw new Error('[chains] passkey reconnect runner is unavailable');
          }
          return await stepUpRuntime.passkeyReconnect.reconnect({
            authorization: {
              kind: 'passkey',
              signingAuthPlan: isPasskeySigningAuthPlan(signingAuthPlan)
                ? signingAuthPlan
                : {
                    kind: 'passkeyReauth',
                    method: 'passkey',
                  },
              credential: confirmation.credential,
              ...(plannedPasskeyReconnect
                ? { plannedPasskeyReconnect }
                : {}),
            },
            usesNeeded: requiredSignatureUses,
          });
        },
      },
    },
  });
  if (prepared.method === 'warm_session') {
    if (!signingAuthPlan || !isWarmSessionSigningAuthPlan(signingAuthPlan)) {
      throw new Error('[chains] warm-session step-up requires an existing warm-session plan');
    }
    return {
      kind: 'warm_session',
      confirmationAuthPayload: {
        signingAuthPlan,
      },
    };
  }

  if (prepared.method === 'email_otp') {
    const stepUpPlan = signingAuthPlanFromPreparedEvmFamilyStepUp({
      signingAuthPlan,
      prepared,
    });
    if (!isEmailOtpSigningAuthPlan(stepUpPlan)) {
      throw new Error('[chains] Email OTP step-up requires an Email OTP signing auth plan');
    }
    return {
      kind: 'email_otp',
      confirmationAuthPayload: {
        signingAuthPlan: stepUpPlan,
      },
      emailOtpPrompt: prepared.prompt,
    };
  }

  const stepUpPlan = signingAuthPlanFromPreparedEvmFamilyStepUp({
    signingAuthPlan,
    prepared,
  });
  if (!isPasskeySigningAuthPlan(stepUpPlan)) {
    throw new Error('[chains] passkey step-up requires a passkey signing auth plan');
  }
  if (!plannedPasskeyReconnect) {
    throw new Error('[chains] passkey ECDSA step-up requires a prepared reconnect challenge');
  }
  return {
    kind: 'passkey',
    confirmationAuthPayload: {
      signingAuthPlan: stepUpPlan,
    },
    plannedPasskeyReconnect,
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
    if (args.prepared.method === 'email_otp' && isEmailOtpSigningAuthPlan(args.signingAuthPlan)) {
      return {
        kind: 'emailOtpReauth',
        method: 'email_otp',
        emailOtpPrompt: args.prepared.prompt,
      };
    }
    return args.signingAuthPlan;
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
