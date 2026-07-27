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
import type { EvmFamilyThresholdEcdsaOperation } from './thresholdAdmission';
import type {
  EvmFamilyEcdsaEmailOtpStepUpAuthorization,
  EvmFamilyEcdsaPasskeyStepUpAuthorization,
} from './stepUpAuthorization';
import type { EvmFamilySigningAuthSideEffect } from './freshAuthRetryPolicy';
import type { OperationDigestSet } from '@shared/authorization/operationFingerprint';
import type { ReadySecp256k1SigningMaterial } from './signers/secp256k1';
import type { PreparedEcdsaOperationStepUp } from '../../threshold/ecdsa/operationStepUp';

export type EvmFamilyEmailOtpStepUpRuntime = {
  prepare: () => Promise<{ challengeId: string; emailHint?: string }>;
  resend?: () => Promise<{ challengeId: string; emailHint?: string }>;
};

export type EvmFamilyOperationStepUpRuntime = {
  prepare: (args: {
    operation: EvmFamilyThresholdEcdsaOperation;
    operationDigests: OperationDigestSet;
    material: ReadySecp256k1SigningMaterial;
  }) => Promise<PreparedEcdsaOperationStepUp>;
  authorize: (args: {
    authorization:
      | EvmFamilyEcdsaEmailOtpStepUpAuthorization
      | EvmFamilyEcdsaPasskeyStepUpAuthorization;
    prepared: PreparedEcdsaOperationStepUp;
    material: ReadySecp256k1SigningMaterial;
  }) => Promise<ReadySecp256k1SigningMaterial>;
};

export type EvmFamilyThresholdEcdsaStepUpRuntime = {
  emailOtpSigning?: EvmFamilyEmailOtpStepUpRuntime;
  operationStepUp: EvmFamilyOperationStepUpRuntime;
  onAuthSideEffectStarted?: (sideEffect: EvmFamilySigningAuthSideEffect) => void;
};

export type EvmFamilyThresholdEcdsaStepUp =
  | {
      kind: 'not_required';
    }
  | {
      kind: 'required';
      authPlan: {
        kind: 'planned';
        signingAuthPlan: SigningAuthPlan;
      };
      operation: EvmFamilyThresholdEcdsaOperation;
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
};

export type EvmFamilyPreparedStepUpAuth =
  | EvmFamilyWarmSessionStepUpAuth
  | EvmFamilyEmailOtpStepUpAuth
  | EvmFamilyPasskeyStepUpAuth;

export function signingAuthPlanFromThresholdEcdsaStepUp(
  stepUp: EvmFamilyThresholdEcdsaStepUp,
): SigningAuthPlan | undefined {
  return stepUp.kind === 'required' ? stepUp.authPlan.signingAuthPlan : undefined;
}

export async function requireEvmFamilyStepUpAuth(args: {
  thresholdEcdsaStepUp: EvmFamilyThresholdEcdsaStepUp;
  hasThresholdEcdsaRequest: boolean;
  needsWebAuthn: boolean;
  requiredSignatureUses: number;
  explicitAuthErrorLabel: 'EVM' | 'Tempo';
}): Promise<EvmFamilyPreparedStepUpAuth> {
  const signingAuthPlan = signingAuthPlanFromThresholdEcdsaStepUp(args.thresholdEcdsaStepUp);
  const runtime =
    args.thresholdEcdsaStepUp.kind === 'required'
      ? args.thresholdEcdsaStepUp.runtime
      : undefined;
  const selectedLane = resolveEvmFamilyStepUpLane({
    signingAuthPlan,
    hasEmailOtpSigning: Boolean(runtime?.emailOtpSigning),
    hasThresholdEcdsaRequest: args.hasThresholdEcdsaRequest,
    needsWebAuthn: args.needsWebAuthn,
  });
  if (!selectedLane) {
    throw new Error(
      `[chains] ${args.explicitAuthErrorLabel} signing requires explicit auth input`,
    );
  }
  const prepared = await prepareStepUpAuth({
    operation: {
      kind: 'evm_family_threshold_ecdsa_step_up' as const,
      usesNeeded: Math.max(1, Math.floor(Number(args.requiredSignatureUses) || 1)),
    },
    selectedLane,
    policy: stepUpPolicyFromSigningAuthPlan(signingAuthPlan),
    methods: {
      ...(runtime?.emailOtpSigning
        ? {
            emailOtp: {
              method: 'email_otp' as const,
              prepareChallenge: runtime.emailOtpSigning.prepare,
              ...(runtime.emailOtpSigning.resend
                ? { resendChallenge: runtime.emailOtpSigning.resend }
                : {}),
              complete: async () => undefined,
            },
          }
        : {}),
      passkey: {
        method: 'passkey' as const,
        prepare: async () => ({}),
        complete: async () => undefined,
      },
    },
  });
  if (prepared.method === 'warm_session') {
    if (!signingAuthPlan || !isWarmSessionSigningAuthPlan(signingAuthPlan)) {
      throw new Error('[chains] warm-session step-up requires an existing warm-session plan');
    }
    return {
      kind: 'warm_session',
      confirmationAuthPayload: { signingAuthPlan },
    };
  }
  if (prepared.method === 'email_otp') {
    const plan = signingAuthPlanFromPreparedEvmFamilyStepUp({ signingAuthPlan, prepared });
    if (!isEmailOtpSigningAuthPlan(plan)) {
      throw new Error('[chains] Email OTP step-up requires an Email OTP signing auth plan');
    }
    return {
      kind: 'email_otp',
      confirmationAuthPayload: { signingAuthPlan: plan },
      emailOtpPrompt: prepared.prompt,
    };
  }
  const plan = signingAuthPlanFromPreparedEvmFamilyStepUp({ signingAuthPlan, prepared });
  if (!isPasskeySigningAuthPlan(plan)) {
    throw new Error('[chains] passkey step-up requires a passkey signing auth plan');
  }
  return {
    kind: 'passkey',
    confirmationAuthPayload: { signingAuthPlan: plan },
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
    return { kind: 'passkeyReauth', method: 'passkey' };
  }
  throw new Error('[chains] warm-session step-up requires an existing signing auth plan');
}
