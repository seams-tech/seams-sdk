import {
  SigningAuthPlanKind,
  type EmailOtpConfirmPrompt,
  type SigningAuthPlan,
} from '@/core/signingEngine/touchConfirm/shared/confirmTypes';
import { WalletAuthPlanKind, type WalletAuthPlan } from '@/core/signingEngine/auth';
import type { KeyRef, SignRequest } from '@/core/signingEngine/interfaces/signing';
import type { ThresholdEcdsaSecp256k1KeyRef } from '@/core/signingEngine/interfaces/signing';
import type {
  SigningOperationIntent,
  SigningSessionPlan,
} from '@/core/signingEngine/session/signingSessionTypes';
import {
  SigningKeyRefIntentKind,
  SigningSessionPlanKind,
} from '@/core/signingEngine/session/signingSessionTypes';
import {
  SigningEventPhase,
  type CreateSigningFlowEventInput,
  type WalletFlowAuthMethod,
  type WalletFlowInteractionKind,
} from '@/core/types/sdkSentEvents';
export { formatEmailOtpSentText } from '@/core/signingEngine/touchConfirm/shared/emailOtpPromptCopy';

export function makeRequestId(prefix: string): string {
  const c = globalThis.crypto;
  if (c?.randomUUID && typeof c.randomUUID === 'function') return c.randomUUID();
  return `${prefix}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

export function inferDigest32FromSignRequest(req: SignRequest): Uint8Array {
  return req.kind === 'digest' ? req.digest32 : req.challenge32;
}

export function asThresholdEcdsaKeyRef(
  value: KeyRef | undefined,
): ThresholdEcdsaSecp256k1KeyRef | null {
  if (!value || typeof value !== 'object') return null;
  return value.type === 'threshold-ecdsa-secp256k1'
    ? (value as ThresholdEcdsaSecp256k1KeyRef)
    : null;
}

export function signingAuthPlanFromWalletAuthPlan(
  plan: WalletAuthPlan,
  emailOtpPrompt?: EmailOtpConfirmPrompt,
): SigningAuthPlan {
  if (plan.kind === WalletAuthPlanKind.WarmSession) {
    return {
      kind: SigningAuthPlanKind.WarmSession,
      method: plan.method,
      accountId: plan.accountId,
      intent: plan.intent,
      ...(plan.curve ? { curve: plan.curve } : {}),
      ...(plan.signingRootId ? { signingRootId: plan.signingRootId } : {}),
      sessionId: plan.sessionId,
      ...(plan.retention !== undefined ? { retention: plan.retention } : {}),
      expiresAtMs: plan.expiresAtMs,
      remainingUses: plan.remainingUses,
    };
  }
  if (plan.kind === WalletAuthPlanKind.EmailOtpReauth) {
    if (!emailOtpPrompt) {
      throw new Error('Email OTP signing auth plan requires an emailOtpPrompt');
    }
    return {
      kind: SigningAuthPlanKind.EmailOtpReauth,
      method: 'email_otp',
      emailOtpPrompt,
    };
  }
  return {
    kind: SigningAuthPlanKind.PasskeyReauth,
    method: 'passkey',
  };
}

export function signingAuthPlanFromSigningSessionPlan(args: {
  plan: Exclude<SigningSessionPlan, { kind: typeof SigningSessionPlanKind.NotReady }>;
  accountId: string;
  intent: SigningOperationIntent;
  curve?: 'ed25519' | 'ecdsa';
  signingRootId?: string;
  expiresAtMs?: number;
  remainingUses?: number;
  emailOtpPrompt?: EmailOtpConfirmPrompt;
}): SigningAuthPlan {
  const plan = args.plan;
  if (plan.kind === SigningSessionPlanKind.WarmSession) {
    if (plan.keyRef.kind !== SigningKeyRefIntentKind.Cached) {
      throw new Error('[SigningEngine] warm signing-session plan requires a cached key ref');
    }
    const expiresAtMs = Math.floor(Number(args.expiresAtMs) || 0);
    const remainingUses = Math.floor(Number(args.remainingUses) || 0);
    if (expiresAtMs <= 0 || remainingUses <= 0) {
      throw new Error(
        '[SigningEngine] warm signing-session auth plan requires positive expiresAtMs and remainingUses',
      );
    }
    return {
      kind: SigningAuthPlanKind.WarmSession,
      method: plan.lane.authMethod,
      accountId: args.accountId,
      intent: args.intent,
      ...(args.curve ? { curve: args.curve } : {}),
      ...(args.signingRootId ? { signingRootId: args.signingRootId } : {}),
      sessionId: String(plan.keyRef.thresholdSessionId),
      retention: plan.lane.retention,
      expiresAtMs,
      remainingUses,
    };
  }
  if (plan.kind === SigningSessionPlanKind.EmailOtpReauth) {
    return {
      kind: SigningAuthPlanKind.EmailOtpReauth,
      method: 'email_otp',
      ...(args.emailOtpPrompt ? { emailOtpPrompt: args.emailOtpPrompt } : {}),
    };
  }
  return {
    kind: SigningAuthPlanKind.PasskeyReauth,
    method: 'passkey',
  };
}

export function emailOtpSigningAuthPlan(emailOtpPrompt: EmailOtpConfirmPrompt): SigningAuthPlan {
  return {
    kind: SigningAuthPlanKind.EmailOtpReauth,
    method: 'email_otp',
    emailOtpPrompt,
  };
}

export function passkeySigningAuthPlan(): SigningAuthPlan {
  return {
    kind: SigningAuthPlanKind.PasskeyReauth,
    method: 'passkey',
  };
}

export async function resolveTouchConfirmSigningAuth(args: {
  needsWebAuthn: boolean;
  signingAuthPlan?: SigningAuthPlan;
  walletAuthPlan?: WalletAuthPlan;
  emailOtpPrompt?: EmailOtpConfirmPrompt;
}): Promise<{
  touchConfirmAuthPayload: { signingAuthPlan: SigningAuthPlan };
}> {
  if (args.signingAuthPlan) {
    const signingAuthPlan =
      args.signingAuthPlan.kind === SigningAuthPlanKind.EmailOtpReauth && args.emailOtpPrompt
        ? { ...args.signingAuthPlan, emailOtpPrompt: args.emailOtpPrompt }
        : args.signingAuthPlan;
    return {
      touchConfirmAuthPayload: { signingAuthPlan },
    };
  }
  if (args.walletAuthPlan) {
    const signingAuthPlan = signingAuthPlanFromWalletAuthPlan(
      args.walletAuthPlan,
      args.emailOtpPrompt,
    );
    return {
      touchConfirmAuthPayload: { signingAuthPlan },
    };
  }
  if (args.emailOtpPrompt) {
    const signingAuthPlan = emailOtpSigningAuthPlan(args.emailOtpPrompt);
    return {
      touchConfirmAuthPayload: { signingAuthPlan },
    };
  }
  if (args.needsWebAuthn) {
    const signingAuthPlan = passkeySigningAuthPlan();
    return {
      touchConfirmAuthPayload: { signingAuthPlan },
    };
  }
  throw new Error('Signing auth resolution requires a concrete SigningAuthPlan');
}

export function resolveTouchConfirmSigningAuthMethod(
  authPlan: Pick<SigningAuthPlan, 'kind'> | WalletAuthPlan | undefined,
  hasEmailOtpPrompt: boolean,
): WalletFlowAuthMethod {
  if (hasEmailOtpPrompt || authPlan?.kind === SigningAuthPlanKind.EmailOtpReauth) return 'email_otp';
  if (authPlan?.kind === SigningAuthPlanKind.WarmSession) return 'warm_session';
  return 'passkey';
}

export function mapTouchConfirmSigningProgress(
  progress: {
    phase: string;
    status: 'running' | 'succeeded' | 'failed';
    message?: string;
    data?: unknown;
  },
  authMethod: WalletFlowAuthMethod,
): Omit<CreateSigningFlowEventInput, 'flowId' | 'accountId' | 'authMethod'> | null {
  const phase = String(progress.phase || '');
  const failed = progress.status === 'failed';
  if (phase === 'intent-confirmation-required') {
    return {
      phase: SigningEventPhase.STEP_05_CONFIRMATION_DISPLAYED,
      status: 'waiting_for_user',
      interaction: { kind: 'transaction_confirmation', overlay: 'show' },
      data: toEventData(progress.data),
    };
  }
  if (phase === 'confirmation.complete') {
    if (failed) {
      return {
        phase: SigningEventPhase.STEP_05_CONFIRMATION_CANCELLED,
        status: 'cancelled',
        interaction: { kind: 'transaction_confirmation', overlay: 'hide' },
        error: { message: progress.message || 'Transaction rejected' },
        data: toEventData(progress.data),
      };
    }
    return {
      phase:
        authMethod === 'email_otp'
          ? SigningEventPhase.STEP_06_AUTH_EMAIL_OTP_VERIFY_SUCCEEDED
          : SigningEventPhase.STEP_05_CONFIRMATION_APPROVED,
      status: 'succeeded',
      interaction: {
        kind: authMethod === 'email_otp' ? 'otp_input' : 'transaction_confirmation',
        overlay: 'hide',
      },
      data: toEventData(progress.data),
    };
  }
  if (phase === 'auth.passkey.prompt.started') {
    return {
      phase: SigningEventPhase.STEP_06_AUTH_PASSKEY_PROMPT_STARTED,
      status: 'waiting_for_user',
      interaction: { kind: 'passkey_assert', overlay: 'show' },
      data: toEventData(progress.data),
    };
  }
  if (phase === 'auth.passkey.prompt.succeeded') {
    const interactionKind: WalletFlowInteractionKind = 'passkey_assert';
    if (failed) {
      return {
        phase: SigningEventPhase.FAILED,
        status: 'failed',
        interaction: { kind: interactionKind, overlay: 'hide' },
        error: { message: progress.message || 'Transaction signing failed' },
        data: toEventData(progress.data),
      };
    }
    return {
      phase: SigningEventPhase.STEP_06_AUTH_PASSKEY_PROMPT_SUCCEEDED,
      status: 'succeeded',
      interaction: { kind: interactionKind, overlay: 'hide' },
      data: toEventData(progress.data),
    };
  }
  return null;
}

export function resolveKeyRefForSignRequest(args: {
  signReq: SignRequest;
  keyRefsByAlgorithm?: Partial<Record<SignRequest['algorithm'], KeyRef>>;
}): { signReq: SignRequest; keyRef: KeyRef } {
  const keyRef = args.keyRefsByAlgorithm?.[args.signReq.algorithm];
  if (!keyRef) {
    throw new Error(`[chains] missing keyRef for algorithm: ${args.signReq.algorithm}`);
  }
  return { signReq: args.signReq, keyRef };
}

function toEventData(value: unknown): Record<string, unknown> | undefined {
  if (value == null) return undefined;
  if (typeof value === 'object' && !Array.isArray(value)) return value as Record<string, unknown>;
  return { value };
}
