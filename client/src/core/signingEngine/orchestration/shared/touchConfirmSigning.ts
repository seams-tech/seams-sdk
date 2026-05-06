import {
  SigningAuthPlanKind,
  type EmailOtpConfirmPrompt,
  type SigningAuthPlan,
} from '@/core/signingEngine/touchConfirm/shared/confirmTypes';
import { WalletAuthPlanKind, type WalletAuthPlan } from '@/core/signingEngine/auth';
import type { SignRequest } from '@/core/signingEngine/interfaces/signing';
import type {
  SigningOperationIntent,
  SigningSessionPlan,
} from '@/core/signingEngine/session/signingSession/types';
import {
  SigningKeyRefIntentKind,
  SigningSessionPlanKind,
} from '@/core/signingEngine/session/signingSession/types';
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

export type TouchConfirmSigningAuthInput =
  | {
      kind: 'signing_plan';
      signingAuthPlan: SigningAuthPlan;
      emailOtpPrompt: EmailOtpConfirmPrompt | null;
    }
  | {
      kind: 'wallet_plan';
      walletAuthPlan: WalletAuthPlan;
      emailOtpPrompt: EmailOtpConfirmPrompt | null;
    }
  | {
      kind: 'email_otp';
      emailOtpPrompt: EmailOtpConfirmPrompt;
    }
  | {
      kind: 'passkey';
    };

export async function resolveTouchConfirmSigningAuth(args: TouchConfirmSigningAuthInput): Promise<{
  touchConfirmAuthPayload: { signingAuthPlan: SigningAuthPlan };
}> {
  if (args.kind === 'signing_plan') {
    const signingAuthPlan =
      args.signingAuthPlan.kind === SigningAuthPlanKind.EmailOtpReauth && args.emailOtpPrompt
        ? { ...args.signingAuthPlan, emailOtpPrompt: args.emailOtpPrompt }
        : args.signingAuthPlan;
    return {
      touchConfirmAuthPayload: { signingAuthPlan },
    };
  }
  if (args.kind === 'wallet_plan') {
    const signingAuthPlan = signingAuthPlanFromWalletAuthPlan(
      args.walletAuthPlan,
      args.emailOtpPrompt || undefined,
    );
    return {
      touchConfirmAuthPayload: { signingAuthPlan },
    };
  }
  if (args.kind === 'email_otp') {
    const signingAuthPlan = emailOtpSigningAuthPlan(args.emailOtpPrompt);
    return {
      touchConfirmAuthPayload: { signingAuthPlan },
    };
  }
  if (args.kind === 'passkey') {
    const signingAuthPlan = passkeySigningAuthPlan();
    return {
      touchConfirmAuthPayload: { signingAuthPlan },
    };
  }
  const exhaustive: never = args;
  throw new Error(`Signing auth resolution received unsupported input ${String(exhaustive)}`);
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

function toEventData(value: unknown): Record<string, unknown> | undefined {
  if (value == null) return undefined;
  if (typeof value === 'object' && !Array.isArray(value)) return value as Record<string, unknown>;
  return { value };
}
