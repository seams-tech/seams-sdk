import type {
  WalletAuthCurve,
  WalletAuthIntent,
  SigningSessionRetention,
  WalletAuthMethod,
} from '@/core/types/seams';

export interface UserConfirmProgressEvent {
  requestId: string;
  step: number;
  phase: string;
  status: 'running' | 'succeeded' | 'failed';
  message?: string;
  data?: unknown;
}

export type SigningAuthMode = 'webauthn' | 'warmSession' | 'emailOtp';

export const SigningAuthPlanKind = {
  WarmSession: 'warmSession',
  PasskeyReauth: 'passkeyReauth',
  EmailOtpReauth: 'emailOtpReauth',
} as const;

export type SigningAuthPlanKind =
  (typeof SigningAuthPlanKind)[keyof typeof SigningAuthPlanKind];

export interface EmailOtpConfirmPrompt {
  challengeId: string;
  emailHint?: string;
  title?: string;
  body?: string;
  helperText?: string;
  resendDebounceMs?: number;
  onResend?: () =>
    | Promise<{ challengeId: string; emailHint?: string } | void>
    | { challengeId: string; emailHint?: string }
    | void;
}

export type SigningAuthPlan =
  | {
      kind: typeof SigningAuthPlanKind.WarmSession;
      method: WalletAuthMethod;
      accountId: string;
      intent: WalletAuthIntent;
      curve?: WalletAuthCurve;
      signingRootId?: string;
      sessionId: string;
      retention?: SigningSessionRetention | null;
      expiresAtMs: number;
      remainingUses: number;
    }
  | {
      kind: typeof SigningAuthPlanKind.PasskeyReauth;
      method: 'passkey';
    }
  | {
      kind: typeof SigningAuthPlanKind.EmailOtpReauth;
      method: 'email_otp';
      emailOtpPrompt?: EmailOtpConfirmPrompt;
    };

export function signingAuthModeFromSigningAuthPlan(plan: SigningAuthPlan): SigningAuthMode {
  if (plan.kind === SigningAuthPlanKind.WarmSession) return 'warmSession';
  if (plan.kind === SigningAuthPlanKind.EmailOtpReauth) return 'emailOtp';
  return 'webauthn';
}
