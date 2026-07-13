import type {
  WalletAuthCurve,
  WalletAuthIntent,
  SigningSessionRetention,
  WalletAuthMethod,
} from '@/core/types/seams';
import type { TransactionContext } from '@/core/types/rpc';
import type { NearTransactionReadiness } from '../nonce/nearTransactionReadiness';
import type {
  WebAuthnAuthenticationCredential,
  WebAuthnRegistrationCredential,
} from '@/core/types/webauthn';
import type { NonceLeaseRef } from '../interfaces/nonceLease';

export interface UserConfirmProgressEvent {
  requestId: string;
  step: number;
  phase: string;
  status: 'running' | 'succeeded' | 'failed';
  message?: string;
  data?: unknown;
}

export type SerializableCredential =
  | WebAuthnAuthenticationCredential
  | WebAuthnRegistrationCredential;

export type RegistrationConfirmationDiagnostics = {
  kind: 'registration_confirmation_diagnostics_v1';
  workerReadyMs: number;
  workerRequestRoundTripMs: number;
  workerResponseValidationMs: number;
  requestSetupMs: number;
  promptUserMs: number;
  promptElementDefineMs: number;
  promptMountMs: number;
  promptHostFirstUpdateMs: number;
  promptHostInteractiveMs: number;
  promptConfirmEventMs: number;
  promptDecisionWaitMs: number;
  credentialCreateStartMs: number;
  credentialCreateMs: number;
  credentialSerializeMs: number;
  duplicateRetryCount: number;
  mainThreadTotalMs: number;
};

export type ForbiddenMainThreadSecrets = {
  prfOutput?: never;
  prf_output?: never;
  wrapKeySeed?: never;
  wrapKeySalt?: never;
  prfKey?: never;
};

export type UserConfirmDecisionBase = ForbiddenMainThreadSecrets & {
  requestId: string;
  intentDigest?: string;
  _confirmHandle?: { close: (confirmed: boolean) => void };
};

type UserConfirmSuccessDecisionBase = UserConfirmDecisionBase & {
  confirmed: true;
  credential?: SerializableCredential;
  otpCode?: string;
  emailOtpChallengeId?: string;
  registrationDiagnostics?: RegistrationConfirmationDiagnostics;
  error?: never;
};

export type UserConfirmSuccessDecision = UserConfirmSuccessDecisionBase &
  (
    | {
        nearTransactionReadiness: NearTransactionReadiness;
        transactionContext?: never;
        nonceLeases?: never;
      }
    | {
        nearTransactionReadiness?: never;
        transactionContext: TransactionContext;
        nonceLeases?: NonceLeaseRef[];
      }
    | {
        nearTransactionReadiness?: never;
        transactionContext?: never;
        nonceLeases?: never;
      }
  );

export type UserConfirmFailureDecision = UserConfirmDecisionBase & {
  confirmed: false;
  error?: string;
  registrationDiagnostics?: RegistrationConfirmationDiagnostics;
  credential?: never;
  otpCode?: never;
  emailOtpChallengeId?: never;
  transactionContext?: never;
  nonceLeases?: never;
  nearTransactionReadiness?: never;
};

export type UserConfirmDecision = UserConfirmSuccessDecision | UserConfirmFailureDecision;

export type SigningAuthMode = 'webauthn' | 'warmSession' | 'emailOtp';

export const SigningAuthPlanKind = {
  WarmSession: 'warmSession',
  PasskeyReauth: 'passkeyReauth',
  EmailOtpReauth: 'emailOtpReauth',
} as const;

export type SigningAuthPlanKind = (typeof SigningAuthPlanKind)[keyof typeof SigningAuthPlanKind];

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

export type WebAuthnChallenge =
  | {
      kind: 'intent_digest';
      challengeB64u: string;
      digest32B64u?: never;
      requestId?: never;
      thresholdSessionId?: never;
      signingGrantId?: never;
    }
  | {
      kind: 'threshold_session_policy';
      digest32B64u: string;
      challengeB64u?: never;
      requestId?: never;
      thresholdSessionId?: never;
      signingGrantId?: never;
    }
  | {
      kind: 'ecdsa_role_local_bootstrap';
      digest32B64u: string;
      requestId: string;
      thresholdSessionId: string;
      signingGrantId: string;
      challengeB64u?: never;
    };

export function isWarmSessionSigningAuthPlan(
  plan: Pick<SigningAuthPlan, 'kind'> | null | undefined,
): plan is Extract<SigningAuthPlan, { kind: typeof SigningAuthPlanKind.WarmSession }> {
  return plan?.kind === SigningAuthPlanKind.WarmSession;
}

export function isPasskeySigningAuthPlan(
  plan: Pick<SigningAuthPlan, 'kind'> | null | undefined,
): plan is Extract<SigningAuthPlan, { kind: typeof SigningAuthPlanKind.PasskeyReauth }> {
  return plan?.kind === SigningAuthPlanKind.PasskeyReauth;
}

export function isEmailOtpSigningAuthPlan(
  plan: Pick<SigningAuthPlan, 'kind'> | null | undefined,
): plan is Extract<SigningAuthPlan, { kind: typeof SigningAuthPlanKind.EmailOtpReauth }> {
  return plan?.kind === SigningAuthPlanKind.EmailOtpReauth;
}

export function signingAuthModeFromSigningAuthPlan(plan: SigningAuthPlan): SigningAuthMode {
  if (plan.kind === SigningAuthPlanKind.WarmSession) return 'warmSession';
  if (plan.kind === SigningAuthPlanKind.EmailOtpReauth) return 'emailOtp';
  return 'webauthn';
}

export type StepUpMethod =
  | 'passkey'
  | 'email_otp'
  | 'authenticator_otp'
  | 'magic_link'
  | 'password';

export type PasskeyPromptPlan = {
  title?: string;
  body?: string;
};

export type StepUpWarmSessionAuthorization = {
  method: WalletAuthMethod;
  sessionId: string;
  expiresAtMs: number;
  remainingUses: number;
};

export type StepUpPolicy =
  | {
      kind: 'use_selected_lane';
    }
  | {
      kind: 'force_method';
      method: StepUpMethod;
    }
  | {
      kind: 'reuse_warm_session';
      authorization: StepUpWarmSessionAuthorization;
    };

export type PasskeyStepUpConfirmation = {
  credential: WebAuthnAuthenticationCredential;
};

export type EmailOtpStepUpConfirmation = {
  otpCode: string;
};

export type StepUpAuthorizationResult<TPasskeyAuthorization, TEmailOtpAuthorization> =
  | {
      method: 'warm_session';
      authorization: StepUpWarmSessionAuthorization;
    }
  | {
      method: 'passkey';
      authorization: TPasskeyAuthorization;
    }
  | {
      method: 'email_otp';
      authorization: TEmailOtpAuthorization;
    };

export type WarmSessionStepUpAuthorization<
  TSigningAuthPlan extends Extract<
    SigningAuthPlan,
    { kind: typeof SigningAuthPlanKind.WarmSession }
  >,
> = {
  kind: 'warm_session';
  signingAuthPlan: TSigningAuthPlan;
  sessionId: string;
  expiresAtMs: number;
  remainingUses: number;
};

export type PasskeyStepUpAuthorization<
  TSigningAuthPlan extends Extract<
    SigningAuthPlan,
    { kind: typeof SigningAuthPlanKind.PasskeyReauth }
  >,
  TIdentity extends object = Record<never, never>,
> = {
  kind: 'passkey';
  signingAuthPlan: TSigningAuthPlan;
  credential: WebAuthnAuthenticationCredential;
} & TIdentity;

export type EmailOtpStepUpAuthorization<
  TSigningAuthPlan extends Extract<
    SigningAuthPlan,
    { kind: typeof SigningAuthPlanKind.EmailOtpReauth }
  >,
  TIdentity extends object = Record<never, never>,
> = {
  kind: 'email_otp';
  signingAuthPlan: TSigningAuthPlan;
  challengeId: string;
  otpCode: string;
  emailHint?: string;
} & TIdentity;
