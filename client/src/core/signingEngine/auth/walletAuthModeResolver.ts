import type {
  SigningSessionRetention,
  WalletAuthMethod,
} from '@/core/types/tatchi';
import { WALLET_AUTH_METHODS } from '@shared/utils';
import { normalizePositiveInteger, toTrimmedString } from '@shared/utils/validation';

export type WalletAuthIntent =
  | 'wallet_unlock'
  | 'transaction_sign'
  | 'ed25519_export'
  | 'ecdsa_export'
  | 'session_mint';

export type WalletAuthCurve = 'ed25519' | 'ecdsa';

export type AccountAuthMetadata = {
  primaryAuthMethod: WalletAuthMethod;
  linkedAuthMethods: WalletAuthMethod[];
  email?: string;
  passkeyCredentialIds?: string[];
};

export type PasskeyWalletAuthProof = {
  method: typeof WALLET_AUTH_METHODS.passkey;
  webauthnAuthentication: unknown;
  prfOutput?: Uint8Array;
};

export type EmailOtpWalletAuthProof = {
  method: typeof WALLET_AUTH_METHODS.emailOtp;
  emailOtpAuthentication: unknown;
};

export type WalletAuthProof = PasskeyWalletAuthProof | EmailOtpWalletAuthProof;

export type WalletAuthPolicyErrorCode =
  | 'passkey_step_up_required'
  | 'fresh_email_otp_required'
  | 'operation_blocked_by_policy';

export type WalletAuthPolicy =
  | 'export_requires_passkey'
  | 'sensitive_operation_requires_passkey'
  | 'sensitive_operation_requires_fresh_email_otp'
  | 'email_otp_denied_by_policy';

export const WalletAuthPlanKind = {
  WarmSession: 'warmSession',
  PasskeyReauth: 'passkeyReauth',
  EmailOtpReauth: 'emailOtpReauth',
} as const;

export type WalletAuthPlanKind =
  (typeof WalletAuthPlanKind)[keyof typeof WalletAuthPlanKind];

export type WalletAuthPlan =
  | {
      kind: typeof WalletAuthPlanKind.WarmSession;
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
      kind: typeof WalletAuthPlanKind.PasskeyReauth;
      method: typeof WALLET_AUTH_METHODS.passkey;
      challenge: () => Promise<unknown>;
      complete: (response: unknown) => Promise<PasskeyWalletAuthProof>;
    }
  | {
      kind: typeof WalletAuthPlanKind.EmailOtpReauth;
      method: typeof WALLET_AUTH_METHODS.emailOtp;
      challenge: () => Promise<{ challengeId: string; email: string }>;
      complete: (input: {
        challengeId: string;
        code: string;
      }) => Promise<EmailOtpWalletAuthProof>;
    };

export type ResolveWalletAuthPlanInput = {
  accountId: string;
  accountAuth: AccountAuthMetadata;
  intent: WalletAuthIntent;
  curve?: WalletAuthCurve;
};

export interface WalletAuthModeResolver {
  resolveWalletAuthPlan(input: ResolveWalletAuthPlanInput): Promise<WalletAuthPlan>;
}

export type PasskeyWalletAuthPlan = Extract<
  WalletAuthPlan,
  { kind: typeof WalletAuthPlanKind.PasskeyReauth }
>;
export type EmailOtpWalletAuthPlan = Extract<
  WalletAuthPlan,
  { kind: typeof WalletAuthPlanKind.EmailOtpReauth }
>;
export type WarmSessionWalletAuthPlan = Extract<
  WalletAuthPlan,
  { kind: typeof WalletAuthPlanKind.WarmSession }
>;

export interface PasskeyWalletAuthAdapter {
  createPasskeyReauthPlan(input: ResolveWalletAuthPlanInput): Promise<PasskeyWalletAuthPlan>;
}

export interface EmailOtpWalletAuthAdapter {
  createEmailOtpReauthPlan(input: ResolveWalletAuthPlanInput): Promise<EmailOtpWalletAuthPlan>;
}

export interface WarmSessionWalletAuthResolver {
  resolveWarmSessionPlan(input: ResolveWalletAuthPlanInput): Promise<WarmSessionWalletAuthPlan | null>;
}

export function resolveAccountAuthMetadataForSignerSource(args?: {
  source?: unknown;
  email?: string;
  passkeyCredentialIds?: string[];
}): AccountAuthMetadata {
  const primaryAuthMethod =
    args?.source === WALLET_AUTH_METHODS.emailOtp
      ? WALLET_AUTH_METHODS.emailOtp
      : WALLET_AUTH_METHODS.passkey;
  return {
    primaryAuthMethod,
    linkedAuthMethods: [primaryAuthMethod],
    ...(args?.email ? { email: args.email } : {}),
    ...(args?.passkeyCredentialIds?.length
      ? { passkeyCredentialIds: args.passkeyCredentialIds }
      : {}),
  };
}

export class WalletAuthModeResolutionError extends Error {
  readonly code:
    | 'missing_auth_metadata'
    | 'unsupported_primary_auth_method'
    | 'unlinked_primary_auth_method'
    | 'invalid_warm_session_plan';

  constructor(
    code: WalletAuthModeResolutionError['code'],
    message: string,
  ) {
    super(message);
    this.name = 'WalletAuthModeResolutionError';
    this.code = code;
  }
}

export class WalletAuthPolicyError extends Error {
  readonly code: WalletAuthPolicyErrorCode;
  readonly policy: WalletAuthPolicy;
  readonly intent?: WalletAuthIntent;
  readonly operationLabel?: string;

  constructor(args: {
    code: WalletAuthPolicyErrorCode;
    policy: WalletAuthPolicy;
    message: string;
    intent?: WalletAuthIntent;
    operationLabel?: string;
  }) {
    super(args.message);
    this.name = 'WalletAuthPolicyError';
    this.code = args.code;
    this.policy = args.policy;
    this.intent = args.intent;
    this.operationLabel = args.operationLabel;
  }
}

function assertWarmSessionPlanMatchesRequest(
  plan: WarmSessionWalletAuthPlan,
  input: ResolveWalletAuthPlanInput,
): void {
  const accountId = toTrimmedString(plan.accountId);
  const sessionId = toTrimmedString(plan.sessionId);
  const expiresAtMs = normalizePositiveInteger(plan.expiresAtMs) || 0;
  const remainingUses = normalizePositiveInteger(plan.remainingUses) || 0;

  if (accountId !== input.accountId) {
    throw new WalletAuthModeResolutionError(
      'invalid_warm_session_plan',
      `warm session accountId mismatch: expected ${input.accountId}, got ${accountId || '<empty>'}`,
    );
  }
  if (plan.intent !== input.intent) {
    throw new WalletAuthModeResolutionError(
      'invalid_warm_session_plan',
      `warm session intent mismatch: expected ${input.intent}, got ${String(plan.intent || '')}`,
    );
  }
  if (plan.method !== input.accountAuth.primaryAuthMethod) {
    throw new WalletAuthModeResolutionError(
      'invalid_warm_session_plan',
      `warm session auth method mismatch: expected ${input.accountAuth.primaryAuthMethod}, got ${String(plan.method || '')}`,
    );
  }
  if (input.curve && plan.curve !== input.curve) {
    throw new WalletAuthModeResolutionError(
      'invalid_warm_session_plan',
      `warm session curve mismatch: expected ${input.curve}, got ${String(plan.curve || '')}`,
    );
  }
  if (!sessionId) {
    throw new WalletAuthModeResolutionError(
      'invalid_warm_session_plan',
      'warm session sessionId is required',
    );
  }
  if (!expiresAtMs) {
    throw new WalletAuthModeResolutionError(
      'invalid_warm_session_plan',
      'warm session expiresAtMs must be a positive integer',
    );
  }
  if (!remainingUses) {
    throw new WalletAuthModeResolutionError(
      'invalid_warm_session_plan',
      'warm session remainingUses must be a positive integer',
    );
  }
}

export function createPasskeyWalletAuthAdapter(args: {
  challenge: (input: ResolveWalletAuthPlanInput) => Promise<unknown>;
  complete: (input: {
    request: ResolveWalletAuthPlanInput;
    response: unknown;
  }) => Promise<PasskeyWalletAuthProof>;
}): PasskeyWalletAuthAdapter {
  return {
    async createPasskeyReauthPlan(input) {
      return {
        kind: WalletAuthPlanKind.PasskeyReauth,
        method: WALLET_AUTH_METHODS.passkey,
        challenge: () => args.challenge(input),
        complete: (response) => args.complete({ request: input, response }),
      };
    },
  };
}

export function createEmailOtpWalletAuthAdapter(args: {
  challenge: (
    input: ResolveWalletAuthPlanInput,
  ) => Promise<{ challengeId: string; email: string }>;
  complete: (input: {
    request: ResolveWalletAuthPlanInput;
    challengeId: string;
    code: string;
  }) => Promise<EmailOtpWalletAuthProof>;
}): EmailOtpWalletAuthAdapter {
  return {
    async createEmailOtpReauthPlan(input) {
      return {
        kind: WalletAuthPlanKind.EmailOtpReauth,
        method: WALLET_AUTH_METHODS.emailOtp,
        challenge: () => args.challenge(input),
        complete: ({ challengeId, code }) =>
          args.complete({
            request: input,
            challengeId,
            code,
          }),
      };
    },
  };
}

export function createWalletAuthModeResolver(args: {
  passkey: PasskeyWalletAuthAdapter;
  emailOtp: EmailOtpWalletAuthAdapter;
  warmSession?: WarmSessionWalletAuthResolver;
}): WalletAuthModeResolver {
  return {
    async resolveWalletAuthPlan(input) {
      const accountAuth = input.accountAuth;
      if (!accountAuth || typeof accountAuth.primaryAuthMethod !== 'string') {
        throw new WalletAuthModeResolutionError(
          'missing_auth_metadata',
          'wallet auth metadata is required',
        );
      }

      const linkedAuthMethods = Array.isArray(accountAuth.linkedAuthMethods)
        ? accountAuth.linkedAuthMethods
        : [];
      if (!linkedAuthMethods.includes(accountAuth.primaryAuthMethod)) {
        throw new WalletAuthModeResolutionError(
          'unlinked_primary_auth_method',
          `primary auth method is not linked: ${accountAuth.primaryAuthMethod}`,
        );
      }

      if (
        accountAuth.primaryAuthMethod !== WALLET_AUTH_METHODS.passkey &&
        accountAuth.primaryAuthMethod !== WALLET_AUTH_METHODS.emailOtp
      ) {
        throw new WalletAuthModeResolutionError(
          'unsupported_primary_auth_method',
          `unsupported primary auth method: ${String(accountAuth.primaryAuthMethod)}`,
        );
      }

      const warmSession = await args.warmSession?.resolveWarmSessionPlan(input);
      if (warmSession) {
        assertWarmSessionPlanMatchesRequest(warmSession, input);
        return warmSession;
      }

      if (accountAuth.primaryAuthMethod === WALLET_AUTH_METHODS.passkey) {
        return args.passkey.createPasskeyReauthPlan(input);
      }
      if (accountAuth.primaryAuthMethod === WALLET_AUTH_METHODS.emailOtp) {
        return args.emailOtp.createEmailOtpReauthPlan(input);
      }

      throw new WalletAuthModeResolutionError(
        'unsupported_primary_auth_method',
        `unsupported primary auth method: ${String(accountAuth.primaryAuthMethod)}`,
      );
    },
  };
}
