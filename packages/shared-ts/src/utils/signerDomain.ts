import { EMAIL_OTP_CHANNEL } from './emailOtpDomain';
import { normalizeOptionalTrimmedString } from './normalize';

export const SIGNER_KINDS = {
  thresholdEd25519: 'threshold-ed25519',
  thresholdEcdsa: 'threshold-ecdsa',
} as const;

export type SignerKind = (typeof SIGNER_KINDS)[keyof typeof SIGNER_KINDS];

export const SIGNER_AUTH_METHODS = {
  passkey: 'passkey',
  emailOtp: EMAIL_OTP_CHANNEL,
} as const;

/** Authentication methods that can authorize a signer capability. */
export type SignerAuthMethod = (typeof SIGNER_AUTH_METHODS)[keyof typeof SIGNER_AUTH_METHODS];

export const WALLET_AUTH_METHODS = {
  passkey: 'passkey',
  emailOtp: EMAIL_OTP_CHANNEL,
} as const;

/** Authentication methods that can be enrolled on a wallet. */
export type WalletAuthMethod = (typeof WALLET_AUTH_METHODS)[keyof typeof WALLET_AUTH_METHODS];

export type WalletAuthMethodSignerResolution =
  | {
      kind: 'supported';
      walletAuthMethod: typeof WALLET_AUTH_METHODS.passkey;
      signerAuthMethod: typeof SIGNER_AUTH_METHODS.passkey;
    }
  | {
      kind: 'supported';
      walletAuthMethod: typeof WALLET_AUTH_METHODS.emailOtp;
      signerAuthMethod: typeof SIGNER_AUTH_METHODS.emailOtp;
    }
  | {
      kind: 'unsupported';
      walletAuthMethod: Exclude<WalletAuthMethod, SignerAuthMethod>;
      signerAuthMethod?: never;
    };

export const WALLET_AUTH_PROOF_METHODS = {
  passkey: SIGNER_AUTH_METHODS.passkey,
  emailOtp: SIGNER_AUTH_METHODS.emailOtp,
  session: 'session',
} as const;

export type WalletAuthProofMethod =
  (typeof WALLET_AUTH_PROOF_METHODS)[keyof typeof WALLET_AUTH_PROOF_METHODS];

export const SIGNING_SESSION_RETENTIONS = {
  session: 'session',
  singleUse: 'single_use',
} as const;

export type SigningSessionRetention =
  (typeof SIGNING_SESSION_RETENTIONS)[keyof typeof SIGNING_SESSION_RETENTIONS];

export const SIGNING_SESSION_POLICIES = {
  session: 'session',
  perOperation: 'per_operation',
} as const;

export type SigningSessionPolicy =
  (typeof SIGNING_SESSION_POLICIES)[keyof typeof SIGNING_SESSION_POLICIES];

export const SENSITIVE_OPERATION_POLICIES = {
  inheritSessionPolicy: 'inherit_session_policy',
  requireFreshSameMethod: 'require_fresh_same_method',
  requirePasskey: 'require_passkey',
  denyEmailOtp: 'deny_email_otp',
} as const;

export type SensitiveOperationPolicy =
  (typeof SENSITIVE_OPERATION_POLICIES)[keyof typeof SENSITIVE_OPERATION_POLICIES];

export const SIGNER_SOURCES = {
  passkeyRegistration: 'passkey_registration',
  emailOtpRegistration: 'email_otp_registration',
  selfHostedImport: 'self_hosted_import',
} as const;

export type SignerSource = (typeof SIGNER_SOURCES)[keyof typeof SIGNER_SOURCES];

export const SIGNER_KIND_VALUES = Object.values(SIGNER_KINDS) as readonly SignerKind[];
export const SIGNER_AUTH_METHOD_VALUES = Object.values(
  SIGNER_AUTH_METHODS,
) as readonly SignerAuthMethod[];
export const WALLET_AUTH_METHOD_VALUES = Object.values(
  WALLET_AUTH_METHODS,
) as readonly WalletAuthMethod[];
export const WALLET_AUTH_PROOF_METHOD_VALUES = Object.values(
  WALLET_AUTH_PROOF_METHODS,
) as readonly WalletAuthProofMethod[];
export const SIGNER_SOURCE_VALUES = Object.values(SIGNER_SOURCES) as readonly SignerSource[];
export const SIGNING_SESSION_POLICY_VALUES = Object.values(
  SIGNING_SESSION_POLICIES,
) as readonly SigningSessionPolicy[];
export const SENSITIVE_OPERATION_POLICY_VALUES = Object.values(
  SENSITIVE_OPERATION_POLICIES,
) as readonly SensitiveOperationPolicy[];

function normalized(value: unknown): string {
  return normalizeOptionalTrimmedString(value)?.toLowerCase() || '';
}

export function isSignerKind(value: unknown): value is SignerKind {
  return (SIGNER_KIND_VALUES as readonly string[]).includes(normalized(value));
}

export function isSignerAuthMethod(value: unknown): value is SignerAuthMethod {
  return (SIGNER_AUTH_METHOD_VALUES as readonly string[]).includes(normalized(value));
}

export function isWalletAuthMethod(value: unknown): value is WalletAuthMethod {
  return (WALLET_AUTH_METHOD_VALUES as readonly string[]).includes(normalized(value));
}

export function resolveSignerAuthMethodForWalletAuthMethod(
  walletAuthMethod: WalletAuthMethod,
): WalletAuthMethodSignerResolution {
  switch (walletAuthMethod) {
    case WALLET_AUTH_METHODS.passkey:
      return {
        kind: 'supported',
        walletAuthMethod,
        signerAuthMethod: SIGNER_AUTH_METHODS.passkey,
      };
    case WALLET_AUTH_METHODS.emailOtp:
      return {
        kind: 'supported',
        walletAuthMethod,
        signerAuthMethod: SIGNER_AUTH_METHODS.emailOtp,
      };
    default: {
      const unsupportedWalletAuthMethod: Exclude<WalletAuthMethod, SignerAuthMethod> =
        walletAuthMethod;
      return {
        kind: 'unsupported',
        walletAuthMethod: unsupportedWalletAuthMethod,
      };
    }
  }
}

export function isWalletAuthProofMethod(value: unknown): value is WalletAuthProofMethod {
  return (WALLET_AUTH_PROOF_METHOD_VALUES as readonly string[]).includes(normalized(value));
}

export function isSignerSource(value: unknown): value is SignerSource {
  return (SIGNER_SOURCE_VALUES as readonly string[]).includes(normalized(value));
}

export function isSigningSessionPolicy(value: unknown): value is SigningSessionPolicy {
  return (SIGNING_SESSION_POLICY_VALUES as readonly string[]).includes(normalized(value));
}

export function isSensitiveOperationPolicy(value: unknown): value is SensitiveOperationPolicy {
  return (SENSITIVE_OPERATION_POLICY_VALUES as readonly string[]).includes(normalized(value));
}
