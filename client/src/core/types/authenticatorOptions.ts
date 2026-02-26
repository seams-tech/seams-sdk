import * as wasmModule from '../../../../wasm/near_signer/pkg/wasm_signer_worker.js';

/**
 * User verification policy for WebAuthn authenticators
 *
 * @example
 * ```typescript
 * // Require user verification (PIN, fingerprint, etc.)
 * UserVerificationPolicy.Required
 *
 * // Prefer user verification but don't require it
 * UserVerificationPolicy.Preferred
 *
 * // Discourage user verification (for performance)
 * UserVerificationPolicy.Discouraged
 * ```
 */
export enum UserVerificationPolicy {
  Required = 'required',
  Preferred = 'preferred',
  Discouraged = 'discouraged',
}

/**
 * Origin policy input for WebAuthn registration (matches WASM OriginPolicyInput struct)
 * Note: choose only one of the fields: single, all_subdomains, multiple
 */
export interface OriginPolicyInput {
  single: boolean | undefined;
  all_subdomains: boolean | undefined;
  multiple: string[] | undefined;
}

export const toEnumUserVerificationPolicy = (
  userVerification: UserVerificationPolicy | undefined,
): wasmModule.UserVerificationPolicy => {
  switch (userVerification) {
    case UserVerificationPolicy.Required:
      return wasmModule.UserVerificationPolicy.Required;
    case UserVerificationPolicy.Preferred:
      return wasmModule.UserVerificationPolicy.Preferred;
    case UserVerificationPolicy.Discouraged:
      return wasmModule.UserVerificationPolicy.Discouraged;
    default:
      return wasmModule.UserVerificationPolicy.Preferred;
  }
};

export interface AuthenticatorOptions {
  userVerification: UserVerificationPolicy;
  originPolicy: OriginPolicyInput;
}

type AuthenticatorOptionsLike =
  | AuthenticatorOptions
  | {
      userVerification: UserVerificationPolicy;
      originPolicy: {
        single: boolean | undefined;
        all_subdomains: boolean | undefined;
        multiple: readonly string[] | string[] | undefined;
      };
    };

/**
 * Default authenticator options (matches contract defaults)
 */
export const DEFAULT_AUTHENTICATOR_OPTIONS: AuthenticatorOptions = {
  userVerification: UserVerificationPolicy.Preferred,
  originPolicy: {
    single: undefined,
    all_subdomains: true,
    multiple: undefined,
  },
};

export function cloneAuthenticatorOptions(
  options: AuthenticatorOptionsLike | undefined,
): AuthenticatorOptions | undefined {
  if (!options) return undefined;
  const multiple = options.originPolicy?.multiple;
  return {
    userVerification: options.userVerification,
    originPolicy: {
      single: options.originPolicy?.single,
      all_subdomains: options.originPolicy?.all_subdomains,
      multiple: Array.isArray(multiple) ? [...multiple] : undefined,
    },
  };
}
