export enum UserVerificationPolicy {
  Required = 'required',
  Preferred = 'preferred',
  Discouraged = 'discouraged',
}

export interface OriginPolicyInput {
  single: boolean | undefined;
  all_subdomains: boolean | undefined;
  multiple: string[] | undefined;
}

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

export function cloneAuthenticatorOptions(
  options: AuthenticatorOptionsLike,
): AuthenticatorOptions {
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
