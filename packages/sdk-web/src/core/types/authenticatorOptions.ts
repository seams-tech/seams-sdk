import type * as wasmModule from '../../../../../wasm/near_signer/pkg/wasm_signer_worker.js';
import {
  cloneAuthenticatorOptions,
  UserVerificationPolicy,
  type AuthenticatorOptions,
  type OriginPolicyInput,
} from '@shared/utils/authenticatorOptions';

export {
  cloneAuthenticatorOptions,
  UserVerificationPolicy,
  type AuthenticatorOptions,
  type OriginPolicyInput,
};

export const toEnumUserVerificationPolicy = (
  userVerification: UserVerificationPolicy | undefined,
): wasmModule.UserVerificationPolicy => {
  switch (userVerification) {
    case UserVerificationPolicy.Required:
      return 'required' as unknown as wasmModule.UserVerificationPolicy;
    case UserVerificationPolicy.Preferred:
      return 'preferred' as unknown as wasmModule.UserVerificationPolicy;
    case UserVerificationPolicy.Discouraged:
      return 'discouraged' as unknown as wasmModule.UserVerificationPolicy;
    default:
      return 'preferred' as unknown as wasmModule.UserVerificationPolicy;
  }
};
