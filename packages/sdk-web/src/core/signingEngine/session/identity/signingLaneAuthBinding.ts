import type { RpId } from './evmFamilyEcdsaIdentity';
import { SIGNER_AUTH_METHODS, type SignerAuthMethod } from '@shared/utils/signerDomain';

export type SigningLaneAuthBinding =
  | {
      kind: typeof SIGNER_AUTH_METHODS.passkey;
      rpId: RpId;
      credentialIdB64u: string;
      providerSubjectId?: never;
    }
  | {
      kind: typeof SIGNER_AUTH_METHODS.emailOtp;
      providerSubjectId: string;
      rpId?: never;
      credentialIdB64u?: never;
    };

export function signingLaneAuthMethod(auth: SigningLaneAuthBinding): SignerAuthMethod {
  switch (auth.kind) {
    case SIGNER_AUTH_METHODS.passkey:
      return SIGNER_AUTH_METHODS.passkey;
    case SIGNER_AUTH_METHODS.emailOtp:
      return SIGNER_AUTH_METHODS.emailOtp;
  }
  auth satisfies never;
  throw new Error('[SigningSession] unsupported signing lane auth binding');
}
