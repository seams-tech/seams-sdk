import {
  type SignerAuthMethod,
  SIGNER_AUTH_METHODS,
} from '@shared/utils/signerDomain';

export type AccountAuthMetadata = {
  primaryAuthMethod: SignerAuthMethod;
  linkedAuthMethods: SignerAuthMethod[];
  email?: string;
  passkeyCredentialIds?: string[];
};

export function resolveAccountAuthMetadataForSignerAuthMethod(args: {
  authMethod: SignerAuthMethod;
  email?: string;
  passkeyCredentialIds?: string[];
}): AccountAuthMetadata {
  const primaryAuthMethod = args.authMethod;
  return {
    primaryAuthMethod,
    linkedAuthMethods: [primaryAuthMethod],
    ...(args.email ? { email: args.email } : {}),
    ...(args.passkeyCredentialIds?.length
      ? { passkeyCredentialIds: args.passkeyCredentialIds }
      : {}),
  };
}

export function signerAuthMethodFromUnknown(value: unknown): SignerAuthMethod | null {
  switch (value) {
    case SIGNER_AUTH_METHODS.passkey:
      return SIGNER_AUTH_METHODS.passkey;
    case SIGNER_AUTH_METHODS.emailOtp:
      return SIGNER_AUTH_METHODS.emailOtp;
    default:
      return null;
  }
}
