import type { WalletAuthMethod } from '@/core/types/seams';
import { WALLET_AUTH_METHODS } from '@shared/utils';

export type AccountAuthMetadata = {
  primaryAuthMethod: WalletAuthMethod;
  linkedAuthMethods: WalletAuthMethod[];
  email?: string;
  passkeyCredentialIds?: string[];
};

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
