import {
  SIGNER_AUTH_METHODS,
  WALLET_AUTH_METHODS,
  type WalletAuthMethodSignerResolution,
} from './signerDomain';

const passkeyResolution: WalletAuthMethodSignerResolution = {
  kind: 'supported',
  walletAuthMethod: WALLET_AUTH_METHODS.passkey,
  signerAuthMethod: SIGNER_AUTH_METHODS.passkey,
};

// @ts-expect-error A supported resolution must preserve the auth-method wire identity.
const crossMethodResolution: WalletAuthMethodSignerResolution = {
  kind: 'supported',
  walletAuthMethod: WALLET_AUTH_METHODS.passkey,
  signerAuthMethod: SIGNER_AUTH_METHODS.emailOtp,
};

void passkeyResolution;
void crossMethodResolution;
