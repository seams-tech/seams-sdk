import { requireTrimmedString } from '@shared/utils/validation';

export type LinkedDeviceWalletSessionCredential = {
  kind: 'wallet_session_jwt';
  walletSessionJwt: string;
};

export function linkedDeviceWalletSessionBearer(
  credential: LinkedDeviceWalletSessionCredential,
): string {
  return requireTrimmedString(credential.walletSessionJwt, 'linked-device Wallet Session JWT');
}

export function isLinkedDeviceWalletSessionCredential(
  value: { readonly kind: string },
): value is LinkedDeviceWalletSessionCredential {
  return value.kind === 'wallet_session_jwt';
}
