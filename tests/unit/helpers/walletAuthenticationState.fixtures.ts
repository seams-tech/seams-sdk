import type { WalletAuthenticationState } from '../../../packages/wallet/src/core/types/seams';
import { walletIdFromString } from '@shared/utils/registrationIntent';

export function passkeyAuthenticatedWalletStateFixture(
  walletId: string,
): Extract<WalletAuthenticationState, { kind: 'authenticated' }> {
  return {
    kind: 'authenticated',
    walletId: walletIdFromString(walletId),
    authMethod: 'passkey',
  };
}

export function signedOutWalletStateFixture(): Extract<
  WalletAuthenticationState,
  { kind: 'signed_out' }
> {
  return { kind: 'signed_out' };
}
