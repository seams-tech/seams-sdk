import type { WalletSession } from '@/core/types/seams';
import {
  buildNoCurrentWalletAuthMethod,
  buildSelectedCurrentWalletAuthMethod,
} from '@shared/utils/walletCapabilityBindings';
import type { LoginState } from '../types';
import { isWalletSessionReadyForUi } from './walletSessionReadiness';

export function buildReactLoggedOutLoginState(): LoginState {
  return {
    isLoggedIn: false,
    walletId: null,
    nearAccountId: null,
    nearPublicKey: null,
    currentAuthMethod: buildNoCurrentWalletAuthMethod(),
    authMethods: [],
    thresholdEcdsaEthereumAddress: null,
    thresholdEcdsaPublicKeyB64u: null,
  };
}

export function buildReactLoggedInLoginStateFromSession(session: WalletSession): LoginState | null {
  if (!isWalletSessionReadyForUi({ session })) return null;
  if (session.appIdentity.kind !== 'resolved') return null;
  const appIdentity = session.appIdentity;
  const authentication = session.authentication;
  if (authentication.kind === 'linked_device_session') {
    return {
      isLoggedIn: true,
      walletId: String(appIdentity.walletId),
      nearAccountId: appIdentity.nearAccountId ? String(appIdentity.nearAccountId) : null,
      nearPublicKey: appIdentity.nearOperationalPublicKey,
      currentAuthMethod: buildNoCurrentWalletAuthMethod(),
      authMethods: appIdentity.authMethods,
      thresholdEcdsaEthereumAddress: appIdentity.thresholdEcdsaEthereumAddress,
      thresholdEcdsaPublicKeyB64u: appIdentity.thresholdEcdsaPublicKeyB64u,
    };
  }
  if (authentication.kind !== 'authenticated') return null;
  const matchingAuthMethods = appIdentity.authMethods.filter(
    (binding) => binding.kind === authentication.authMethod,
  );
  if (matchingAuthMethods.length !== 1) return null;
  const currentAuthMethod = buildSelectedCurrentWalletAuthMethod({
    binding: matchingAuthMethods[0],
  });
  return {
    isLoggedIn: true,
    walletId: String(appIdentity.walletId),
    nearAccountId: appIdentity.nearAccountId ? String(appIdentity.nearAccountId) : null,
    nearPublicKey: appIdentity.nearOperationalPublicKey,
    currentAuthMethod,
    authMethods: appIdentity.authMethods,
    thresholdEcdsaEthereumAddress: appIdentity.thresholdEcdsaEthereumAddress,
    thresholdEcdsaPublicKeyB64u: appIdentity.thresholdEcdsaPublicKeyB64u,
  };
}
