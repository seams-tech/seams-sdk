import type { WalletSession } from '@/core/types/seams';
import { buildNoCurrentWalletAuthMethod } from '@shared/utils/walletCapabilityBindings';
import type { LoginState } from '../types';

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
  const { login } = session;
  const walletId = login.walletId ? String(login.walletId) : '';
  if (!walletId) return null;
  return {
    isLoggedIn: true,
    walletId,
    nearAccountId: login.nearAccountId ? String(login.nearAccountId) : null,
    nearPublicKey: login.publicKey || null,
    currentAuthMethod: session.currentAuthMethod,
    authMethods: session.authMethods,
    thresholdEcdsaEthereumAddress: login.thresholdEcdsaEthereumAddress || null,
    thresholdEcdsaPublicKeyB64u: login.thresholdEcdsaPublicKeyB64u || null,
  };
}
