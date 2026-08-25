import {
  getRecentUnlocksDomain,
  getWalletSessionDomain,
  hasPasskeyCredentialDomain,
  lockDomain,
  prefillRouterAbEcdsaDerivationPresignaturePoolDomain,
  unlockDomain,
  type WalletAuthDomainDeps,
} from '@/SeamsWeb/operations/auth/walletAuth';
import type { AuthCapability } from '@/SeamsWeb/signingSurface/types';

export type AuthCapabilityDomainMethods = {
  requestEmailOtpChallenge: AuthCapability['requestEmailOtpChallenge'];
  requestEmailOtpSigningSessionChallenge: AuthCapability['requestEmailOtpSigningSessionChallenge'];
  refreshEmailOtpSigningSession: AuthCapability['refreshEmailOtpSigningSession'];
  loginWithEmailOtpEcdsaCapability: AuthCapability['loginWithEmailOtpEcdsaCapability'];
  unlockAddedEmailOtpWallet: AuthCapability['unlockAddedEmailOtpWallet'];
  beginGoogleEmailOtpWalletAuth: AuthCapability['beginGoogleEmailOtpWalletAuth'];
};

export function createAuthCapability(deps: {
  getWalletAuthDeps: () => WalletAuthDomainDeps;
  domain: AuthCapabilityDomainMethods;
}): AuthCapability {
  return {
    unlock: async (walletId, options) =>
      await unlockDomain(deps.getWalletAuthDeps(), walletId, options),
    lock: async () => await lockDomain(deps.getWalletAuthDeps()),
    getWalletSession: async (walletId) =>
      await getWalletSessionDomain(deps.getWalletAuthDeps(), walletId),
    getRecentUnlocks: async () => await getRecentUnlocksDomain(deps.getWalletAuthDeps()),
    hasPasskeyCredential: async (walletId) =>
      await hasPasskeyCredentialDomain(deps.getWalletAuthDeps(), walletId),
    prefillRouterAbEcdsaDerivationPresignaturePool: async (args) =>
      await prefillRouterAbEcdsaDerivationPresignaturePoolDomain(deps.getWalletAuthDeps(), args),
    requestEmailOtpChallenge: deps.domain.requestEmailOtpChallenge,
    requestEmailOtpSigningSessionChallenge: deps.domain.requestEmailOtpSigningSessionChallenge,
    refreshEmailOtpSigningSession: deps.domain.refreshEmailOtpSigningSession,
    loginWithEmailOtpEcdsaCapability: deps.domain.loginWithEmailOtpEcdsaCapability,
    unlockAddedEmailOtpWallet: deps.domain.unlockAddedEmailOtpWallet,
    beginGoogleEmailOtpWalletAuth: deps.domain.beginGoogleEmailOtpWalletAuth,
  } satisfies AuthCapability;
}
