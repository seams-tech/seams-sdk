import {
  getRecentUnlocksDomain,
  getWalletSessionDomain,
  hasPasskeyCredentialDomain,
  lockDomain,
  prefillRouterAbEcdsaHssPresignaturePoolDomain,
  unlockDomain,
  type WalletAuthDomainDeps,
} from '@/SeamsWeb/operations/auth/walletAuth';
import type { AuthCapability } from '@/SeamsWeb/signingSurface/types';

export type AuthCapabilityDomainMethods = {
  requestEmailOtpChallenge: AuthCapability['requestEmailOtpChallenge'];
  requestEmailOtpSigningSessionChallenge: AuthCapability['requestEmailOtpSigningSessionChallenge'];
  refreshEmailOtpSigningSession: AuthCapability['refreshEmailOtpSigningSession'];
  exchangeGoogleEmailOtpSession: AuthCapability['exchangeGoogleEmailOtpSession'];
  loginWithEmailOtpEcdsaCapability: AuthCapability['loginWithEmailOtpEcdsaCapability'];
  beginGoogleEmailOtpWalletAuth: AuthCapability['beginGoogleEmailOtpWalletAuth'];
};

export function createAuthCapability(deps: {
  getWalletAuthDeps: () => WalletAuthDomainDeps;
  domain: AuthCapabilityDomainMethods;
}): AuthCapability {
  return {
    unlock: async (nearAccountId, options) =>
      await unlockDomain(deps.getWalletAuthDeps(), nearAccountId, options),
    lock: async () => await lockDomain(deps.getWalletAuthDeps()),
    getWalletSession: async (walletId) =>
      await getWalletSessionDomain(deps.getWalletAuthDeps(), walletId),
    getRecentUnlocks: async () => await getRecentUnlocksDomain(deps.getWalletAuthDeps()),
    hasPasskeyCredential: async (nearAccountId) =>
      await hasPasskeyCredentialDomain(deps.getWalletAuthDeps(), nearAccountId),
    prefillRouterAbEcdsaHssPresignaturePool: async (args) =>
      await prefillRouterAbEcdsaHssPresignaturePoolDomain(deps.getWalletAuthDeps(), args),
    requestEmailOtpChallenge: deps.domain.requestEmailOtpChallenge,
    requestEmailOtpSigningSessionChallenge: deps.domain.requestEmailOtpSigningSessionChallenge,
    refreshEmailOtpSigningSession: deps.domain.refreshEmailOtpSigningSession,
    exchangeGoogleEmailOtpSession: deps.domain.exchangeGoogleEmailOtpSession,
    loginWithEmailOtpEcdsaCapability: deps.domain.loginWithEmailOtpEcdsaCapability,
    beginGoogleEmailOtpWalletAuth: deps.domain.beginGoogleEmailOtpWalletAuth,
  } satisfies AuthCapability;
}
