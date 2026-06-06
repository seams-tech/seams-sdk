import {
  getRecentUnlocksDomain,
  getWalletSessionDomain,
  hasPasskeyCredentialDomain,
  lockDomain,
  prefillThresholdEcdsaPresignPoolDomain,
  unlockDomain,
  type AuthSessionDomainDeps,
} from '@/SeamsWeb/operations/auth/authSessions';
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
  getAuthSessionDeps: () => AuthSessionDomainDeps;
  domain: AuthCapabilityDomainMethods;
}): AuthCapability {
  return {
    unlock: async (nearAccountId, options) =>
      await unlockDomain(deps.getAuthSessionDeps(), nearAccountId, options),
    lock: async () => await lockDomain(deps.getAuthSessionDeps()),
    getWalletSession: async (walletId) =>
      await getWalletSessionDomain(deps.getAuthSessionDeps(), walletId),
    getRecentUnlocks: async () => await getRecentUnlocksDomain(deps.getAuthSessionDeps()),
    hasPasskeyCredential: async (nearAccountId) =>
      await hasPasskeyCredentialDomain(deps.getAuthSessionDeps(), nearAccountId),
    prefillThresholdEcdsaPresignPool: async (args) =>
      await prefillThresholdEcdsaPresignPoolDomain(deps.getAuthSessionDeps(), args),
    requestEmailOtpChallenge: deps.domain.requestEmailOtpChallenge,
    requestEmailOtpSigningSessionChallenge: deps.domain.requestEmailOtpSigningSessionChallenge,
    refreshEmailOtpSigningSession: deps.domain.refreshEmailOtpSigningSession,
    exchangeGoogleEmailOtpSession: deps.domain.exchangeGoogleEmailOtpSession,
    loginWithEmailOtpEcdsaCapability: deps.domain.loginWithEmailOtpEcdsaCapability,
    beginGoogleEmailOtpWalletAuth: deps.domain.beginGoogleEmailOtpWalletAuth,
  } satisfies AuthCapability;
}
