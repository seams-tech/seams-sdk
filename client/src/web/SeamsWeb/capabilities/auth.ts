import type { AuthCapability } from '../interfaces';

export function createAuthCapability(handlers: AuthCapability): AuthCapability {
  return {
    unlock: async (nearAccountId, options) => await handlers.unlock(nearAccountId, options),
    lock: async () => await handlers.lock(),
    getWalletSession: async (walletId) => await handlers.getWalletSession(walletId),
    getRecentUnlocks: async () => await handlers.getRecentUnlocks(),
    hasPasskeyCredential: async (nearAccountId) =>
      await handlers.hasPasskeyCredential(nearAccountId),
    prefillThresholdEcdsaPresignPool: async (args) =>
      await handlers.prefillThresholdEcdsaPresignPool(args),
    requestEmailOtpChallenge: async (args) => await handlers.requestEmailOtpChallenge(args),
    requestEmailOtpEnrollmentChallenge: async (args) =>
      await handlers.requestEmailOtpEnrollmentChallenge(args),
    requestEmailOtpSigningSessionChallenge: async (args) =>
      await handlers.requestEmailOtpSigningSessionChallenge(args),
    refreshEmailOtpSigningSession: async (args) =>
      await handlers.refreshEmailOtpSigningSession(args),
    exchangeGoogleEmailOtpSession: async (args) =>
      await handlers.exchangeGoogleEmailOtpSession(args),
    enrollEmailOtp: async (args) => await handlers.enrollEmailOtp(args),
    acknowledgeEmailOtpRecoveryCodeBackup: async (args) =>
      await handlers.acknowledgeEmailOtpRecoveryCodeBackup(args),
    getEmailOtpRecoveryCodeStatus: async (args) =>
      await handlers.getEmailOtpRecoveryCodeStatus(args),
    loginWithEmailOtpEcdsaCapability: async (args) =>
      await handlers.loginWithEmailOtpEcdsaCapability(args),
    enrollAndLoginWithEmailOtpEcdsaCapability: async (args) =>
      await handlers.enrollAndLoginWithEmailOtpEcdsaCapability(args),
  };
}
