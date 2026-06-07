import { EmailRecoveryDomain } from '@/SeamsWeb/operations/recovery/emailRecovery';
import type {
  EmailRecoveryWebContext,
  RecoveryCapability,
} from '@/SeamsWeb/signingSurface/types';
import type { WalletIframeCoordinator } from '@/SeamsWeb/walletIframe/coordinator';

export type RecoveryCapabilityDomainMethods = {
  getEmailOtpRecoveryCodeStatus: RecoveryCapability['getEmailOtpRecoveryCodeStatus'];
  rotateEmailOtpRecoveryCodes: RecoveryCapability['rotateEmailOtpRecoveryCodes'];
};

export function createRecoveryCapability(deps: {
  getContext: () => EmailRecoveryWebContext;
  walletIframe: Pick<WalletIframeCoordinator, 'shouldUseWalletIframe' | 'requireRouter'>;
  domain: RecoveryCapabilityDomainMethods;
}): RecoveryCapability {
  const emailRecovery = new EmailRecoveryDomain({
    getContext: deps.getContext,
    walletIframe: deps.walletIframe,
  });
  return {
    getRecoveryEmails: async (accountId) => await emailRecovery.getRecoveryEmails(accountId),
    setRecoveryEmails: async (args) => await emailRecovery.setRecoveryEmails(args),
    syncAccount: async (args) => await emailRecovery.syncAccount(args),
    startEmailRecovery: async (args) => await emailRecovery.startEmailRecovery(args),
    finalizeEmailRecovery: async (args) => await emailRecovery.finalizeEmailRecovery(args),
    cancelEmailRecovery: async (args) => await emailRecovery.cancelEmailRecovery(args),
    getEmailOtpRecoveryCodeStatus: deps.domain.getEmailOtpRecoveryCodeStatus,
    rotateEmailOtpRecoveryCodes: deps.domain.rotateEmailOtpRecoveryCodes,
  } satisfies RecoveryCapability;
}
