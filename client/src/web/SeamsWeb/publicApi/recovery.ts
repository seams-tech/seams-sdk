import { EmailRecoveryDomain } from '@/web/SeamsWeb/operations/recovery/emailRecovery';
import type {
  EmailRecoveryWebContext,
  RecoveryCapability,
} from '@/web/SeamsWeb/signingSurface/types';
import type { WalletIframeCoordinator } from '@/web/SeamsWeb/walletIframe/coordinator';

export type RecoveryCapabilityDomainMethods = {
  acknowledgeEmailOtpRecoveryCodeBackup: RecoveryCapability['acknowledgeEmailOtpRecoveryCodeBackup'];
  getEmailOtpRecoveryCodeStatus: RecoveryCapability['getEmailOtpRecoveryCodeStatus'];
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
    acknowledgeEmailOtpRecoveryCodeBackup: deps.domain.acknowledgeEmailOtpRecoveryCodeBackup,
    getEmailOtpRecoveryCodeStatus: deps.domain.getEmailOtpRecoveryCodeStatus,
  } satisfies RecoveryCapability;
}
