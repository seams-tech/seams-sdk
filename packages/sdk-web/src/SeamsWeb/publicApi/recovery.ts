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
    getRecoveryEmails: async (walletId) => await emailRecovery.getRecoveryEmails(walletId),
    setRecoveryEmails: async (args) => await emailRecovery.setRecoveryEmails(args),
    syncAccount: async (args) => await emailRecovery.syncAccount(args),
    getEmailOtpRecoveryCodeStatus: deps.domain.getEmailOtpRecoveryCodeStatus,
    rotateEmailOtpRecoveryCodes: deps.domain.rotateEmailOtpRecoveryCodes,
  } satisfies RecoveryCapability;
}
