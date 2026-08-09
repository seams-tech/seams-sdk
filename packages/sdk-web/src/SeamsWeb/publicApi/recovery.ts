import { EmailRecoveryDomain } from '@/SeamsWeb/operations/recovery/emailRecovery';
import type {
  EmailRecoveryWebContext,
  RecoveryCapability,
} from '@/SeamsWeb/signingSurface/types';
import type { WalletIframeCoordinator } from '@/SeamsWeb/walletIframe/coordinator';

export type RecoveryCapabilityDomainMethods = {
  getEmailOtpRecoveryCodeStatus: RecoveryCapability['getEmailOtpRecoveryCodeStatus'];
  rotateEmailOtpRecoveryCodes: RecoveryCapability['rotateEmailOtpRecoveryCodes'];
  requestWalletRecoveryChallenge: RecoveryCapability['requestWalletRecoveryChallenge'];
  requestWalletRecoveryBootstrapChallenge: RecoveryCapability['requestWalletRecoveryBootstrapChallenge'];
  verifyWalletRecoveryBootstrap: RecoveryCapability['verifyWalletRecoveryBootstrap'];
  prepareWalletRecovery: RecoveryCapability['prepareWalletRecovery'];
  prepareWalletRecoveryWithBootstrap: RecoveryCapability['prepareWalletRecoveryWithBootstrap'];
  completeWalletRecovery: RecoveryCapability['completeWalletRecovery'];
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
    requestWalletRecoveryChallenge: deps.domain.requestWalletRecoveryChallenge,
    requestWalletRecoveryBootstrapChallenge: deps.domain.requestWalletRecoveryBootstrapChallenge,
    verifyWalletRecoveryBootstrap: deps.domain.verifyWalletRecoveryBootstrap,
    prepareWalletRecovery: deps.domain.prepareWalletRecovery,
    prepareWalletRecoveryWithBootstrap: deps.domain.prepareWalletRecoveryWithBootstrap,
    completeWalletRecovery: deps.domain.completeWalletRecovery,
  } satisfies RecoveryCapability;
}
