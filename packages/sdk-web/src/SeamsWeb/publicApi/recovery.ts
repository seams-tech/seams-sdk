import { EmailRecoveryDomain } from '@/SeamsWeb/operations/recovery/emailRecovery';
import type { EmailRecoveryWebContext, RecoveryCapability } from '@/SeamsWeb/signingSurface/types';
import type { WalletIframeCoordinator } from '@/SeamsWeb/walletIframe/coordinator';

export type RecoveryCapabilityDomainMethods = {
  getWalletRecoveryCodeStatus: RecoveryCapability['getWalletRecoveryCodeStatus'];
  acknowledgeWalletRecoveryCodeBackup: RecoveryCapability['acknowledgeWalletRecoveryCodeBackup'];
  rotateWalletRecoveryCodes: RecoveryCapability['rotateWalletRecoveryCodes'];
  requestWalletRecoveryBootstrapChallenge: RecoveryCapability['requestWalletRecoveryBootstrapChallenge'];
  verifyWalletRecoveryBootstrap: RecoveryCapability['verifyWalletRecoveryBootstrap'];
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
    getWalletRecoveryCodeStatus: deps.domain.getWalletRecoveryCodeStatus,
    acknowledgeWalletRecoveryCodeBackup: deps.domain.acknowledgeWalletRecoveryCodeBackup,
    rotateWalletRecoveryCodes: deps.domain.rotateWalletRecoveryCodes,
    requestWalletRecoveryBootstrapChallenge: deps.domain.requestWalletRecoveryBootstrapChallenge,
    verifyWalletRecoveryBootstrap: deps.domain.verifyWalletRecoveryBootstrap,
    prepareWalletRecoveryWithBootstrap: deps.domain.prepareWalletRecoveryWithBootstrap,
    completeWalletRecovery: deps.domain.completeWalletRecovery,
  } satisfies RecoveryCapability;
}
