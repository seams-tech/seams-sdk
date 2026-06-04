import { EmailRecoveryDomain } from '../near/emailRecovery';
import { DeviceLinkingDomain } from '../near/linkDevice';
import type { RecoveryCapability, SeamsWebContext } from '../interfaces';
import type { WalletIframeCoordinator } from '../walletIframeCoordinator';

export function createRecoveryCapability(deps: {
  getContext: () => SeamsWebContext;
  getWalletIframe: () => WalletIframeCoordinator;
}): RecoveryCapability {
  const domainDeps = {
    getContext: deps.getContext,
    get walletIframe(): WalletIframeCoordinator {
      return deps.getWalletIframe();
    },
  };
  const emailRecovery = new EmailRecoveryDomain(domainDeps);
  const deviceLinking = new DeviceLinkingDomain(domainDeps);
  return {
    getRecoveryEmails: async (accountId) => await emailRecovery.getRecoveryEmails(accountId),
    setRecoveryEmails: async (args) => await emailRecovery.setRecoveryEmails(args),
    syncAccount: async (args) => await emailRecovery.syncAccount(args),
    startEmailRecovery: async (args) => await emailRecovery.startEmailRecovery(args),
    finalizeEmailRecovery: async (args) => await emailRecovery.finalizeEmailRecovery(args),
    cancelEmailRecovery: async (args) => await emailRecovery.cancelEmailRecovery(args),
    startDevice2LinkingFlow: async (args) => await deviceLinking.startDevice2LinkingFlow(args),
    stopDevice2LinkingFlow: async () => await deviceLinking.stopDevice2LinkingFlow(),
    linkDeviceWithScannedQRData: async (qrData, options) =>
      await deviceLinking.linkDeviceWithScannedQRData(qrData, options),
  };
}
