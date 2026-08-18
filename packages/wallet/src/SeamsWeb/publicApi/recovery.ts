import { AccountSyncDomain } from '@/SeamsWeb/operations/recovery/accountSync';
import type {
  AccountSyncWebContext,
  RecoveryCapability,
} from '@/SeamsWeb/signingSurface/types';
import type { WalletIframeCoordinator } from '@/SeamsWeb/walletIframe/coordinator';

export type RecoveryCapabilityDomainMethods = {
  getWalletRecoveryCodeStatus: RecoveryCapability['getWalletRecoveryCodeStatus'];
  acknowledgeWalletRecoveryCodeBackup: RecoveryCapability['acknowledgeWalletRecoveryCodeBackup'];
  requestWalletCustodyEmailOtpChallenge: RecoveryCapability['requestWalletCustodyEmailOtpChallenge'];
  rotateWalletRecoveryCodes: RecoveryCapability['rotateWalletRecoveryCodes'];
  requestWalletRecoveryBootstrapChallenge: RecoveryCapability['requestWalletRecoveryBootstrapChallenge'];
  verifyWalletRecoveryBootstrap: RecoveryCapability['verifyWalletRecoveryBootstrap'];
  prepareWalletRecoveryWithBootstrap: RecoveryCapability['prepareWalletRecoveryWithBootstrap'];
  completeWalletRecovery: RecoveryCapability['completeWalletRecovery'];
};

export function createRecoveryCapability(deps: {
  getContext: () => AccountSyncWebContext;
  walletIframe: Pick<WalletIframeCoordinator, 'shouldUseWalletIframe' | 'requireRouter'>;
  domain: RecoveryCapabilityDomainMethods;
}): RecoveryCapability {
  const accountSync = new AccountSyncDomain({
    getContext: deps.getContext,
    walletIframe: deps.walletIframe,
  });
  return {
    syncAccount: async (args) => await accountSync.syncAccount(args),
    getWalletRecoveryCodeStatus: deps.domain.getWalletRecoveryCodeStatus,
    acknowledgeWalletRecoveryCodeBackup: deps.domain.acknowledgeWalletRecoveryCodeBackup,
    requestWalletCustodyEmailOtpChallenge: deps.domain.requestWalletCustodyEmailOtpChallenge,
    rotateWalletRecoveryCodes: deps.domain.rotateWalletRecoveryCodes,
    requestWalletRecoveryBootstrapChallenge: deps.domain.requestWalletRecoveryBootstrapChallenge,
    verifyWalletRecoveryBootstrap: deps.domain.verifyWalletRecoveryBootstrap,
    prepareWalletRecoveryWithBootstrap: deps.domain.prepareWalletRecoveryWithBootstrap,
    completeWalletRecovery: deps.domain.completeWalletRecovery,
  } satisfies RecoveryCapability;
}
