import { SigningSessionCoordinator } from '../../session/SigningSessionCoordinator';
import type { WarmSessionStatusResult } from '../../uiConfirm/uiConfirm.types';
import type { CreateSigningEnginePortsArgs } from './shared';
import type { EmailOtpWarmMaterialTarget } from '../../workerManager/workerTypes';
import { IndexedDBManager, walletSessionAuthorizations } from '@/core/indexedDB';
import type { ExactWalletSessionReadPorts } from '../../session/identity/exactWalletSessionCredential';

export const browserExactWalletSessionReadPorts: ExactWalletSessionReadPorts = {
  resolveSelectedWalletAuthority:
    IndexedDBManager.resolveSelectedWalletAuthority.bind(IndexedDBManager),
  readExactWithOperationCredential:
    walletSessionAuthorizations.readExactWithOperationCredential.bind(walletSessionAuthorizations),
};

export function createEmailOtpWarmSessionStatusReader(
  args: CreateSigningEnginePortsArgs,
): (target: EmailOtpWarmMaterialTarget) => Promise<WarmSessionStatusResult> {
  return (
    args.getEmailOtpWarmSessionStatus ||
    (async (target: EmailOtpWarmMaterialTarget): Promise<WarmSessionStatusResult> => {
      return await args.passkeyMpcSession.getWarmSessionStatus({
        thresholdSessionId: target.thresholdSessionId,
      });
    })
  );
}

export function createSigningSessionCoordinatorPort(args: {
  createArgs: CreateSigningEnginePortsArgs;
  getEmailOtpWarmSessionStatus: (
    target: EmailOtpWarmMaterialTarget,
  ) => Promise<WarmSessionStatusResult>;
}): SigningSessionCoordinator {
  const { createArgs, getEmailOtpWarmSessionStatus } = args;
  return new SigningSessionCoordinator({
    exactWalletSessionReadPorts: browserExactWalletSessionReadPorts,
    getStatus: createArgs.getWalletSessionStatus,
    touchConfirm: createArgs.passkeyMpcSession,
    getEmailOtpWarmSessionStatus: (thresholdSessionId) =>
      getEmailOtpWarmSessionStatus({ kind: 'ecdsa', thresholdSessionId }),
    clearEmailOtpWarmSessionMaterial: createArgs.clearEmailOtpWarmSessionMaterial,
  });
}
