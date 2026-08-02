import { SigningSessionCoordinator } from '../../session/SigningSessionCoordinator';
import type { WarmSessionStatusResult } from '../../uiConfirm/uiConfirm.types';
import type { CreateSigningEnginePortsArgs } from './shared';
import type { EmailOtpWarmMaterialTarget } from '../../workerManager/workerTypes';

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
    getStatus: createArgs.getWalletSessionStatus,
    touchConfirm: createArgs.passkeyMpcSession,
    getEmailOtpWarmSessionStatus: (thresholdSessionId) =>
      getEmailOtpWarmSessionStatus({ kind: 'ecdsa', thresholdSessionId }),
    clearEmailOtpWarmSessionMaterial: createArgs.clearEmailOtpWarmSessionMaterial,
  });
}
