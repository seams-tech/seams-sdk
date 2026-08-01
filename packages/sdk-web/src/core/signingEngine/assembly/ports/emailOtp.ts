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
        sessionId: target.thresholdSessionId,
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
    getStatus: createArgs.getWalletSigningBudgetStatus,
    touchConfirm: createArgs.passkeyMpcSession,
    getEmailOtpWarmSessionStatus: (sessionId) =>
      getEmailOtpWarmSessionStatus({ kind: 'ecdsa', thresholdSessionId: sessionId }),
    consumeEmailOtpWarmSessionUses: createArgs.consumeEmailOtpWarmSessionUses,
    clearEmailOtpWarmSessionMaterial: createArgs.clearEmailOtpWarmSessionMaterial,
  });
}
