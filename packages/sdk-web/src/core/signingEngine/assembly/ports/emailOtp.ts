import { SigningSessionCoordinator } from '../../session/SigningSessionCoordinator';
import type { WarmSessionStatusResult } from '../../uiConfirm/uiConfirm.types';
import type { CreateSigningEnginePortsArgs } from './shared';

export function createEmailOtpWarmSessionStatusReader(
  args: CreateSigningEnginePortsArgs,
): (sessionId: string) => Promise<WarmSessionStatusResult> {
  return (
    args.getEmailOtpWarmSessionStatus ||
    (async (sessionId: string): Promise<WarmSessionStatusResult> => {
      return await args.passkeyMpcSession.getWarmSessionStatus({ sessionId });
    })
  );
}

export function createSigningSessionCoordinatorPort(args: {
  createArgs: CreateSigningEnginePortsArgs;
  getEmailOtpWarmSessionStatus: (sessionId: string) => Promise<WarmSessionStatusResult>;
}): SigningSessionCoordinator {
  const { createArgs, getEmailOtpWarmSessionStatus } = args;
  return new SigningSessionCoordinator({
    getStatus: createArgs.getWalletSigningBudgetStatus,
    touchConfirm: createArgs.passkeyMpcSession,
    getEmailOtpWarmSessionStatus,
    consumeEmailOtpWarmSessionUses: createArgs.consumeEmailOtpWarmSessionUses,
    clearEmailOtpWarmSessionMaterial: createArgs.clearEmailOtpWarmSessionMaterial,
  });
}
