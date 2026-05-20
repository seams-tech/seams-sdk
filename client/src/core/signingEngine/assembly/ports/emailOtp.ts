import { SigningSessionCoordinator } from '../../session/SigningSessionCoordinator';
import { createWarmSessionStatusReader } from '../../session/warmCapabilities/statusReader';
import type { EmailOtpPublicDeps } from '../../flows/signEvmFamily/emailOtpPublic';
import type { WarmSessionStatusResult } from '../../uiConfirm/types';
import type { CreateSigningEnginePortsArgs } from './shared';

export function createEmailOtpWarmSessionStatusReader(
  args: CreateSigningEnginePortsArgs,
): (sessionId: string) => Promise<WarmSessionStatusResult> {
  return (
    args.getEmailOtpWarmSessionStatus ||
    (async (sessionId: string): Promise<WarmSessionStatusResult> => {
      if (typeof args.touchConfirm.getWarmSessionStatus === 'function') {
        return await args.touchConfirm.getWarmSessionStatus({ sessionId });
      }
      return {
        ok: false,
        code: 'not_found',
        message: 'Email OTP warm-session status reader is unavailable',
      };
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
    touchConfirm: createArgs.touchConfirm,
    getEmailOtpWarmSessionStatus,
    consumeEmailOtpWarmSessionUses: createArgs.consumeEmailOtpWarmSessionUses,
    clearThresholdEcdsaSessionRecordForWalletTarget: ({ walletId, chainTarget, source }) =>
      createArgs.clearThresholdEcdsaSessionRecordForWalletTarget({
        walletId,
        chainTarget,
        ...(source ? { source } : {}),
      }),
    markThresholdEd25519EmailOtpSessionConsumedForAccount:
      createArgs.markThresholdEd25519EmailOtpSessionConsumedForAccount,
  });
}

export function createWarmThresholdEd25519SessionStatusReader(args: {
  createArgs: CreateSigningEnginePortsArgs;
  getEmailOtpWarmSessionStatus: (sessionId: string) => Promise<WarmSessionStatusResult>;
}) {
  return createWarmSessionStatusReader({
    touchConfirm: args.createArgs.touchConfirm,
    getEmailOtpWarmSessionStatus: args.getEmailOtpWarmSessionStatus,
  }).getEd25519SigningSessionStatus;
}

export function createEmailOtpPublicDeps(args: {
  ecdsaSessions: EmailOtpPublicDeps['ecdsaSessions'];
  relayerUrl: string;
  shamirPrimeB64u: string;
  getSignerWorkerContext: EmailOtpPublicDeps['getSignerWorkerContext'];
  emailOtpSessions: EmailOtpPublicDeps['emailOtpSessions'];
}): EmailOtpPublicDeps {
  return {
    ecdsaSessions: args.ecdsaSessions,
    relayerUrl: args.relayerUrl,
    shamirPrimeB64u: args.shamirPrimeB64u,
    getSignerWorkerContext: args.getSignerWorkerContext,
    emailOtpSessions: args.emailOtpSessions,
  };
}
