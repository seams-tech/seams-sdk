import type { NearSigningApiDeps } from '../../interfaces/operationDeps';
import { SigningSessionCoordinator } from '../../session/SigningSessionCoordinator';
import { resolveEvmFamilyTransactionWalletAuth } from '../../flows/signEvmFamily/accountAuth';
import type { EvmFamilyWalletSignerStorePort } from '../../flows/signEvmFamily/accountAuth';
import { createWarmSessionStatusReader } from '../../session/warmCapabilities/statusReader';
import { generateSessionId as generateSessionIdValue } from '../../session/passkey/prfCache';
import type { WarmSessionStatusResult } from '../../uiConfirm/uiConfirm.types';
import type { CreateSigningEnginePortsArgs } from './shared';
import type { Ed25519YaoActiveClientRegistryPort } from '../../threshold/ed25519/yaoActiveClientRegistry';
import { readPersistedEd25519SessionRecordForSigning } from '../../session/availability/persistedAvailableSigningLanes';

export function createNearSigningDeps(args: {
  createArgs: CreateSigningEnginePortsArgs;
  walletSignerStore: EvmFamilyWalletSignerStorePort;
  nearRpcUrl: string;
  signingSessionCoordinator: SigningSessionCoordinator;
  ed25519YaoActiveClients: Ed25519YaoActiveClientRegistryPort;
  getEmailOtpWarmSessionStatus: (sessionId: string) => Promise<WarmSessionStatusResult>;
}): NearSigningApiDeps {
  const { createArgs, nearRpcUrl, signingSessionCoordinator, getEmailOtpWarmSessionStatus } = args;
  return {
    nearRpcUrl,
    resolveActiveEd25519YaoSigningCapability: (scope) =>
      args.ed25519YaoActiveClients.resolveForWalletAccount(scope),
    readPersistedEd25519SessionRecordForSigning,
    rehydratePasskeyEd25519YaoCapabilityForSigning:
      createArgs.rehydratePasskeyEd25519YaoCapabilityForSigning,
    preparePasskeyEd25519YaoOperationStepUpForSigning:
      createArgs.preparePasskeyEd25519YaoOperationStepUpForSigning,
    recoverEmailOtpEd25519YaoCapabilitySilentlyForSigning:
      createArgs.recoverEmailOtpEd25519YaoCapabilitySilentlyForSigning,
    createSigningSessionId: (prefix: string): string => generateSessionIdValue(prefix),
    getSignerWorkerContext: () => createArgs.signerWorkerManager.getContext(),
    readAvailableSigningLanesForSigning: (snapshotArgs) =>
      createArgs.readAvailableSigningLanesForSigning(snapshotArgs),
    resolveAccountAuthMethodForSigning: async ({ walletId }) => {
      const accountAuth = await resolveEvmFamilyTransactionWalletAuth({
        deps: { walletSignerStore: args.walletSignerStore },
        walletId: String(walletId),
        senderSignatureAlgorithm: 'secp256k1',
      });
      return accountAuth.primaryAuthMethod;
    },
    ...(createArgs.requestEmailOtpEd25519SigningChallenge
      ? {
          requestEmailOtpEd25519SigningChallenge: (challengeArgs) =>
            createArgs.requestEmailOtpEd25519SigningChallenge!(challengeArgs),
        }
      : {}),
    ...(createArgs.rehydrateEmailOtpEd25519CapabilityForSigning
      ? {
          rehydrateEmailOtpEd25519CapabilityForSigning: (rehydrationArgs) =>
            createArgs.rehydrateEmailOtpEd25519CapabilityForSigning!(rehydrationArgs),
        }
      : {}),
    signingSessionCoordinator,
    getWarmThresholdEd25519SessionStatusForSession: ({ nearAccountId, thresholdSessionId }) =>
      createWarmSessionStatusReader({
        touchConfirm: createArgs.touchConfirm,
        getEmailOtpWarmSessionStatus,
      }).getEd25519SigningSessionStatusForSession({ nearAccountId, thresholdSessionId }),
    withThresholdEd25519CommitQueue: (queueArgs) =>
      createArgs.withThresholdEd25519CommitQueue(queueArgs),
  };
}
