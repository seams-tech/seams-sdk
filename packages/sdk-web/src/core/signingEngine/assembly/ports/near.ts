import type { NearSigningApiDeps } from '../../interfaces/operationDeps';
import {
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
  getStoredThresholdEd25519SessionRecordForAccount,
} from '../../session/persistence/records';
import { SigningSessionCoordinator } from '../../session/SigningSessionCoordinator';
import { resolveEvmFamilyTransactionWalletAuth } from '../../flows/signEvmFamily/accountAuth';
import type { EvmFamilyWalletSignerStorePort } from '../../flows/signEvmFamily/accountAuth';
import { createWarmSessionStatusReader } from '../../session/warmCapabilities/statusReader';
import { generateSessionId as generateSessionIdValue } from '../../session/passkey/prfCache';
import { refreshPasskeyEd25519CapabilityForSigning } from '../../session/passkey/ed25519BudgetRefresh';
import type { WarmSessionStatusResult } from '../../uiConfirm/uiConfirm.types';
import type { CreateSigningEnginePortsArgs } from './shared';
import type { Ed25519YaoActiveClientRegistryPort } from '../../threshold/ed25519/yaoActiveClientRegistry';
import { resolveManagedRuntimeScopeBootstrap } from '../../../config/managedRuntimeScope';
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
    resolveActiveEd25519YaoSigningCapability: (identity) =>
      args.ed25519YaoActiveClients.resolve(identity),
    resolveThresholdEd25519SessionIdForNearAccount: (nearAccountId: string): string | null => {
      try {
        const record = getStoredThresholdEd25519SessionRecordForAccount(nearAccountId);
        const thresholdSessionId = String(record?.thresholdSessionId || '').trim();
        return thresholdSessionId || null;
      } catch {
        return null;
      }
    },
    readPersistedEd25519SessionRecordForSigning,
    rehydratePasskeyEd25519YaoCapabilityForSigning:
      createArgs.rehydratePasskeyEd25519YaoCapabilityForSigning,
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
    refreshPasskeyEd25519CapabilityForSigning: async ({
      record,
      laneIdentity,
      policySecretSource,
      operationUsesNeeded,
    }) =>
      refreshPasskeyEd25519CapabilityForSigning({
        record,
        laneIdentity,
        policySecretSource,
        operationUsesNeeded,
        runtimeScopeBootstrap: resolveManagedRuntimeScopeBootstrap(createArgs.seamsWebConfigs),
        provisionThresholdEd25519Session: (provisionArgs) =>
          createArgs.provisionThresholdEd25519Session(provisionArgs),
        readStoredThresholdEd25519SessionRecordByThresholdSessionId: (thresholdSessionId) =>
          getStoredThresholdEd25519SessionRecordByThresholdSessionId(thresholdSessionId),
        resolveActiveEd25519YaoSigningCapability: (identity) =>
          args.ed25519YaoActiveClients.resolve(identity),
        rehydratePasskeyEd25519YaoCapabilityAfterRefresh:
          createArgs.rehydratePasskeyEd25519YaoCapabilityAfterRefresh,
        refreshActiveEd25519YaoWalletSession: ({
          identity,
          signingGrantId,
          nextWalletSessionState,
        }) =>
          args.ed25519YaoActiveClients.refreshWalletSession({
            kind: 'same_identity_wallet_session_refresh_v1',
            identity,
            signingGrantId,
            nextWalletSessionState,
          }),
      }),
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
