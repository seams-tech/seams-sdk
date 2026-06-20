import type { SeamsConfigsReadonly } from '@/core/types/seams';
import type { ThresholdEcdsaCanonicalExportArtifact } from '../../interfaces/signing';
import {
  getStoredThresholdEcdsaSessionRecordByThresholdSessionId,
  getThresholdEcdsaSessionRecordByThresholdSessionId,
  type ThresholdEcdsaSessionRecord,
  type ThresholdEcdsaSessionStoreDeps,
} from '../../session/persistence/records';
import { createWarmSessionCapabilityReader } from '../../session/warmCapabilities/capabilityReader';
import {
  createWarmSessionStatusReader,
  type WarmSigningStatusReader,
} from '../../session/warmCapabilities/statusReader';
import type { WarmSessionCapabilityReader } from '../../session/warmCapabilities/types';
import type {
  HydrateSigningSessionInput,
  PersistThresholdEcdsaBootstrapForWalletTargetInput,
  WarmCapabilitiesPublicDeps,
} from '../../session/warmCapabilities/public';
import type { PasskeyPublicDeps } from '../../session/passkey/public';
import {
  createWarmSessionStatusOnlyUiConfirm,
  type WarmSessionStatusOnlyReaderPort,
} from '../../uiConfirm/warmSessionUiConfirm';
import type { UiConfirmRuntimeBridgePort, WarmSessionStatusResult } from '../../uiConfirm/uiConfirm.types';
import { persistThresholdEcdsaBootstrapForWalletTarget } from '../../session/warmCapabilities/ecdsaBootstrapPersistence';
import type { ThresholdEcdsaBootstrapStorePort } from '../../session/warmCapabilities/ecdsaBootstrapPersistence';
import {
  bootstrapWarmEcdsaCapabilityResult,
  reuseWarmEcdsaBootstrapFailureToError,
} from '../../session/passkey/ecdsaWarmCapabilityBootstrap';
import { provisionThresholdEd25519Session } from '../../session/passkey/ed25519SessionProvision';
import { clearVolatileWarmSigningMaterial } from '../../session/warmCapabilities/clearVolatileWarmSigningMaterial';
import { cacheSigningSessionPrfFirst } from '../../session/passkey/prfCache';
import { createEcdsaLoginPrefillClientSigningMaterialSource } from '../../session/warmCapabilities/ecdsaLoginPrefillSigningMaterialSource';
import type { WalletSessionActivationDeps } from '../../session/passkey/ecdsaBootstrap';
import type { SigningEnginePorts } from './shared';
import type { TouchIdPrompt } from '../../stepUpConfirmation/passkeyPrompt/touchIdPrompt';

export type EcdsaRoleLocalReadyRecordStorePorts = {
  recordsByLane: Map<string, ThresholdEcdsaSessionRecord>;
  exportArtifactsByLane: Map<string, ThresholdEcdsaCanonicalExportArtifact>;
};

type WarmSigningPortsArgs = {
  touchConfirm: UiConfirmRuntimeBridgePort;
  getEmailOtpWarmSessionStatus: (sessionId: string) => Promise<WarmSessionStatusResult>;
  signingSessionSeal: SeamsConfigsReadonly['signing']['sessionSeal'];
  ecdsaRoleLocalReadyRecords: EcdsaRoleLocalReadyRecordStorePorts;
};

export type WarmSigningPorts = {
  ecdsaSessions: ThresholdEcdsaSessionStoreDeps & {
    exportArtifactsByLane: Map<string, ThresholdEcdsaCanonicalExportArtifact>;
  };
  statusUiConfirm: WarmSessionStatusOnlyReaderPort;
  capabilityReader: WarmSessionCapabilityReader;
  statusReader: WarmSigningStatusReader;
  getThresholdEcdsaSessionRecordByThresholdSessionId: (
    thresholdSessionId: string,
  ) => ThresholdEcdsaSessionRecord | null;
};

export function createWarmSigningPorts(args: WarmSigningPortsArgs): WarmSigningPorts {
  const ecdsaSessions: WarmSigningPorts['ecdsaSessions'] = {
    recordsByLane: args.ecdsaRoleLocalReadyRecords.recordsByLane,
    exportArtifactsByLane: args.ecdsaRoleLocalReadyRecords.exportArtifactsByLane,
  };
  const getSessionRecordByThresholdSessionId: WarmSigningPorts['getThresholdEcdsaSessionRecordByThresholdSessionId'] =
    (thresholdSessionIdRaw) => {
      const thresholdSessionId = String(thresholdSessionIdRaw || '').trim();
      if (!thresholdSessionId) return null;
      return (
        getThresholdEcdsaSessionRecordByThresholdSessionId(ecdsaSessions, thresholdSessionId) ||
        getStoredThresholdEcdsaSessionRecordByThresholdSessionId(thresholdSessionId)
      );
    };
  const statusUiConfirm = createWarmSessionStatusOnlyUiConfirm({
    base: args.touchConfirm,
    secondary: {
      readWarmSessionStatusOnly: args.getEmailOtpWarmSessionStatus,
    },
  });
  const readCombinedEmailOtpWarmSessionStatus = (sessionId: string) =>
    statusUiConfirm.getWarmSessionStatus({ sessionId });
  const statusReader = createWarmSessionStatusReader({
    touchConfirm: statusUiConfirm,
    getThresholdEcdsaSessionRecordByThresholdSessionId: getSessionRecordByThresholdSessionId,
    getEmailOtpWarmSessionStatus: readCombinedEmailOtpWarmSessionStatus,
  });
  const capabilityReader = createWarmSessionCapabilityReader({
    touchConfirm: args.touchConfirm,
    signingSessionSeal:
      args.signingSessionSeal.keyVersion && args.signingSessionSeal.shamirPrimeB64u
        ? {
            keyVersion: args.signingSessionSeal.keyVersion,
            shamirPrimeB64u: args.signingSessionSeal.shamirPrimeB64u,
          }
        : null,
    getThresholdEcdsaSessionRecordByThresholdSessionId: getSessionRecordByThresholdSessionId,
    getEmailOtpWarmSessionStatus: readCombinedEmailOtpWarmSessionStatus,
  });

  return {
    ecdsaSessions,
    statusUiConfirm,
    capabilityReader,
    statusReader,
    getThresholdEcdsaSessionRecordByThresholdSessionId: getSessionRecordByThresholdSessionId,
  };
}

export function createPasskeyPublicDeps(args: {
  seamsWebConfigs: {
    network: SeamsConfigsReadonly['network'];
    signing: SeamsConfigsReadonly['signing'];
  };
  credentialStore: WalletSessionActivationDeps['credentialStore'];
  touchIdPrompt: TouchIdPrompt;
  touchConfirm: UiConfirmRuntimeBridgePort;
  warmSigning: Pick<WarmSigningPorts, 'ecdsaSessions' | 'capabilityReader' | 'statusReader'>;
  thresholdEcdsaBootstrapQueueByWallet: Map<string, Promise<void>>;
  ensureSealedRefreshStartupParity: () => Promise<void>;
  walletSessionActivationDeps: WalletSessionActivationDeps;
}): PasskeyPublicDeps {
  return {
    getWarmSession: (nearAccountId) =>
      args.warmSigning.capabilityReader.getWarmSession(nearAccountId),
    provisionThresholdEd25519Session: async (provisionArgs) =>
      await provisionThresholdEd25519Session(
        {
          credentialStore: args.credentialStore,
          touchIdPrompt: args.touchIdPrompt,
          touchConfirm: args.touchConfirm,
          defaultRelayerUrl: args.seamsWebConfigs.network.relayer?.url || '',
          getSignerWorkerContext: () =>
            args.walletSessionActivationDeps.getSignerWorkerContext(),
        },
        provisionArgs,
      ),
    bootstrapEcdsaSession: async (bootstrapArgs) => {
      const result = await bootstrapWarmEcdsaCapabilityResult(
        {
          ensureSealedRefreshStartupParity: args.ensureSealedRefreshStartupParity,
          queueByWallet: args.thresholdEcdsaBootstrapQueueByWallet,
          activationDeps: args.walletSessionActivationDeps,
          touchConfirm: args.touchConfirm,
          ecdsaSessions: args.warmSigning.ecdsaSessions,
          capabilityReader: args.warmSigning.capabilityReader,
        },
        bootstrapArgs,
      );
      if (result.ok) return result.bootstrap;
      const failureKind = result.kind;
      switch (failureKind) {
        case 'reuse_failed':
          throw reuseWarmEcdsaBootstrapFailureToError(result.failure);
      }
      failureKind satisfies never;
      throw new Error('[SigningEngine][ecdsa] unsupported warm bootstrap result');
    },
  };
}

export function createWarmCapabilitiesPublicDeps(args: {
  seamsWebConfigs: {
    network: SeamsConfigsReadonly['network'];
    signing: SeamsConfigsReadonly['signing'];
  };
  bootstrapStore: ThresholdEcdsaBootstrapStorePort;
  touchConfirm: UiConfirmRuntimeBridgePort;
  warmSigning: Pick<WarmSigningPorts, 'ecdsaSessions' | 'capabilityReader' | 'statusReader'>;
  walletSessionActivationDeps: WalletSessionActivationDeps;
  resolveCanonicalThresholdEcdsaSessionIdForWalletTarget: SigningEnginePorts['resolveCanonicalThresholdEcdsaSessionIdForWalletTarget'];
  signingSessionCoordinator: Pick<
    SigningEnginePorts['signingSessionCoordinator'],
    'getAvailableStatus'
  >;
}): WarmCapabilitiesPublicDeps {
  return {
    statusReader: args.warmSigning.statusReader,
    persistThresholdEcdsaBootstrapForWalletTarget: async (
      persistArgs: PersistThresholdEcdsaBootstrapForWalletTargetInput,
    ) =>
      await persistThresholdEcdsaBootstrapForWalletTarget({
        bootstrapStore: args.bootstrapStore,
        walletId: persistArgs.walletId,
        chainTarget: persistArgs.chainTarget,
        bootstrap: persistArgs.bootstrap,
        signerAuth: persistArgs.signerAuth,
      }),
    hydrateSigningSession: async (hydrateArgs: HydrateSigningSessionInput) =>
      await cacheSigningSessionPrfFirst(args.touchConfirm, hydrateArgs),
    clearVolatileWarmSigningMaterial: async (walletId) =>
      await clearVolatileWarmSigningMaterial(
        {
          touchConfirm: args.touchConfirm,
          ecdsaSessions: args.warmSigning.ecdsaSessions,
          clearVolatileThresholdSessionMaterial: async (command) =>
            await args.touchConfirm.clearVolatileWarmSessionMaterial(command),
        },
        walletId,
      ),
    getWalletSigningBudgetStatus: (statusArgs) =>
      args.signingSessionCoordinator.getAvailableStatus(statusArgs),
    resolveCanonicalThresholdEcdsaSessionIdForWalletTarget: (walletId, chainTarget) =>
      args.resolveCanonicalThresholdEcdsaSessionIdForWalletTarget(walletId, chainTarget),
    routerAbEcdsaHssPresignaturePoolPolicy: args.seamsWebConfigs.signing.routerAbEcdsaHss.presignaturePool,
    getSignerWorkerContext: () => args.walletSessionActivationDeps.getSignerWorkerContext(),
    resolveClientSigningMaterialSource: createEcdsaLoginPrefillClientSigningMaterialSource,
  };
}
