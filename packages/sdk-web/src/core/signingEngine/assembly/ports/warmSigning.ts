import type { SeamsConfigsReadonly } from '@/core/types/seams';
import type { ThresholdEcdsaCanonicalExportArtifact } from '../../interfaces/signing';
import { createWarmSessionCapabilityReader } from '../../session/warmCapabilities/capabilityReader';
import {
  createWarmSessionStatusReader,
  type WarmSessionStatusReaderDeps,
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
import type {
  PasskeyMpcSessionPort,
  UiConfirmRuntimeBridgePort,
  WarmSessionStatusResult,
} from '../../uiConfirm/uiConfirm.types';
import { SIGNING_SESSION_SEAL_GROUP_ID } from '@shared/utils/signingSessionSeal';
import { persistThresholdEcdsaBootstrapForWalletTarget } from '../../session/warmCapabilities/ecdsaBootstrapPersistence';
import type { ThresholdEcdsaBootstrapStorePort } from '../../session/warmCapabilities/ecdsaBootstrapPersistence';
import {
  bootstrapWarmEcdsaCapabilityResult,
  reuseWarmEcdsaBootstrapFailureToError,
} from '../../session/passkey/ecdsaWarmCapabilityBootstrap';
import { provisionThresholdEd25519Session } from '../../session/passkey/ed25519SessionProvision';
import { clearVolatileWarmSigningMaterial } from '../../session/warmCapabilities/clearVolatileWarmSigningMaterial';
import { cacheCredentialBoundarySetupExportPrfFirst } from '../../session/passkey/prfCache';
import { createEcdsaLoginPrefillClientSigningMaterialSource } from '../../session/warmCapabilities/ecdsaLoginPrefillSigningMaterialSource';
import type { WalletSessionActivationDeps } from '../../session/passkey/ecdsaBootstrap';
import type { SigningEnginePorts } from './shared';
import type { TouchIdPrompt } from '../../stepUpConfirmation/passkeyPrompt/touchIdPrompt';
import { toWalletId } from '../../interfaces/ecdsaChainTarget';
import type { DurableRecordStore } from '@/core/platform';
import type { ActiveEvmFamilyWalletSessionAuthorization } from '../../session/material/ecdsaSigningCapability';
import type { ActiveWalletSessionAuthorizationProjection } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import type { EmailOtpWarmMaterialTarget } from '../../workerManager/workerTypes';

export type EcdsaExportArtifactStorePorts = {
  exportArtifactsByLane: Map<string, ThresholdEcdsaCanonicalExportArtifact>;
};

type WarmSigningAuthorizationResolver = (
  walletId: import('../../interfaces/ecdsaChainTarget').WalletId,
) => Promise<ActiveEvmFamilyWalletSessionAuthorization | null>;

type WarmSigningEd25519AuthorizationResolver = (
  walletId: import('../../interfaces/ecdsaChainTarget').WalletId,
) => Promise<ActiveWalletSessionAuthorizationProjection | null>;

type WarmSigningPortsArgs = {
  touchConfirm: UiConfirmRuntimeBridgePort;
  passkeyMpcSession: PasskeyMpcSessionPort;
  getEmailOtpWarmSessionStatus: (
    target: EmailOtpWarmMaterialTarget,
  ) => Promise<WarmSessionStatusResult>;
  signingSessionSeal: SeamsConfigsReadonly['signing']['sessionSeal'];
  ecdsaExportArtifacts: EcdsaExportArtifactStorePorts;
  resolveActiveEcdsaWalletSessionAuthorization?: WarmSigningAuthorizationResolver;
  resolveActiveEd25519WalletSessionAuthorization?: WarmSigningEd25519AuthorizationResolver;
};

export type WarmSigningPorts = {
  ecdsaSessions: EcdsaExportArtifactStorePorts;
  statusUiConfirm: WarmSessionStatusOnlyReaderPort;
  capabilityReader: WarmSessionCapabilityReader;
  statusReader: WarmSigningStatusReader;
};

export function createWarmSigningPorts(args: WarmSigningPortsArgs): WarmSigningPorts {
  const ecdsaSessions: WarmSigningPorts['ecdsaSessions'] = {
    exportArtifactsByLane: args.ecdsaExportArtifacts.exportArtifactsByLane,
  };
  const statusUiConfirm = createWarmSessionStatusOnlyUiConfirm({
    base: args.passkeyMpcSession,
    secondary: {
      readWarmSessionStatusOnly: (thresholdSessionId) =>
        args.getEmailOtpWarmSessionStatus({
          kind: 'ecdsa',
          thresholdSessionId,
        }),
    },
  });
  const statusReader = createWarmSessionStatusReader({
    touchConfirm: statusUiConfirm,
    getEmailOtpWarmSessionStatus: args.getEmailOtpWarmSessionStatus,
  });
  const capabilityReader = createWarmSessionCapabilityReader({
    touchConfirm: args.passkeyMpcSession,
    signingSessionSeal:
      args.signingSessionSeal.mode === 'sealed_refresh_v1'
        ? { groupId: SIGNING_SESSION_SEAL_GROUP_ID }
        : null,
    getEmailOtpWarmSessionStatus: args.getEmailOtpWarmSessionStatus,
    ...(args.resolveActiveEcdsaWalletSessionAuthorization
      ? {
          resolveActiveEcdsaWalletSessionAuthorization:
            args.resolveActiveEcdsaWalletSessionAuthorization,
        }
      : {}),
    ...(args.resolveActiveEd25519WalletSessionAuthorization
      ? {
          resolveActiveEd25519WalletSessionAuthorization:
            args.resolveActiveEd25519WalletSessionAuthorization,
        }
      : {}),
  });

  return {
    ecdsaSessions,
    statusUiConfirm,
    capabilityReader,
    statusReader,
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
  passkeyMpcSession: PasskeyMpcSessionPort;
  warmSigning: Pick<WarmSigningPorts, 'ecdsaSessions' | 'capabilityReader' | 'statusReader'>;
  thresholdEcdsaBootstrapQueueByWallet: Map<string, Promise<void>>;
  ensureSealedRefreshStartupParity: () => Promise<void>;
  walletSessionActivationDeps: WalletSessionActivationDeps;
  persistEcdsaRoleLocalReadyRecord: DurableRecordStore['persistEcdsaRoleLocalReadyRecord'];
}): PasskeyPublicDeps {
  return {
    getWarmSession: (walletId) =>
      args.warmSigning.capabilityReader.getWarmSession(toWalletId(walletId)),
    provisionThresholdEd25519Session: async (provisionArgs) =>
      await provisionThresholdEd25519Session(
        {
          credentialStore: args.credentialStore,
          touchIdPrompt: args.touchIdPrompt,
          touchConfirm: args.passkeyMpcSession,
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
          passkeyMpcSession: args.passkeyMpcSession,
          persistEcdsaRoleLocalReadyRecord: args.persistEcdsaRoleLocalReadyRecord,
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
  passkeyMpcSession: PasskeyMpcSessionPort;
  warmSigning: Pick<WarmSigningPorts, 'ecdsaSessions' | 'capabilityReader' | 'statusReader'>;
  walletSessionActivationDeps: WalletSessionActivationDeps;
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
      await cacheCredentialBoundarySetupExportPrfFirst(args.passkeyMpcSession, hydrateArgs),
    clearVolatileWarmSigningMaterial: async (walletId) =>
      await clearVolatileWarmSigningMaterial(
        {
          touchConfirm: args.passkeyMpcSession,
          clearVolatileThresholdSessionMaterial: async (command) =>
            await args.passkeyMpcSession.clearVolatileWarmSessionMaterial(command),
        },
        walletId,
      ),
    getWalletSessionStatus: (statusArgs) =>
      args.signingSessionCoordinator.getAvailableStatus(statusArgs),
    routerAbEcdsaDerivationPresignaturePoolPolicy: args.seamsWebConfigs.signing.routerAbEcdsaDerivation.presignaturePool,
    getSignerWorkerContext: () => args.walletSessionActivationDeps.getSignerWorkerContext(),
    resolveClientSigningMaterialSource: createEcdsaLoginPrefillClientSigningMaterialSource,
  };
}
