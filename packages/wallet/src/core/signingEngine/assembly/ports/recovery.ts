import { configuredThresholdEcdsaChainTargets } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { thresholdEcdsaChainTargetKey } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  readOwnerScopedAvailableSigningLanes,
  readPersistedAvailableSigningLanesForTargets,
} from '../../session/availability/persistedAvailableSigningLanes';
import type {
  PasskeyMpcExportPort,
  PasskeyMpcSessionPort,
  UiConfirmRuntimeBridgePort,
  WarmSessionStatusResult,
} from '../../uiConfirm/uiConfirm.types';
import type { WalletSigningSessionStatusDeps } from '../../session/lifecycle/walletSessionStatus';
import type {
  RecoveryPublicDeps,
  RecoveryPublicEcdsaSessionStoreDeps,
} from '../../flows/recovery/public';
import type { EmailOtpExportAuthorizationDeps } from '../../flows/recovery/keyExportConfirmation';
import type { CreateSigningEnginePortsArgs } from './shared';
import type {
  EmailOtpEcdsaExportArtifact,
  ExportEcdsaKeyWithDurableAuthorizationArgs,
} from '../../session/emailOtp/exportRecoveryRuntime';
import type { PersistedAvailableSigningLanesDeps } from '../../session/availability/persistedAvailableSigningLanes';
import type { EcdsaExportFlowDeps } from '../../flows/recovery/ecdsaExportFlow';
import type { Ed25519YaoExportFlowDeps } from '../../flows/recovery/ed25519YaoExportFlow';
import type { EmailOtpWarmMaterialTarget } from '../../workerManager/workerTypes';
import type { OwnerLaneScope } from '../../session/identity/signingLaneAuthBinding';

export function createRecoveryPublicDeps(args: {
  seamsWebConfigs: CreateSigningEnginePortsArgs['seamsWebConfigs'];
  signerWorkerManager: CreateSigningEnginePortsArgs['signerWorkerManager'];
  getTheme: CreateSigningEnginePortsArgs['getTheme'];
  withThresholdEcdsaSigningQueue: EcdsaExportFlowDeps['withThresholdEcdsaSigningQueue'];
  withThresholdEd25519CommitQueue: Ed25519YaoExportFlowDeps['withThresholdEd25519CommitQueue'];
  ecdsaSessions: Pick<RecoveryPublicEcdsaSessionStoreDeps, 'exportArtifactsByLane'>;
  relayerUrl: string;
  readActiveWalletSessionAuthorization: PersistedAvailableSigningLanesDeps['readActiveWalletSessionAuthorization'];
  ed25519YaoPublicCapabilityLanes: PersistedAvailableSigningLanesDeps['ed25519YaoPublicCapabilityLanes'];
  isEd25519YaoPublicCapabilityActive: PersistedAvailableSigningLanesDeps['isEd25519YaoPublicCapabilityActive'];
  listEcdsaSigningCapabilitiesForWallet: PersistedAvailableSigningLanesDeps['listEcdsaSigningCapabilitiesForWallet'];
  resolveOwnerLaneScope(walletId: string): Promise<OwnerLaneScope>;
  touchConfirm: UiConfirmRuntimeBridgePort;
  passkeyMpcExport: PasskeyMpcExportPort;
  passkeyMpcSession: PasskeyMpcSessionPort;
  emailOtpSessions: {
    readWarmSessionStatusOnly: (
      target: EmailOtpWarmMaterialTarget,
    ) => Promise<WarmSessionStatusResult>;
    requestExportChallenge: EmailOtpExportAuthorizationDeps['requestExportChallenge'];
    exportEcdsaKeyWithDurableAuthorization: (
      request: ExportEcdsaKeyWithDurableAuthorizationArgs,
    ) => Promise<EmailOtpEcdsaExportArtifact>;
    exportEd25519YaoSeedWithFreshEmailOtpLane: RecoveryPublicDeps['ed25519Yao']['emailOtp']['exportSeedWithFreshAuthorization'];
  };
  provisionPasskeyEcdsaExplicitExportSession: RecoveryPublicDeps['ecdsa']['provisionPasskeyEcdsaExplicitExportSession'];
  getWalletSessionStatus: WalletSigningSessionStatusDeps['getAvailableStatus'];
  resolvePasskeyEd25519YaoExportContext: RecoveryPublicDeps['ed25519Yao']['resolvePasskeyExportContext'];
  resolveEmailOtpEd25519YaoExportContext: RecoveryPublicDeps['ed25519Yao']['emailOtp']['resolveExportContext'];
  sessionLifecycle: RecoveryPublicDeps['sessionLifecycle'];
}): RecoveryPublicDeps {
  const getEmailOtpWarmSessionStatus = (target: EmailOtpWarmMaterialTarget) =>
    args.emailOtpSessions.readWarmSessionStatusOnly(target);
  const configuredChainTargets = configuredThresholdEcdsaChainTargets(
    args.seamsWebConfigs.network.chains,
  );
  const completeConfiguredEcdsaTargets = <
    TArgs extends { ecdsaChainTargets: readonly (typeof configuredChainTargets)[number][] },
  >(
    availableLanesArgs: TArgs,
  ): TArgs => {
    if (availableLanesArgs.ecdsaChainTargets.length === 0) return availableLanesArgs;
    const targetsByKey = new Map<string, (typeof configuredChainTargets)[number]>();
    for (const chainTarget of [
      ...availableLanesArgs.ecdsaChainTargets,
      ...configuredChainTargets,
    ]) {
      targetsByKey.set(thresholdEcdsaChainTargetKey(chainTarget), chainTarget);
    }
    return {
      ...availableLanesArgs,
      ecdsaChainTargets: [...targetsByKey.values()],
    };
  };
  return {
    sessionLifecycle: args.sessionLifecycle,
    laneSelection: {
      readPersistedAvailableSigningLanesForTargets: (availableLanesArgs) =>
        readPersistedAvailableSigningLanesForTargets(
          {
            ed25519YaoPublicCapabilityLanes: args.ed25519YaoPublicCapabilityLanes,
            isEd25519YaoPublicCapabilityActive: args.isEd25519YaoPublicCapabilityActive,
            readActiveWalletSessionAuthorization: args.readActiveWalletSessionAuthorization,
            listEcdsaSigningCapabilitiesForWallet: args.listEcdsaSigningCapabilitiesForWallet,
          },
          completeConfiguredEcdsaTargets(availableLanesArgs),
        ),
      readOwnerScopedAvailableSigningLanesForTargets: async (availableLanesArgs) =>
        await readOwnerScopedAvailableSigningLanes(
          {
            ed25519YaoPublicCapabilityLanes: args.ed25519YaoPublicCapabilityLanes,
            isEd25519YaoPublicCapabilityActive: args.isEd25519YaoPublicCapabilityActive,
            readActiveWalletSessionAuthorization: args.readActiveWalletSessionAuthorization,
            listEcdsaSigningCapabilitiesForWallet: args.listEcdsaSigningCapabilitiesForWallet,
          },
          {
            ...completeConfiguredEcdsaTargets(availableLanesArgs),
            ownerScope: await args.resolveOwnerLaneScope(String(availableLanesArgs.walletId)),
          },
        ),
    },
    ecdsa: {
      sessionStore: {
        ...args.ecdsaSessions,
        relayerUrl: String(args.relayerUrl).trim().replace(/\/+$/g, ''),
      },
      touchConfirm: args.touchConfirm,
      emailOtp: {
        requestExportChallenge: (
          request: Parameters<EmailOtpExportAuthorizationDeps['requestExportChallenge']>[0],
        ) => args.emailOtpSessions.requestExportChallenge(request),
        exportEcdsaKeyWithDurableAuthorization: (request) =>
          args.emailOtpSessions.exportEcdsaKeyWithDurableAuthorization(request),
      },
      provisionPasskeyEcdsaExplicitExportSession: (request) =>
        args.provisionPasskeyEcdsaExplicitExportSession(request),
      getSignerWorkerContext: () => args.signerWorkerManager.getContext(),
      withThresholdEcdsaSigningQueue: args.withThresholdEcdsaSigningQueue,
    },
    ed25519Yao: {
      touchConfirm: args.touchConfirm,
      passkeyMpcExport: args.passkeyMpcExport,
      resolvePasskeyExportContext: args.resolvePasskeyEd25519YaoExportContext,
      withThresholdEd25519CommitQueue: args.withThresholdEd25519CommitQueue,
      emailOtp: {
        requestExportChallenge: (request) => args.emailOtpSessions.requestExportChallenge(request),
        resolveExportContext: (subject) => args.resolveEmailOtpEd25519YaoExportContext(subject),
        exportSeedWithFreshAuthorization: (request) =>
          args.emailOtpSessions.exportEd25519YaoSeedWithFreshEmailOtpLane(request),
      },
    },
    getTheme: args.getTheme,
  };
}
