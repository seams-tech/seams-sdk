import { IndexedDBManager } from '@/core/indexedDB';
import type { PrivateKeyExportRecoveryDeps } from '../../interfaces/operationDeps';
import { configuredThresholdEcdsaChainTargets } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  readPersistedAvailableSigningLanes,
  readPersistedAvailableSigningLanesForTargets,
} from '../../session/availability/persistedAvailableSigningLanes';
import type { UiConfirmRuntimeBridgePort } from '../../uiConfirm/types';
import type { WarmSessionCapabilityReader } from '../../session/warmSigning/types';
import type { WarmSigningStatusReader } from '../../session/warmSigning/statusReader';
import type {
  RecoveryPublicDeps,
  RecoveryPublicEcdsaSessionStoreDeps,
} from '../../flows/recovery/public';
import type { CreateSigningEnginePortsArgs } from './shared';

export function createPrivateKeyExportRecoveryDeps(
  args: CreateSigningEnginePortsArgs,
): PrivateKeyExportRecoveryDeps {
  return {
    indexedDB: IndexedDBManager,
    relayerUrl: args.seamsPasskeyConfigs.network.relayer.url,
    getRpId: () => args.touchIdPrompt.getRpId(),
    requestExportPrivateKeysWithUi: (payload) =>
      args.signerWorkerManager.requestExportPrivateKeysWithUi(payload),
    getTheme: args.getTheme,
  };
}

export function createRecoveryPublicDeps(args: {
  seamsPasskeyConfigs: CreateSigningEnginePortsArgs['seamsPasskeyConfigs'];
  touchIdPrompt: CreateSigningEnginePortsArgs['touchIdPrompt'];
  signerWorkerManager: CreateSigningEnginePortsArgs['signerWorkerManager'];
  privateKeyExportRecovery: PrivateKeyExportRecoveryDeps;
  ecdsaSessions: RecoveryPublicEcdsaSessionStoreDeps;
  touchConfirm: UiConfirmRuntimeBridgePort;
  emailOtpSessions: {
    restorePersistedSessionForSigning: RecoveryPublicDeps['laneSelection']['restoreEmailOtpPersistedSessionForSigning'];
    requestExportChallenge: RecoveryPublicDeps['ecdsa']['emailOtp']['requestExportChallenge'];
    exportEcdsaKeyWithFreshEmailOtpLane: RecoveryPublicDeps['ecdsa']['emailOtp']['exportEcdsaKeyWithFreshEmailOtpLane'];
    exportEcdsaKeyWithAuthorization: RecoveryPublicDeps['ecdsa']['emailOtp']['exportEcdsaKeyWithAuthorization'];
    recoverEd25519ExportPrfFirst: RecoveryPublicDeps['nearSingleKeyHss']['emailOtpSessions']['recoverEd25519ExportPrfFirst'];
  };
  warmSessionPolicy: {
    getWarmSession: WarmSessionCapabilityReader['getWarmSession'];
    resolveCurrentEcdsaRecord: WarmSigningStatusReader['resolveCurrentEcdsaRecord'];
  };
}): RecoveryPublicDeps {
  const configuredChainTargets = configuredThresholdEcdsaChainTargets(
    args.seamsPasskeyConfigs.network.chains,
  );
  return {
    laneSelection: {
      readPersistedAvailableSigningLanes: (availableLanesArgs) =>
        readPersistedAvailableSigningLanes(
          {
            ecdsaSessions: args.ecdsaSessions,
            statusReader: args.touchConfirm,
          },
          availableLanesArgs,
          configuredChainTargets,
        ),
      readPersistedAvailableSigningLanesForTargets: (availableLanesArgs) =>
        readPersistedAvailableSigningLanesForTargets(
          {
            ecdsaSessions: args.ecdsaSessions,
            statusReader: args.touchConfirm,
          },
          availableLanesArgs,
        ),
      restorePasskeyPersistedSessionForSigning: (restoreArgs) =>
        args.touchConfirm.restorePersistedSessionForSigning(restoreArgs),
      restoreEmailOtpPersistedSessionForSigning: (restoreArgs) =>
        args.emailOtpSessions.restorePersistedSessionForSigning(restoreArgs),
    },
    nearSingleKeyHss: {
      indexedDB: {
        clientDB: IndexedDBManager.clientDB,
        accountKeyMaterialDB: IndexedDBManager.accountKeyMaterialDB,
      },
      touchConfirm: args.touchConfirm,
      emailOtpSessions: {
        requestExportChallenge: (request) => args.emailOtpSessions.requestExportChallenge(request),
        recoverEd25519ExportPrfFirst: (request) =>
          args.emailOtpSessions.recoverEd25519ExportPrfFirst(request),
      },
      getSignerWorkerContext: () =>
        args.signerWorkerManager.getContext(),
    },
    ecdsa: {
      sessionStore: args.ecdsaSessions,
      touchConfirm: args.touchConfirm,
      getRpId: () => args.touchIdPrompt.getRpId(),
      emailOtp: {
        requestExportChallenge: (request) => args.emailOtpSessions.requestExportChallenge(request),
        exportEcdsaKeyWithFreshEmailOtpLane: (request) =>
          args.emailOtpSessions.exportEcdsaKeyWithFreshEmailOtpLane(request),
        exportEcdsaKeyWithAuthorization: (request) =>
          args.emailOtpSessions.exportEcdsaKeyWithAuthorization(request),
      },
      warmSessionPolicy: args.warmSessionPolicy,
      getSignerWorkerContext: () =>
        args.signerWorkerManager.getContext(),
    },
    touchConfirm: args.touchConfirm,
    getTheme: () => args.privateKeyExportRecovery.getTheme(),
    getSignerWorkerContext: () => args.signerWorkerManager.getContext(),
    privateKeyExportRecovery: args.privateKeyExportRecovery,
  };
}
