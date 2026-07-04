import type { PrivateKeyExportRecoveryDeps } from '../../interfaces/operationDeps';
import { configuredThresholdEcdsaChainTargets } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { thresholdEcdsaChainTargetKey } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  readPersistedAvailableSigningLanes,
  readPersistedAvailableSigningLanesForTargets,
} from '../../session/availability/persistedAvailableSigningLanes';
import type { UiConfirmRuntimeBridgePort, WarmSessionStatusResult } from '../../uiConfirm/uiConfirm.types';
import type { WarmSessionCapabilityReader } from '../../session/warmCapabilities/types';
import type { WarmSigningStatusReader } from '../../session/warmCapabilities/statusReader';
import type { WalletSigningBudgetAvailableStatusDeps } from '../../session/budget/budgetStatusReader';
import type {
  RecoveryPublicDeps,
  RecoveryPublicEcdsaSessionStoreDeps,
} from '../../flows/recovery/public';
import type {
  EmailOtpNearAccountExportAuthorizationDeps,
  EmailOtpWalletSessionExportAuthorizationDeps,
} from '../../flows/recovery/keyExportConfirmation';
import type { CreateSigningEnginePortsArgs } from './shared';
import type {
  EmailOtpEcdsaExportArtifact,
  ExportEcdsaKeyWithAuthorizationArgs,
} from '../../session/emailOtp/exportRecoveryRuntime';

export function createPrivateKeyExportRecoveryDeps(
  args: CreateSigningEnginePortsArgs,
  runtimeDeps: { keyMaterialStore: PrivateKeyExportRecoveryDeps['keyMaterialStore'] },
): PrivateKeyExportRecoveryDeps {
  return {
    keyMaterialStore: runtimeDeps.keyMaterialStore,
    relayerUrl: args.seamsWebConfigs.network.relayer.url,
    getRpId: () => args.touchIdPrompt.getRpId(),
    requestExportPrivateKeysWithUi: (payload) =>
      args.signerWorkerManager.requestExportPrivateKeysWithUi(payload),
    getTheme: args.getTheme,
  };
}

export function createRecoveryPublicDeps(args: {
  seamsWebConfigs: CreateSigningEnginePortsArgs['seamsWebConfigs'];
  touchIdPrompt: CreateSigningEnginePortsArgs['touchIdPrompt'];
  signerWorkerManager: CreateSigningEnginePortsArgs['signerWorkerManager'];
  privateKeyExportRecovery: PrivateKeyExportRecoveryDeps;
  ecdsaSessions: RecoveryPublicEcdsaSessionStoreDeps;
  touchConfirm: UiConfirmRuntimeBridgePort;
  emailOtpSessions: {
    readWarmSessionStatusOnly: (sessionId: string) => Promise<WarmSessionStatusResult>;
    restorePersistedSessionForSigning: RecoveryPublicDeps['laneSelection']['restoreEmailOtpPersistedSessionForSigning'];
    requestExportChallenge:
      & EmailOtpNearAccountExportAuthorizationDeps['requestExportChallenge']
      & EmailOtpWalletSessionExportAuthorizationDeps['requestExportChallenge'];
    exportEcdsaKeyWithFreshEmailOtpLane: RecoveryPublicDeps['ecdsa']['emailOtp']['exportEcdsaKeyWithFreshEmailOtpLane'];
    exportEcdsaKeyWithAuthorization: (
      request: ExportEcdsaKeyWithAuthorizationArgs,
    ) => Promise<EmailOtpEcdsaExportArtifact>;
    exportEd25519SeedWithAuthorization: RecoveryPublicDeps['nearSingleKeyHss']['emailOtpSessions']['exportEd25519SeedWithAuthorization'];
  };
  keyMaterialStore: PrivateKeyExportRecoveryDeps['keyMaterialStore'];
  provisionThresholdEd25519Session: RecoveryPublicDeps['nearSingleKeyHss']['provisionThresholdEd25519Session'];
  provisionThresholdEcdsaSession: RecoveryPublicDeps['ecdsa']['provisionThresholdEcdsaSession'];
  warmSessionPolicy: {
    getWarmSession: WarmSessionCapabilityReader['getWarmSession'];
    resolveExactEcdsaRecord: WarmSigningStatusReader['resolveExactEcdsaRecord'];
  };
  getWalletSigningBudgetStatus: WalletSigningBudgetAvailableStatusDeps['getAvailableStatus'];
}): RecoveryPublicDeps {
  const getEmailOtpWarmSessionStatus = (sessionId: string) =>
    args.emailOtpSessions.readWarmSessionStatusOnly(sessionId);
  const configuredChainTargets = configuredThresholdEcdsaChainTargets(
    args.seamsWebConfigs.network.chains,
  );
  const completeConfiguredEcdsaTargets = <
    TArgs extends { ecdsaChainTargets: readonly (typeof configuredChainTargets)[number][] },
  >(
    availableLanesArgs: TArgs,
  ): TArgs => {
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
    laneSelection: {
      readPersistedAvailableSigningLanes: (availableLanesArgs) =>
        readPersistedAvailableSigningLanes(
          {
            ecdsaSessions: args.ecdsaSessions,
            statusReader: args.touchConfirm,
            getEmailOtpWarmSessionStatus,
            getWalletSigningBudgetStatus: args.getWalletSigningBudgetStatus,
          },
          availableLanesArgs,
          configuredChainTargets,
        ),
      readPersistedAvailableSigningLanesForTargets: (availableLanesArgs) =>
        readPersistedAvailableSigningLanesForTargets(
          {
            ecdsaSessions: args.ecdsaSessions,
            statusReader: args.touchConfirm,
            getEmailOtpWarmSessionStatus,
            getWalletSigningBudgetStatus: args.getWalletSigningBudgetStatus,
          },
          completeConfiguredEcdsaTargets(availableLanesArgs),
        ),
      restorePasskeyPersistedSessionForSigning: (restoreArgs) =>
        args.touchConfirm.restorePersistedSessionForSigning(restoreArgs),
      restoreEmailOtpPersistedSessionForSigning: (restoreArgs) =>
        args.emailOtpSessions.restorePersistedSessionForSigning(restoreArgs),
    },
    nearSingleKeyHss: {
      keyMaterialStore: args.keyMaterialStore,
      touchConfirm: args.touchConfirm,
      provisionThresholdEd25519Session: (request) =>
        args.provisionThresholdEd25519Session(request),
      emailOtpSessions: {
        requestExportChallenge: (
          request: Parameters<EmailOtpNearAccountExportAuthorizationDeps['requestExportChallenge']>[0],
        ) => args.emailOtpSessions.requestExportChallenge(request),
        exportEd25519SeedWithAuthorization: (request) =>
          args.emailOtpSessions.exportEd25519SeedWithAuthorization(request),
      },
      getSignerWorkerContext: () =>
        args.signerWorkerManager.getContext(),
    },
    ecdsa: {
      sessionStore: args.ecdsaSessions,
      touchConfirm: args.touchConfirm,
      emailOtp: {
        requestExportChallenge: (
          request: Parameters<EmailOtpWalletSessionExportAuthorizationDeps['requestExportChallenge']>[0],
        ) => args.emailOtpSessions.requestExportChallenge(request),
        exportEcdsaKeyWithFreshEmailOtpLane: (request) =>
          args.emailOtpSessions.exportEcdsaKeyWithFreshEmailOtpLane(request),
        exportEcdsaKeyWithAuthorization: (request) =>
          args.emailOtpSessions.exportEcdsaKeyWithAuthorization(request),
      },
      warmSessionPolicy: args.warmSessionPolicy,
      provisionThresholdEcdsaSession: (request) =>
        args.provisionThresholdEcdsaSession(request),
      getSignerWorkerContext: () =>
        args.signerWorkerManager.getContext(),
    },
    touchConfirm: args.touchConfirm,
    getTheme: () => args.privateKeyExportRecovery.getTheme(),
    getSignerWorkerContext: () => args.signerWorkerManager.getContext(),
    privateKeyExportRecovery: args.privateKeyExportRecovery,
  };
}
