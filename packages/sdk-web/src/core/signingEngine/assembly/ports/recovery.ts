import type { PrivateKeyExportRecoveryDeps } from '../../interfaces/operationDeps';
import { configuredThresholdEcdsaChainTargets } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { thresholdEcdsaChainTargetKey } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { readPersistedAvailableSigningLanesForTargets } from '../../session/availability/persistedAvailableSigningLanes';
import type {
  UiConfirmRuntimeBridgePort,
  WarmSessionStatusResult,
} from '../../uiConfirm/uiConfirm.types';
import type { WarmSessionCapabilityReader } from '../../session/warmCapabilities/types';
import type { WarmSigningStatusReader } from '../../session/warmCapabilities/statusReader';
import type { WalletSigningBudgetAvailableStatusDeps } from '../../session/budget/budgetStatusReader';
import type {
  RecoveryPublicDeps,
  RecoveryPublicEcdsaSessionStoreDeps,
} from '../../flows/recovery/public';
import type { EmailOtpWalletSessionExportAuthorizationDeps } from '../../flows/recovery/keyExportConfirmation';
import type { CreateSigningEnginePortsArgs } from './shared';
import type {
  EmailOtpEcdsaExportArtifact,
  ExportEcdsaKeyWithAuthorizationArgs,
  ExportEcdsaKeyWithDurableAuthorizationArgs,
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
  signerWorkerManager: CreateSigningEnginePortsArgs['signerWorkerManager'];
  getTheme: PrivateKeyExportRecoveryDeps['getTheme'];
  ecdsaSessions: RecoveryPublicEcdsaSessionStoreDeps;
  touchConfirm: UiConfirmRuntimeBridgePort;
  emailOtpSessions: {
    readWarmSessionStatusOnly: (sessionId: string) => Promise<WarmSessionStatusResult>;
    requestExportChallenge: EmailOtpWalletSessionExportAuthorizationDeps['requestExportChallenge'];
    exportEcdsaKeyWithAuthorization: (
      request: ExportEcdsaKeyWithAuthorizationArgs,
    ) => Promise<EmailOtpEcdsaExportArtifact>;
    exportEcdsaKeyWithDurableAuthorization: (
      request: ExportEcdsaKeyWithDurableAuthorizationArgs,
    ) => Promise<EmailOtpEcdsaExportArtifact>;
    exportEd25519YaoSeedWithFreshEmailOtpLane: RecoveryPublicDeps['ed25519Yao']['emailOtp']['exportSeedWithFreshAuthorization'];
  };
  provisionThresholdEcdsaSession: RecoveryPublicDeps['ecdsa']['provisionThresholdEcdsaSession'];
  warmSessionPolicy: {
    getWarmSession: WarmSessionCapabilityReader['getWarmSession'];
    resolveExactEcdsaRecord: WarmSigningStatusReader['resolveExactEcdsaRecord'];
  };
  getWalletSigningBudgetStatus: WalletSigningBudgetAvailableStatusDeps['getAvailableStatus'];
  resolveActiveEd25519YaoCapability: RecoveryPublicDeps['ed25519Yao']['resolveActiveCapability'];
  recoverPasskeyEd25519YaoCapability: RecoveryPublicDeps['ed25519Yao']['recoverPasskeyCapability'];
  resolvePasskeyEd25519YaoExportContext: RecoveryPublicDeps['ed25519Yao']['resolvePasskeyExportContext'];
  resolveEmailOtpEd25519YaoExportContext: RecoveryPublicDeps['ed25519Yao']['emailOtp']['resolveExportContext'];
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
    },
    ecdsa: {
      sessionStore: args.ecdsaSessions,
      touchConfirm: args.touchConfirm,
      emailOtp: {
        requestExportChallenge: (
          request: Parameters<
            EmailOtpWalletSessionExportAuthorizationDeps['requestExportChallenge']
          >[0],
        ) => args.emailOtpSessions.requestExportChallenge(request),
        exportEcdsaKeyWithAuthorization: (request) =>
          args.emailOtpSessions.exportEcdsaKeyWithAuthorization(request),
        exportEcdsaKeyWithDurableAuthorization: (request) =>
          args.emailOtpSessions.exportEcdsaKeyWithDurableAuthorization(request),
      },
      warmSessionPolicy: args.warmSessionPolicy,
      provisionThresholdEcdsaSession: (request) => args.provisionThresholdEcdsaSession(request),
      getSignerWorkerContext: () => args.signerWorkerManager.getContext(),
    },
    ed25519Yao: {
      touchConfirm: args.touchConfirm,
      resolveActiveCapability: args.resolveActiveEd25519YaoCapability,
      recoverPasskeyCapability: args.recoverPasskeyEd25519YaoCapability,
      resolvePasskeyExportContext: args.resolvePasskeyEd25519YaoExportContext,
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
