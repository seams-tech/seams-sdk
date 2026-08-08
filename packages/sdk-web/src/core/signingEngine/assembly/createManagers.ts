import type { NearClient } from '@/core/rpcClients/near/NearClient';
import { createEvmNonceBackend } from '@/core/rpcClients/evm/nonceBackend';
import { createNonceCoordinator, type NonceCoordinator } from '../nonce/NonceCoordinator';
import { resolvePrimaryExplorerUrl } from '@/core/config/chains';
import type { AppearanceConfig, ThemeMode, SeamsConfigsReadonly } from '@/core/types/seams';
import { createUiConfirmManager } from '../uiConfirm/UiConfirmManager';
import { createPasskeyMpcExportManager } from '../uiConfirm/PasskeyMpcExportManager';
import { createPasskeyMpcSessionManager } from '../uiConfirm/PasskeyMpcSessionManager';
import type {
  PasskeyMpcExportPort,
  PasskeyMpcSessionPort,
  UiConfirmRuntimeBridgePort,
} from '../uiConfirm/uiConfirm.types';
import type { UiConfirmContext } from '../uiConfirm/uiConfirm.types';
import { TouchIdPrompt } from '../stepUpConfirmation/passkeyPrompt/touchIdPrompt';
import { SignerWorkerManager } from '../workerManager/SignerWorkerManager';
import type { SignerWorkerManagerDeps } from '../workerManager/SignerWorkerManager';
import { getWorkerTransport } from '../workerManager/workerTransport';
import { type UserPreferencesStorePort, UserPreferencesManager } from '../session/userPreferences';
import type { NonceLaneCoordinationStore } from '../nonce/NonceCoordinator';
import type { DurableRecordStore } from '@/core/platform';
import { nearOperationStepUpPreparationPort } from '../flows/signNear/shared/operationStepUpPreparation';
import { nearImplicitAccountFundingPort } from '../flows/signNear/shared/implicitAccountFundingPort';
import type { ThresholdEcdsaSigningQueueByKey } from '../threshold/ecdsa/signingQueue';
import { resolveActiveEcdsaCapabilityRuntime } from '../session/material/activeEcdsaCapabilityRuntime';

export type ManagerAssembly = {
  touchIdPrompt: TouchIdPrompt;
  userPreferencesManager: UserPreferencesManager;
  nonceCoordinator: NonceCoordinator;
  touchConfirm: UiConfirmRuntimeBridgePort;
  passkeyMpcExport: PasskeyMpcExportPort;
  passkeyMpcSession: PasskeyMpcSessionPort;
  signerWorkerManager: SignerWorkerManager;
};

export type ManagerAssemblyStores = {
  userPreferencesStore: UserPreferencesStorePort;
  nonceLaneCoordinationStore: NonceLaneCoordinationStore;
  webauthnCredentialStore: UiConfirmContext['webauthnCredentialStore'];
  passkeyAuthenticatorStore: UiConfirmContext['passkeyAuthenticatorStore'];
  nearKeyMaterialStore: SignerWorkerManagerDeps['nearKeyMaterialStore'];
};

export function createManagerAssembly(args: {
  resolveOperationStepUpCredential: SignerWorkerManagerDeps['resolveOperationStepUpCredential'];
  stores: ManagerAssemblyStores;
  seamsWebConfigs: SeamsConfigsReadonly;
  nearClient: NearClient;
  loadEcdsaRoleLocalReadyRecord: DurableRecordStore['loadEcdsaRoleLocalReadyRecord'];
  getTheme: () => ThemeMode;
  getAppearance: () => AppearanceConfig;
  thresholdEcdsaSigningQueueByKey: ThresholdEcdsaSigningQueueByKey;
}): ManagerAssembly {
  const touchIdPrompt = new TouchIdPrompt(args.seamsWebConfigs.wallet.iframe?.rpIdOverride, true);
  const userPreferencesManager = new UserPreferencesManager({
    store: args.stores.userPreferencesStore,
  });
  const chains = args.seamsWebConfigs.network.chains;
  const evmNonceBackend = createEvmNonceBackend({
    chains,
  });
  const nonceCoordinator = createNonceCoordinator({
    evmNonceBackend,
    nearClient: args.nearClient,
    nonceLaneCoordinationStore: args.stores.nonceLaneCoordinationStore,
  });
  const nearExplorerUrl = resolvePrimaryExplorerUrl(chains, 'near');
  const tempoExplorerUrl = resolvePrimaryExplorerUrl(chains, 'tempo');
  const evmExplorerUrl = resolvePrimaryExplorerUrl(chains, 'evm');
  const passkeyMpcSession = createPasskeyMpcSessionManager({
    signingSessionPersistenceMode: args.seamsWebConfigs.signing.sessionPersistenceMode,
    thresholdEcdsaSigningQueueByKey: args.thresholdEcdsaSigningQueueByKey,
    resolveCurrentEcdsaCapabilityRuntime: resolveActiveEcdsaCapabilityRuntime,
  });
  const touchConfirm = createUiConfirmManager(
    {},
    {
      touchIdPrompt: touchIdPrompt,
      nearClient: args.nearClient,
      webauthnCredentialStore: args.stores.webauthnCredentialStore,
      passkeyAuthenticatorStore: args.stores.passkeyAuthenticatorStore,
      userPreferencesManager: userPreferencesManager,
      nonceCoordinator: nonceCoordinator,
      operationStepUpPreparation: nearOperationStepUpPreparationPort,
      nearImplicitAccountFunding: nearImplicitAccountFundingPort,
      relayerUrl: args.seamsWebConfigs.network.relayer.url,
      chains,
      rpIdOverride: touchIdPrompt.getRpId(),
      nearExplorerUrl,
      tempoExplorerUrl,
      evmExplorerUrl,
      getTheme: args.getTheme,
      getAppearance: args.getAppearance,
      loadEcdsaRoleLocalReadyRecord: args.loadEcdsaRoleLocalReadyRecord,
      surfaceMeasurementBinding: { kind: 'disabled' },
    },
  );
  const passkeyMpcExport = createPasskeyMpcExportManager(touchConfirm.getContext());

  const signerWorkerManager = new SignerWorkerManager({
    resolveOperationStepUpCredential: args.resolveOperationStepUpCredential,
    nearKeyMaterialStore: args.stores.nearKeyMaterialStore,
    touchIdPrompt,
    touchConfirm,
    passkeyMpcSession,
    nearClient: args.nearClient,
    userPreferencesManager,
    nonceCoordinator,
    relayerUrl: args.seamsWebConfigs.network.relayer.url,
    workerTransport: getWorkerTransport(),
    chains,
    nearExplorerUrl,
    tempoExplorerUrl,
    evmExplorerUrl,
    getTheme: args.getTheme,
  });

  return {
    touchIdPrompt,
    userPreferencesManager,
    nonceCoordinator,
    touchConfirm,
    passkeyMpcExport,
    passkeyMpcSession,
    signerWorkerManager,
  };
}
