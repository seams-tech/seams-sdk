import type { UnifiedIndexedDBManager } from '@/core/indexedDB';
import type { ThresholdEd25519LifecycleDeps } from '../../threshold/ed25519/hssLifecycle';
import type { ThresholdSessionActivationDeps } from '../../session/passkey/ecdsaBootstrap';
import type { RegistrationAccountLifecycleDeps } from '../../interfaces/operationDeps';
import { generateSessionId as generateSessionIdValue } from '../../session/passkey/prfCache';
import type { CreateSigningEnginePortsArgs } from './shared';

export function createThresholdEd25519LifecycleDeps(
  args: CreateSigningEnginePortsArgs,
): ThresholdEd25519LifecycleDeps {
  return {
    signingKeyOps: args.signerWorkerManager.nearKeyOps,
    createSessionId: (prefix: string): string => generateSessionIdValue(prefix),
    getSignerWorkerContext: () => args.signerWorkerManager.getContext(),
  };
}

export function createThresholdSessionActivationDeps(args: {
  createArgs: CreateSigningEnginePortsArgs;
  indexedDB: UnifiedIndexedDBManager;
  getOrCreateActiveThresholdEcdsaSessionId: ThresholdSessionActivationDeps['getOrCreateActiveThresholdEcdsaSessionId'];
}): ThresholdSessionActivationDeps {
  return {
    indexedDB: args.indexedDB,
    touchIdPrompt: args.createArgs.touchIdPrompt,
    touchConfirm: args.createArgs.touchConfirm,
    getSignerWorkerContext: () => args.createArgs.signerWorkerManager.getContext(),
    getOrCreateActiveThresholdEcdsaSessionId: args.getOrCreateActiveThresholdEcdsaSessionId,
    defaultRelayerUrl: args.createArgs.seamsPasskeyConfigs.network.relayer?.url || '',
    persistThresholdEcdsaBootstrapForWalletTarget:
      args.createArgs.persistThresholdEcdsaBootstrapForWalletTarget,
    upsertThresholdEcdsaSessionFromBootstrap: args.createArgs.upsertThresholdEcdsaSessionFromBootstrap,
  };
}

export function createRegistrationAccountLifecycleDeps(args: {
  createArgs: CreateSigningEnginePortsArgs;
  indexedDB: UnifiedIndexedDBManager;
}): RegistrationAccountLifecycleDeps {
  return {
    indexedDB: args.indexedDB,
    userPreferencesManager: args.createArgs.userPreferencesManager,
    nonceCoordinator: args.createArgs.nonceCoordinator,
    extractCosePublicKey: args.createArgs.extractCosePublicKey,
  };
}
