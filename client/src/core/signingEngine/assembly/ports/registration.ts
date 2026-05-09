import { IndexedDBManager } from '@/core/indexedDB';
import type { ThresholdEd25519LifecycleDeps } from '../../threshold/ed25519/hssLifecycle';
import type {
  RegistrationAccountLifecycleDeps,
  RegistrationSessionDeps,
} from '../../interfaces/operationDeps';
import type { ThresholdSessionActivationDeps } from '../../session/passkey/ecdsaBootstrap';
import { generateSessionId as generateSessionIdValue } from '../../session/passkey/prfCache';
import type { NearKeyOpsDeps, CreateSigningEnginePortsArgs } from './shared';

export function createThresholdEd25519LifecycleDeps(
  args: CreateSigningEnginePortsArgs,
): ThresholdEd25519LifecycleDeps {
  return {
    signingKeyOps: args.signerWorkerManager.nearKeyOps,
    createSessionId: (prefix: string): string => generateSessionIdValue(prefix),
    getSignerWorkerContext: () => args.signerWorkerManager.getContext(),
  };
}

export function createRegistrationAccountLifecycleDeps(
  args: CreateSigningEnginePortsArgs,
): RegistrationAccountLifecycleDeps {
  return {
    indexedDB: IndexedDBManager,
    userPreferencesManager: args.userPreferencesManager,
    nonceCoordinator: args.nonceCoordinator,
    extractCosePublicKey: args.extractCosePublicKey,
  };
}

export function createRegistrationSessionDeps(args: {
  createArgs: CreateSigningEnginePortsArgs;
  nearRpcUrl: string;
}): RegistrationSessionDeps {
  return {
    nearRpcUrl: args.nearRpcUrl,
    touchConfirm: args.createArgs.touchConfirm,
    touchIdPrompt: args.createArgs.touchIdPrompt,
  };
}

export function createThresholdSessionActivationDeps(args: {
  createArgs: CreateSigningEnginePortsArgs;
  getOrCreateActiveThresholdEcdsaSessionId: ThresholdSessionActivationDeps['getOrCreateActiveThresholdEcdsaSessionId'];
}): ThresholdSessionActivationDeps {
  return {
    indexedDB: IndexedDBManager,
    touchIdPrompt: args.createArgs.touchIdPrompt,
    touchConfirm: args.createArgs.touchConfirm,
    getSignerWorkerContext: () => args.createArgs.signerWorkerManager.getContext(),
    getOrCreateActiveThresholdEcdsaSessionId: args.getOrCreateActiveThresholdEcdsaSessionId,
    defaultRelayerUrl: args.createArgs.seamsPasskeyConfigs.network.relayer?.url || '',
    persistThresholdEcdsaBootstrapChainAccount:
      args.createArgs.persistThresholdEcdsaBootstrapChainAccount,
    upsertThresholdEcdsaSessionFromBootstrap: args.createArgs.upsertThresholdEcdsaSessionFromBootstrap,
  };
}

export function createNearKeyOpsDeps(args: CreateSigningEnginePortsArgs): NearKeyOpsDeps {
  return {
    signingKeyOps: args.signerWorkerManager.nearKeyOps,
  };
}
