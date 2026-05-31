import { getBrowserPlatformIndexedDB } from '@/core/platform';
import {
  createEmailOtpWarmSessionStatusReader,
  createSigningSessionCoordinatorPort,
  createWarmThresholdEd25519SessionStatusReader,
} from './ports/emailOtp';
import { createEvmFamilySigningDeps } from './ports/evmFamily';
import { createNearSigningDeps } from './ports/near';
import {
  createThresholdEd25519LifecycleDeps,
  createThresholdSessionActivationDeps,
} from './ports/registration';
import { createPrivateKeyExportRecoveryDeps } from './ports/recovery';
import {
  createGetOrCreateActiveThresholdEcdsaSessionId,
  createManagerConveniencePortsFactory,
  createResolveCanonicalThresholdEcdsaSessionIdForWalletTarget,
  createWorkerResourceWarmupDepsFactory,
  resolveNearRpcUrl,
  type CreateSigningEnginePortsArgs,
  type SigningEnginePorts,
} from './ports/shared';

export type {
  CreateSigningEnginePortsArgs,
  NearKeyOpsDeps,
  SignTempoPortInput,
  SigningEngineConveniencePorts,
  SigningEnginePorts,
} from './ports/shared';

export function createSigningEnginePorts(
  args: CreateSigningEnginePortsArgs,
): SigningEnginePorts {
  const indexedDB = getBrowserPlatformIndexedDB(args.platformRuntime);
  const runtimeDeps = { indexedDB };
  const nearRpcUrl = resolveNearRpcUrl(args);
  const getEmailOtpWarmSessionStatus = createEmailOtpWarmSessionStatusReader(args);
  const signingSessionCoordinator = createSigningSessionCoordinatorPort({
    createArgs: args,
    getEmailOtpWarmSessionStatus,
  });
  const getOrCreateActiveThresholdEcdsaSessionId =
    createGetOrCreateActiveThresholdEcdsaSessionId();
  const getWorkerResourceWarmupDeps = createWorkerResourceWarmupDepsFactory(args, runtimeDeps);
  const getWarmThresholdEd25519SessionStatus = createWarmThresholdEd25519SessionStatusReader({
    createArgs: args,
    getEmailOtpWarmSessionStatus,
  });

  return {
    indexedDB,
    thresholdEd25519LifecycleDeps: createThresholdEd25519LifecycleDeps(args),
    nearSigningDeps: createNearSigningDeps({
      createArgs: args,
      indexedDB,
      nearRpcUrl,
      signingSessionCoordinator,
      getEmailOtpWarmSessionStatus,
    }),
    tempoSigningDeps: createEvmFamilySigningDeps({
      createArgs: args,
      indexedDB,
      signingSessionCoordinator,
      getEmailOtpWarmSessionStatus,
    }),
    privateKeyExportRecoveryDeps: createPrivateKeyExportRecoveryDeps(args, runtimeDeps),
    registrationAccountLifecycleDeps: {
      indexedDB,
      userPreferencesManager: args.userPreferencesManager,
      nonceCoordinator: args.nonceCoordinator,
      extractCosePublicKey: args.extractCosePublicKey,
    },
    registrationSessionDeps: {
      touchConfirm: args.touchConfirm,
      touchIdPrompt: args.touchIdPrompt,
    },
    thresholdSessionActivationDeps: createThresholdSessionActivationDeps({
      createArgs: args,
      indexedDB,
      getOrCreateActiveThresholdEcdsaSessionId,
    }),
    nearKeyOpsDeps: {
      signingKeyOps: args.signerWorkerManager.nearKeyOps,
    },
    resolveCanonicalThresholdEcdsaSessionIdForWalletTarget:
      createResolveCanonicalThresholdEcdsaSessionIdForWalletTarget(args),
    signingSessionCoordinator,
    getWorkerResourceWarmupDeps,
    getManagerConveniencePorts: createManagerConveniencePortsFactory({
      createArgs: args,
      getWorkerResourceWarmupDeps,
      getEmailOtpWarmSessionStatus,
      getWarmThresholdEd25519SessionStatus,
    }),
  };
}
