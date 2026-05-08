import { IndexedDBManager } from '@/core/indexedDB';
import {
  createEmailOtpWarmSessionStatusReader,
  createSigningSessionCoordinatorPort,
  createWarmThresholdEd25519SessionStatusReader,
} from './ports/emailOtp';
import { createEvmFamilySigningDeps } from './ports/evmFamily';
import { createNearSigningDeps } from './ports/near';
import {
  createNearKeyOpsDeps,
  createRegistrationAccountLifecycleDeps,
  createRegistrationSessionDeps,
  createThresholdEd25519LifecycleDeps,
  createThresholdSessionActivationDeps,
} from './ports/registration';
import { createPrivateKeyExportRecoveryDeps } from './ports/recovery';
import {
  createGetOrCreateActiveThresholdEcdsaSessionId,
  createManagerConveniencePortsFactory,
  createResolveCanonicalThresholdEcdsaSessionIdForChain,
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
  const nearRpcUrl = resolveNearRpcUrl(args);
  const getEmailOtpWarmSessionStatus = createEmailOtpWarmSessionStatusReader(args);
  const signingSessionCoordinator = createSigningSessionCoordinatorPort({
    createArgs: args,
    getEmailOtpWarmSessionStatus,
  });
  const getOrCreateActiveThresholdEcdsaSessionId =
    createGetOrCreateActiveThresholdEcdsaSessionId();
  const getWorkerResourceWarmupDeps = createWorkerResourceWarmupDepsFactory(args);
  const getWarmThresholdEd25519SessionStatus = createWarmThresholdEd25519SessionStatusReader({
    createArgs: args,
    getEmailOtpWarmSessionStatus,
  });

  return {
    indexedDB: IndexedDBManager,
    thresholdEd25519LifecycleDeps: createThresholdEd25519LifecycleDeps(args),
    nearSigningDeps: createNearSigningDeps({
      createArgs: args,
      nearRpcUrl,
      signingSessionCoordinator,
      getEmailOtpWarmSessionStatus,
    }),
    tempoSigningDeps: createEvmFamilySigningDeps({
      createArgs: args,
      signingSessionCoordinator,
      getEmailOtpWarmSessionStatus,
    }),
    privateKeyExportRecoveryDeps: createPrivateKeyExportRecoveryDeps(args),
    registrationAccountLifecycleDeps: createRegistrationAccountLifecycleDeps(args),
    registrationSessionDeps: createRegistrationSessionDeps({
      createArgs: args,
      nearRpcUrl,
    }),
    thresholdSessionActivationDeps: createThresholdSessionActivationDeps({
      createArgs: args,
      getOrCreateActiveThresholdEcdsaSessionId,
    }),
    nearKeyOpsDeps: createNearKeyOpsDeps(args),
    resolveCanonicalThresholdEcdsaSessionIdForChain:
      createResolveCanonicalThresholdEcdsaSessionIdForChain(args),
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
