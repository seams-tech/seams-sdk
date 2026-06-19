import {
  createEmailOtpWarmSessionStatusReader,
  createSigningSessionCoordinatorPort,
  createWarmThresholdEd25519SessionStatusReader,
} from './ports/emailOtp';
import { createEvmFamilySigningDeps } from './ports/evmFamily';
import { createNearSigningDeps } from './ports/near';
import {
  createRegistrationAccountLifecycleDeps,
  createThresholdEd25519LifecycleDeps,
  createWalletSessionActivationDeps,
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
  const nearRpcUrl = resolveNearRpcUrl(args);
  const getEmailOtpWarmSessionStatus = createEmailOtpWarmSessionStatusReader(args);
  const signingSessionCoordinator = createSigningSessionCoordinatorPort({
    createArgs: args,
    getEmailOtpWarmSessionStatus,
  });
  const getOrCreateActiveThresholdEcdsaSessionId =
    createGetOrCreateActiveThresholdEcdsaSessionId();
  const getWorkerResourceWarmupDeps = createWorkerResourceWarmupDepsFactory(args, {
    warmupStore: args.stores.warmup.store,
  });
  const getWarmThresholdEd25519SessionStatus = createWarmThresholdEd25519SessionStatusReader({
    createArgs: args,
    getEmailOtpWarmSessionStatus,
  });

  return {
    thresholdEd25519LifecycleDeps: createThresholdEd25519LifecycleDeps(args),
    nearSigningDeps: createNearSigningDeps({
      createArgs: args,
      walletSignerStore: args.stores.walletProfileAndSignerRecords.walletSignerStore,
      nearRpcUrl,
      signingSessionCoordinator,
      getEmailOtpWarmSessionStatus,
    }),
    tempoSigningDeps: createEvmFamilySigningDeps({
      createArgs: args,
      walletSignerStore: args.stores.walletProfileAndSignerRecords.walletSignerStore,
      passkeyAuthenticatorStore:
        args.stores.walletProfileAndSignerRecords.passkeyAuthenticatorStore,
      signingSessionCoordinator,
      getEmailOtpWarmSessionStatus,
    }),
    privateKeyExportRecoveryDeps: createPrivateKeyExportRecoveryDeps(args, {
      keyMaterialStore: args.stores.recoveryAndDeviceLinking.keyMaterialStore,
    }),
    registrationAccountLifecycleDeps: createRegistrationAccountLifecycleDeps({
      createArgs: args,
      accountStore: args.stores.walletProfileAndSignerRecords.accountStore,
    }),
    registrationSessionDeps: {
      touchConfirm: args.touchConfirm,
      touchIdPrompt: args.touchIdPrompt,
    },
    walletSessionActivationDeps: createWalletSessionActivationDeps({
      createArgs: args,
      credentialStore: args.stores.recoveryAndDeviceLinking.credentialStore,
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
