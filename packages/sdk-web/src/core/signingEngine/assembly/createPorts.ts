import {
  createEmailOtpWarmSessionStatusReader,
  createSigningSessionCoordinatorPort,
} from './ports/emailOtp';
import { createEvmFamilySigningDeps } from './ports/evmFamily';
import { createNearSigningDeps } from './ports/near';
import {
  createRegistrationAccountLifecycleDeps,
  createWalletSessionActivationDeps,
} from './ports/registration';
import { Ed25519YaoActiveClientRegistry } from '../threshold/ed25519/yaoActiveClientRegistry';
import {
  createManagerConveniencePortsFactory,
  createWorkerResourceWarmupDepsFactory,
  resolveNearRpcUrl,
  type CreateSigningEnginePortsArgs,
  type SigningEnginePorts,
} from './ports/shared';

export type {
  CreateSigningEnginePortsArgs,
  SignTempoPortInput,
  SigningEngineConveniencePorts,
  SigningEnginePorts,
} from './ports/shared';

export function createSigningEnginePorts(args: CreateSigningEnginePortsArgs): SigningEnginePorts {
  const ed25519YaoActiveClients = new Ed25519YaoActiveClientRegistry(
    args.ed25519YaoPublicCapabilityReferences,
  );
  const nearRpcUrl = resolveNearRpcUrl(args);
  const getEmailOtpWarmSessionStatus = createEmailOtpWarmSessionStatusReader(args);
  const signingSessionCoordinator = createSigningSessionCoordinatorPort({
    createArgs: args,
    getEmailOtpWarmSessionStatus,
  });
  const getWorkerResourceWarmupDeps = createWorkerResourceWarmupDepsFactory(args, {
    warmupStore: args.stores.warmup.store,
  });
  return {
    ed25519YaoActiveClients,
    nearSigningDeps: createNearSigningDeps({
      createArgs: args,
      nearRpcUrl,
      signingSessionCoordinator,
    }),
    tempoSigningDeps: createEvmFamilySigningDeps({
      createArgs: args,
      walletSignerStore: args.stores.walletProfileAndSignerRecords.walletSignerStore,
      passkeyAuthenticatorStore:
        args.stores.walletProfileAndSignerRecords.passkeyAuthenticatorStore,
      signingSessionCoordinator,
      getEmailOtpWarmSessionStatus,
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
    }),
    signingSessionCoordinator,
    getWorkerResourceWarmupDeps,
    getManagerConveniencePorts: createManagerConveniencePortsFactory({
      createArgs: args,
      getWorkerResourceWarmupDeps,
    }),
  };
}
